#!/usr/bin/env python3
"""Run built areas sequentially through the disposable Wine wrapper; never an oracle."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def run_command(command, *, cwd, env, stream, timeout, grace=30):
    # A blocked copy/cleanup command must not survive the wrapper's hard deadline.
    proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                            stderr=subprocess.STDOUT, start_new_session=True)
    try:
        return proc.wait(timeout=timeout), False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        return 124, True


def row_failed(row):
    return (not row['completed'] or row['exit_code'] != 0 or
            row.get('failed', 0) != 0 or row.get('checks_fail', 0) != 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--results', type=Path, default=Path('results/wine'))
    parser.add_argument('--destructive', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.timeout <= 3600:
        parser.error('--timeout must be 1..3600')
    root = Path(__file__).resolve().parent.parent
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    # Invalidate previous success before any launch can fail or be interrupted.
    (results / 'run.json').write_text('[]\n')
    env = dict(os.environ, TP_TIMEOUT=str(args.timeout), TMPDIR='/tmp/opencode')
    rows = []
    for exe in sorted((root / 'build').glob('*.exe')):
        if exe.stem.startswith('dx_') and not args.destructive:
            continue
        start = time.monotonic()
        timed_out = False
        log = results / (exe.stem + '.txt')
        with log.open('w') as stream:
            # The wrapper owns process-tree cleanup and has its own inner timeout.
            code, timed_out = run_command([str(root / 'tools/wine_run.sh'), str(exe)],
                                         cwd=root, env=env, stream=stream,
                                         timeout=args.timeout + 60)
        text = log.read_text(errors='replace')
        summaries = re.findall(r'^SUMMARY tests=(\d+) failed=(\d+) skipped=(\d+) checks_pass=(\d+) checks_fail=(\d+)\s*$', text, re.M)
        row = dict(area=exe.stem, exit_code=code, timeout=timed_out or code in (124, 137),
                   seconds=round(time.monotonic() - start, 3), log=str(log))
        if len(summaries) == 1:
            row.update(zip(('tests', 'failed', 'skipped', 'checks_pass', 'checks_fail'), map(int, summaries[0])))
        row['completed'] = (len(summaries) == 1 and len(re.findall(r'^SUMMARY\b', text, re.M)) == 1
                            and row.get('tests', 0) > 0
                            and row.get('failed', 0) + row.get('skipped', 0) <= row.get('tests', 0)
                            and not row['timeout'] and code in (0, 1))
        rows.append(row)
        print(json.dumps(row), flush=True)
    if not rows:
        parser.error('no build/*.exe; run make first')
    (results / 'run.json').write_text(json.dumps(rows, indent=2) + '\n')
    return int(any(row_failed(r) for r in rows))


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run built areas sequentially through the disposable Wine wrapper; never an oracle."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time


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
            proc = subprocess.Popen([str(root / 'tools/wine_run.sh'), str(exe)], cwd=root,
                                    env=env, stdout=stream, stderr=subprocess.STDOUT)
            try:
                code = proc.wait(timeout=args.timeout + 60)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                code = 124
        text = log.read_text(errors='replace')
        summaries = re.findall(r'^SUMMARY tests=(\d+) failed=(\d+) skipped=(\d+) checks_pass=(\d+) checks_fail=(\d+)\s*$', text, re.M)
        row = dict(area=exe.stem, exit_code=code, timeout=timed_out or code == 124,
                   seconds=round(time.monotonic() - start, 3), log=str(log))
        if len(summaries) == 1:
            row.update(zip(('tests', 'failed', 'skipped', 'checks_pass', 'checks_fail'), map(int, summaries[0])))
        row['completed'] = len(summaries) == 1 and not row['timeout'] and code in (0, 1)
        rows.append(row)
        print(json.dumps(row), flush=True)
    if not rows:
        parser.error('no build/*.exe; run make first')
    (results / 'run.json').write_text(json.dumps(rows, indent=2) + '\n')
    return int(any(not r['completed'] or r.get('failed', 0) for r in rows))


if __name__ == '__main__':
    raise SystemExit(main())

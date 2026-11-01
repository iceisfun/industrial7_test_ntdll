#!/usr/bin/env python3
"""Bind an integrated Wine run to source/binary hashes without calling it a Windows pass."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, default=Path('results/wine/run.json'))
    parser.add_argument('--audit', type=Path, default=Path('results/build_audit.json'))
    parser.add_argument('--out', type=Path, default=Path('validation/wine-summary.json'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    rows = json.loads(args.run.read_text())
    audit = json.loads(args.audit.read_text())
    failures = []
    for row in rows:
        log = Path(row['log'])
        row['log_sha256'] = digest(log)
        row['executable_sha256'] = digest(root / 'build' / (row['area'] + '.exe'))
        current = ''
        for line in log.read_text(errors='replace').splitlines():
            if line.startswith('RUN '):
                current = line[5:].strip()
            elif line.startswith('  FAIL'):
                failures.append(dict(area=row['area'], test=current, detail=line.strip()))
    sources = [root / 'Makefile'] + sorted(p for directory in ('common', 'tests', 'tools') for p in (root / directory).rglob('*')
                                          if p.suffix in ('.c', '.h', '.inc', '.py', '.sh', '.bat', '.ps1'))
    source_hashes = {str(p.relative_to(root)): digest(p) for p in sources}
    totals = {key: sum(row.get(key, 0) for row in rows) for key in ('tests', 'failed', 'skipped', 'checks_pass', 'checks_fail')}
    audit_counts = {r['area']: r['tests'] for r in audit['areas']}
    counts_match = (len(rows) == len(audit['areas']) == len({r['area'] for r in rows})
                    and audit_counts == {r['area']: r.get('tests') for r in rows})
    wine = os.environ.get('WINE', str(Path.home() / 'work/wine/proton-ge-custom/build/dist/files/bin/wine'))
    report = dict(
        generated_utc=datetime.now(timezone.utc).isoformat(),
        source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        authority='Wine smoke validation only; not native Windows conformance',
        provenance_caveat='Commit/source/binary/log hashes describe files at recording time. Use an unchanged clean-build/run/record sequence; the recorder alone cannot prove historical compiler or execution provenance.',
        command='python3 tools/smoke_all.py --timeout 120 --results results/wine',
        compiler=subprocess.check_output(['x86_64-w64-mingw32-gcc', '--version'], text=True).splitlines()[0],
        wine_path=wine, wine_version=subprocess.check_output([wine, '--version'], text=True).strip(),
        totals=totals, all_areas_completed=bool(rows) and counts_match and all(r['completed'] for r in rows),
        all_checks_pass=bool(rows) and counts_match and not audit['errors'] and all(
            r['completed'] and r['exit_code'] == 0 and r.get('failed') == 0 and r.get('checks_fail') == 0 for r in rows),
        compiled_runtime_test_counts_match=counts_match, build_audit=audit,
        source_hashes=source_hashes, areas=rows, failed_checks=failures,
        windows_validation_performed=False, powershell_runner_executed=False)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(totals=totals, areas=len(rows), completed=report['all_areas_completed'], counts_match=counts_match)))
    return int(bool(audit['errors']) or not report['all_areas_completed'] or not counts_match)


if __name__ == '__main__':
    raise SystemExit(main())

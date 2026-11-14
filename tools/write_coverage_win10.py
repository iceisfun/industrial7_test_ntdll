#!/usr/bin/env python3
"""Render COVERAGE.md from tools/coverage.json, tools/uncovered_justified.txt and per-area
Windows 10 result logs (one directory per run mode, each holding <area>.txt with a SUMMARY line).

  python3 tools/write_coverage_win10.py --adm DIR --std DIR [--out COVERAGE.md]

Counts come from the tooling and logs only. The static inventory is source-level (not proof of
behavior); per-area numbers are what the Windows 10 guest actually reported.
"""
import argparse
import json
import re
from pathlib import Path

SUM = re.compile(r'SUMMARY tests=(\d+) failed=(\d+) skipped=(\d+) checks_pass=(\d+) checks_fail=(\d+)')


def load_run(d):
    rows = {}
    for f in sorted(Path(d).glob('*.txt')):
        if f.name == 'oracle.log' or f.name.startswith('make-'):
            continue
        m = SUM.findall(f.read_text(errors='replace'))
        rows[f.stem] = tuple(map(int, m[-1])) if m else None
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adm', required=True)
    p.add_argument('--std', required=True)
    p.add_argument('--out', default='COVERAGE.md')
    a = p.parse_args()
    root = Path(__file__).resolve().parent.parent
    cov = json.loads((root / 'tools/coverage.json').read_text())
    adm, std = load_run(a.adm), load_run(a.std)
    justified = {}
    for line in (root / 'tools/uncovered_justified.txt').read_text().splitlines():
        if line and not line.startswith('#') and '\t' in line:
            n, r = line.split('\t', 1)
            justified[n] = r
    not_invoked = set(cov['not_invoked'])
    just = {n: r for n, r in justified.items() if n in not_invoked}
    untested = sorted(not_invoked - set(just))
    areas = sorted(set(adm) | set(std))

    def tot(rows):
        t = [0] * 5
        for v in rows.values():
            if v:
                t = [x + y for x, y in zip(t, v)]
        return t

    ta, ts = tot(adm), tot(std)
    L = ['# Coverage', '',
         'Windows 10 22H2 is the oracle. Per-area numbers below are the SUMMARY lines of runs on a Windows 10 guest (build 19045, ntdll 10.0.19041.2788); '
         'see [VALIDATION.md](VALIDATION.md). Export counts are a **static source-level inventory** (`tools/coverage.py --preprocess`): they show an export is invoked, not that its assertions are deep.', '',
         '- Reference: ntdll 10.0.19041.2788, 2,433 exports (2,432 named, one ordinal-only).',
         '- %d areas (executables), %d tests run (administrator), %d tests run (standard user).' % (len(areas), ta[0], ts[0]),
         '- %d of 2,432 named exports have a static invocation candidate; %d do not.' % (cov['static_invocation_candidates'], len(not_invoked)),
         '- Of the %d without one: **%d justified** (`tools/uncovered_justified.txt`, with a reason each) and **%d untested** (`tools/uncovered.txt` minus the justified list).' % (len(not_invoked), len(just), len(untested)),
         '- Nt/Zw pairs share an RVA: behavior is tested through one name and the alias relationship is asserted; `export_surface` checks are existence/alias integrity and are not behavioral coverage.', '',
         '## Areas on Windows 10 (administrator / standard user)', '',
         '| Area | Tests adm | Failed adm | Skipped adm | Checks adm pass/fail | Tests std | Failed std | Skipped std | Checks std pass/fail |',
         '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for ar in areas:
        x, y = adm.get(ar), std.get(ar)
        fx = '%d | %d | %d | %d / %d' % x if x else 'no summary | - | - | -'
        fy = '%d | %d | %d | %d / %d' % y if y else 'no summary | - | - | -'
        L.append('| [%s](tests/%s/) | %s | %s |' % (ar, ar, fx, fy))
    L += ['', '| Total | %d | %d | %d | %d / %d | %d | %d | %d | %d / %d |' % (tuple(ta) + tuple(ts)), '',
          'Most areas have `tests/<area>/EVIDENCE.md`: where each expected value came from (documentation, decompilation of the 22H2 binary, or observed Windows 10 behavior), skips and why.', '',
          '## Justified without a behavioral test', '',
          'These exports are deliberately not exercised (no service connection, unsafe even in a disposable VM, or not meaningfully callable). Reasons are in `tools/uncovered_justified.txt`; this is a separate category from untested.', '',
          '%d exports: %s' % (len(just), ', '.join('`%s`' % n for n in sorted(just))), '',
          '## Untested (remaining gaps)', '',
          '%d exports have neither a test nor a recorded reason; the full list is the difference of `tools/uncovered.txt` and `tools/uncovered_justified.txt`.' % len(untested), '',
          '## Limits', '',
          '- Static candidates are not proof of executed, asserted, deep or correct behavior; depth on already-covered exports (error paths, boundaries, races) is ongoing work.',
          '- Destructive and special-setup tests are not part of this corpus yet (SOW section 5: needs an opt-in area).',
          '- Only build 19045 was available as a baseline; other Windows 10 builds, locales and SKUs are unverified.',
          '- Ordinal-only export 8 is never invoked.', '',
          'Regenerate: `python3 tools/coverage.py --preprocess`, run all areas on a Windows 10 guest (administrator and standard user), then `python3 tools/write_coverage_win10.py --adm <dir> --std <dir>`.', '']
    (root / a.out).write_text('\n'.join(L))
    print('wrote', a.out, 'areas', len(areas), 'justified', len(just), 'untested', len(untested))


if __name__ == '__main__':
    main()

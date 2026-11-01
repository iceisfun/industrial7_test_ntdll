#!/usr/bin/env python3
"""Aggregate harness logs; missing/duplicate summaries and failed checks fail the command."""
import argparse
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results', type=Path)
    parser.add_argument('--failures', action='store_true')
    args = parser.parse_args()
    totals = [0] * 5
    incomplete = 0
    files = [p for p in sorted(args.results.glob('*.txt')) if not p.name.endswith('.stderr.txt')]
    for path in files:
        text = path.read_text(errors='replace')
        matches = re.findall(r'^SUMMARY tests=(\d+) failed=(\d+) skipped=(\d+) checks_pass=(\d+) checks_fail=(\d+)\s*$', text, re.M)
        if len(matches) != 1 or len(re.findall(r'^SUMMARY\b', text, re.M)) != 1:
            print('%-32s INCOMPLETE (summary count=%d)' % (path.name, len(matches)))
            incomplete += 1
            continue
        values = list(map(int, matches[0]))
        if not values[0] or values[1] + values[2] > values[0]:
            print('%-32s INCOMPLETE (invalid test counts)' % path.name)
            incomplete += 1
            continue
        totals = [a + b for a, b in zip(totals, values)]
        print('%-32s tests=%d failed=%d skipped=%d checks_pass=%d checks_fail=%d' % (path.name, *values))
        if args.failures:
            current = ''
            for line in text.splitlines():
                if line.startswith('RUN '):
                    current = line[5:]
                elif line.startswith('  FAIL'):
                    print('%s: %s: %s' % (path.name, current, line.strip()))
    manifest = args.results / 'run.json'
    if manifest.exists():
        try:
            rows = json.loads(manifest.read_text(encoding='utf-8-sig'))
            if not isinstance(rows, list) or not rows:
                raise ValueError('expected a nonempty run array')
            for row in rows:
                code = row.get('exit_code', row.get('exitCode'))
                if (code != 0 or row.get('timeout') or row.get('completed') is False or
                        row.get('ok') is False or
                        row.get('area') not in {p.stem for p in files}):
                    print('RUN INCOMPLETE/FAILED: %s' % row.get('area', '<unknown>'))
                    incomplete += 1
        except (ValueError, TypeError, AttributeError) as error:
            print('INVALID run.json: %s' % error)
            incomplete += 1
    print('TOTAL tests=%d failed=%d skipped=%d checks_pass=%d checks_fail=%d incomplete=%d' % (*totals, incomplete))
    return int(not files or incomplete > 0 or totals[1] > 0 or totals[4] > 0)


if __name__ == '__main__':
    raise SystemExit(main())

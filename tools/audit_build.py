#!/usr/bin/env python3
"""Check built test inventory and reject static imports of ntdll.dll."""
import collections
import json
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parent.parent
rows, names, children, errors = [], collections.defaultdict(list), collections.defaultdict(list), []
for exe in sorted((root / 'build').glob('*.exe')):
    symbols = subprocess.check_output(['x86_64-w64-mingw32-nm', '--defined-only', str(exe)], text=True)
    tests = re.findall(r'^\S+ [tT] test_(\w+)$', symbols, re.M)
    child = re.findall(r'^\S+ [tT] child_(\w+)$', symbols, re.M)
    for name in tests:
        names[name].append(exe.stem)
    for name in child:
        children[name].append(exe.stem)
    pe = subprocess.check_output(['x86_64-w64-mingw32-objdump', '-p', str(exe)], text=True)
    imports = re.findall(r'DLL Name: (\S+)', pe)
    if 'ntdll.dll' in {name.lower() for name in imports}:
        errors.append('%s statically imports ntdll.dll' % exe.name)
    if not tests:
        errors.append('%s has no registered test functions' % exe.name)
    rows.append(dict(area=exe.stem, tests=len(tests), children=len(child), imports=imports))
for kind, entries in [('TEST', names), ('CHILD', children)]:
    errors.extend('%s collision %s: %s' % (kind, name, ', '.join(areas)) for name, areas in entries.items() if len(areas) > 1)
if not rows:
    errors.append('no build/*.exe')
missing = {p.name for p in (root / 'tests').iterdir() if p.is_dir()} - {r['area'] for r in rows}
errors.extend('missing executable for %s' % name for name in sorted(missing))
report = dict(areas=rows, total_tests=sum(r['tests'] for r in rows), errors=errors)
print(json.dumps(report, indent=2))
raise SystemExit(bool(errors))

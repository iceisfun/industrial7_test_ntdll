#!/usr/bin/env python3
"""Conservative source inventory, not execution coverage or proof of checked behavior.

Detects direct U/UN/UIN invocations and locally assigned resolved pointers followed
by a textual call. Comments and resolution-only REQUIREs do not count as calls.
Macro-built names, helper indirection and aliases may require manual refinement.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess


def strip_comments(text):
    token = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*', re.S)
    return token.sub(lambda m: ('\n' * m[0].count('\n') or ' ') if m[0].startswith(('/', '/*')) else m[0], text)


def preprocessed_test_source(root, path):
    output = subprocess.check_output(['x86_64-w64-mingw32-gcc', '-E', '-O1', '-Icommon', str(path)], cwd=root, text=True)
    selected, active = [], False
    for line in output.splitlines():
        marker = re.match(r'#\s+\d+\s+"([^"]+)"', line)
        if marker:
            origin = Path(marker[1])
            if not origin.is_absolute():
                origin = root / origin
            active = origin.resolve().is_relative_to(root / 'tests')
        elif active:
            selected.append(line)
    return '\n'.join(selected)


def inventory(root, preprocess=False):
    exports = set((root / 'tools/ntdll_exports.txt').read_text().splitlines())
    called, resolved = {}, {}
    resolver = r'(?:\b(?:U|UN)\s*\(\s*(?P<plain>\w+)\s*\)|\bUIN\s*\(\s*"[^"]+"\s*,\s*(?P<pinned>\w+)\s*\)|\bt_proc(?:_in)?\s*\(\s*(?:"[^"]+"\s*,\s*)?"(?P<quoted>\w+)"\s*\))'
    paths = sorted(p for p in (root / 'tests').rglob('*') if p.suffix in ('.c', '.h'))
    sources = [(p, p.read_text(), False) for p in paths]
    if preprocess:
        sources += [(p, preprocessed_test_source(root, p), True) for p in paths if p.suffix == '.c']
    for path, source, expanded in sources:
        text = strip_comments(source)
        literals = list(re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', text))
        code = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', lambda m: ' ' * len(m[0]), text)
        for match in re.finditer(resolver, text):
            if any(literal.start() <= match.start() < literal.end() for literal in literals):
                continue
            name = next(value for value in match.groupdict().values() if value)
            if name not in exports:
                continue
            location = '%s:%d' % (path.relative_to(root), text.count('\n', 0, match.start()) + 1)
            if expanded:
                location = '%s [preprocessed; not an original line number]' % path.relative_to(root)
            resolved.setdefault(name, set()).add(location)
            tail = text[match.end():]
            if re.match(r'\s*\(', tail) or (expanded and re.match(r'\s*(?:\)\s*)+\(', tail)):
                called.setdefault(name, set()).add(location)
                continue
            # Restrict alias inference to the same source file and exact variable spelling.
            prefix = text[max(0, match.start() - 200):match.start()]
            assignment = re.search(r'([A-Za-z_]\w*(?:\s*(?:\.|->)\s*[A-Za-z_]\w*)?)\s*=\s*(?:\([^;=]*\)\s*)?$', prefix)
            if assignment:
                variable = re.sub(r'\s+', '', assignment[1])
                if re.search(r'(?<![\w])' + re.escape(variable) + r'\s*\(', code):
                    called.setdefault(name, set()).add(location)
    public_path = root / 'tools/public_surface.txt'
    public = set(public_path.read_text().splitlines()) & exports if public_path.exists() else set()
    evidence_path = root / 'tools/public_surface_evidence.json'
    evidence = json.loads(evidence_path.read_text()) if evidence_path.exists() else {}
    full = {name for name, record in evidence.get('exports', {}).items()
            if any(doc.get('contract') == 'full' for doc in record['docs'])} & exports
    return dict(total_named_exports=len(exports), static_invocation_candidates=len(called), preprocessed=preprocess,
                documented_surface=len(public), documented_invocation_candidates=len(public & called.keys()),
                full_user_contract_surface=len(full), full_user_contract_invocation_candidates=len(full & called.keys()),
                full_user_contract_not_invoked=sorted(full - called.keys()),
                calls={name: sorted(locations) for name, locations in sorted(called.items())},
                resolutions={name: sorted(locations) for name, locations in sorted(resolved.items())},
                not_invoked=sorted(exports - called.keys()), documented_not_invoked=sorted(public - called.keys()),
                caveat='Static candidate inventory only: does not prove runtime execution, assertions, depth or Windows correctness. Macro-generated names and indirect helpers can be missed. Export manifest sweep deliberately excluded.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path, nargs='?', default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--preprocess', action='store_true', help='also expand test macros with the build compiler (no execution)')
    args = parser.parse_args()
    root = args.root.resolve()
    data = inventory(root, preprocess=args.preprocess)
    (root / 'tools/coverage.json').write_text(json.dumps(data, indent=2) + '\n')
    for filename, names in [('uncovered.txt', data['not_invoked']), ('public_uncovered.txt', data['documented_not_invoked']),
                            ('full_user_uncovered.txt', data['full_user_contract_not_invoked'])]:
        (root / 'tools' / filename).write_text('\n'.join(names) + ('\n' if names else ''))
    print('%d named exports; %d static invocation candidates; %d documented names, %d documented invocation candidates' %
          (data['total_named_exports'], data['static_invocation_candidates'], data['documented_surface'], data['documented_invocation_candidates']))
    print(data['caveat'])


if __name__ == '__main__':
    main()

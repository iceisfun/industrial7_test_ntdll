#!/usr/bin/env python3
"""Render coverage/validation reports from recorded evidence, not source TEST counts."""
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
coverage = json.loads((root / 'tools/coverage.json').read_text())
validation = json.loads((root / 'validation/wine-summary.json').read_text())
totals = validation['totals']
rows = validation['areas']
lines = ['# Coverage', '',
         '**Initial broad corpus, not complete ntdll conformance.** Counts below come from compiled test symbols and the integrated smoke summaries, including macro-generated cases.', '',
         '- Reference: ntdll 10.0.19041.2788, 2,433 exports (2,432 named, one ordinal-only).',
         '- %d executables, %d compiled/runtime tests in this smoke pass.' % (len(rows), totals['tests']),
         '- %d named exports have static invocation candidates; %d do not.' % (coverage['static_invocation_candidates'], len(coverage['not_invoked'])),
         '- %d names in the documentation-derived surface; %d have static invocation candidates.' % (coverage['documented_surface'], coverage['documented_invocation_candidates']), '',
         '- Of those, %d names have full user-context documentation matches; %d have static invocation candidates. The remaining documentation matches are partial/variant/kernel-context evidence, not full user-mode contracts.' % (coverage['full_user_contract_surface'], coverage['full_user_contract_invocation_candidates']), '',
         'These are **source-level candidates**, not proof of executed, asserted, deep, or Windows-correct behavior. Resolution-only checks do not count as calls. Macro-built names/helper indirection can be missed. See `tools/coverage.json` for detected source locations, `tools/uncovered.txt` for all static gaps, `tools/public_uncovered.txt` for documentation-surface gaps, and `tools/full_user_uncovered.txt` for full-user-context gaps.', '',
         'The documented surface is derived reproducibly by `tools/map_public_surface.py`; its evidence distinguishes user-mode contracts from partial/kernel-context documentation. Header presence alone is not a behavioral contract. Consult `tools/public_surface_evidence.json` and `tools/public_surface_gaps.txt` before interpreting a denominator.', '',
         '## Areas and integrated Wine smoke', '',
         '| Area | Tests | Failed | Skipped | Checks pass/fail | Completed |',
         '|---|---:|---:|---:|---:|---|']
for row in rows:
    lines.append('| [%s](tests/%s/) | %d | %d | %d | %d / %d | %s |' %
                 (row['area'], row['area'], row.get('tests', 0), row.get('failed', 0), row.get('skipped', 0),
                  row.get('checks_pass', 0), row.get('checks_fail', 0), 'yes' if row['completed'] else '**NO**'))
lines += ['', 'Most behavioral areas include `tests/<area>/EVIDENCE.md` with actual contract branches/URLs, reviewer changes, failure classifications and gaps. `core_smoke` and `harness_checks` test infrastructure; `export_surface` is export/alias integrity, **not behavioral API coverage**. Their checks are included in totals but must not inflate behavioral coverage claims.', '',
          '## Explicit limits and next depth pass', '',
          '- Native Windows results remain outstanding; current failure triage is static Windows evidence plus Wine smoke, not runtime confirmation.',
          '- Resolve-only handling of unknown signatures and ordinal 8 is deliberate; they are never invoked.',
          '- Exhaustive syscall validation/ordering, ALPC/LPC, ETW, transactions, loader internals, WNF, activation contexts, exception/unwind edge cases, advanced threadpool/I/O and undocumented internal RTL families remain gap/depth work.',
          '- Locale/NLS/DBCS, alternate architecture, privilege/elevation, hardware/SKU, alternate heap modes, real-world filesystem and cross-process races need dedicated passes.',
          '- No shutdown, account/security disabling, raw-disk or system-process destructive tests are included.', '',
          'Regenerate after a clean build/run:', '', '```sh', 'python3 tools/coverage.py',
          'python3 tools/audit_build.py > results/build_audit.json', 'python3 tools/record_validation.py', 'python3 tools/write_reports.py', '```', '']
(root / 'COVERAGE.md').write_text('\n'.join(lines))

lines = ['# Integrated validation', '',
         '**Wine smoke only; native Windows and the PowerShell runner have not been executed here.**', '',
         '- Source commit recorded after the clean build/run sequence: `%s`.' % validation['source_commit'],
         '- Recorded UTC: `%s`.' % validation['generated_utc'],
         '- Compiler: `%s`.' % validation['compiler'],
         '- Wine executable: `%s`.' % validation['wine_path'],
         '- Wine version: `%s`.' % validation['wine_version'],
         '- Command: `%s`.' % validation['command'], '',
         '## Result', '',
         '- %d executables; %d tests; %d failed tests; %d skipped tests.' % (len(rows), totals['tests'], totals['failed'], totals['skipped']),
         '- %d passing checks; %d failing checks.' % (totals['checks_pass'], totals['checks_fail']),
         '- Every area completed: **%s**. Every check passed: **%s**.' % ('yes' if validation['all_areas_completed'] else 'NO', 'yes' if validation['all_checks_pass'] else 'NO'),
         '- Compiled/runtime test counts agree: **%s**. Build-audit errors: **%d**.' % ('yes' if validation['compiled_runtime_test_counts_match'] else 'NO', len(validation['build_audit']['errors'])), '',
         'The smoke command exits nonzero when checks fail. Those failures are not hidden or reported as a conformance pass. Area evidence records Windows-supported expectations and the reviewed Wine discrepancies. **A real Windows baseline is still required to confirm every classification.**', '',
         'Per-area counts are in [COVERAGE.md](COVERAGE.md). `validation/wine-summary.json` records exact source/binary/log SHA-256 hashes, exit codes, durations, imports and failed-check text. Full stdout logs remain at the paths recorded there (local `results/wine/`, ignored by Git).', '',
         'Provenance limit: hashes and commit are captured at recording time. The integration sequence must keep sources and binaries unchanged between clean build, smoke and recording; the recorder alone does not prove which historical files produced a log.', '',
         '## Reproduce', '', '```sh', 'make clean', 'make -j8',
         'PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools -p "test_*.py"',
         'mkdir -p results', 'python3 tools/audit_build.py > results/build_audit.json',
         'python3 tools/smoke_all.py --timeout 120 --results results/wine',
         '# A nonzero smoke exit is expected while reviewed Wine differences remain.',
         'python3 tools/summarize.py results/wine --failures', 'python3 tools/record_validation.py', '```', '',
         '## Not verified here', '',
         '- Genuine Windows 10 standard-user/admin execution and exact reference-DLL strict export sweep.',
         '- Windows PowerShell process-tree timeout behavior; source-reviewed only because PowerShell is unavailable on this Linux host.',
         '- Hostile filesystem races during path-based scratch cleanup; child-helper timeout kills the direct child, not arbitrary descendants. The corpus is for disposable VMs, not a security sandbox.',
         '- Full correctness of static coverage inference or all version/environment-dependent behavior.', '',
         'See [HANDOFF.md](HANDOFF.md) for Windows execution, collection and triage.', '']
(root / 'VALIDATION.md').write_text('\n'.join(lines))

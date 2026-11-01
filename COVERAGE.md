# Coverage

**Initial broad corpus, not complete ntdll conformance.** Counts below come from compiled test symbols and the integrated smoke summaries, including macro-generated cases.

- Reference: ntdll 10.0.19041.2788, 2,433 exports (2,432 named, one ordinal-only).
- 29 executables, 1640 compiled/runtime tests in this smoke pass.
- 337 named exports have static invocation candidates; 2095 do not.
- 613 names in the documentation-derived surface; 189 have static invocation candidates.

- Of those, 158 names have full user-context documentation matches; 52 have static invocation candidates. The remaining documentation matches are partial/variant/kernel-context evidence, not full user-mode contracts.

These are **source-level candidates**, not proof of executed, asserted, deep, or Windows-correct behavior. Resolution-only checks do not count as calls. This inventory also uses compiler preprocessing to expand test macros; indirect helpers/aliases may still require manual review. Expanded locations are explicitly not original source line numbers. See `tools/coverage.json` for detected source locations, `tools/uncovered.txt` for all static gaps, `tools/public_uncovered.txt` for documentation-surface gaps, and `tools/full_user_uncovered.txt` for full-user-context gaps.

The documented surface is derived reproducibly by `tools/map_public_surface.py`; its evidence distinguishes user-mode contracts from partial/kernel-context documentation. Header presence alone is not a behavioral contract. Consult `tools/public_surface_evidence.json` and `tools/public_surface_gaps.txt` before interpreting a denominator.

## Areas and integrated Wine smoke

| Area | Tests | Failed | Skipped | Checks pass/fail | Completed |
|---|---:|---:|---:|---:|---|
| [core_smoke](tests/core_smoke/) | 3 | 0 | 0 | 4 / 0 | yes |
| [crt_algorithms](tests/crt_algorithms/) | 159 | 0 | 0 | 45166 / 0 | yes |
| [crt_strings](tests/crt_strings/) | 181 | 2 | 0 | 741 / 2 | yes |
| [export_surface](tests/export_surface/) | 5 | 0 | 0 | 5905 / 0 | yes |
| [harness_checks](tests/harness_checks/) | 11 | 0 | 1 | 39 / 0 | yes |
| [ldr_image](tests/ldr_image/) | 44 | 2 | 0 | 95 / 6 | yes |
| [nt_file](tests/nt_file/) | 50 | 0 | 0 | 383 / 0 | yes |
| [nt_process](tests/nt_process/) | 47 | 12 | 0 | 258 / 21 | yes |
| [nt_registry](tests/nt_registry/) | 42 | 0 | 0 | 449 / 0 | yes |
| [nt_sync](tests/nt_sync/) | 69 | 7 | 0 | 685 / 9 | yes |
| [nt_token](tests/nt_token/) | 28 | 7 | 0 | 518 / 14 | yes |
| [nt_vm](tests/nt_vm/) | 52 | 5 | 0 | 489 / 5 | yes |
| [rtl_bitmap](tests/rtl_bitmap/) | 41 | 2 | 1 | 1768 / 12 | yes |
| [rtl_compression](tests/rtl_compression/) | 45 | 4 | 7 | 829 / 4 | yes |
| [rtl_context](tests/rtl_context/) | 25 | 1 | 0 | 230 / 1 | yes |
| [rtl_conversion](tests/rtl_conversion/) | 81 | 8 | 0 | 1282 / 11 | yes |
| [rtl_environment](tests/rtl_environment/) | 46 | 5 | 0 | 711 / 5 | yes |
| [rtl_hash](tests/rtl_hash/) | 59 | 0 | 34 | 2808 / 0 | yes |
| [rtl_heap](tests/rtl_heap/) | 47 | 3 | 0 | 340 / 3 | yes |
| [rtl_memory](tests/rtl_memory/) | 55 | 0 | 0 | 4349 / 0 | yes |
| [rtl_numeric](tests/rtl_numeric/) | 82 | 3 | 3 | 534 / 17 | yes |
| [rtl_path](tests/rtl_path/) | 68 | 0 | 0 | 215 / 0 | yes |
| [rtl_security](tests/rtl_security/) | 73 | 11 | 0 | 351 / 12 | yes |
| [rtl_status](tests/rtl_status/) | 55 | 1 | 0 | 406 / 3 | yes |
| [rtl_strings](tests/rtl_strings/) | 65 | 4 | 0 | 984 / 9 | yes |
| [rtl_sync](tests/rtl_sync/) | 50 | 7 | 0 | 192 / 10 | yes |
| [rtl_tables](tests/rtl_tables/) | 50 | 1 | 25 | 1537 / 5 | yes |
| [rtl_threadpool](tests/rtl_threadpool/) | 28 | 0 | 0 | 28 / 0 | yes |
| [rtl_time](tests/rtl_time/) | 79 | 5 | 0 | 354 / 10 | yes |

Most behavioral areas include `tests/<area>/EVIDENCE.md` with actual contract branches/URLs, reviewer changes, failure classifications and gaps. `core_smoke` and `harness_checks` test infrastructure; `export_surface` is export/alias integrity, **not behavioral API coverage**. Their checks are included in totals but must not inflate behavioral coverage claims.

## Explicit limits and next depth pass

- Native Windows results remain outstanding; current failure triage is static Windows evidence plus Wine smoke, not runtime confirmation.
- Resolve-only handling of unknown signatures and ordinal 8 is deliberate; they are never invoked.
- Exhaustive syscall validation/ordering, ALPC/LPC, ETW, transactions, loader internals, WNF, activation contexts, exception/unwind edge cases, advanced threadpool/I/O and undocumented internal RTL families remain gap/depth work.
- Locale/NLS/DBCS, alternate architecture, privilege/elevation, hardware/SKU, alternate heap modes, real-world filesystem and cross-process races need dedicated passes.
- No shutdown, account/security disabling, raw-disk or system-process destructive tests are included.

Regenerate after a clean build/run:

```sh
python3 tools/coverage.py --preprocess
python3 tools/audit_build.py > results/build_audit.json
python3 tools/record_validation.py
python3 tools/write_reports.py
```

# Integrated-run observations

An earlier integrated run against source commit `381c114` completed all 29 executables, but was not a green conformance result: 90 tests failed under Wine and 72 skipped. Final recorded totals are in `VALIDATION.md`. The failed expectations remain grounded in static Windows evidence; native Windows execution is still required.

## Child-start availability

That run had one additional prerequisite skip in `rtl_sync_cv_cs_wake_handshake`, preserved in `validation/rtl-sync-child-start.txt`:

```text
results/wine/rtl_sync.txt:38:
  SKIP bounded child fixture prerequisite unavailable (dead0000)
```

`common/t.c` returns `0xDEAD0000` when `t_spawn_child` cannot start the child. This is **not a successful condition-variable behavioral test**, and the underlying CreateProcess error was not captured. Do not classify it as a Windows/Wine API semantic difference without further evidence.

An earlier reviewed run of the unchanged synchronization test source did execute the scenario: `/tmp/opencode/ntdll_review_rtl_sync.log:113` records `tests=50 failed=7 skipped=0 checks_pass=192 checks_fail=10`. The archived integrated run records `tests=50 failed=7 skipped=1 checks_pass=191 checks_fail=10`. The extra skip is preserved, not silently retried away. A later integration run was needed after correcting the summarizer's distinction between failed checks and incomplete execution; the synchronization test source was not changed.

Re-run this scenario on native Windows and record the child-start error if it recurs. Other skips and retained assertion failures are described in `tests/*/EVIDENCE.md` and `HANDOFF.md`.

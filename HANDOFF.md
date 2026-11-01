# Windows 10 validation handoff

## Status

This corpus targets Windows 10 x64 ntdll 10.0.19041.2788. Tests have been cross-compiled and smoke-tested under Wine; **no native Windows pass has been performed in this session**. Windows results must settle all remaining expectation and environment questions. See `VALIDATION.md` for the exact integrated evidence and `tests/*/EVIDENCE.md` for per-area contracts and retained Wine failures.

## Prerequisites and build

1. Disposable Windows 10 22H2 x64 VM; snapshot before each pass. Record OS build, ntdll file version, locale, elevation and architecture.
2. Standard-user and administrator accounts; no domain membership required.
3. On Linux: `make clean && make -j8`, then `python3 tools/audit_build.py`. Transfer the repository and `build/*.exe` to the VM. Binaries are not committed.
4. Windows PowerShell is sufficient to run all tests. Python 3 is optional for `tools/summarize.py`.

## Run and collect

Keep each pass in its own results directory; restore the VM snapshot between passes:

```powershell
tools\run_all.ps1 -ResultsDir results\standard -TimeoutSeconds 120
# In a fresh, elevated VM session:
tools\run_all.ps1 -ResultsDir results\admin -TimeoutSeconds 120
```

The default entry point `tools\run_all.bat` writes `build\results`. Use `build\<area>.exe <substring>` to isolate a test. Timeout kills the executable's process tree. Collect **all stdout/stderr `.txt` files plus `run.json`**, not just the summaries. Record the tested git commit. Missing/duplicate summaries, timeout, and abnormal exit codes mean incomplete execution.

Optional strict export pass, **only with exact reference DLL version 10.0.19041.2788**:

```powershell
$env:NTDLL_STRICT_EXPORTS = '1'
build\export_surface.exe
Remove-Item Env:NTDLL_STRICT_EXPORTS
```

Never invoke the ordinal-only export: presence/identity metadata is not a recovered signature.

## Triage every failure

- **Wrong expectation:** inspect docs and actual reference branches, fix the test, rebuild and rerun. Wine passing is not evidence that an expectation is correct.
- **Environment/build/privilege:** record the actual prerequisite; skip when absent or log inherently variable values. Do not accept arbitrary alternative errors merely to pass.
- **Implementation divergence:** retain an exact Windows-validated assertion and report the observed return, NTSTATUS/HRESULT/last-error and output state separately.
- **Crash/hang:** preserve the last `RUN`, stderr, exit code and timeout. Fix harness/fixture defects before interpreting other results. Do not call an incomplete run a conformance pass.

Use `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp`, `/docs`, and `/asm`; syscall stubs may require following the service into ntoskrnl. Kernel Nt/Zw documentation can differ from user-mode PreviousMode/probe behavior.

## Expected skips and known gaps

Missing optional exports, emulation-only safety guards and missing fixture prerequisites are reported in each area's log. Locale-sensitive conversion data, privileged/kernel-only facilities, undocumented unknown signatures, real exception/unwind corner cases, ALPC, ETW, transactions, threadpool and exhaustive native system information remain depth/gap work, not claimed coverage. See `COVERAGE.md` for the concrete static gap lists.

## Cleanup

Normal completion removes scratch fixtures and closes owned handles. After a crash, inspect the exact PID-tagged paths recorded by tests before deleting leftovers; never broadly delete `%TEMP%`, current-user registry branches or other corpora's artifacts. Reverting the disposable VM snapshot is the authoritative cleanup. No `/destructive` run is needed unless separately scoped `dx_*` areas are added.

## Report back

Return tested commit, OS/DLL versions, privilege/locale, per-area tests/failed/skipped/checks, logs, incomplete areas, wrong expectations corrected, confirmed implementation differences, and remaining environment limitations. Keep native results distinct from Wine smoke results.

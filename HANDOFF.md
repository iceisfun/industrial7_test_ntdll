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

The default entry point `tools\run_all.bat` writes `build\results`. Use `build\<area>.exe <substring>` to isolate a test. On timeout the runner attempts process-tree termination with `taskkill` and checks the root process exits; it cannot prove all descendants were removed. Collect **all stdout/stderr `.txt` files plus `run.json`**, not just the summaries. Record the tested git commit. Missing/duplicate summaries, timeout, and abnormal exit codes mean incomplete execution.

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

Missing optional exports, emulation-only safety guards and missing fixture prerequisites are reported in each area's log. Locale-sensitive conversion data, privileged/kernel-only facilities, undocumented unknown signatures, real exception/unwind corner cases, ALPC, ETW, transactions, advanced threadpool/I/O and exhaustive native system information remain depth/gap work, not claimed coverage. See `COVERAGE.md` for the concrete static gap lists.

- Reference x64 Windows: three optional byte-swap probes concern names absent from the reference export table; they are not behavioral coverage.
- This Wine build: CRC32/CRC64, decompression Ex and `RtlTestBit` availability probes skip when exports are missing. Table tests also have explicit Wine safety guards around aborting AVL/allocator-rejection paths; these guards are not version-probed.
- `harness_checks_exception_probe` skips in the parent and is exercised separately in controlled subprocesses. Symlink cleanup probes can be unavailable without the relevant privilege/platform support.
- Own-token access and fixture/thread/event setup can be prerequisite-dependent. Watchdog timeouts remain failures, never skips.

## Cleanup

Tests attempt to remove scratch fixtures and close owned handles; cleanup failures are not comprehensively observable. A recovered main-thread fault can bypass test-local cleanup and contaminate subsequent tests even when the executable prints a final summary. After any fault or crash, inspect the exact PID-tagged paths recorded by tests before deleting leftovers; never broadly delete `%TEMP%`, current-user registry branches or other corpora's artifacts. Reverting the disposable VM snapshot is the authoritative cleanup. No `/destructive` run is needed unless separately scoped `dx_*` areas are added.

## Report back

Return tested commit, OS/DLL versions, privilege/locale, per-area tests/failed/skipped/checks, logs, incomplete areas, wrong expectations corrected, confirmed implementation differences, and remaining environment limitations. Keep native results distinct from Wine smoke results.

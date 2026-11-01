# ntdll conformance corpus

Black-box C tests for Windows 10 x64 `ntdll.dll`, intended as an executable behavioral specification for an independent implementation. **Windows is authoritative; Wine is only development smoke validation. Native Windows results are not yet available.**

Each API under test is resolved at runtime through `GetModuleHandle`/`LoadLibrary` and `GetProcAddress`, then called through a typed function pointer. `U()` searches **only ntdll.dll**; `UIN()` pins a module explicitly. Undeclared APIs use locally verified typedefs and `UN()`. The executables do not statically import ntdll; ordinary CRT/kernel32 calls may construct fixtures and implement the harness.

## Build

Requires Linux, `x86_64-w64-mingw32-gcc`, GNU make, and Python 3 for tooling. No Python packages are needed.

```sh
make -j8                      # one build/<area>.exe per tests/<area>/
make build/rtl_strings.exe    # one area
python3 -m unittest discover -s tools -p "test_*.py"  # tooling regressions
python3 tools/audit_build.py  # compiled TEST/CHILD inventory, collisions, import audit
```

`build/` and `results/` are ignored. Tests use the supplied harness; there is no dependency on a testing framework or external runtime DLL beyond normal Windows system libraries.

## Run on Windows

Use a **disposable Windows 10 x64 VM with a snapshot**, initially as a standard user, then as an administrator in a separate pass. Copy the whole repository plus Linux-built `build/` to the VM.

```bat
tools\run_all.bat
build\rtl_strings.exe unicode
python tools\summarize.py build\results --failures
```

The batch entry point uses Windows PowerShell to apply a real per-executable timeout (120 seconds by default), attempt timed-out process-tree termination, and write `build\results\<area>.txt`, separate stderr logs, and `run.json`. PowerShell is part of Windows 10; Python is optional for aggregation, not execution.

```powershell
tools\run_all.ps1 -TimeoutSeconds 300 -ResultsDir results\standard
```

Output is `RUN/OK/FAIL/SKIP` per test and one `SUMMARY` per executable. `CHECK` is nonfatal; a test must explicitly return after an unmet prerequisite. `NOTE` is informational. Exit code 1 means test failures; missing summaries/nonzero abnormal exits indicate an incomplete run. The runner and summarizer do not silently treat those as success.

## Headless Wine smoke validation

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_strings.exe
python3 tools/smoke_all.py --timeout 120 --results results/wine
python3 tools/summarize.py results/wine --failures
```

The default Wine is `~/work/wine/proton-ge-custom/build/dist/files/bin/wine`; override `WINE` if necessary. The wrapper copies a disposable prefix, unsets desktop display variables, applies a timeout, and shuts down the prefix's wineserver on exit. Do not run Wine directly against your normal prefix. A Wine prefix is **not a security boundary**: Wine may access host files, so safe fixture design still matters.

Known Windows-supported Wine differences are retained as failures, not converted to permissive checks. Area `EVIDENCE.md` files explain contracts, uncertainty and smoke triage. See [VALIDATION.md](VALIDATION.md) for the integrated run and [HANDOFF.md](HANDOFF.md) for the authoritative Windows pass.

[validation/OBSERVATIONS.md](validation/OBSERVATIONS.md) preserves an additional child-start prerequisite skip observed during integration; it is not classified as a semantic API divergence.

## Scope and evidence

The reference is ntdll **10.0.19041.2788** from the Windows 10 22H2 corpus. `tools/reference_module.json` preserves module metadata; `tools/ntdll_exports.json` preserves 2,433 export records (2,432 named and one ordinal-only), with ordinals and RVAs. The reference API is read-only:

`http://docker1.dev.moonlightcompanies.com:8765/SKILL.md`

Hard assertions are grounded in documentation, actual implementation branches, or image metadata. Kernel DDI documentation is not automatically a full user-mode Nt/Zw contract. Environment-, privilege-, locale- and version-dependent observations are notes or skips. All test code is independently written.

See [COVERAGE.md](COVERAGE.md) for areas, static call inventory, documented surface and explicit gaps. Regenerate the conservative source inventory with:

```sh
python3 tools/coverage.py --preprocess
```

This is **not** runtime coverage or proof of checked behavior. Resolution-only expressions do not count as invocations. `--preprocess` expands test macros with the build compiler, recovering macro-generated names; indirect/aliased calls can still require manual review. Preprocessed locations are explicitly not original source line numbers. The export sweep inspects the host's PE export table, checks name/ordinal consistency and image-evidenced Nt/Zw aliases, and resolves baseline entries without invoking unknown signatures.

The optional `tools/map_public_surface.py` regeneration tool also needs **libclang** and matching builtin headers (defaults: the already-installed libclang 15). This is not a build/test dependency; it uses Python `ctypes`, not an added Python package. Use `--libclang`/`--resource-dir` to override. Its 613 documented-name matches include partial kernel/variant evidence; only 158 are full user-context matches under the recorded mapping rules.

`NTDLL_STRICT_EXPORTS=1` additionally requires the exact reference export/ordinal manifest. Enable it only with DLL version **10.0.19041.2788**; another Windows patch, Wine, or an independent implementation may legitimately assign different ordinals or export a different surface. An ordinal resolving on another build does not identify the function.

## Safety

- Files are private, bounded scratch fixtures under newly created `%TEMP%\ntdllt_<pid>_<tick>_<attempt>\` directories; registry fixtures are private current-user subkeys with unique names and cleanup. Existing scratch directories are never reused.
- No shutdown/reboot/logoff, raw disk access, system process termination, real account changes, security disabling, or deliberate resource exhaustion.
- Tests attempt to close/free owned process/thread/heap/section/token objects. Waits and child processes are bounded; process-global irreversible changes belong in children. Recovered faults can bypass local cleanup and contaminate later tests despite a final summary.
- State-changing system-wide tests, if added later, must live under `tests/dx_*` and be opt-in (`tools\run_all.bat /destructive`). A disposable prefix is not permission to mutate host state.
- The exception handler reports main-thread faults as failures; it cannot safely recover worker-thread faults or guarantee cleanup after arbitrary memory corruption. Missing summaries are therefore failures, not skips.
- `t_run_child` terminates its direct child on timeout, not an arbitrary descendant tree. Current children must not launch unbounded descendants; the outer runners provide separate executable-level process-tree/prefix cleanup. Path-based scratch cleanup avoids reparse traversal but is not hardened against a concurrent hostile filesystem race.

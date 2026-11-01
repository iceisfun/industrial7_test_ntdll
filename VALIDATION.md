# Integrated validation

**Wine smoke only; native Windows and the PowerShell runner have not been executed here.**

- Source commit recorded after the clean build/run sequence: `fb923256207e728b3b82e53f110900b6b8aea28a`.
- Recorded UTC: `2026-11-01T02:39:56.906507+00:00`.
- Compiler: `x86_64-w64-mingw32-gcc (GCC) 13-win32`.
- Wine executable: `/home/iceisfun/work/wine/proton-ge-custom/build/dist/files/bin/wine`.
- Wine version: `wine-11.0 (Staging)`.
- Command: `python3 tools/smoke_all.py --timeout 120 --results results/wine`.

## Result

- 29 executables; 1640 tests; 90 failed tests; 71 skipped tests.
- 71650 passing checks; 159 failing checks.
- Every area completed: **yes**. Every check passed: **NO**.
- Compiled/runtime test counts agree: **yes**. Build-audit errors: **0**.

The smoke command exits nonzero when checks fail. Those failures are not hidden or reported as a conformance pass. Area evidence records Windows-supported expectations and the reviewed Wine discrepancies. **A real Windows baseline is still required to confirm every classification.**

Per-area counts are in [COVERAGE.md](COVERAGE.md). `validation/wine-summary.json` records exact source/binary/log SHA-256 hashes, exit codes, durations, imports and failed-check text. Full stdout logs remain at the paths recorded there (local `results/wine/`, ignored by Git).

Provenance limit: hashes and commit are captured at recording time. The integration sequence must keep sources and binaries unchanged between clean build, smoke and recording; the recorder alone does not prove which historical files produced a log.

## Reproduce

```sh
make clean
make -j8
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools -p "test_*.py"
mkdir -p results
python3 tools/audit_build.py > results/build_audit.json
python3 tools/smoke_all.py --timeout 120 --results results/wine
# A nonzero smoke exit is expected while reviewed Wine differences remain.
python3 tools/summarize.py results/wine --failures
python3 tools/record_validation.py
```

## Not verified here

- Genuine Windows 10 standard-user/admin execution and exact reference-DLL strict export sweep.
- Windows PowerShell process-tree timeout behavior; source-reviewed only because PowerShell is unavailable on this Linux host.
- Hostile filesystem races during path-based scratch cleanup; child-helper timeout kills the direct child, not arbitrary descendants. The corpus is for disposable VMs, not a security sandbox.
- Full correctness of static coverage inference or all version/environment-dependent behavior.

See [HANDOFF.md](HANDOFF.md) for Windows execution, collection and triage.

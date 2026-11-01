# RTL context and unwind lookup evidence

Reference: Windows 10 x64 ntdll **10.0.19041.2788**:
<http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntdll>.
No native Windows run is available; Wine is smoke validation only.

## CaptureContext ABI and assertions

SDK declarations supply the function-pointer types for RtlCaptureContext,
RtlCaptureStackBackTrace, RtlLookupFunctionEntry and RtlPcToFileHeader. Calls use
`U` and `REQUIRE`, never linked ntdll calls. RtlRaiseException's one-argument VOID
signature is locally declared with `UDECL`/`UN`, checked against its Windows
decompilation and dynamically required before launching the exception child.

PDB layout:
<http://docker1.dev.moonlightcompanies.com:8765/api/types/ntdll/_CONTEXT>.
It reports size **1232**, ContextFlags **48**, MxCsr **52**, Rcx **128**,
Rsp **152**, Rip **248**, FltSave **256** (512 bytes). Compile-time assertions
check the layout used by the x64 tests.

Actual code:
<http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCaptureContext/asm>
and its `/decomp` sibling. Specific Windows instructions:

- VA `0x1800a1186`: stores RCX at offset 0x80 (the context argument itself).
- `0x1800a11b0`: FXSAVE at offset 0x100; `0x1800a1201`: STMXCSR at 0x34.
- `0x1800a11b7` through `0x1800a11c6`: saves segment selectors.
- `0x1800a1205`/`0x1800a120a`: saves caller RSP after the return address;
  ordinary Win64 call-site alignment is 16 bytes.
- `0x1800a1211`/`0x1800a1216`: saves the return address as RIP.
- `0x1800a1223`: writes **0x10000f**, CONTEXT_FULL | CONTEXT_SEGMENTS.

Eight focused capture tests check these fields, the return image, stack mapping,
and buffer guards. No fixed segment values, stack addresses, or floating-point
control defaults are assumed; MXCSR is compared with this thread's current value.

## Backtrace and the retained Wine difference

<http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCaptureStackBackTrace/decomp>
and
<http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCaptureStackBackTrace/asm>.

Windows caps capture at 0xffff, skips its own frame, and hashes by summing the
low DWORD of every returned address modulo 2^32. The tests use only 1 or 8
frames and 12 real compiler-generated recursive frames; no synthetic unwind
records or stacks. Tests check bounded counts, non-NULL addresses, optional
hash, exact hash sum, image membership, skip behavior and untouched trailing
buffer slots.

The rejection path is unambiguous in assembly: VA `0x180051616` compares ECX
with **0xfe**, `0x18005161c` branches with **JA** to `0x180051661`, which returns
zero without writing the hash or output array. Only `0x1800ba646` on the normal
hashing path stores `[rsi]`. Thus **FramesToSkip=255 returns zero and preserves
the caller's 0xdeadbeef hash** on the reference Windows implementation.

Wine instead writes zero to the hash. The corresponding failure is intentionally
retained, not relaxed into a skip or a permissive check.

## Runtime function and image lookup

- <http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlLookupFunctionEntry/decomp>:
  signature `(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE)`; static lookup uses
  `BeginAddress <= relative PC < EndAddress`, outputs image base, and returns
  NULL on an unregistered non-image allocation. History storage is optional;
  successful lookups can append while Count < 12.
- <http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/winnt/nf-winnt-rtllookupfunctionentry.md>:
  NULL if no matching function-table entry. Its generic HistoryTable text is
  architecture-mixed; the x64 SDK declaration and Windows code determine the ABI.
- <http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlPcToFileHeader/decomp>:
  sets BaseOfImage and returns that same module base for an image PC.

Six lookup tests use a real nonleaf function in this executable, the actual
nonleaf ntdll lookup function, optional history, the inclusive begin and last
included byte of a real runtime-function range, and a live VirtualAlloc page
without registered unwind metadata. Two image tests cover this EXE and ntdll.
No function-base or failure-output value is guessed; no executable synthetic
frames or dynamic function tables are installed.

## Continuable exceptions and isolation

<http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlRaiseException/decomp>
shows context capture, lookup/unwind of the real caller, assignment of
ExceptionAddress, dispatch, and context restoration on a handled exception.
Two children raise only private code **0xe0421234**, flags zero, with zero or
EXCEPTION_MAXIMUM_PARAMETERS (15) information values. An own first-priority VEH
handles only that code, checks flags/count/payload and nonzero context/address,
and returns EXCEPTION_CONTINUE_EXECUTION. The test verifies one delivery and
normal return, then removes the handler. Other exceptions are not swallowed.
Each child has a 10-second timeout; no handler is installed in the parent test.

## Validation and gaps

`make build/rtl_context.exe` builds without diagnostics.

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_context.exe
```

`/tmp/opencode/ntdll_rtl_context.log` records:
`SUMMARY tests=24 failed=1 skipped=0 checks_pass=210 checks_fail=1`.
The sole failure is `rtl_context_backtrace_skip_limit`: hash got 0, expected
0xdeadbeef. 23 other tests pass, including both child exception cases.
Import inspection with `x86_64-w64-mingw32-objdump -p` finds only KERNEL32.dll
and msvcrt.dll, with no static ntdll dependency.

Native Windows validation remains required. This area does not test context
restoration, modified instruction pointers, fabricated unwind tables,
RtlVirtualUnwind, noncontinuable exceptions, guard-page faults, XSTATE/CET,
cross-architecture contexts, debugger-dependent dispatch, or arbitrary-register
values. No last-error expectations are invented for these native routines.

## Adversarial review (2026-10-31)

Reviewed writer commit `f7b566e` and the original 24-test log above. The only
failure is a justified Wine difference, not a fixture error. Re-read the actual
Windows `/asm` and `/decomp` for RtlCaptureStackBackTrace: `cmp ecx,0xfe` at
`0x180051616`, unsigned `ja` at `0x18005161c`, and the zero-return path at
`0x180051661` bypass the sole hash store at `0x1800ba646`. The skip=255 hash
preservation assertion remains strict; there is no Wine alternative or skip.

Review fixes and added coverage:

- Guard the returned runtime-function pointer **before** dereferencing it. Its
  full 12-byte span must be committed, accessible storage in the independently
  known expected image; the returned base is checked, never used to read PE
  headers. Validate ordered code endpoints and a nonzero readable four-byte
  unwind header within that image before endpoint lookups. A failed CHECK is
  retained, then `t_skip` plus explicit return prevents a secondary fault.
- Add compile-time CONTEXT type and embedded-buffer alignment checks (at least
  16-byte alignment and offset divisible by 16). Windows RtlCaptureContext
  uses FXSAVE `[rcx+0x100]` at `0x1800a11b0`; the PDB size/offset assertions
  alone did not explicitly enforce this prerequisite.
- Add `rtl_context_backtrace_skip_matches_suffix`: compare skip=2 against the
  suffix of a ten-frame capture from the same twelve-level recursive helper.
  Unlike image membership alone, this detects an implementation ignoring skip.
  Counts are checked before indexing. Built disassembly confirms the recursive
  CALL at `0x140001cb7`, post-call use, and indirect export CALL at
  `0x140001cec`; no tail-recursion or static Rtl import substitutes the fixture.

Reconsulted Windows RtlCaptureContext `/asm`, RtlLookupFunctionEntry `/decomp`
and `/docs`, RtlPcToFileHeader `/decomp`, RtlRaiseException `/decomp`, and PDB
`_CONTEXT` and `_IMAGE_RUNTIME_FUNCTION_ENTRY` (size 12, offsets 0/4/8).
The guessed `_RUNTIME_FUNCTION` and `_UNWIND_HISTORY_TABLE` type endpoints
returned 404; no new history-layout assertion is based on those missing types.
All corpus requests were serialized, with retry handling for HTTP 503.
Raised exceptions remain CHILD-only with 10-second parent bounds, private-code
VEH filtering and removal; callback counters never call the harness. Export
prerequisites use REQUIRE (which explicitly returns), and nonfatal CHECK guards
have explicit returns before dependent reads. Fixture allocation is released.

Review build: `make build/rtl_threadpool.exe build/rtl_context.exe`, no diagnostics.
Review smoke (exit **1**, expected retained difference):

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_context.exe
```

`/tmp/opencode/ntdll_review_context.log:25` reports hash **0** versus
**0xdeadbeef** in `rtl_context_backtrace_skip_limit`; line 53 reports:
`SUMMARY tests=25 failed=1 skipped=0 checks_pass=230 checks_fail=1`.
Thus **24/25 tests pass**, including the new suffix comparison, all five
guarded image-entry cases and both exception children. `objdump -p` again
reports only KERNEL32.dll and msvcrt.dll imports. No Windows execution or i7
run was performed; the native-validation and broader unwind/XSTATE gaps above
remain. Guard checks validate spans, not full unwind-code semantics.

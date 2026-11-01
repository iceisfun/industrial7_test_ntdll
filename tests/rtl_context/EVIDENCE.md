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

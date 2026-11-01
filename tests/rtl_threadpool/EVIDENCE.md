# RTL thread pool evidence

Reference: Windows 10 x64 ntdll **10.0.19041.2788**, confirmed by
<http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntdll>.
Windows is authoritative; the run below is only Wine smoke validation.

## ABI and implementation

Typed declarations were checked against
<https://raw.githubusercontent.com/winsiderss/phnt/master/nttp.h>
(`TpAllocPool`, `TpReleasePool`, `TpSetPoolMaxThreads`, work, simple callback,
timer and wait declarations). `LOGICAL` parameters/results are 32-bit `ULONG`,
not byte-sized `BOOLEAN`. Callbacks and opaque pointers use the SDK types.
All tested ntdll entry points are resolved dynamically with `UDECL`/`UN` and
parent-side `REQUIRE`; no ntdll import library is added.

The Windows PDB layout at
<http://docker1.dev.moonlightcompanies.com:8765/api/types/ntdll/_TP_CALLBACK_ENVIRON_V3>
reports size **72**, Pool **8**, flags **56**, CallbackPriority **60**, Size **64**.
Compile-time assertions enforce those exact x64 offsets; the zero-initialized
environment sets Version=3, Size=72, a live private pool and a valid priority.

Implementation endpoints actually consulted (prefix
`http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/`):

| Endpoint suffix | Relevant contract |
| --- | --- |
| `TpAllocPool/decomp`, `TpReleasePool/decomp` | Optional reserved argument is NULL; allocate/release owned pools. |
| `TpSetPoolMaxThreads/decomp` | Valid pool and positive bounded maximum reach the worker-factory update. |
| `TpAllocWork/decomp` | Four arguments: output, callback, context, optional environment; successful output assignment and STATUS_SUCCESS. |
| `TpPostWork/decomp` | Posts an allocated work object. The native export is **TpPostWork**, not TpSetWork. |
| `TpWaitForWork/decomp` | Passes the cancellation argument to `TppWorkWait`. |
| `TpReleaseWork/decomp` | Releases a validated work object. |
| `TpSimpleTryPost/decomp` | Callback/context/environment allocation and submission; success is zero NTSTATUS. |
| `TpAllocTimer/decomp`, `TpSetTimer/decomp` | Callback/context/environment; non-NULL due time arms, NULL cancels. The decompiler guesses a return value for TpSetTimer; the verified header declares VOID, and no return is asserted. |
| `TpWaitForTimer/decomp`, `TpReleaseTimer/decomp` | Drain/cancel callback work before release. |
| `TpAllocWait/decomp`, `TpSetWait/decomp` | Callback/context/environment and wait handle/optional timeout. |
| `TpWaitForWait/decomp`, `TpReleaseWait/decomp` | Drain/cancel callbacks before release. |

## Documentation contracts

These vendored Microsoft user-mode pages were read, not inferred from kernel DDIs:

- <http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/threadpoolapiset/nf-threadpoolapiset-waitforthreadpoolworkcallbacks.md>:
  waits for outstanding callbacks; cancellation removes queued callbacks not yet started.
- <http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/threadpoolapiset/nf-threadpoolapiset-setthreadpoolthreadmaximum.md>:
  maximum number of workers. A one-worker private pool plus an already-entered,
  bounded blocker makes queued-work cancellation deterministic; canceled work
  is subsequently reposted to check object reuse.
- <http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/threadpoolapiset/nf-threadpoolapiset-seteventwhencallbackreturns.md>:
  event is set **when the current callback completes**. Simple callbacks use
  `TpCallbackSetEventOnCompletion`, not an early signal followed by context destruction.
- <http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/threadpoolapiset/nf-threadpoolapiset-setthreadpooltimer.md>:
  negative due time is relative, positive is absolute in 100ns units; zero period
  is one-shot; NULL due time stops new callbacks but does not drain existing ones.
- <http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/threadpoolapiset/nf-threadpoolapiset-setthreadpoolwait.md>:
  callback on signaling/timeout; NULL handle disarms; live handle must outlast
  pending waits; explicit re-registration is required for another callback.
- <https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms687017(v=vs.85)>:
  exact four-argument wait callback signature and WAIT_OBJECT_0 / WAIT_TIMEOUT
  results. The guessed corpus callback page returned 404 and the symbol index
  had no callback entry, so this archived Microsoft page supplies that detail.

## Scope and safety

26 separately registered tests cover two live pools, idle/cancel/drain work,
single/batch/reused work, distinct contexts, default/private pools and valid
priorities, deterministic queued cancellation, simple completion, idle/fired/
disarmed/rearmed timers, and idle/signaled/timed-out/rearmed/disarmed waits.
Priority tests check accepted dispatch, not scheduler ordering.

Every case runs in a `CHILD` with a 15-second parent timeout. Event waits and
the cancellation blocker have 5-second bounds; native drain APIs have no timeout
parameter and are therefore never invoked in the parent. Success paths drain
before releasing callback objects, contexts, pools and events. Failure paths
call ExitProcess immediately rather than returning a live callback's stack
storage. Events are unnamed process-owned fixtures. No invalid pointers, closed
handles, resource exhaustion, timing-window ordering, or parent exception state.

## Validation and gaps

`make build/rtl_threadpool.exe` builds without diagnostics. Smoke command:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_threadpool.exe
```

Log: `/tmp/opencode/ntdll_rtl_threadpool.log`:
`SUMMARY tests=26 failed=0 skipped=0 checks_pass=26 checks_fail=0`.
Child checks propagate through each parent's checked exit code; they are not
included individually in the harness check counter. Import inspection with
`x86_64-w64-mingw32-objdump -p` finds only KERNEL32.dll and msvcrt.dll.
No native Windows execution yet. No unsupported/invalid-environment probes,
cleanup groups, callback disassociation, periodic overlap, IO/ALPC callbacks,
pool exhaustion, or scheduler fairness assertions are included. Win32 last-error
preservation is not asserted for NTSTATUS/VOID native APIs without a verified
contract.

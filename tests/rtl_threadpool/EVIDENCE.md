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

## Adversarial review (2026-10-31)

Reviewed writer commit `ecd788e`, all 26 original cases and
`/tmp/opencode/ntdll_rtl_threadpool.log:54` (26/26 pass, zero skips/failures).
No erroneous ABI, callback-lifetime or cancellation-order contract was found.
Re-read phnt `nttp.h` and serialized Windows corpus `/decomp` requests for all
tested exports, plus TppWorkWait and TpSetWaitEx. Re-read the V3 environment
PDB and vendored user-mode callback-completion/work-drain/wait docs above.
The TpIsTimerSet decompiler's `bool` is misleading as a prototype: `/asm`
at `0x180012014` zeroes EDX, `0x180012021` uses SETNE DL, and
`0x180012024` copies EDX to EAX. The existing ULONG/LOGICAL declaration is
correct and is retained. No decompiler-guessed VOID return is asserted.

Safety triage:

- `calls`/`bad` updates are interlocked; no worker calls CHECK/t_check. Parent
  checks run only after native drains, or after the simple callback's deferred
  completion event. The wait result has one outstanding writer and is read
  after completion/drain; it is not read on an early in-body event alone.
- Work's object/context assignment precedes posting. Timers/waits assign the
  expected object before arming. Simple callbacks keep state/events alive until
  TpCallbackSetEventOnCompletion fires after callback return.
- The private one-worker gate is entered before queued cancellation; gate wait
  is bounded at five seconds. Cancellation drains before gate release and work
  reuse. All native no-timeout drains/releases are CHILD-only, with 15-second
  parent bounds (`common/t.c:84-91` also bounds termination and closes process
  handles). Callback event waits are five seconds.
- Success releases other/blocker work, main work and private pool in that order;
  timers are disarmed/drained before release, waits disarmed/drained/released
  before trigger-handle closure, and completion events closed last. Failure
  paths deliberately ExitProcess rather than attempt an unsafe drain or return
  live stack storage; child-owned pools/objects/handles die with the process.
  Fixture failures use child code 77, mapped to explicit `t_skip; return`.
  REQUIRE explicitly returns when an export is missing. UDECL/UN remains
  dynamic lookup against `common/modules.h`'s ntdll-only module list.

Added two verified wait gaps: already-expired absolute timeout returns
WAIT_TIMEOUT (`wait_expired_absolute_timeout`), and a disarmed/drained wait can
be registered and fired again (`wait_reuse_after_disarm`). The vendored
SetThreadpoolWait page explicitly specifies positive absolute 100ns timeouts,
NULL-handle disarm and re-registration. Existing two-round explicit-rearm
coverage now resets, registers, **then signals** each round; the separate
pre-signaled-event test is preserved. All added paths use the existing bounded
child, callback result checks and disarm/drain/release cleanup.

Review build: `make build/rtl_threadpool.exe build/rtl_context.exe`, no diagnostics.
Review smoke:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_threadpool.exe
```

`/tmp/opencode/ntdll_review_threadpool.log:58` reports:
`SUMMARY tests=28 failed=0 skipped=0 checks_pass=28 checks_fail=0` (exit **0**).
All **28/28** pass. Checks inside children are deliberately represented only
by the checked parent exit code. Import inspection again reports only
KERNEL32.dll and msvcrt.dll. No native Windows execution or i7 run was done;
the original broader cleanup-group/IO/periodic-overlap gaps remain.

Do not hide the intervening failed smoke: preserved at
`/tmp/opencode/ntdll_review_threadpool_spawn_failure.log:15`, the unchanged
`wait_idle_drain` case returned harness sentinel **0xDEAD0000**; line 59 is
`SUMMARY tests=28 failed=1 skipped=0 checks_pass=27 checks_fail=1` (exit **1**).
`common/t.c:85-89` uses that value for failed child creation, or leaves it
unchanged if exit-code retrieval fails. There was no child diagnostic and the
other 27 cases passed. A full same-command retry produced the 28/28 final log
above without code changes. This is an observed harness/Wine process-control
failure, not evidence of a failing TpWaitForWait contract; the precise host
cause is unverified. No skip or permissive native assertion was introduced.

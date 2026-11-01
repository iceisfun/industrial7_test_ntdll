# RTL synchronization: Windows 10 contracts

Reference queried 2026-10-31, serial HTTP requests, retry on 503.
Instructions: <http://docker1.dev.moonlightcompanies.com:8765/SKILL.md>.
Pinned module: [ntdll 10.0.19041.2788](http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntdll).
All function names in the tables were queried through their function `/decomp` APIs.
No third-party test source was used. `common/t.{h,c}` and corpus writing/safety rules
were read before implementation.

The RTL APIs are dynamically resolved with UDECL/UN and REQUIRE. Thread/event
fixture helpers are dynamically pinned to kernel32 with UIN, independent of the
shared module search list. Assertions distinguish NTSTATUS from BOOLEAN and never
interpret GLE as NTSTATUS. Unlike the native syscall-stub suite, this suite does
not assert GLE preservation across arbitrary RTL implementation internals.

## Critical sections

| Windows 10 function evidence | Branch/contract checked |
| --- | --- |
| [RtlInitializeCriticalSection, 0x61570](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInitializeCriticalSection/decomp) | RecursionCount=0, OwningThread=NULL, unlocked; successful initialization returns 0. No DebugInfo allocation/address assumptions. |
| [RtlInitializeCriticalSectionAndSpinCount, 0x64940](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInitializeCriticalSectionAndSpinCount/decomp) | Zero and nonzero spin initialization produce usable unlocked sections. Default/dynamic spin differs by processor count; no fixed effective default asserted. |
| [RtlInitializeCriticalSectionEx, 0x20bc0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInitializeCriticalSectionEx/decomp) | Flags mask `0xe0000000` rejected with **0xc00000f1** before any structure write; spin high byte rejected with **0xc00000f0**. Valid flags 0 and NO_DEBUG_INFO 0x01000000 initialize usable sections. Tests compare untouched buffer only on these explicit early-return branches. |
| [RtlEnterCriticalSection, 0x2faa0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlEnterCriticalSection/decomp) | Free -> owner=current thread ID, recursion=1; same owner increments recursion; successful entry returns 0. |
| [RtlTryEnterCriticalSection, 0x207e0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlTryEnterCriticalSection/decomp) | Free and current-owner return BOOLEAN TRUE; foreign owner returns FALSE without acquisition. Successful recursive try increments recursion. |
| [RtlLeaveCriticalSection, 0x2f230](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlLeaveCriticalSection/decomp) | Decrements recursion; only final release clears owner; successful valid-owner release returns 0. No unlock-unowned misuse test. |
| [RtlIsCriticalSectionLocked, 0xe8de0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlIsCriticalSectionLocked/decomp), [RtlIsCriticalSectionLockedByThread, 0x14890](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlIsCriticalSectionLockedByThread/decomp) | Locked tests bit of LockCount; ByThread compares owner with TEB client thread ID. Current and foreign thread outcomes tested under event synchronization. |
| [RtlSetCriticalSectionSpinCount, 0x71620](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSetCriticalSectionSpinCount/decomp) | Returns previous low 24 bits, preserves internal high flags; uniprocessor forces low spin count zero. Set-to-zero and returned prior values checked; effective 99 is observation only. |
| [RtlDeleteCriticalSection, 0x10fc0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlDeleteCriticalSection/decomp) | Releases deferred event/debug storage and clears section; no-event normal path returns 0. Delete only after owner releases and workers have joined. Reinitialize only after delete. |

## SRW locks and condition variables

| Windows 10 function evidence | Branch/contract checked |
| --- | --- |
| [RtlInitializeSRWLock](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInitializeSRWLock/decomp) | Initializes pointer-sized lock word to zero. Static zero initialization is also exercised. |
| [RtlAcquireSRWLockExclusive](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAcquireSRWLockExclusive/decomp), [RtlReleaseSRWLockExclusive](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlReleaseSRWLockExclusive/decomp) | Free exclusive acquire/release and later shared acquisition; foreign exclusive and shared tries fail while exclusive held. |
| [RtlAcquireSRWLockShared](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAcquireSRWLockShared/decomp), [RtlReleaseSRWLockShared, 0x21920](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlReleaseSRWLockShared/decomp) | Shared reader count and last-reader release allow later exclusive acquisition. Two **different threads** hold/read simultaneously; no unsupported same-thread shared recursion or upgrade. |
| [RtlTryAcquireSRWLockExclusive, 0x81f60](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlTryAcquireSRWLockExclusive/decomp), [RtlTryAcquireSRWLockShared, 0x76d90](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlTryAcquireSRWLockShared/decomp) | Exclusive try returns old owned-bit clear; shared try accepts free/reader state, rejects exclusive ownership. Result is BOOLEAN, not NTSTATUS. Every successful try is released by acquiring thread. |
| [RtlInitializeConditionVariable](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInitializeConditionVariable/decomp) | Initializes pointer word zero. |
| [RtlWakeConditionVariable, 0x54ab0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlWakeConditionVariable/decomp), [RtlWakeAllConditionVariable, 0x55420](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlWakeAllConditionVariable/decomp) | Both return without changing an initially zero CV with no waiters; actual handshakes exercise single/all wake. No promise about opaque CV word after a nonempty wait. |
| [RtlSleepConditionVariableCS, 0x642a0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSleepConditionVariableCS/decomp) | Enqueues waiter before leaving section, waits, handles timeout 0x102, re-enters before returning. Single-level ownership is mandatory; recursion>1 deliberately not used. Timeout test verifies current-thread ownership and recursion=1 afterward. |
| [RtlSleepConditionVariableSRW, 0x64000](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSleepConditionVariableSRW/decomp) | `(flags & ~1) != 0` -> **0xc00000f0** before any CV/lock operation. Flag 0 releases/reacquires exclusive, flag 1 shared. Both zero-timeout return/reacquire paths and producer/waiter handshakes exercised. Invalid-flag test still supplies a legitimately held exclusive lock and releases it afterward. |

## Run once

| Windows 10 function evidence | Branch/contract checked |
| --- | --- |
| [RtlRunOnceInitialize](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlRunOnceInitialize/decomp) | Stores zero. No reinitialization while pending or with waiters. |
| [RtlRunOnceBeginInitialize, 0xa530](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlRunOnceBeginInitialize/decomp) | Flags only 0, CHECK_ONLY=1, ASYNC=2; combined 3 -> **0xc00000f0**, outputs unchanged. Uninitialized normal/async returns **0x103 STATUS_PENDING**; CHECK_ONLY on uninitialized/pending returns **0xc0000001**, does not write context. Completed state returns 0 and context with reserved two bits removed. |
| [RtlRunOnceComplete, 0x43af0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlRunOnceComplete/decomp) | No begin -> 0xc0000001. Matching sync/async completion publishes aligned context or NULL; INIT_FAILED=4 with NULL resets sync once to retryable state. Context storage is a real aligned static LONG, never an invented pointer. |
| [RtlRunOnceExecuteOnce, 0x43870](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlRunOnceExecuteOnce/decomp) | TRUE callback completes once with supplied context; repeated calls bypass callback. FALSE callback resets via Complete(INIT_FAILED) and returns **0xc0000001**, allowing retry. NULL context output is legal and publishes NULL. Worker callback publication is observed only after join; callback count remains 1 when main calls ExecuteOnce again. |

## Thread safety and evidence limits

48 focused TESTs, including ten child-isolated thread scenarios. Parents REQUIRE
all worker exports. Children use static fixture storage (not dangling stack arguments),
5-second event/join waits, 15-second process watchdog, and no TerminateThread.
Timeout/setup-unavailable return 77 is a skip; a child watchdog timeout is a failure.
All normal paths join workers before closing helper handles or deleting sections.
An early fixture failure exits the isolated process instead of freeing live locks.
All helper events are unnamed; no global state is changed.

CV producers publish under the same lock that Sleep releases atomically; predicate
loops tolerate spurious wakes with at most four attempts and finite relative waits.
No assertion measures time or relies on a sleep to establish readiness. Once tests
use an entered-event/gate callback handshake; CS handoff uses separate probe and gate.

Evidence gaps: no native Windows run here. Fairness, starvation, exact opaque SRW/CV
representations after contention, recursion misuse, lock deletion with live users,
RunOnce asynchronous collisions and actual concurrent ExecuteOnce waiter queues are
not asserted. The callback test publishes from a worker and checks once completion
from the parent, but does not claim to cover two simultaneous ExecuteOnce waiters.
Native decompiler signatures omit some register arguments; tests use full ABI
signatures and check only branches/outputs whose data flow is visible.
Wine differences are smoke findings, never the authority for expected status values.

## Smoke result (not Windows validation)

Built with `make build/rtl_sync.exe`, no compiler warnings on final build.
Ran only `TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_sync.exe >/tmp/opencode/ntdll_rtl_sync.log 2>&1`.
Exit 1; `SUMMARY tests=48 failed=6 skipped=0 checks_pass=186 checks_fail=8`.
All ten isolated thread scenarios completed successfully, without skips/timeouts.

Retained, evidence-backed Wine divergences:

* RunOnce Begin flags 3 returns 0xc000000d rather than 0xc00000f0.
* CV SRW sleep flags 2 returns timeout rather than rejecting with 0xc00000f0.
* Wake and WakeAll on an empty CV each change its word from zero to 1; pinned Windows code returns at zero.
* Critical-section Ex accepts high spin bits and reserved flags and writes the structure,
  rather than returning 0xc00000f0 / 0xc00000f1 before mutation (two tests, four failed checks).

Initial helper-export skips were a fixture lookup issue: the shared module list
contains ntdll only. Pinning kernel32 fixture helpers with UIN removed all ten skips.
The final run above is after that correction; no native expectation was relaxed.

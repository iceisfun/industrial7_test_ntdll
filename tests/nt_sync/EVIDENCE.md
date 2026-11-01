# Native synchronization: Windows 10 contracts

Reference queried 2026-10-31, one HTTP request at a time, with retry on 503.
Explorer instructions: <http://docker1.dev.moonlightcompanies.com:8765/SKILL.md>.
Module metadata: [ntdll 10.0.19041.2788](http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntdll),
[ntoskrnl 10.0.19041.2965](http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntoskrnl).
This is a Windows 10 x64-specific suite, not a claim about all NT releases.

## Boundary and error channels

The ntdll routines are syscall stubs, not the implementations of their contracts.
All 24 called Nt exports were queried at `/api/function/ntdll/<name>/asm`:
NtCreateEvent, NtOpenEvent, NtSetEvent, NtResetEvent, NtPulseEvent, NtQueryEvent,
NtCreateSemaphore, NtOpenSemaphore, NtReleaseSemaphore, NtQuerySemaphore,
NtCreateMutant, NtOpenMutant, NtReleaseMutant, NtQueryMutant,
NtCreateTimer, NtOpenTimer, NtSetTimer, NtCancelTimer, NtQueryTimer,
NtWaitForSingleObject, NtWaitForMultipleObjects, NtDuplicateObject, NtQueryObject, NtClose.
For example [NtCreateEvent assembly](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/NtCreateEvent/asm)
loads service 0x48 and returns after syscall/int 0x2e; there is no Win32 error translation.
`STATUS` captures NTSTATUS and GLE immediately, independently, before assertions.
It checks that the GLE sentinel survives; it never compares GLE to an NTSTATUS.

Kernel service decompilations below were inspected on their **user PreviousMode**
branches. All supplied buffers are valid, aligned, writable storage; no kernel handles,
pointer-probing exception tests, arbitrary addresses, or kernel-only access assumptions.
The [NtWaitForSingleObject user-mode documentation](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/winternl/nf-winternl-ntwaitforsingleobject.md)
explicitly documents zero timeout and SUCCESS/TIMEOUT.
The [ZwCreateEvent DDI page](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-zwcreateevent.md)
is a **partial kernel-context** contract, used for notification/synchronization semantics,
not to infer user-mode probing or invalid-parameter status.

## Branches and outputs checked

| Implementation evidence | Contract used |
| --- | --- |
| [NtCreateEvent, 0x601020](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtCreateEvent/decomp) | Type `< 2` creates and initializes; type 2 returns **0xc000000d**, before writing the output handle. This differs from the DDI page's suggested INVALID_PARAMETER_4; the pinned binary wins. |
| [KeInitializeEvent](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/KeInitializeEvent/decomp) | Stores supplied event type and BOOLEAN initial state. |
| [NtSetEvent, 0x6b0500](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtSetEvent/decomp) | References with access 2, sets event, writes previous state only on success and only if output non-NULL. Query-only handle returns ACCESS_DENIED without writing previous state. |
| [NtResetEvent, 0x6d1170](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtResetEvent/decomp), [KeClearEvent](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/KeClearEvent/decomp) | Access 2; clear returns old state; optional previous-state output. |
| [NtPulseEvent, 0x6b4ca0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtPulseEvent/decomp), [KePulseEvent](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/KePulseEvent/decomp) | Returns old state; without waiters the resulting state is clear. No pulse/wait race test. |
| [NtQueryEvent, 0x6d0f00](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQueryEvent/decomp), [0x6d0f8a continuation](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/0x6d0f8a/decomp) | Class 0 requires exactly 8 bytes. Other class -> 0xc0000003; size 7 or 9 -> 0xc0000004. Both early returns preserve buffer/return length. Success writes type, state, length 8. Modify-only access cannot query. |
| [NtCreateSemaphore, 0x684ee0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtCreateSemaphore/decomp) | Maximum `<1`, initial `<0`, or initial `>maximum` -> 0xc000000d; no output handle write. |
| [NtQuerySemaphore, 0x959290](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQuerySemaphore/decomp) | Valid aligned buffer is probed even before class/size validation. Class 0, exact size 8; query access 1; outputs current count, maximum, return length 8. Invalid class/length does not modify either output. |
| [NtReleaseSemaphore, 0x6a8290](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtReleaseSemaphore/decomp), [KeReleaseSemaphore, 0x2faeb0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/KeReleaseSemaphore/decomp) | Release `<1` -> 0xc000000d. Access 2/type check precedes release. Exceeding limit raises 0xc0000047 through syscall exception handling, before count mutation or previous-count output. Successful release writes old count, optional output. Event handle -> 0xc0000024. |
| [NtCreateMutant](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtCreateMutant/decomp), [KiInitializeMutant, 0x36093c](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/KiInitializeMutant/decomp) | Initial unowned count 1; initial owner count 0 and owner=current thread. Abandoned bit cleared. |
| [NtQueryMutant, 0x9596d0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQueryMutant/decomp) | Basic class 0, exact 8 bytes, query access 1. Writes signed signal count, current-thread owner BOOLEAN, abandoned BOOLEAN and length. Does not promise padding contents. Class 9 invalid; size 7 mismatch; outputs untouched on these branches. |
| [NtReleaseMutant, 0x6b0a10](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtReleaseMutant/decomp), [KeReleaseMutant, 0x218050](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/KeReleaseMutant/decomp) | Returns previous signed count, increments count, clears owner at 1. Non-owner/non-abandoned raises **0xc0000046**, before native wrapper output write. Recursive wait decrements count, so successive releases report -1 then 0. |
| [NtCreateTimer, 0x6f8aa0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtCreateTimer/decomp), [KeInitializeTimerEx](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/KeInitializeTimerEx/decomp) | Types 0/1 supported, initial signal state zero; type 2 -> **0xc00000f2**, no handle write. |
| [NtQueryTimer, 0x951a40](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQueryTimer/decomp) | Class 0, exact 16 bytes, query access 1; writes remaining LARGE_INTEGER, state byte, length 16. No assertion on padding or remaining-time numeric value. Early class/length failure leaves outputs untouched. |
| [NtSetTimer, 0x378c00](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtSetTimer/decomp), [ExpSetTimer](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/ExpSetTimer/decomp), [ExpSetTimerObject](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/ExpSetTimerObject/decomp) | Negative period -> **0xc00000f4**, before output mutation. Nonnegative period references handle with access 2 before timer implementation; access failure does not write previous state. Set returns old **signal** state, not whether timer was queued. Resume=FALSE, no APC routine/context. |
| [NtCancelTimer, 0x288ec0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtCancelTimer/decomp) | Cancels queued timer; optional current signal-state output, not queued/active BOOLEAN. Inactive and armed-but-not-fired timer both report FALSE. |
| [NtOpenEvent](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtOpenEvent/decomp), [NtOpenSemaphore](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtOpenSemaphore/decomp), [NtOpenMutant](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtOpenMutant/decomp), [NtOpenTimer](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtOpenTimer/decomp) | ObOpenObjectByName with the corresponding type; successful open publishes handle. Private named object state survives closing original handle while opened handle remains. |
| [NtWaitForSingleObject](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtWaitForSingleObject/decomp), [KeWaitForSingleObject](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/KeWaitForSingleObject/decomp) | Signal consumption: notification event retained, synchronization event cleared, semaphore decremented, mutant recursive/current ownership. Zero timeout does not block; infinite used only after successful query confirms a private notification event is signaled. |
| [NtWaitForMultipleObjects, 0x688310](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtWaitForMultipleObjects/decomp), [ObWaitForMultipleObjects](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/ObWaitForMultipleObjects/decomp) | Count 0 or 65 -> **0xc00000ef** before array traversal; type 2 -> **0xc00000f1**. Type 0=all, 1=any; any reports zero-based satisfied index, lowest if both signaled; all needs both. Tests use two distinct private notification events and zero timeout. |
| [NtDuplicateObject, 0x5face0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtDuplicateObject/decomp), [ObDuplicateObject](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/ObDuplicateObject/decomp), [NtClose](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtClose/decomp) | Current-process pseudo handle -1 and option 2 (same access) yield a second reference to same object; closing original does not destroy object while duplicate remains. No stale-handle or double-close/debugger exception assumptions. |
| [NtQueryObject, 0x634be0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQueryObject/decomp) | Basic class 0 requires 0x38 bytes; writes granted access, handle attributes, handle count and return length. Private unnamed noninheritable event has attributes 0, handle count 1. Pointer/reference count deliberately not asserted. |

## Safety and uncertainty

65 focused TESTs. Named fixtures use only `\\BaseNamedObjects\\ntdllt_<PID>_<serial>_roundtrip`.
Every opened/duplicated/created handle is closed. Timers use a one-day relative due
time and are canceled; no clock-precision assertion, expiration race, APC, wake-system
request or timer-resolution change. Exact remaining time is intentionally untested.
No abandoned-owner thread termination, process-wide native namespace mutation, or
indefinite unsignaled wait. Query buffers are real storage even for invalid lengths.

Evidence gaps: no Windows execution in this environment; user-mode Nt/Zw probing
differences, abandoned mutants, alertable/APC waits, timer firing/coalescing, and
security-descriptor/integrity policy behavior remain outside this suite. The DDI
invalid event-type status disagrees with this binary (documented above).
Wine is only smoke, not a source of expected values; observed differences are retained.

## Smoke result (not Windows validation)

Built with `make build/nt_sync.exe`, no compiler warnings on final build.
Ran only `TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_sync.exe >/tmp/opencode/ntdll_nt_sync.log 2>&1`.
Exit 1; `SUMMARY tests=65 failed=7 skipped=0 checks_pass=661 checks_fail=9`.

Retained, evidence-backed Wine divergences:

* Invalid multiple-wait type 2 returns success rather than 0xc00000f1.
* Query-only timer Set fails with ACCESS_DENIED but overwrites previous-state output with 0.
* Negative timer period succeeds/overwrites output rather than returning 0xc00000f4 untouched.
* Timer type 2 returns 0xc000000d rather than 0xc00000f2.
* Unowned mutant release returns expected 0xc0000046 but overwrites previous count with 1.
* Negative semaphore release returns 0xc0000047 rather than 0xc000000d.
* Zero semaphore release succeeds/overwrites previous count rather than rejecting untouched.

No crash, missing export, skip, or watchdog timeout in this smoke run.

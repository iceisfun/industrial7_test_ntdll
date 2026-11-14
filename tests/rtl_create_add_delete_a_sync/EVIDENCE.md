# rtl_create_add_delete_a_sync

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), standard-user and administrator runs.
Decompilation from the Corpus Explorer (`/api/function/ntdll/<Name>/decomp`) was used to learn field offsets and
validation order; values were then confirmed by running on the guest.

## Exports covered (behavioral)
RtlAcquirePebLock (+RtlReleasePebLock), RtlAcquireReleaseSRWLockExclusive, RtlAcquireResourceExclusive,
RtlAcquireResourceShared (+Initialize/Release/DeleteResource), RtlAddVectoredExceptionHandler,
RtlAddVectoredContinueHandler (+Remove*), RtlCreateTimerQueue, RtlCreateTimer (+RtlDeleteTimer, RtlDeleteTimerQueueEx),
RtlCheckForOrphanedCriticalSections, RtlCreateAtomTable, RtlAddAtomToAtomTable (+Lookup/Query/Delete/Destroy),
RtlAcquirePrivilege (+RtlReleasePrivilege).

## Expected values
| Test | Source |
| --- | --- |
| PEB lock | Decompiled body: RtlEnterCriticalSection on the CRITICAL_SECTION pointed to by PEB+0x38. Test reads RecursionCount/OwningThread of that section and shows a second thread blocks until release. |
| SRW wait | Decompiled body: if the lock word's low bit is set, acquire exclusive then release; otherwise return at once. Observed: free lock stays 0; waiter completes only after a held exclusive or shared lock is released and leaves the lock word 0. |
| RTL_RESOURCE | Field offsets from decompilation (+0x40 waiting exclusive, +0x44 NumberOfActive, +0x48 owner TID). Observed: exclusive = -1, recursive exclusive and shared-by-owner decrement further, shared = +1 each; a shared owner cannot upgrade without waiting; other-thread non-waiting attempts fail/succeed accordingly; blocking writer proceeds after the last reader releases. |
| Vectored handlers | Documented AddVectoredExceptionHandler/AddVectoredContinueHandler semantics (First != 0 = head of list; Remove returns 1 on success, 0 when the handle is unknown). Continue handler invoked once after an exception handler returned EXCEPTION_CONTINUE_EXECUTION. Exception/continue handle namespaces are separate. |
| Timers | Documented RtlCreateTimer semantics (period 0 = one shot). Observed: callback receives TimerOrWaitFired TRUE, RtlDeleteTimer / RtlDeleteTimerQueueEx with INVALID_HANDLE_VALUE return STATUS_SUCCESS after outstanding callbacks drain, queue deletion cancels a pending 60 s timer. Deleting an already deleted timer is not tested: it raises an exception on Windows 10 (use-after-free). |
| Orphan scan | Decompiled body calls the held-critical-section checker; test asserts that a section legitimately held by the (live) calling thread is left untouched (RecursionCount/OwningThread unchanged). Weak: the orphan-detection output path needs a terminated thread holding a section, which would break into a debugger. |
| Atom tables | Observed: string atoms 0xC000..0xFFFF, same name -> same atom with reference count, lookup case-insensitive and non-referencing, integer names "#n" give atom n (1..0xBFFF) and "#49152" is STATUS_INVALID_PARAMETER, empty name STATUS_OBJECT_NAME_INVALID (c0000033), names above 255 characters STATUS_INVALID_PARAMETER, lookup miss STATUS_OBJECT_NAME_NOT_FOUND (c0000034), NULL table STATUS_INVALID_PARAMETER, query with a short name buffer succeeds and truncates (length 8 for a 10-byte buffer) with a terminator, integer atoms are reported as "#nnnn". |
| Privileges | Decompiled flow: flags & ~3 -> STATUS_INVALID_PARAMETER; flags 0 impersonates self (thread token appears, privilege enabled, RtlReleasePrivilege reverts: NtOpenThreadToken -> STATUS_NO_TOKEN c000007c); flags 2 adjusts the process token and release restores the previous state; a single privilege the token lacks -> STATUS_PRIVILEGE_NOT_HELD (c0000061); several privileges where one is missing still succeed. A privilege held by every token is chosen at run time (14 increase-working-set for administrators, otherwise 23 change-notify, observed: the standard-user token lacks 14); privilege 7 (TCB) is held by neither the administrator nor the standard-user token -- the tests query the token first and skip with a reason if that assumption does not hold. |

## Skips
- rtl_acquire_privilege_*: skip only if the process token holds neither privilege 14 nor 23 (not seen), or the not-held test finds SeTcb present.

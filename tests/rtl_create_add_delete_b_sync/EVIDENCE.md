# RTL synchronization and lock helpers

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), x64, adm and std modes; all expectations passed there.
Decompilations from the Corpus Explorer give the validation order; the guest run is the authority.

| Export | Expectation | Source |
| --- | --- | --- |
| RtlTryAcquirePebLock / RtlReleasePebLock | TryAcquire is RtlTryEnterCriticalSection on PEB.FastPebLock (PEB+0x38): TRUE when free or already owned (recursion count 2), FALSE from another thread; release restores recursion 0 / owner NULL. | decomp 0x7b590 / 0x77520; observed |
| RtlTryConvertSRWLockSharedToExclusiveOrRelease | Sole shared owner: TRUE and the lock is exclusive; with another shared owner: FALSE and the caller's share is dropped. | decomp 0xe8cb0; observed |
| RtlWaitOnAddress | Size not 1/2/4/8 returns 0xC000000D; value differs: returns 0 at once; value equal with zero timeout: STATUS_TIMEOUT 0x102; 50 ms relative timeout elapses; Wake (All and Single) completes a blocked waiter with 0. | decomp 0x63460, RtlpWaitOnAddress; observed |
| RtlReleaseResource / RtlDeleteResource | NumberOfActive (+0x44) tracks shared (+n), exclusive (-n, recursive) and shared-by-exclusive-owner; shared-to-exclusive conversion yields -1; a contending shared try fails, a blocking one is released by the owner's RtlReleaseResource; delete zeroes the 0x60-byte structure. RtlConvertSharedToExclusive returns no meaningful value (VOID). | decomp 0x64d20 / 0x10f30; observed |
| RtlDeleteBarrier (RtlInitBarrier, RtlBarrier) | One-thread barrier always reports "last"; NULL barrier init gives 0xC000000D; with two threads exactly one caller is the last to arrive. | decomp 0xed890 / 0xed8c0 / 0xed870; observed |
| RtlDeleteTimer | NULL queue 0xC00000EF, NULL timer 0xC00000F0; waiting delete (INVALID_HANDLE_VALUE) returns 0; non-waiting delete while the callback runs returns STATUS_PENDING (0x103); periodic timer stops after delete. | decomp 0x9c00; observed |
| RtlDeleteTimerQueueEx / RtlDeleteTimerQueue | NULL queue 0xC00000EF; blocking delete 0 with live timers; non-waiting delete of an idle queue 0. | decomp 0x84a20 / 0x112ea0; observed |
| RtlRegisterWait | NULL / -1 / -2 object and NULL callback give 0xC000000D; signaled object calls back with TimerOrWaitFired FALSE, timeout path TRUE; deregistration with INVALID_HANDLE_VALUE returns 0. Flag 0x8 is WT_EXECUTEONLYONCE. | decomp 0xbe70; observed |
| RtlLockCurrentThread / RtlUnlockCurrentThread | Unlock without lock 0xC000002A; lock is counted (two locks need two unlocks), extra unlock 0xC000002A. Uses NtLockVirtualMemory: the test enlarges the working set first; if locking still returns 0xC00000A1 it skips. | decomp 0x83590 / 0x86cc0; observed |
| RtlLockModuleSection / RtlUnlockModuleSection | Address inside a small section of the test image: lock 0, counted, unlock 0 twice, then 0xC000002A; an address outside any module 0xC0000225. Skips on 0xC00000A1. | decomp 0x5d780 / 0x5d6d0; observed |
| RtlLockMemoryZone / UnlockMemoryZone, RtlLockMemoryBlockLookaside / UnlockMemoryBlockLookaside | Unlock before lock 0xC0000001; lock counted; extra unlock 0xC0000001. | decomp 0x5d4f0, 0x5cf00, 0x5d480, 0x5cea0; observed |
| RtlRemoveVectoredExceptionHandler / ContinueHandler | Returns 1 for a registered handle then 0; NULL gives 0; an exception-handler handle is not accepted by the continue remover and vice versa; a removed handler is no longer invoked while other handlers still are. | decomp 0x82180 / 0xd9780; observed |
| RtlLockBootStatusData | Always 0xC00000BB (STATUS_NOT_SUPPORTED) with the output handle cleared on this build. RtlUnlockBootStatusData with a non-NULL handle is a no-op and has no observable result (called, not asserted). | decomp 0xee0a0 / 0xee250; observed |
| RtlEnumProcessHeaps | Returns 0; the callback sees the process heap and a freshly created heap exactly once, and not a destroyed one; a failing callback status stops the enumeration and is returned. | decomp 0xf2490; observed |
| RtlRegisterSecureMemoryCacheCallback | Returns 0; RtlDeregisterSecureMemoryCacheCallback returns TRUE then FALSE. | decomp 0xf7bf0; observed |
| RtlRegisterFeatureConfigurationChangeNotification / Unregister | Returns 0 with distinct non-NULL registrations for two registrations; unregister releases them. A non-zero return skips. | decomp 0x93b0 / 0x7eef0; observed |
| RtlRegisterForWnfMetaNotification | Flags 0, 0x1 or 0x10 give 0xC000000D and clear the output subscription. Successful registration is not tested (needs live WNF meta state). | decomp 0x63c80; observed |

Skips are conditional and concrete: lock tests skip only on STATUS_WORKING_SET_QUOTA; feature notification skips only on a
non-zero registration status. In both guest modes nothing skipped.

# Thread pool configuration, cleanup groups, callback completion actions

Reference: Windows 10 22H2 ntdll 10.0.19041.2788. Decompilation of the exports (RVAs in the Corpus Explorer) gives the argument
validation; the guest run (admin and standard user) is the authority.

Invalid parameters in ntdll thread pool code call TppRaiseInvalidParameter, which raises a continuable exception with code
0xC000000D (decompilation: memset of the record, ExceptionCode 0xC000000D, RtlRaiseException). The tests install a vectored
handler that counts the exception and continues, then assert the count and the returned status.

| Check | Source |
| --- | --- |
| TpSetPoolMinThreads: valid -> 0; negative or NULL pool -> raises + returns 0xC000000D | decompilation (0x83510), observed |
| TpSetPoolMaxThreadsSoftLimit / TpSetPoolMaxThreads: valid silent; negative / NULL raise | decompilation (0x810c0, 0x61730), observed |
| TpSetPoolThreadBasePriority: NULL pool 0xC000000D without exception; valid -> 0 | decompilation (0x85830), observed |
| TpSetPoolWorkerThreadIdleTimeout: negative -> 0; zero/positive/NULL pool -> raise + 0xC000000D | decompilation (0x617a0), observed |
| TpDisablePoolCallbackChecks: valid -> 0; NULL -> 0xC000000D without exception | decompilation (0x85500), observed |
| TpQuery/TpSetPoolStackInformation: NULL arguments 0xC000000D; a set value is returned by the next query; TpSetDefaultPoolStackInformation(NULL) 0xC000000D, valid 0 | decompilation (0x111bf0, 0x6fb30, 0x6fa10), observed |
| TpSetPoolThreadCpuSets: NULL pool or NULL set 0xC000000D; count 0 accepted (observed) | decompilation (0x111e00), observed |
| TpTrimPools, TpSetDefaultPoolMaxThreads (value below the default limit), TpCaptureCaller, TpCheckTerminateWorker on non-worker threads (NULL and a real thread handle) return without exceptions | decompilation (0x63ce0, 0x111cb0, 0x714e0, 0x546a0), observed |
| TpAllocCleanupGroup: valid -> 0 distinct objects; NULL -> raise + 0xC000000D. TpReleaseCleanupGroup(NULL) and TpReleaseCleanupGroupMembers(NULL) raise | decompilation (0x7e8c0, 0x81a60, 0x526d0), observed |
| TpReleaseCleanupGroupMembers(FALSE) waits for all member callbacks (counts 1 and 2 exactly) and the group is reusable afterwards; with cancelPending TRUE the queued callback never runs, the running one is waited for, and the cancel callback in the environment runs once per member with the cleanup parameter | observed |
| TpCallbackReleaseSemaphoreOnCompletion: the semaphore receives exactly the requested count after the callback returns; NULL / -1 handle, zero count, NULL instance and a second registration raise | decompilation (0x112160), observed |
| TpCallbackReleaseMutexOnCompletion, TpCallbackLeaveCriticalSectionOnCompletion: owned in the callback, released afterwards (mutex not abandoned, critical section recursion count 1 for a new owner); NULL arguments raise | decompilation (0x112120, 0x88610), observed |
| TpCallbackUnloadDllOnCompletion: module is unloaded after the callback returns (dbghelp.dll loaded once by the test; skipped when already loaded) | decompilation (0x7d7d0), observed |
| TpCallbackMayRunLong and TpCallbackIndependent inside a callback return 0; TpCallbackIndependent(NULL) raises | decompilation (0x6ff70, 0x62300), observed |
| TpDisassociateCallback: TpWaitForWork returns while the callback is still blocked | decompilation (0x801b0), observed |

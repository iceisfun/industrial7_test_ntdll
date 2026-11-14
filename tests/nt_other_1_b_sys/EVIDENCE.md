# nt_other_1_b_sys: process, thread and system natives, Windows 10 22H2 (ntdll 10.0.19041.2788)

The exports are syscall stubs in the decompilation (no validation visible); expectations come from the public
docs of the Win32 wrappers and were confirmed on the guest in adm and std mode. Nt/Zw alias pairs are compared
by address in `alias_pairs`.

| Export | Checked | Source |
| --- | --- | --- |
| NtGetCurrentProcessorNumber(Ex) | value below the active processor count; Ex fills group/number, reserved byte 0; after pinning to CPU 0 both report 0. | docs + observed |
| NtGetTickCount | within 2 s of GetTickCount, advances by the slept interval. | observed |
| NtGetNextProcess | enumerate from NULL until `STATUS_NO_MORE_ENTRIES` (**8000001A**, warning severity), current pid seen exactly once, reverse flag (1), invalid handle C0000008, bad flags 0x80 C000000D. | observed |
| NtGetNextThread | enumerates the current process threads, current tid seen once, an extra thread adds exactly one entry, same error cases. | observed |
| NtIsProcessInJob | suspended child with breakaway: not in a fresh job `STATUS_PROCESS_NOT_IN_JOB` (123); after assignment `STATUS_PROCESS_IN_JOB` (124), also with a NULL job; current process vs that job 123; bad handles C0000008; process handle as job `STATUS_OBJECT_TYPE_MISMATCH` (C0000024). | docs + observed |
| NtIsSystemResumeAutomatic | FALSE on the guest. | observed |
| NtIsUILanguageComitted | status 0. | observed |
| NtGetContextThread | suspended new thread: Rip inside ntdll (RtlUserThreadStart), Rcx = start routine, Rdx = parameter, SegCs 0x33; only requested groups written; flags 0 -> 0; bad handle C0000008; process handle C0000024; NULL buffer C0000005; handle without THREAD_GET_CONTEXT C0000022. | observed |
| NtQueueApcThread / Ex | APC delivered on alertable wait with the three arguments, FIFO order, pseudo handle, Ex with a NULL reserve object; errors: C0000008, C0000024, access denied C0000022 without THREAD_SET_CONTEXT, exited thread `STATUS_UNSUCCESSFUL` (C0000001), bad reserve handle C0000008 (nothing delivered). | observed |
| NtImpersonateThread | worker thread impersonates another thread of the same process: impersonation token present, level Impersonation(2), same user SID as the process token. | observed |
| NtImpersonateAnonymousToken | thread token user is S-1-5-7; level Identification (1); errors C0000008 (invalid and NULL), C0000024, C0000022 (no THREAD_IMPERSONATE). Impersonation removed afterwards via NtSetInformationThread (helper). | observed |
| NtPrivilegeCheck | impersonation token (SQOS level Impersonation): SeChangeNotify held+enabled -> result 1 and USED_FOR_ACCESS set; SeTcb not held -> 0 (true for admin and standard); any-of vs ALL_NECESSARY; zero count -> TRUE; a primary token is accepted; bad handle C0000008; wrong type C0000024; token without TOKEN_QUERY C0000022. An impersonation token with default (anonymous) level gives C00000A5, so SQOS is set. | observed |
| NtPowerInformation | SystemPowerCapabilities(4) 76 bytes OK, 8 bytes C0000023; SystemExecutionState(16); ProcessorInformation(11) entries numbered 0..n-1, 4 bytes C0000023; LastWakeTime(14)/LastSleepTime(15) 0, 4 bytes C0000023; level 0x7fff C000000D. | docs (CallNtPowerInformation) + observed |

Skips: none. Observed-only values: the exact STATUS_UNSUCCESSFUL for an APC to an exited thread, NtIsUILanguageComitted
status 0, LastWake/LastSleep success. Unsafe or service-bound exports of the group are listed as justified-uncovered in the report.

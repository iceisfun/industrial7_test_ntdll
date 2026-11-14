# nt_other_2_a_exec: suspension, termination, alerts, waits, VM and file leftovers

Oracle: Windows 10 22H2 guest (ntdll 10.0.19041.2788), elevated and standard-user runs. The kernel-side bodies
of these services are not available in the corpus (ntdll only holds the syscall stub), so every expected value is either
public documentation or **observed on Windows 10**; observed-only values are marked (obs).

| Export | Expectation | Source |
| --- | --- | --- |
| NtSuspendThread / NtResumeThread | Previous count returned through the optional out pointer; creation-suspended thread has count 1; resume of a non-suspended thread returns 0 and keeps 0; BOGUS handle `STATUS_INVALID_HANDLE`, event handle `STATUS_OBJECT_TYPE_MISMATCH`, handle lacking THREAD_SUSPEND_RESUME `STATUS_ACCESS_DENIED`, unwritable out pointer `STATUS_ACCESS_VIOLATION` | SuspendThread/ResumeThread docs; (obs) |
| NtSuspendProcess / NtResumeProcess | Each thread count rises/falls by one (checked on a child's initial thread, count 2 after process suspend of a creation-suspended thread) | (obs) |
| NtTerminateThread / NtTerminateProcess | Exit code equals the status; terminating an already-exited thread through a handle returns 0 (obs); an already-terminated process returns `STATUS_PROCESS_IS_TERMINATING` (0xC000010A) | TerminateThread docs; (obs) |
| NtTerminateJobObject | Kills member process with the given exit status; empty job still returns 0; PROCESS/JOB access rights enforced | TerminateJobObject docs; (obs) |
| NtTestAlert | Returns 0 whether or not APCs were pending; queued user APCs run before it returns | (obs) |
| NtYieldExecution | 0 or `STATUS_NO_YIELD_PERFORMED` (0x40000024) | docs of SwitchToThread; stable part only |
| NtWaitForAlertByThreadId | Timeout -> 0x102; alert delivered earlier is remembered and consumed once; the wait returns `STATUS_ALERTED` (0x101) when alerted; invalid thread id for NtAlertThreadByThreadId (helper) -> `STATUS_INVALID_CID` | (obs) |
| NtSignalAndWaitForSingleObject | Signal side effect (event set, semaphore released, mutex released) happens even when the wait times out; released unowned mutex `STATUS_MUTANT_NOT_OWNED`; semaphore at max `STATUS_SEMAPHORE_LIMIT_EXCEEDED`; handle with SYNCHRONIZE only `STATUS_ACCESS_DENIED`; process handle as signal object `STATUS_OBJECT_TYPE_MISMATCH`; pending user APC with alertable wait `STATUS_USER_APC` (0xC0) | SignalObjectAndWait docs; (obs) |
| NtWaitForMultipleObjects32 | 32-bit sign-extended handle array; count 0 or 65 -> `STATUS_INVALID_PARAMETER_1` (0xC00000EF); wait type 2 -> `STATUS_INVALID_PARAMETER_3` (0xC00000F1); WaitAny index and WaitAll | (obs) |
| NtWaitHigh/LowEventPair | `STATUS_NOT_IMPLEMENTED` for every handle, including NULL; NtCreateEventPair (helper) is also not implemented | (obs) |
| NtWaitForKeyedEvent / NtReleaseKeyedEvent | Key with low bit set `STATUS_INVALID_PARAMETER_1`; timeout without partner 0x102; a releaser/waiter pair on equal keys both return 0, different keys do not match | KeyedEvent semantics (obs) |
| NtResetWriteWatch | Reset clears tracking for the range (verified with kernel32 GetWriteWatch); size 0 -> `STATUS_INVALID_PARAMETER_3`; range outside a write-watch region, a plain region or free memory -> `STATUS_INVALID_PARAMETER_1` | (obs) |
| NtUnlockVirtualMemory | Not locked -> `STATUS_NOT_LOCKED` (0xC000002A); bounds rounded to the page; map types 0 and 4 -> `STATUS_INVALID_PARAMETER`; size 0 -> `STATUS_INVALID_PARAMETER` | VirtualUnlock docs; (obs) |
| NtUnmapViewOfSectionEx | Flags 0 only; invalid flags -> `STATUS_INVALID_PARAMETER_3`; any address inside the view unmaps the whole view; second unmap and private memory -> `STATUS_NOT_MAPPED_VIEW` | (obs) |
| NtUnlockFile | Matches lock by offset, length, key and owner handle; mismatch or double unlock `STATUS_RANGE_NOT_LOCKED` (0xC000007E); IO_STATUS_BLOCK.Status is set | UnlockFile docs; (obs) |
| NtWriteFileGather | Page-sized segments written in listed order; Information equals the byte count; unaligned length or offset and handles not opened NO_BUFFERING|OVERLAPPED -> `STATUS_INVALID_PARAMETER` | WriteFileGather docs; (obs) |
| NtWaitForDebugEvent / NtRemoveProcessDebug | Fresh debug object times out (0x102); process not attached `STATUS_PORT_NOT_SET` (0xC0000353) | (obs) |
| NtStartProfile / NtStopProfile | invalid handle and wrong type only | (obs) |
| NtSystemDebugControl | An undefined command never succeeds (observed 0xC0000354 `STATUS_DEBUGGER_INACTIVE`); only "fails" is asserted | (obs) |

Nt/Zw aliases: asserted by comparing resolved addresses for the pairs named in the tests.
Not covered here: NtShutdownSystem (powers the guest off).

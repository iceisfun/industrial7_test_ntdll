# Zw-named memory, thread, process, job, section, debug and file services: Windows 10 contracts

Oracle: Windows 10 22H2 x64, elevated and standard user (both identical). Behaviour through `Zw*` names; `zw_proc_aliases`
asserts every `Nt*`/`Zw*` pair shares an address. Fixtures use kernel32 (`VirtualAlloc`, `CreateThread`, `CreateFileA`,
`OpenProcess`, `GetWriteWatch`) plus `NtCreateSection/NtMapViewOfSection/NtLockVirtualMemory/NtLockFile/NtCreateJobObject/
NtAssignProcessToJobObject/NtCreateDebugObject/NtDebugActiveProcess/NtQueryInformationThread`. Child processes are throwaway
sleepers terminated by the test. NULL handles are never passed to `ZwTerminateThread`/`ZwTerminateProcess` (NULL means the caller).

| Export | Expectation | Source |
| --- | --- | --- |
| ZwReadVirtualMemory | exact copy and byte count for self and a PROCESS_VM_READ handle; count output optional; zero length -> 0, count 0; handle without VM_READ -> 0xc0000022; unreadable/NULL source -> 0x8000000d (partial copy); straddling into reserved memory -> 0x8000000d with at most the in-page bytes (observed count 0); NULL handle -> 0xc0000008; thread handle -> 0xc0000024 | doc + obs |
| ZwWriteVirtualMemory | same shape; VM_WRITE|VM_OPERATION handle accepted; VM_READ-only -> 0xc0000022; read-only page -> 0x8000000d count 0 | doc + obs |
| ZwUnlockVirtualMemory | lock (MAP_PROCESS=1) then unlock -> 0; unlock again or never locked -> 0xc000002a; map type 0 or 4 -> 0xc000000d; zero size -> 0xc000000d; NULL handle -> 0xc0000008 | obs |
| ZwResetWriteWatch | clears the write-watch bits (verified with GetWriteWatch before/after, full and partial reset); non write-watch region -> 0xc00000ef; unaligned base accepted (0); NULL handle -> 0xc0000008 | obs |
| ZwSuspendThread / ZwResumeThread | previous suspend count output; CREATE_SUSPENDED thread has count 1; counts verified with ThreadSuspendCount (class 35); resume of running thread reports 0; terminated thread: suspend -> 0xc000004b, resume -> 0; wrong type -> 0xc0000024; no SUSPEND_RESUME access -> 0xc0000022 | doc + obs |
| ZwTerminateThread | exit code delivered; second terminate of a dead thread -> 0 (exit code unchanged); no TERMINATE access -> 0xc0000022 | obs |
| ZwSuspendProcess / ZwResumeProcess | counts stack on the child's thread (1, 2, then back to 0); query-limited handle -> 0xc0000022; thread handle -> 0xc0000024 | obs |
| ZwTerminateProcess | exit status delivered; second terminate -> 0xc000010a with exit code unchanged; no PROCESS_TERMINATE -> 0xc0000022 | obs |
| ZwTerminateJobObject | child in the job gets the exit status; empty job terminate -> 0; no JOB_OBJECT_TERMINATE -> 0xc0000022; process handle -> 0xc0000024 | obs |
| ZwUnmapViewOfSection | any address inside a view removes the whole view (verified with VirtualQuery); a second unmap -> 0xc0000019; a private allocation -> 0xc0000019; thread handle -> 0xc0000024; no VM_OPERATION -> 0xc0000022 | obs |
| ZwUnmapViewOfSectionEx | flags 0 and 1 accepted; undefined high flag -> 0xc00000f1; otherwise as above | obs |
| ZwRemoveProcessDebug | not debugged -> 0xc0000353; after NtDebugActiveProcess -> 0; again -> 0xc0000353; NULL handles -> 0xc0000008; swapped handles -> 0xc0000024 | obs |
| ZwWaitForDebugEvent | empty queue with zero timeout -> 0x102; after attaching to a suspended child the first state change has NewState 3 (create-process); bad/wrong handles 0xc0000008/0xc0000024 | obs |
| ZwWriteFile | status/Information; byte offset honoured; FILE_WRITE_TO_END_OF_FILE and FILE_USE_FILE_POINTER_POSITION specials; zero length -> Information 0; read-only handle -> 0xc0000022; pseudo handle -1 and unused handle -> 0xc0000008 | doc + obs |
| ZwUnlockFile | key and range must match the lock: wrong key, wrong length, repeat unlock, never locked -> 0xc000007e; process handle -> 0xc0000024 | obs |
| ZwWriteFileGather | unbuffered overlapped handle, two page elements: Information 0x2000, data verified by reading back; length not sector multiple -> 0xc000000d; missing byte offset -> 0xc000000d; NULL handle -> 0xc0000008. Skips with the Win32 error if an unbuffered overlapped file cannot be created | doc + obs |
| ZwTerminateEnclave | ordinary allocation -> 0xc0000018; unallocated address -> 0xc00000a0 | obs |
| ZwRevertContainerImpersonation | no active container impersonation -> 0xc0000001 | obs |

Skips: setup failures only (file, thread, child, section, debug-object creation), each with the failing status in the skip text.

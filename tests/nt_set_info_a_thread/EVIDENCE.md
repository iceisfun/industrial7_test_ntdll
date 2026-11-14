# NtSetInformationThread, NtSetContextThread, NtSetThreadExecutionState, NtSetLdtEntries

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), run as elevated administrator and as a standard
user. The ntdll routines are syscall stubs; argument validation lives in the kernel services, whose
decompilation (`/api/function/ntoskrnl/<name>/decomp` of the Corpus Explorer) was read for ordering and
status codes. Every expectation below was then confirmed on the guest.

| Check | Expected | Source |
|---|---|---|
| ThreadBasePriority (3) with LONG 1 / -1 / 0 | STATUS_SUCCESS; `GetThreadPriority` agrees | documented SetThreadPriority mapping; observed |
| any length other than 4 for classes 3, 14, 13, 5, 10 | STATUS_INFO_LENGTH_MISMATCH | decompilation, observed |
| ThreadPriorityBoost (14) 1/0 | success; `GetThreadPriorityBoost` reports disabled TRUE/FALSE | documented, observed |
| ThreadAffinityMask (4): lowest allowed CPU | success; `SetThreadAffinityMask` returns that mask as previous | documented, observed |
| affinity 0 or CPUs outside the process mask | STATUS_INVALID_PARAMETER | observed |
| ThreadIdealProcessor (13) | success status is non-negative (the previous ideal processor is returned as the status; observed 3 on the first call); setting the same value twice yields 0 | observed only |
| ThreadHideFromDebugger (17): length 0 | success; query class 17 afterwards returns 1 (0 before) | observed |
| ThreadHideFromDebugger length 1 | STATUS_INFO_LENGTH_MISMATCH | observed |
| ThreadNameInformation (38) set/query round trip | success; same UNICODE_STRING text | observed (Windows 10 1607+); skips on STATUS_INVALID_INFO_CLASS |
| ThreadQuerySetWin32StartAddress (9) | already set by CreateThread; second set STATUS_INVALID_PARAMETER and query keeps the CreateThread start address | observed |
| ThreadZeroTlsCell (10) on the current thread | the TLS slot value becomes 0 | observed |
| ThreadImpersonationToken (5) with a NULL token | success (clears nothing) ; length 4 mismatch | observed |
| class 0x7fffffff | STATUS_INVALID_INFO_CLASS | observed |
| invalid / NULL handle | STATUS_INVALID_HANDLE | observed |
| handle without THREAD_SET_INFORMATION | STATUS_ACCESS_DENIED | observed |
| NtSetContextThread on a suspended thread, CONTEXT_INTEGER | success; `NtGetContextThread` and `GetThreadContext` read back Rbx/R12/R15 | documented, observed |
| NtSetContextThread invalid handle / no THREAD_SET_CONTEXT | STATUS_INVALID_HANDLE / STATUS_ACCESS_DENIED | decompilation (ObReferenceObjectByHandle with 0x10), observed |
| NtSetThreadExecutionState(ES_CONTINUOUS \| ES_SYSTEM_REQUIRED), then ES_CONTINUOUS | success; the second call reports the previous state with both bits | decompilation (flags/previous state), observed |
| flags 0x100, 0x80000100, 0x4, 0x40 without ES_CONTINUOUS | STATUS_INVALID_PARAMETER | decompilation: `flags & 0x7fffffbc` must be 0 and 0x40 only with the sign bit; observed |
| NtSetLdtEntries on x64 | STATUS_NOT_IMPLEMENTED | shared stub in the decompilation, observed |

Notes: the helper threads wait on an event with a 20 s timeout and are always released, waited for and
closed. The execution-state test clears its request before returning. Nt/Zw alias pairs are compared by
address for all four exports.

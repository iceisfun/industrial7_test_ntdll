# NtSetInformationProcess and NtSetInformationVirtualMemory

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), administrator and standard user. All process
classes are applied to a suspended child process created from the test exe (never resumed, terminated at
the end), so the test process keeps its priority, affinity and error mode. The kernel decompilations were
read for class dispatch and length rules; all values below were observed on the guest.

| Check | Expected | Source |
|---|---|---|
| ProcessPriorityClass (18), PROCESS_PRIORITY_CLASS{Foreground, Class} 5/1/3/2 | success; `GetPriorityClass` returns BELOW_NORMAL / IDLE / HIGH / NORMAL | documented, observed |
| class byte 0 | success, priority class unchanged | observed |
| class byte 7 | STATUS_INVALID_PARAMETER | observed |
| length 1 or 4 for class 18 | STATUS_INFO_LENGTH_MISMATCH | observed |
| ProcessPriorityBoost (22) | `GetProcessPriorityBoost` reflects the set value; length 8 mismatch | observed |
| ProcessDefaultHardErrorMode (12) | `NtQueryInformationProcess` class 12 returns the value set; length 2 mismatch | observed |
| ProcessAffinityMask (21) | `GetProcessAffinityMask` of the child returns the mask; 0 -> STATUS_INVALID_PARAMETER; length 4 mismatch | observed |
| ProcessIoPriority (33) 1, 2 | query class 33 returns the value; 99 -> STATUS_INVALID_PARAMETER; length mismatch | observed |
| ProcessPagePriority (39) 3 | query class 39 returns 3; 99 -> STATUS_INVALID_PARAMETER | observed |
| ProcessDebugFlags (31) 0/1 | query returns the same value; 2 -> STATUS_INVALID_PARAMETER; length 1 mismatch | observed |
| class 0x7fffffff | STATUS_INVALID_INFO_CLASS | observed |
| NULL / invalid handle | STATUS_INVALID_HANDLE | observed |
| handle without PROCESS_SET_INFORMATION | STATUS_ACCESS_DENIED | observed |
| NtSetInformationVirtualMemory(VmPrefetchInformation=0) on a committed private range | STATUS_SUCCESS | documented (PrefetchVirtualMemory), observed |
| VM class 0x7f / zero entries / length 2 / NULL data | STATUS_INVALID_PARAMETER_2 (C00000F0) / PARAMETER_3 (C00000F1) / PARAMETER_6 (C00000F4) / PARAMETER_5 (C00000F3) | decompilation of the kernel service (explicit status constants), observed |
| VM invalid handle | STATUS_INVALID_HANDLE | observed |

Not set on purpose: ProcessBreakOnTermination (would bugcheck when the process ends), ProcessExecuteFlags
(permanent DEP changes), quota and token-related classes that need privileges.

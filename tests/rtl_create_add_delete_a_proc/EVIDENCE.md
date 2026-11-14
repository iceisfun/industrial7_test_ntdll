# rtl_create_add_delete_a_proc

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). The child process is this very test image started with
`--child rtl_cup_child` (exits with code 37). No other processes are created.

## Exports covered (behavioral)
RtlCreateUserProcess, RtlCreateUserProcessEx, RtlCreateProcessReflection (plus RtlCreateProcessParametersEx
as a setup helper).

## Expected values
| Check | Source |
| --- | --- |
| RtlCreateUserProcess/Ex success | Decompiled RtlCreateUserProcess builds the extended-parameter block (Version 1; process/thread SD, parent, debug port, token) and calls RtlCreateUserProcessEx. Observed on guest: process and suspended thread handles returned, ClientId matches GetProcessId/GetThreadId, process has not run before ResumeThread, exit code of the child is 37, SECTION_IMAGE_INFORMATION (at +0x28 of RTL_USER_PROCESS_INFORMATION) shows TransferAddress != 0 and SubSystemType 3 (console). |
| Ex argument validation | Decompiled: NULL image path or NULL parameters -> STATUS_INVALID_PARAMETER before any system call. |
| Errors | Observed: missing image file -> STATUS_OBJECT_NAME_NOT_FOUND (c0000034); text file named .exe -> STATUS_INVALID_IMAGE_NOT_MZ (c000012f); output handles stay NULL. |
| Reflection arguments | Decompiled: flags outside {0x02,0x04,0x08,0x10} -> STATUS_INVALID_PARAMETER_2 (c00000f0); NO_SYNCHRONIZE (8) together with a start routine -> c00000f3. |
| Reflection clone | Observed: reflecting the current process (pseudo handle) yields a new process whose id equals ClientId.UniqueProcess, differs from ours and whose image is the test executable; it is terminated and waited for by the test. |

Process creation uses the parent pseudo handle -1; no tokens, jobs or debug ports are involved.

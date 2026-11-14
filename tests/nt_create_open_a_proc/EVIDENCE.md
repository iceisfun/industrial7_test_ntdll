# nt_create_open_a_proc: process, thread and token creation

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). All exports are syscall stubs; statuses are **observed on
Windows 10** (guest, administrator and, where the guest allows, standard user). Documentation only covers
the Win32 wrappers (CreateProcess, CreateThread, OpenProcessToken, OpenThreadToken); the native contracts
below come from running them.

| Test | Check | Source |
| --- | --- | --- |
| process_create_no_section_object | `NtCreateProcess` with the current process as parent and no section creates an empty process object: parent PID reported by `NtQueryInformationProcess` is ours, PID differs, `GetProcessId` agrees, exit status `STILL_ACTIVE`; `NtTerminateProcess` on it succeeds (status 0x122 is only noted, not asserted) | observed |
| process_ex_create_variants | `NtCreateProcessEx` flags 0 and 4 (INHERIT_FROM_PARENT) | observed |
| process_create_invalid_arguments | bogus parent -> 0xC0000008, NULL parent -> 0xC000000D, flags 0x80000000 -> 0xC000000D, access 0 -> 0xC0000022, bogus section -> 0xC0000008 | observed |
| thread_ex_runs_start_routine | start routine receives its argument; return value is the exit code; thread ID differs from ours | observed |
| thread_ex_create_suspended | flag 1 leaves the thread suspended (wait times out); `NtResumeThread` reports previous count 1 | observed |
| thread_ex_invalid_arguments | bogus process -> 0xC0000008; flags 0x80000000 -> 0xC00000F5 (parameter 7); MaxStackSize 0x7FFFFFFFFFFF -> 0xC000000D; a thread pseudo handle as process -> 0xC0000024 | observed |
| thread_legacy_create_with_context | `NtCreateThread` with a caller stack, INITIAL_TEB and CONTEXT (Rip = kernel32 ExitThread, Rcx = exit code) runs; CLIENT_ID returned and matches `GetThreadId`; exit code 0x2A | observed |
| thread_legacy_invalid_arguments | NULL context -> 0xC000000D; NULL INITIAL_TEB -> 0xC0000005; CLIENT_ID output is optional | observed |
| user_process_runs_image_and_returns_handles | minimal `NtCreateUserProcess` (image-name attribute 0x20005, normalized RTL_USER_PROCESS_PARAMETERS, zeroed PS_CREATE_INFO of size 0x58) starts `cmd.exe /c exit 7`; parent PID, process/thread handles consistent; exit code 7. Skips if cmd.exe is absent | observed |
| user_process_invalid_arguments | no attribute list, create-info size 0x50, empty image name, flags 0x80000000 in either flag word -> 0xC000000D; NULL parameters, NULL create-info, NULL process handle pointer -> 0xC0000005; image path that does not exist -> 0xC0000034 | observed |
| open_process_token_ex_* | pseudo handle opens a token with the same TokenStatistics id each time; HandleAttributes 2 (OBJ_INHERIT) makes the handle inheritable and 0 does not; bogus handle -> 0xC0000008; a thread pseudo handle -> 0xC0000024; desired access 0 -> 0xC0000022 | observed |
| open_thread_token_ex_no_token_and_errors | no impersonation: 0xC000007C (NO_TOKEN) for OpenAsSelf FALSE and TRUE; bogus handle 0xC0000008; process pseudo handle 0xC0000024 | observed |
| open_thread_token_ex_impersonating | after `NtSetInformationThread(ThreadImpersonationToken)` with a duplicated impersonation token, the call returns that token (same TokenStatistics id) for OpenAsSelf TRUE and FALSE; after reverting it is 0xC000007C again | observed |

Cleanup: empty processes are terminated, the legacy thread has its stack freed, the child process is waited
for (15 s limit) and killed if still running, tokens are closed.
Threads created by NtCreateThreadEx/NtCreateThread are always started with a start routine that exits.

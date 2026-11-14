# nt_create_open_b_proc: process, thread, token open and thread/process creation

Reference queried 2026-11-14: Windows 10 22H2 corpus (ntdll 10.0.19041.2788). The ntdll exports in this
area are syscall stubs (`/api/function/ntdll/<name>/decomp` shows only the service-number load and
`syscall`/`int 2e` dispatch, no argument checks), so every expected value below was **observed on a
real Windows 10 22H2 guest** (adm = elevated administrator, std = standard user) and, where the name
describes a documented contract, cross-checked against public documentation. Nt/Zw pairs share one
RVA: each test asserts `t_proc("NtX") == t_proc("ZwX")` and exercises behavior through the Zw name.
Status codes are written as NTSTATUS values. Tests do not depend on order and clean up what they create.
Object names are made unique per process in the caller's session namespace
(`\BaseNamedObjects` for session 0, `\Sessions\<n>\BaseNamedObjects` otherwise).

Exports: ZwOpenProcess, ZwOpenThread, ZwOpenProcessToken, ZwOpenProcessTokenEx, ZwOpenThreadToken, ZwOpenThreadTokenEx,
ZwCreateThread, ZwCreateThreadEx, ZwCreateProcess, ZwCreateProcessEx.

| Behavior | Status / value | Source |
|---|---|---|
| ZwOpenProcess own pid | 0; GetProcessId(handle)==pid; granted mask is exactly the request; OBJ_INHERIT is reflected in the handle flags | observed |
| ZwOpenProcess: pid 0 or 0xFFFFFFF0 | STATUS_INVALID_CID C000000B; NULL ClientId, or ObjectName set: STATUS_INVALID_PARAMETER_MIX C0000030; System (pid 4) with PROCESS_ALL_ACCESS: C0000022 | observed |
| ZwOpenThread | own tid ok (GetThreadId matches); wrong pid or unknown/zero tid C000000B; NULL ClientId C0000030 | observed |
| Process token | type `Token`; TokenType (class 8) 1; MAXIMUM_ALLOWED includes QUERY and DUPLICATE; access 0 or 0x800000/0x1FFFFFF: C0000022; NULL handle C0000008; thread handle C0000024; process handle without PROCESS_QUERY_INFORMATION C0000022 | observed |
| Thread token | no impersonation: STATUS_NO_TOKEN C000007C; after NtSetInformationThread(ThreadImpersonationToken) the open yields a token with TokenType 2; OpenAsSelf both ways; OBJ_INHERIT attribute honoured by the Ex form; NULL out pointer C0000005; process handle C0000024; NULL handle C0000008 | observed |
| ZwCreateThreadEx | suspended thread does not run until NtResumeThread (previous suspend count 1); start routine receives its argument; exit code 7; NULL/invalid process C0000008, thread handle as process C0000024, NULL out pointer C0000005, bad create flags C00000F5 (PARAM_7), bad attribute list pointer C0000005 | observed |
| ZwCreateThread (legacy) | with NULL context and initial TEB every call fails C000000D regardless of the process handle | observed |
| ZwCreateProcessEx / ZwCreateProcess | from a SEC_IMAGE section of the test exe: new pid differs, process has no thread, not signalled, NtTerminateProcess returns STATUS_NOTHING_TO_TERMINATE 00000122; NULL parent C000000D; invalid parent C0000008; thread handle as parent C0000024; invalid section C0000008; NULL output C0000005 | observed |

Skips: none. Standard users get the same results (all targets are the caller's own objects).

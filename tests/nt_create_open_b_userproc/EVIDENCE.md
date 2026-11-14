# nt_create_open_b_userproc: ZwCreateUserProcess

Reference queried 2026-11-14: Windows 10 22H2 corpus (ntdll 10.0.19041.2788). The ntdll exports in this
area are syscall stubs (`/api/function/ntdll/<name>/decomp` shows only the service-number load and
`syscall`/`int 2e` dispatch, no argument checks), so every expected value below was **observed on a
real Windows 10 22H2 guest** (adm = elevated administrator, std = standard user) and, where the name
describes a documented contract, cross-checked against public documentation. Nt/Zw pairs share one
RVA: each test asserts `t_proc("NtX") == t_proc("ZwX")` and exercises behavior through the Zw name.
Status codes are written as NTSTATUS values. Tests do not depend on order and clean up what they create.
Object names are made unique per process in the caller's session namespace
(`\BaseNamedObjects` for session 0, `\Sessions\<n>\BaseNamedObjects` otherwise).

Exports: ZwCreateUserProcess.

The test builds RTL_USER_PROCESS_PARAMETERS with RtlCreateProcessParametersEx, a PS_CREATE_INFO of 0x58 bytes in
the initial state and a one-entry attribute list with PS_ATTRIBUTE_IMAGE_NAME (0x20005) naming
`\??\<system directory>\cmd.exe`. The process is created with a suspended initial thread, inspected, terminated
with NtTerminateProcess(0x77) and waited for.

| Behavior | Status / value | Source |
|---|---|---|
| Suspended creation | 0; process and thread handles of types `Process` / `Thread`; thread belongs to the new process; process not signalled while suspended; terminate status 0, exit code 0x77 | observed |
| No image-name attribute | C000000D | observed |
| NULL process parameters, or NULL create-info/attribute list pointers | C0000005 | observed |
| PS_CREATE_INFO size 0x10 | C000000D | observed |
| Missing image file | STATUS_OBJECT_NAME_NOT_FOUND C0000034 | observed |

Skips: none.

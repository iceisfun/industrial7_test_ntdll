# nt_create_open_b_misc: privileged and rarely used create/open services

Reference queried 2026-11-14: Windows 10 22H2 corpus (ntdll 10.0.19041.2788). The ntdll exports in this
area are syscall stubs (`/api/function/ntdll/<name>/decomp` shows only the service-number load and
`syscall`/`int 2e` dispatch, no argument checks), so every expected value below was **observed on a
real Windows 10 22H2 guest** (adm = elevated administrator, std = standard user) and, where the name
describes a documented contract, cross-checked against public documentation. Nt/Zw pairs share one
RVA: each test asserts `t_proc("NtX") == t_proc("ZwX")` and exercises behavior through the Zw name.
Status codes are written as NTSTATUS values. Tests do not depend on order and clean up what they create.
Object names are made unique per process in the caller's session namespace
(`\BaseNamedObjects` for session 0, `\Sessions\<n>\BaseNamedObjects` otherwise).

Exports: ZwCreatePartition, ZwOpenPartition, ZwOpenSession, ZwCreateJobSet, ZwOpenObjectAuditAlarm, ZwCreateToken,
ZwCreateTokenEx, ZwCreateLowBoxToken, ZwCreateProfile, ZwCreateProfileEx, ZwCreatePort, ZwCreateWaitablePort,
ZwCreateWnfStateName.

| Behavior | Status / value | Source |
|---|---|---|
| ZwOpenPartition / ZwOpenSession | missing name C0000034; NULL OA C000000D | observed |
| ZwCreatePartition with valid pointers | STATUS_PRIVILEGE_NOT_HELD C0000061 for any parent handle (NULL, -1, garbage), checked before the parent is examined; NULL output pointer C0000005. If a run holds the privilege the test skips | observed |
| ZwCreateJobSet | STATUS_NOT_SUPPORTED C00000BB for every argument combination | observed |
| ZwOpenObjectAuditAlarm | C0000061 (SeAuditPrivilege), output flag untouched; also with all-NULL arguments | observed |
| ZwCreateToken / ZwCreateTokenEx | C0000061 (SeCreateTokenPrivilege) before any argument check | observed |
| ZwCreateLowBoxToken | package SID S-1-15-2-1-2-3-4-5-6-7 (8 sub-authorities) from a duplicable process token: 0; the new token has TokenIsAppContainer 1, TokenType 1, TokenAppContainerSid equal to the input; the source token stays non-AppContainer; NULL SID C000000D; SID with 6 sub-authorities C000A202 (STATUS_INVALID_PACKAGE_SID_LENGTH); NULL/invalid token C0000008; process handle as token C0000024 | observed |
| ZwCreateProfile | own process handle: 0, type `Profile` (created stopped); no process: C0000061; bucket size 1 or 40, buffer size 0 (PARAM_7 C00000F5), unknown profile source (C00000BB) are rejected before the privilege check; invalid process handle C0000008 | observed |
| ZwCreateProfileEx | own process: 0 (note logged); no process: C0000061; bad bucket size C000000D | observed |
| ZwCreatePort / ZwCreateWaitablePort | unnamed and named; type name `ALPC Port`; collision C0000035; MaxMessageLength 0x10000 C000000D; large connection info and zero lengths accepted; NULL handle C0000005 | observed |
| ZwCreateWnfStateName | lifetime 0, 3, 9; scope 5; max state size 0x100000: C000000D; NULL name or NULL security descriptor C0000005; a valid request returns C0000061 for non-privileged callers and leaves the name untouched | observed |

Skips: none unless the caller holds a privilege the test expects to be missing (each such check is written so that
success deletes/closes what it created and the test then reports a skip or note).

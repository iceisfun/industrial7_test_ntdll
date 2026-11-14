# nt_create_open_b_tm: kernel transaction manager objects

Reference queried 2026-11-14: Windows 10 22H2 corpus (ntdll 10.0.19041.2788). The ntdll exports in this
area are syscall stubs (`/api/function/ntdll/<name>/decomp` shows only the service-number load and
`syscall`/`int 2e` dispatch, no argument checks), so every expected value below was **observed on a
real Windows 10 22H2 guest** (adm = elevated administrator, std = standard user) and, where the name
describes a documented contract, cross-checked against public documentation. Nt/Zw pairs share one
RVA: each test asserts `t_proc("NtX") == t_proc("ZwX")` and exercises behavior through the Zw name.
Status codes are written as NTSTATUS values. Tests do not depend on order and clean up what they create.
Object names are made unique per process in the caller's session namespace
(`\BaseNamedObjects` for session 0, `\Sessions\<n>\BaseNamedObjects` otherwise).

Exports: ZwCreateTransaction, ZwOpenTransaction, ZwCreateTransactionManager, ZwOpenTransactionManager,
ZwCreateResourceManager, ZwOpenResourceManager, ZwOpenEnlistment.

| Behavior | Status / value | Source |
|---|---|---|
| ZwCreateTransaction (default manager) | type name `TmTx`; NtQueryInformationTransaction class 0 returns 24 bytes: State 1 (normal), Outcome 1 (undetermined); a smaller buffer gives STATUS_INFO_LENGTH_MISMATCH | observed |
| Caller-chosen UOW GUID | reported back and usable in ZwOpenTransaction (with or without an OBJECT_ATTRIBUTES block) | observed |
| ZwOpenTransaction unknown UOW | C019004E; no UOW and no name C000000D; NULL handle pointer C0000005 | observed |
| ZwCreateTransaction bad CreateOptions or bad TM handle | C000000D | observed |
| Volatile transaction manager (options 1, no log file) | type name `TmTm`; NtQueryInformationTransactionManager class 0 returns a nonzero identity GUID; non-volatile without log file C000000D; open by identity is refused with C0000022 even for the creator; unknown identity C0190051 | observed |
| Resource manager under the volatile TM | type name `TmRm`; same GUID twice C0000035; open by GUID ok; open with neither GUID nor name C000000D; invalid TM handle C0000008 | observed |
| ZwOpenEnlistment | unknown GUID fails; no GUID C000000D; invalid RM handle C0000008; TM handle instead of RM C0000024 | observed |

Skips: if the guest refuses volatile transaction managers (C0000061, C0000022, C00000BB) the TM and RM tests t_skip with the status.

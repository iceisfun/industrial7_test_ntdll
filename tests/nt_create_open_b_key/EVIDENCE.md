# nt_create_open_b_key: registry key create/open and registry transactions

Reference queried 2026-11-14: Windows 10 22H2 corpus (ntdll 10.0.19041.2788). The ntdll exports in this
area are syscall stubs (`/api/function/ntdll/<name>/decomp` shows only the service-number load and
`syscall`/`int 2e` dispatch, no argument checks), so every expected value below was **observed on a
real Windows 10 22H2 guest** (adm = elevated administrator, std = standard user) and, where the name
describes a documented contract, cross-checked against public documentation. Nt/Zw pairs share one
RVA: each test asserts `t_proc("NtX") == t_proc("ZwX")` and exercises behavior through the Zw name.
Status codes are written as NTSTATUS values. Tests do not depend on order and clean up what they create.
Object names are made unique per process in the caller's session namespace
(`\BaseNamedObjects` for session 0, `\Sessions\<n>\BaseNamedObjects` otherwise).

Exports: ZwCreateKey, ZwOpenKey, ZwOpenKeyEx, ZwCreateKeyTransacted, ZwOpenKeyTransacted, ZwOpenKeyTransactedEx,
ZwCreateRegistryTransaction, ZwOpenRegistryTransaction.

All keys live under `\Registry\User\<sid>\Software\cobkey_<pid>_<tag>` of the caller and are deleted by the test.

| Behavior | Status / value | Source |
|---|---|---|
| Create new / reopen | Disposition REG_CREATED(1) / REG_OPENED(2); NULL disposition accepted; type name `Key` | observed |
| Create below a missing parent | STATUS_OBJECT_NAME_NOT_FOUND C0000034 | observed |
| Persistent child below a volatile key | STATUS_CHILD_MUST_BE_VOLATILE C0000181 | observed |
| NtDeleteKey on a key with subkeys | STATUS_CANNOT_DELETE C0000121 (the test deletes leaf first) | observed |
| After NtDeleteKey of the last handle's key | open by name C0000034; relative open through the stale root handle STATUS_KEY_DELETED C000017C | observed |
| NULL ObjectAttributes, NULL name | STATUS_ACCESS_VIOLATION C0000005; relative name without root C000003B; OA length 8 C000000D; invalid root handle C0000008 | observed |
| ZwOpenKeyEx options | 0 and REG_OPTION_OPEN_LINK ok; bit 0x4 (BACKUP_RESTORE) without SeBackupPrivilege enabled: C0000022; unknown bits 0x100/0xFFFFFFFF: STATUS_INVALID_PARAMETER_4 | observed |
| Link keys | creating needs KEY_CREATE_LINK + REG_OPTION_CREATE_LINK; opened with OBJ_OPENLINK; a dangling link cannot be followed without it | observed |
| Registry transaction | access 0x1F003F (anything lacking the TRANSACTION_* bits gets C0000022 on use); rollback hides keys created inside, commit publishes them; non-transacted ZwOpenKey of a key created in the pending transaction gives C0000034; invalid/NULL transaction handles C0000008; a key handle used as transaction C0000024 | observed |
| ZwCreateRegistryTransaction | flags 1 or 0xFFFFFFFF C000000D; NULL handle C0000005; named transaction: collision C0000035, ZwOpenRegistryTransaction opens it (type `RegistryTransaction`), missing C0000034, NULL OA C000000D | observed |

Skips: if registry transactions are unavailable the transacted test t_note-s and returns.

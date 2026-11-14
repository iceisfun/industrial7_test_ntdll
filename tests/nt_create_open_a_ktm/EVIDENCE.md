# nt_create_open_a_ktm: registry open variants, transactions, transaction managers, registry transactions

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), elevated guest. All entry points are syscall stubs; the
statuses below were **observed on Windows 10** (the helper-less kernel status values are from ntstatus.h).
Kernel Transaction Manager objects are in the public WDK documentation (ktmw32.h family); the native calls
here are not documented, so nothing below is asserted from documentation alone.

| Test | Check | Source |
| --- | --- | --- |
| open_key_ex_options | `NtOpenKeyEx` on `\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion` with options 0 and 8 (REG_OPTION_OPEN_LINK) succeeds and the handle reads `ProductName` as REG_SZ through `RegQueryValueExA`; option bits 1, 0x100, 0x80000000 -> 0xC00000F2 (parameter 4). The BACKUP_RESTORE option (4) is not tested: it depends on the account's privilege | observed |
| open_key_ex_missing_and_null | missing key -> 0xC0000034, NULL ObjectAttributes -> 0xC0000005 | observed |
| transacted_key_requires_valid_transaction | NtOpenKeyTransacted, NtOpenKeyTransactedEx, NtCreateKeyTransacted with a NULL or bogus transaction handle -> 0xC0000008 | observed |
| transacted_key_create_visibility_and_commit | key created under HKCU (via `RtlOpenCurrentUser` as root) with a transaction: disposition REG_CREATED_NEW_KEY (1), invisible to a plain open (0xC0000034), visible through `NtOpenKeyTransacted`, visible after `NtCommitTransaction`; the key is deleted afterwards | observed |
| transacted_key_rollback_discards_create | same, but `NtRollbackTransaction` makes the key disappear; `NtOpenKeyTransactedEx` option 0 works | observed |
| transaction_create_options_and_uow | `NtCreateTransaction` with an explicit unit-of-work GUID: `NtQueryInformationTransaction(TransactionBasicInformation)` returns that GUID with state `TransactionStateNormal` (1); `NtOpenTransaction` by GUID succeeds; after the last handle closes the transaction is rolled back and freed (open -> 0xC019004E); options DO_NOT_PROMOTE (1), isolation level 1, isolation flags 1, a timeout and a description are accepted | observed |
| transaction_invalid_arguments | options 0x10 and 0xFF, bogus TmHandle, and NtOpenTransaction with neither name nor GUID -> 0xC000000D | observed |
| transaction_manager_volatile_and_errors | volatile manager (option 1) is created; non-volatile without a log name (options 0 and 8) -> 0xC000000D; NtOpenTransactionManager with nothing -> 0xC000000D, with an unknown identity GUID -> 0xC0190051 | observed |
| resource_manager_requires_online_manager | on a manager that is not recovered, a non-volatile RM -> 0xC019003B, a volatile one (option 1) is created; unknown RM GUID -> 0xC019004F; bogus manager handle -> 0xC0000008; NULL GUID -> 0xC0000005 | observed |
| enlistment_requires_transaction_of_same_manager | a transaction cannot be created inside the private volatile manager (0xC000000D), and a default-manager transaction cannot be enlisted in a private RM (0xC000000D) | observed |
| enlistment_invalid_handles_and_guid | NtCreateEnlistment / NtOpenEnlistment with bogus or NULL handles -> 0xC0000008, NtOpenEnlistment with NULL GUID -> 0xC000000D | observed |
| registry_transaction_create_open | flags 0 ok, flags 1 -> 0xC000000D, named create + open by name gives a second handle, gone after the last close (0xC0000034), NULL ObjectAttributes -> 0xC000000D | observed |

Gaps: a successful NtCreateEnlistment/NtOpenEnlistment needs a manager that can host transactions *and* a resource
manager, which Windows 10 does not allow for a private volatile manager from an ordinary test process (see the
enlistment test); only the rejection paths are asserted. Persistent managers need a CLFS log and are not created.
Skips: manager tests skip with the actual status if the account is refused (ACCESS_DENIED / PRIVILEGE_NOT_HELD).

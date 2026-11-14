# nt_other_2_a_ktm: transaction manager services

Oracle: Windows 10 22H2 guest. Values are **observed on Windows 10**; transaction object creation uses public
KTM semantics (volatile manager, CLFS-logged manager in the scratch directory).

| Behaviour | Value |
| --- | --- |
| Invalid / wrong-type handle for NtRollbackTransaction, NtRecoverTransactionManager, NtRollforwardTransactionManager, NtRollbackComplete, NtRollbackEnlistment, NtSinglePhaseReject, NtRollbackRegistryTransaction | `STATUS_INVALID_HANDLE` / `STATUS_OBJECT_TYPE_MISMATCH` |
| Volatile manager | NtRecoverTransactionManager and NtRollforwardTransactionManager -> `STATUS_TM_VOLATILE` (0xC019003B); resource manager creation under it the same; transaction creation under it `STATUS_INVALID_PARAMETER` |
| Logged manager (CLFS log in scratch dir) | creation, resource manager creation, recover and rollforward all return 0. Skipped when the log cannot be created |
| Standalone transaction | NtRollbackTransaction 0, repeated rollback 0 |
| Registry transaction | flags != 0 `STATUS_INVALID_PARAMETER`; rollback 0; second rollback 0xC0190015 |
| NtThawTransactions / NtThawRegistry | privilege disabled `STATUS_PRIVILEGE_NOT_HELD`; with SeBackup+SeRestore and nothing frozen: 0xC0190045 (`STATUS_TRANSACTIONS_NOT_FROZEN`) and 0xC0000189 |
| NtRenameTransactionManager | log in a missing directory fails (observed 0xC000003A); `STATUS_OBJECT_PATH_NOT_FOUND` (0xC000003A) asserted |

Enlistment-level success paths (NtRollbackEnlistment, NtRollbackComplete, NtSinglePhaseReject with a real
enlistment) are not reached: creating a transaction under a manager returned `STATUS_INVALID_PARAMETER` with
the plain NtCreateTransaction call here, so these are covered by validation only.

Validation: administrator run green three times. The standard-user run skips only the thaw test whose success
path needs SeBackup and SeRestore (RtlAdjustPrivilege status 0xC0000061); the denial assertions run first.

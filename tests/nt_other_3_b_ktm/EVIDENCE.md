# Zw-named kernel transaction manager services: Windows 10 contracts

Oracle: Windows 10 22H2 x64. A transaction manager with a log file in the per-process scratch directory is created for the lifecycle
test and closed at the end; transactions use the default manager. Volatile managers (no log) never come online here, so a log-backed
manager is used. Observed: binding NtCreateTransaction to an explicit manager handle -> 0xc000000d, so enlistments cannot be built and the enlistment
services are exercised only through their handle checks.

| Export | Expectation | Source |
| --- | --- | --- |
| ZwRollbackTransaction | fresh transaction: rollback (wait and no-wait) -> 0; NULL/unused handle -> 0xc0000008; event -> 0xc0000024 | obs |
| ZwRecoverTransactionManager | log-backed manager -> 0 | obs |
| ZwRollforwardTransactionManager | log-backed manager -> 0 | obs |
| ZwRecoverResourceManager | on a created resource manager returns a status recorded in the test log; NULL/event handle -> 0xc0000008 / 0xc0000024 | obs |
| ZwRollbackEnlistment, ZwRollbackComplete, ZwReadOnlyEnlistment, ZwSinglePhaseReject, ZwRecoverEnlistment | NULL/unused handle -> 0xc0000008; event handle -> 0xc0000024 | obs |
| ZwRenameTransactionManager | unknown manager id -> status recorded (0xc0000034) | obs |

Valid transaction, resource-manager and transaction-manager handles passed to a service of another kind -> 0xc0000024 (type mismatch), also for the enlistment services. Volatile managers (no log) are not online: recover/rollforward -> 0xc019003b and resource-manager creation fails, so they cannot be used.

Skip: manager creation failure (status in the skip text).

# nt_query_info_b_ktm: kernel transaction manager object queries

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), x64. The exports are syscall stubs (Nt/Zw alias asserted)
and the kernel side is a thunk into the transaction manager driver, so every expectation is an observed result
on the guest, with the structure layouts taken from the public `wdm.h` definitions
(TRANSACTIONMANAGER_BASIC_INFORMATION, RESOURCEMANAGER_BASIC_INFORMATION, TRANSACTION_BASIC_INFORMATION,
ENLISTMENT_BASIC_INFORMATION).

Fixture: a volatile transaction manager (CreateOptions 1, no log file), a volatile resource manager with a fixed
GUID and description "qib resource manager", and a transaction with a fixed unit-of-work GUID. From user mode
an explicit TmHandle in NtCreateTransaction is refused (STATUS_INVALID_PARAMETER, observed with volatile and
logged managers), so the transaction belongs to the default manager.

| Export | Behaviour asserted | Source |
| --- | --- | --- |
| NtQueryInformationTransactionManager | class 0: 24 bytes (identity GUID nonzero and stable, virtual clock); exact length required (23 and 25 -> INFO_LENGTH_MISMATCH); class 0x100/0xFFFF -> INVALID_INFO_CLASS; NULL handle -> INVALID_HANDLE; process or resource manager handle -> OBJECT_TYPE_MISMATCH; no query access -> ACCESS_DENIED. Class 1 (log information) on a volatile manager and class 3 are only logged | observed |
| NtQueryInformationResourceManager | class 0: ResourceManagerId equals the supplied GUID, DescriptionLength and Description equal the supplied text, ReturnLength 20 + description bytes (60); 19 or 22 byte buffer -> STATUS_BUFFER_TOO_SMALL; bad class, NULL handle, TM handle, access checks as above | observed |
| NtQueryInformationTransaction | class 0: TransactionId equals the supplied unit-of-work GUID, State Normal (1), Outcome Undetermined (1), 24 bytes; after NtRollbackTransaction the outcome is Aborted (3); classes 1 (properties, 32 bytes) and 2 (enlistments, 36 bytes) succeed and are only logged; bad class, NULL handle, TM handle, access checks | observed |
| NtQueryInformationEnlistment | NULL / stale handle -> INVALID_HANDLE; transaction, resource manager and process handles -> OBJECT_TYPE_MISMATCH. The success path (class 0: 48 bytes of EnlistmentId, TransactionId, ResourceManagerId; exact length, class and access errors) runs only if an enlistment can be created; the status of that attempt is logged and the rest of the test is skipped with it otherwise | observed |

## Skips

* All tests skip with the exact creation status if a volatile transaction manager chain cannot be built.
* `query_enlistment` skips the success half with the NtCreateEnlistment status when the enlistment cannot be created.

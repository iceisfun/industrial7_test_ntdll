# NtSetInformationTransaction, NtSetInformationEnlistment, NtSetInformationResourceManager, NtSetInformationTransactionManager

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), administrator and standard user. The ntoskrnl exports are
thin forwarders into the transaction manager driver, whose code is not in the Corpus Explorer, so every
expectation below is observed on the guest (class/length/handle probing), not derived from decompilation.

| Check | Expected |
|---|---|
| NtSetInformationTransaction class 1 with TRANSACTION_PROPERTIES_INFORMATION (timeout -300 s, description) | success; NtQueryInformationTransaction class 1 returns the same description length and text, timeout -3000000000 |
| class 0x7fff and 0 | STATUS_INVALID_INFO_CLASS |
| buffer of 4 bytes for class 1 | STATUS_INFO_LENGTH_MISMATCH |
| event handle, class 1, 32 bytes | STATUS_OBJECT_TYPE_MISMATCH |
| enlistment classes 0, 2; resource manager 0, 2; transaction manager 0, 1, 4 | STATUS_INVALID_INFO_CLASS, even with an invalid handle |
| resource manager class 1 / transaction manager class 3 with 4 bytes | STATUS_INFO_LENGTH_MISMATCH (before the handle is resolved) |
| enlistment class 1 and resource manager class 1 (16 bytes) with invalid handle, event handle, transaction handle | STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH, STATUS_OBJECT_TYPE_MISMATCH |

Creating a transaction manager, resource manager or enlistment needs a log/CLFS setup and privileges that
vary by configuration, so their success paths are not exercised; the test skips if no transaction can be created.

# nt_set_info_b_ktm: kernel transaction manager setters

Oracle: Windows 10 22H2 x64. Everything was observed on the guest. A volatile transaction manager
(`NtCreateTransactionManager`, no log file, CreateOptions 1) is created per test; a transaction is created with a NULL
transaction-manager handle (default manager) and a resource manager is created under the volatile manager. All handles
are closed and open transactions rolled back at the end.

| Export | Expectation |
|---|---|
| NtSetInformationTransaction | class 1 (properties): buffer shorter than 32 bytes STATUS_INFO_LENGTH_MISMATCH; with 32 bytes the Timeout at offset 8 (the layout of TRANSACTION_PROPERTIES_INFORMATION) is stored and read back by NtQueryInformationTransaction(class 1, ReturnLength 32); a zero Timeout leaves it unchanged; classes 0 and 99 STATUS_INVALID_INFO_CLASS; NULL handle INVALID_HANDLE; event handle TYPE_MISMATCH; SYNCHRONIZE-only handle ACCESS_DENIED |
| NtSetInformationTransactionManager | the only settable class is 3 (recovery): every other class gives STATUS_INVALID_INFO_CLASS even for a NULL handle (class is checked before the handle); class 3 with every non-zero length up to 32 tried (including 8) gives STATUS_INFO_LENGTH_MISMATCH (size is checked before the handle) so no success path is asserted |
| NtSetInformationResourceManager | class 1 (completion port + key, 16 bytes): other lengths STATUS_INFO_LENGTH_MISMATCH; NULL port INVALID_HANDLE; event as port TYPE_MISMATCH; real completion port accepted once, a second set STATUS_INVALID_DEVICE_STATE (0xC0000184); event/NULL resource-manager handle TYPE_MISMATCH / INVALID_HANDLE; SYNCHRONIZE-only handle ACCESS_DENIED; classes 0, 2, 3, 99 INVALID_INFO_CLASS. A non-volatile resource manager under a volatile transaction manager is refused with status 0xC019003B |
| NtSetInformationEnlistment | class 1 (recovery information): length 0 STATUS_INVALID_PARAMETER, 8 and 16 bytes succeed; classes 0, 2, 3, 99 INVALID_INFO_CLASS; NULL handle INVALID_HANDLE; event TYPE_MISMATCH; SYNCHRONIZE-only handle ACCESS_DENIED |

Skips: the whole area skips if the volatile transaction manager cannot be created.

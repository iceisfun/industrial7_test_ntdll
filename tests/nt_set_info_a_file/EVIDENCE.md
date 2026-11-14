# NtSetEaFile, NtSetQuotaInformationFile, NtSetVolumeInformationFile

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), administrator and standard user. The scratch file lives
in the per-process temp directory (NTFS on the guest) and is deleted by the test. The EA test skips with
STATUS_EAS_NOT_SUPPORTED when the scratch volume cannot hold EAs.

| Check | Expected | Source |
|---|---|---|
| NtSetEaFile with two entries, then NtQueryEaFile | both attributes present, names upper-cased, values intact; IO_STATUS_BLOCK.Status 0 | documented FILE_FULL_EA_INFORMATION, observed |
| overwrite one value | the other attribute is untouched (entry order is not asserted) | observed |
| zero-length value | deletes the attribute | documented, observed |
| name containing `=` or `*` | STATUS_INVALID_EA_NAME (80000013, a warning code) | observed |
| list shorter than its entry | STATUS_EA_LIST_INCONSISTENT (80000014) | observed |
| invalid / NULL handle | STATUS_INVALID_HANDLE | observed |
| handle opened GENERIC_READ | STATUS_ACCESS_DENIED | decompilation (IopSetEaOrQuotaInformationFile references the file with write-EA access), observed |
| NtSetQuotaInformationFile on invalid handle / regular file handle | STATUS_INVALID_HANDLE / STATUS_ACCESS_DENIED | observed |
| NtSetVolumeInformationFile classes 0 and 0x7fff | STATUS_INVALID_INFO_CLASS | observed |
| class 4 (FileFsDeviceInformation) | STATUS_INVALID_INFO_CLASS (not settable) | observed |
| FileFsLabelInformation on a regular file handle, and on a read-only handle | STATUS_ACCESS_DENIED | observed |
| invalid / NULL handle | STATUS_INVALID_HANDLE | observed |

Quota and label changes on a valid volume handle change machine-wide volume state and are deliberately not performed.

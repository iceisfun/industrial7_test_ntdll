# NtSetInformationToken, NtSetInformationKey

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), administrator and standard user. Token changes are
applied to a primary duplicate of the process token opened with `NtOpenProcessToken`/`NtDuplicateToken`,
never to the process token. Registry changes use a unique subkey under HKCU\Software that is deleted again.

| Check | Expected | Source |
|---|---|---|
| TokenDefaultDacl (6): ACL with one ACE (Everyone, GENERIC_ALL) | success; NtQueryInformationToken returns that ACL (AceCount 1, same mask and SID) | documented, observed |
| TokenDefaultDacl with a NULL ACL | success; query returns a NULL ACL pointer | observed |
| class 6 length 4 | STATUS_INFO_LENGTH_MISMATCH (lengths of 8 or more are accepted) | observed |
| TokenOwner (4): the user SID | success; query returns the same SID | documented, observed |
| TokenOwner: S-1-5-123 | STATUS_INVALID_OWNER (C000005A) | documented, observed |
| TokenPrimaryGroup (5): current group | success; bogus S-1-5-123 -> STATUS_INVALID_PRIMARY_GROUP (C000005B) and the group is unchanged | observed |
| TokenSessionId (12) | STATUS_PRIVILEGE_NOT_HELD (needs SeTcbPrivilege); skip if enabled | observed |
| classes 0x7fff, 0, 1 (TokenUser) | STATUS_INVALID_INFO_CLASS | observed |
| handle with only TOKEN_QUERY | STATUS_ACCESS_DENIED; event handle STATUS_OBJECT_TYPE_MISMATCH; invalid/NULL handle STATUS_INVALID_HANDLE | observed |
| NtSetInformationKey class 1 (Wow64 flags) 4 and 8 | success; NtQueryKey class 5 (12 bytes) returns the value in its first field; 0x100 and 0x10 -> STATUS_INVALID_PARAMETER and the value is kept | decompilation (class table), observed |
| class 0 (write time, 8 bytes) | success; NtQueryKey KeyBasicInformation.LastWriteTime equals the value | observed |
| classes 2..5 with value 0 | success | observed |
| class 0x7f and 6 | STATUS_INVALID_INFO_CLASS | decompilation (`return -0x3ffffffd`), observed |
| class 1 length 2 or 8, class 0 length 4 | STATUS_INFO_LENGTH_MISMATCH | decompilation, observed |
| invalid handle, event handle, key opened KEY_READ | STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH, STATUS_ACCESS_DENIED | observed |

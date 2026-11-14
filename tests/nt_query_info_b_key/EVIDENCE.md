# nt_query_info_b_key: registry query services

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), x64. All exports are syscall stubs (Nt/Zw share an RVA,
asserted by `alias_pairs`); status codes and layouts below were observed on the guest. The fixture is a
private key `qib_key_<pid>` under HKCU (opened with RtlOpenCurrentUser) with class "MyClass", subkeys
`alpha` and `beta_longer`, and values `dw` (REG_DWORD 0x12345678), `str` (REG_SZ "hello"), `bin`
(REG_BINARY 01 02 03). Everything is deleted at the end of each test.

| Export | Behaviour asserted | Source |
| --- | --- | --- |
| NtQueryKey | class 0 {LastWriteTime, TitleIndex, NameLength, Name}: ReturnLength = 16 + name; <16 bytes -> STATUS_BUFFER_TOO_SMALL; partial name -> STATUS_BUFFER_OVERFLOW with full ReturnLength. class 3 name: `\REGISTRY\USER\<sid>\<leaf>`, subkey name = key name + `\` + leaf. class 2 full: ClassOffset 44, ClassLength 14, SubKeys 2, MaxNameLen 22, MaxClassLen 0, Values 3, MaxValueNameLen 6, MaxValueDataLen 12. class 4 cached: same counts + NameLength, ReturnLength 40. classes 5..8 succeed (ReturnLength 12/4/4/4, zero values). class 9, 0x100, 0xFFFF -> STATUS_INVALID_PARAMETER (not INVALID_INFO_CLASS); handle with only READ_CONTROL -> ACCESS_DENIED | observed |
| NtQueryValueKey | classes 0/1/2 (basic/full/partial) and 3/4 (Align64 variants: partial-align64 has no TitleIndex, ReturnLength 8 + data); sizes and offsets as in the Win32 headers; names are case-insensitive; fixed part too small -> BUFFER_TOO_SMALL, data truncated -> BUFFER_OVERFLOW; missing value -> STATUS_OBJECT_NAME_NOT_FOUND; bad class -> INVALID_PARAMETER; no KEY_QUERY_VALUE -> ACCESS_DENIED | observed |
| NtQueryMultipleValueKey | three values: data packed back to back in the output buffer (offsets 0, 4, 16, total 19), entry type/length filled; too small -> BUFFER_OVERFLOW with the required size in ReturnLength; missing value -> OBJECT_NAME_NOT_FOUND | observed |
| NtQueryOpenSubKeys | for the HKCU hive root: success, count includes the three handles of the fixture and rises by exactly one when another handle to `alpha` is opened and falls back when it is closed; missing key -> OBJECT_NAME_NOT_FOUND; a key that is not a hive root -> STATUS_INVALID_PARAMETER | observed |
| NtQueryOpenSubKeysEx | signature (OBJECT_ATTRIBUTES, BufferLength, Buffer, RequiredSize), decompiled kernel service (Corpus Explorer `ntoskrnl/NtQueryOpenSubKeysEx`): requires SeRestorePrivilege first (else STATUS_PRIVILEGE_NOT_HELD), length < 8 -> BUFFER_TOO_SMALL, odd length -> INVALID_PARAMETER, header-only buffer -> BUFFER_OVERFLOW with required size; the result is a count followed by 24-byte entries {ProcessId, UNICODE_STRING key name}; our process appears for every handle of the fixture | decomp + observed |

## Skips

* `query_open_subkeys_ex` skips with the exact status STATUS_PRIVILEGE_NOT_HELD if RtlAdjustPrivilege(SeRestorePrivilege) fails (unprivileged mode).
* `query_open_subkeys` skips if the HKCU query itself reports STATUS_PRIVILEGE_NOT_HELD.

# nt_set_info_b_sys: privileged and system-state setters, cached signing level, virtual-memory information

Oracle: Windows 10 22H2 x64. Calls that would change machine state are made only when they are known to fail
(privilege confirmed absent or disabled in the token first, otherwise the test skips with the privilege name) or when they
re-assert the current value. SeDebugPrivilege is enabled in the elevated runner token, so the debug-filter test takes its
"privilege enabled" branch there and the "not held" branch for a standard user.

| Export | Expectation |
|---|---|
| NtSetSystemTime | SeSystemtimePrivilege disabled: STATUS_PRIVILEGE_NOT_HELD, PreviousTime untouched |
| NtSetIntervalProfile | SeSystemProfilePrivilege absent: STATUS_PRIVILEGE_NOT_HELD |
| NtSetUuidSeed | no SeTcbPrivilege: STATUS_ACCESS_DENIED (0xC0000022) |
| NtSetDefaultHardErrorPort | no SeTcbPrivilege: STATUS_PRIVILEGE_NOT_HELD for NULL and for an event handle |
| NtSetSystemEnvironmentValue / Ex | no SeSystemEnvironmentPrivilege: the plain form is STATUS_PRIVILEGE_NOT_HELD; the Ex form is PRIVILEGE_NOT_HELD or STATUS_NOT_IMPLEMENTED (guest firmware dependent, both accepted; BIOS guest observed NOT_IMPLEMENTED) |
| NtSetSystemInformation | unknown class (0x7fff, 0xFFFFFFFF) INVALID_INFO_CLASS; SystemTimeAdjustment (28): bad length INFO_LENGTH_MISMATCH and PRIVILEGE_NOT_HELD; class 21 (file cache) ACCESS_DENIED or PRIVILEGE_NOT_HELD |
| NtSetDriverEntryOrder | STATUS_NOT_IMPLEMENTED (BIOS guest) or PRIVILEGE_NOT_HELD |
| NtSetDebugFilterState | SeDebugPrivilege disabled/absent: STATUS_PRIVILEGE_NOT_HELD. Enabled: the current state of component 0 level 3 (NtQueryDebugFilterState returns 1 when enabled, 0 when not) is set again and queried back unchanged |
| NtSetDefaultLocale / NtSetDefaultUILanguage | re-asserting the current user locale, system locale and UI language succeeds and queries back the same value (the FALSE/system form may be refused on other configurations: logged only) |
| NtSetLdtEntries | x64: STATUS_NOT_IMPLEMENTED |
| NtSetCachedSigningLevel / NtSetCachedSigningLevel2 | argument validation in a fixed order on a non-PE file: level 0 ACCESS_DENIED, flags 0/1 with level 4 STATUS_INVALID_PARAMETER_2 (0xC00000F0), flags 4 STATUS_INVALID_IMAGE_FORMAT (0xC000007B), zero sources STATUS_INVALID_PARAMETER_4 (0xC00000F2), NULL / bad target or bad source handle STATUS_INVALID_PARAMETER_5 (0xC00000F3); an unsigned PE (a copy of the test image) with flags 4 gives STATUS_INVALID_IMAGE_HASH (0xC0000428) for levels 1, 4, 8, 12. A success path needs a validly signed image and is not exercised |
| NtSetInformationVirtualMemory | class 0 (prefetch): one and two ranges succeed, unmapped range succeeds, zero entries STATUS_INVALID_PARAMETER_3 (0xC00000F1), bad class STATUS_INVALID_PARAMETER_2 (0xC00000F0), wrong length STATUS_INVALID_PARAMETER_6 (0xC00000F4), flags 1 STATUS_INVALID_PARAMETER_5 (0xC00000F3), zero-sized range STATUS_INVALID_PARAMETER_4 (0xC00000F2), NULL range array STATUS_ACCESS_VIOLATION; NULL handle INVALID_HANDLE, event TYPE_MISMATCH |

Not covered here (see group report): NtSetSystemPowerState (suspend/hibernate/shutdown).

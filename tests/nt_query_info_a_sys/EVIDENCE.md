# nt_query_info_a_sys evidence

Oracle: Windows 10 22H2 guest (ntdll 10.0.19041.2788), run as elevated administrator and as a standard user.
Reference: Corpus Explorer function records and decompilations (`/api/function/ntdll/<Name>/decomp`) were read for
every export. Except for NtQuerySystemTime (reads KUSER_SHARED_DATA at 0x7ffe0014 and returns 0, so a NULL pointer
faults in user mode and is not tested) every export is a bare syscall stub, so argument validation comes from the
guest run, not from the decompilation.

| Export | Expected values | Source |
|---|---|---|
| NtQuerySystemTime | status 0; value within 1 s of GetSystemTimeAsFileTime, monotonic over a 50 ms sleep | docs + decompilation (shared-data read), observed |
| NtQueryPerformanceCounter | 0; frequency equals QueryPerformanceFrequency; counter increases across a sleep and tracks QueryPerformanceCounter; frequency pointer optional; NULL or 0x10 counter pointer returns STATUS_ACCESS_VIOLATION | docs, observed |
| NtQueryTimerResolution | 0; Maximum <= Current <= Minimum, Minimum in 10..20 ms; each NULL pointer returns STATUS_ACCESS_VIOLATION | docs, observed |
| NtQueryDefaultLocale | 0; user flag TRUE equals GetUserDefaultLCID, FALSE equals GetSystemDefaultLCID; NULL out STATUS_ACCESS_VIOLATION | docs, observed |
| NtQueryDefaultUILanguage / NtQueryInstallUILanguage | 0; equals GetUserDefaultUILanguage / GetSystemDefaultUILanguage; nonzero | docs, observed |
| NtQueryIntervalProfile | source 0 (ProfileTime) returns 0 with a nonzero interval; NULL out STATUS_ACCESS_VIOLATION. Other sources are observed-only (an invalid source is NOT rejected: source 0x1000 returns 0), so they are notes | observed |
| NtQueryDebugFilterState | returns 0 or 1 (not an error) for component 0, levels 0..3; other arguments logged only | observed |
| NtQueryAuxiliaryCounterFrequency | success (nonzero value) or an error status; the VM returns STATUS_NOT_SUPPORTED, hardware without an auxiliary counter does too; NULL out is STATUS_ACCESS_VIOLATION (observed, note only) | observed |
| NtQuerySystemInformationEx | class 107 (SystemLogicalProcessorInformationEx) with a RelationProcessorCore input: STATUS_INFO_LENGTH_MISMATCH with the required length for a zero-length buffer, success with identical ReturnLength and the bytes match GetLogicalProcessorInformationEx length; input length 0 STATUS_INVALID_PARAMETER; unknown class 0x7777 STATUS_INVALID_INFO_CLASS | observed |
| NtQueryLicenseValue | "Kernel-ProductInfo": 0, type REG_DWORD, length 4, nonzero; 2-byte buffer STATUS_BUFFER_TOO_SMALL with ResultDataSize 4; unknown name STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034) | observed |
| NtQueryPortInformationProcess | returns STATUS_SUCCESS(0) or 1 (a boolean-style result, observed 1); an error here is tolerated only as 0xC0000001/0xC00000BB | observed |
| NtQueryBootEntryOrder / NtQueryDriverEntryOrder / NtQueryBootOptions | on a BIOS-booted guest they return STATUS_NOT_IMPLEMENTED (0xC0000002) before any privilege check, for both administrator and standard users; UEFI systems would return STATUS_PRIVILEGE_NOT_HELD without the privilege. Both are accepted | observed |
| NtQuerySystemEnvironmentValue / Ex | without SeSystemEnvironmentPrivilege enabled: STATUS_PRIVILEGE_NOT_HELD (0xC0000061) for Value; with the privilege (administrator only) the answer depends on firmware and only "not PRIVILEGE_NOT_HELD" and not-success for a nonexistent variable is asserted | observed |

Skips: `sys_firmware_privileged` skips when the token cannot enable SeSystemEnvironmentPrivilege (standard user:
the privilege adjust returns STATUS_PRIVILEGE_NOT_HELD).

Nt/Zw pairs: the test compares the exported addresses of every Nt/Zw pair (they share an RVA).

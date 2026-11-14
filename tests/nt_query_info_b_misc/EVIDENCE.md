# nt_query_info_b_misc: time, counter, language, license, firmware, driver-order, WNF and port queries

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), x64. All exports are syscall stubs (Nt/Zw alias asserted).
Values were observed on the guest unless a Win32 equivalent is cited.

| Export | Behaviour asserted | Source |
| --- | --- | --- |
| NtQuerySystemTime | within 20 ms of GetSystemTimeAsFileTime, strictly increases across a 30 ms sleep, agrees with the shared user data time | docs + observed |
| NtQueryPerformanceCounter | counter increases, frequency >= 1 MHz and identical across calls and to QueryPerformanceFrequency, optional frequency pointer may be NULL, elapsed time over a 20 ms sleep is between 15 ms and 2 s | docs |
| NtQueryTimerResolution | maximum (coarsest) >= minimum (finest) > 0, current in range, 100 ns units (156250 / 5000 / 156250 observed on the guest; only the ordering and sanity bounds are asserted) | observed |
| NtQueryIntervalProfile | ProfileTime (0) and ProfileAlignmentFixup (1) succeed, value nonzero and stable (9999 observed) | observed |
| NtQueryInstallUILanguage | success, nonzero primary-language bits, stable (0x0409 on the guest, not asserted) | observed |
| NtQueryLicenseValue | `Kernel-ProductInfo`: REG_DWORD, 4 bytes, equals GetProductInfo; 2-byte buffer -> BUFFER_TOO_SMALL with ResultDataSize 4; NULL type pointer accepted; unknown value -> OBJECT_NAME_NOT_FOUND | observed |
| NtQuerySystemEnvironmentValue / Ex | without SeSystemEnvironmentPrivilege enabled: STATUS_PRIVILEGE_NOT_HELD (privilege is checked first). With it enabled (RtlAdjustPrivilege 22): on non-UEFI guests the value form returned STATUS_UNSUCCESSFUL and the Ex form STATUS_NOT_IMPLEMENTED; the test accepts those plus STATUS_VARIABLE_NOT_FOUND since the answer depends on the firmware type. Skips (privilege cannot be enabled) with the exact status | observed |
| NtQueryDriverEntryOrder | firmware boot entries: STATUS_NOT_IMPLEMENTED on a BIOS guest (with and without SeLoadDriverPrivilege); success, STATUS_BUFFER_TOO_SMALL or STATUS_PRIVILEGE_NOT_HELD are also accepted for UEFI systems. Weak, firmware dependent | observed |
| NtQuerySecurityPolicy | signature from the kernel service (policy owner, policy sub key and value name as UNICODE_STRINGs, value type, buffer, size): an owner name that no component registered -> STATUS_NOT_FOUND (0xC0000225) with and without an output buffer, value type untouched. Registered owners are internal to the code-integrity components and are not exercised | decomp + observed |
| NtQueryWnfStateData | a temporary session-scope state name created with NtCreateWnfStateName and a NULL-DACL descriptor: before publishing the stamp is 0 and size 0; after NtUpdateWnfStateData the stamp is 1 and the 5 payload bytes are returned; 2-byte buffer -> STATUS_BUFFER_TOO_SMALL with the required size; second update bumps the stamp to 2; deleted name -> STATUS_OBJECT_NAME_NOT_FOUND; an unregistered name value -> STATUS_INVALID_PARAMETER. Process-scope temporary names are refused with INVALID_PARAMETER (observed) | observed |
| NtQueryWnfStateNameInformation | class 0 (name exists) = 1 for the live name and 0 after deletion; class 1 (subscribers present) = 0; unknown class 0x77, 1-byte buffer and unregistered name -> STATUS_INVALID_PARAMETER | observed |
| NtQueryInformationPort | classes 0..4 on a NULL handle -> INVALID_INFO_CLASS (class is rejected before the handle is looked at); stale handle with class 0 -> INVALID_HANDLE; process pseudo handle -> OBJECT_TYPE_MISMATCH. No portable success path exists in user mode without a service connection | observed |
| NtQueryPortInformationProcess | takes no arguments, returns a boolean-style result (1 on the guest, 0 or 1 accepted) that is stable across calls | observed |

## Skips

* `system_environment_value` skips when SeSystemEnvironmentPrivilege cannot be enabled (unprivileged mode), after asserting the PRIVILEGE_NOT_HELD results.
* `driver_entry_order` skips the privileged half when SeLoadDriverPrivilege cannot be enabled.
* `wnf_state` skips when a temporary WNF state name cannot be created.

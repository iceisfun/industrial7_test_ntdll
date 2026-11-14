# System-wide setters (privilege and firmware gated)

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788) in a QEMU guest booted from BIOS firmware, administrator
and standard user. Kernel decompilations show each service checks an enabled privilege (or the firmware
type) before touching state; the tests only use calls that fail on those checks, so nothing is modified.
A caller that does hold the privilege makes the test skip, never fail.

| Export | Check | Expected | Source |
|---|---|---|---|
| NtSetSystemTime | non-NULL time without SeSystemtimePrivilege enabled; previous-time output not written | STATUS_PRIVILEGE_NOT_HELD | decompilation (SeSinglePrivilegeCheck), observed in both modes |
| NtSetIntervalProfile | without SeSystemProfilePrivilege | STATUS_PRIVILEGE_NOT_HELD | decompilation, observed |
| NtSetBootEntryOrder, NtSetDriverEntryOrder, NtSetBootOptions | BIOS boot: STATUS_NOT_IMPLEMENTED; UEFI boot: STATUS_PRIVILEGE_NOT_HELD (BootOptions may also report INVALID_PARAMETER) | firmware-type test at the top of each service | decompilation; observed NOT_IMPLEMENTED on the guest |
| bounds (UEFI only) | count 0x40000000 -> STATUS_INVALID_PARAMETER before the privilege check | decompilation; test skips on BIOS guests | not exercised on the guest |
| NtSetSystemEnvironmentValue / ...Ex | STATUS_NOT_IMPLEMENTED or STATUS_PRIVILEGE_NOT_HELD | decompilation; observed PRIVILEGE_NOT_HELD and NOT_IMPLEMENTED respectively on BIOS | observed |
| NtSetSystemInformation | class 0x7fff and 0xffffffff, and the query-only class 0 | STATUS_INVALID_INFO_CLASS | observed |
| NtSetDebugFilterState (clears a level bit only) | STATUS_ACCESS_DENIED without SeDebugPrivilege enabled; skips when the administrator token has it enabled | decompilation, observed | observed (standard user) |
| NtSetDefaultHardErrorPort | STATUS_PRIVILEGE_NOT_HELD (SeTcbPrivilege) before the handle is looked at | decompilation, observed | observed |
| NtSetUuidSeed | STATUS_ACCESS_DENIED (fixed DACL access check) | decompilation (SeAccessCheck, ExRaiseStatus(0xc0000022)), observed | observed |
| NtSetCachedSigningLevel / ...2 | source count 0 or 0x2000 -> STATUS_INVALID_PARAMETER_4 (C00000F2) | decompilation (count-1 < 0x1000), observed | observed |
| NtSetDefaultLocale(TRUE, 0) | success; `GetUserDefaultLCID` unchanged (LCID 0 reapplies the configured locale) | decompilation, observed | observed |
| NtSetDefaultUILanguage(0x0409) | success (non-zero ids are accepted and ignored by the kernel) | decompilation, observed | observed |
| aliases | Nt/Zw addresses equal for all 17 exports in this area, including SetSystemPowerState and SetLdtEntries | RVA sharing | observed |

Not called: NtSetSystemPowerState (can suspend or power off the guest; the call would only be refused by
SeShutdownPrivilege, which is not worth the risk), NtSetDefaultLocale with a non-zero LCID (rewrites the
user profile), NtSetUuidSeed/NtSetSystemTime/NtSetIntervalProfile with the privilege held.

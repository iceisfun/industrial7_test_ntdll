# nt_other_1_a_system evidence

Oracle: Windows 10 22H2 guest (BIOS-style firmware, no auxiliary counter). Services here depend on privilege or hardware, so each assertion
spells out the permitted outcomes.

* Boot entry, driver entry, firmware environment and boot option services: STATUS_NOT_IMPLEMENTED on BIOS firmware (observed), expected
  STATUS_PRIVILEGE_NOT_HELD on UEFI machines when SeSystemEnvironmentPrivilege is not enabled; the test accepts exactly those two codes, never enables the privilege, and
  never calls the delete services with a plausible id. NtFilterBootOption returns a non-success code (0x80430006 observed).
* NtApphelpCacheControl: NULL data for classes 0..11 STATUS_ACCESS_VIOLATION; classes 0x7FFF and 0xFFFFFFFF STATUS_INVALID_PARAMETER (observed).
* NtAcquireProcessActivityReference: STATUS_ACCESS_DENIED for ordinary callers (self, NULL, event handle), type 1 STATUS_INVALID_PARAMETER_3 (0xC00000F1),
  NULL output pointer STATUS_ACCESS_VIOLATION (observed).
* NtAcquireCrossVmMutant: only the cross-VM mutant type is accepted; a NULL handle or an ordinary mutex give STATUS_OBJECT_TYPE_MISMATCH (observed).
* NtConvertBetweenAuxiliaryCounterAndPerformanceCounter: STATUS_NOT_SUPPORTED (0xC00000BB) without auxiliary counter hardware, with outputs untouched and
  NULL input/output pointers probed first (STATUS_ACCESS_VIOLATION); the optional error output may be NULL. If the hardware supports it the test only checks that it succeeds.
* NtCompactKeys / NtCompressKey: STATUS_PRIVILEGE_NOT_HELD for any argument (observed, both modes); skipped if the token holds SeTcbPrivilege.
* NtDisplayString / NtDrawText: STATUS_PRIVILEGE_NOT_HELD, except NtDisplayString(NULL) STATUS_INVALID_PARAMETER (observed); skipped if the token holds SeTcbPrivilege.
  Nothing is ever drawn.

Justified-uncovered from the same list (not in this exe): NtEnableLastKnownGood / NtDisableLastKnownGood (change boot configuration state), NtFlushInstallUILanguage
(changes machine UI language state), NtCallEnclave (needs an initialised enclave), NtDirectGraphicsCall (kernel graphics driver interface).

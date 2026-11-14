# rtl_rest_crt_other_3_a_rtl: internal Rtlp helpers and small exports

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). All expected values were confirmed on the guest in
administrator mode (two runs). Standard-user mode could not be run at the time of writing: the
guest's standard-account launch failed with a logon error for every area (infrastructure), so no
standard-user result is recorded. None of the tests needs elevation (the registry test uses a
scratch key under HKCU, removed at the end).

| Test | Export(s) | Expectation and source |
| --- | --- | --- |
| time_to_fields | `RtlpTimeToTimeFields` | 14 reference instants (epoch, leap days, century rules 1900/2000/2100, 9999, 30827) checked field-for-field including weekday, computed with an independent civil-calendar algorithm; result equals `RtlTimeToTimeFields`; sub-millisecond ticks dropped. Third argument (leap-second table offset) passed as NULL. Source: decomp `RtlpTimeToTimeFieldsNoLeapSeconds` (taken when no leap-second table is attached to the PEB), observed |
| fields_to_time, fields_to_time_invalid | `RtlpTimeFieldsToTime` | same instants round trip, Weekday input ignored, result equals `RtlTimeFieldsToTime`; invalid fields (month 0/13, day 0/32, Feb 29 in non-leap years, hour 24, minute/second 60, ms 1000, year below 1601, negatives) return FALSE. Source: decomp, observed |
| string_size_helpers | `RtlxAnsiStringToUnicodeSize`, `RtlxOemStringToUnicodeSize`, `RtlxUnicodeStringToAnsiSize`, `RtlxUnicodeStringToOemSize` | ASCII text: 2n+2 bytes for ANSI/OEM to Unicode, n+1 for the reverse; only `Length` counts; the two Ansi/Oem forms and `RtlAnsiStringToUnicodeSize`/`RtlOemStringToUnicodeSize` share one address. Source: decomp (single body at the shared RVA, `RtlMultiByteToUnicodeSize` + 2), observed |
| ver_set_condition_mask | `VerSetConditionMask` | type mask 0 returns 0; otherwise result is the input mask OR (condition & 7) << 3*index OR bit 63, where index is the position of the highest set bit of the type mask. Documented behaviour for single type bits (MSDN VerSetConditionMask); the highest-bit rule for multi-bit masks and type bits above 0x80 is from the decompilation and observed |
| ship_assert_buffer_info | `ShipAssertGetBufferInfo` | both outputs optional, fixed non-NULL addresses inside ntdll, second is a 4-byte-aligned counter. Source: decomp, observed |
| ship_assert_counter | `ShipAssert` | the call bumps the shared record counter by one and clears the TEB re-entrancy bit (TEB+0x17ee, 0x10) afterwards; with the bit pre-set the call is ignored. Source: decomp, observed |
| nt_set_value_key | `RtlpNtSetValueKey` | sets the unnamed value of an open key (type, data, length), replacing earlier data and type; empty binary value allowed; NULL or stale handle gives STATUS_INVALID_HANDLE (0xC0000008), key opened without KEY_SET_VALUE gives STATUS_ACCESS_DENIED (0xC0000022). Source: disassembly (tail call into NtSetValueKey with an empty name), observed |
| critical_section_event | `RtlpUnWaitCriticalSection`, `RtlpWaitForCriticalSection` | the wait routine is a no-op stub (same address as `LdrStandardizeSystemPath`) and leaves the section untouched; the un-wait routine wakes a waiter blocked in `RtlWaitOnAddress` on `LockCount` (address-wait flavour) or signals the lazily created auto-reset event (event flavour). Source: decomp, observed |
| ui_language_arg_validation | `RtlpSetInstallLanguage`, `RtlpRefreshCachedUILanguage` | argument checks that run before any system access: NULL name, neither name nor LCID flag, unknown culture name, NULL name for refresh give STATUS_INVALID_PARAMETER (0xC000000D). Source: decomp, observed |

No call changes persistent settings: install-language setters are only called with arguments that
fail before any state is touched.

# rtl_query_set_b_misc

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), standard user and elevated administrator runs. Decompilation (Corpus Explorer, /api/function/ntdll/<Name>/decomp) was consulted for argument validation order; every value below was then confirmed by running on the Windows 10 guest.

## Exports covered (behavioral)
RtlSetProxiedProcessId, RtlSetThreadPlaceholderCompatibilityMode, RtlSetProcessPlaceholderCompatibilityMode,
RtlSetThreadSubProcessTag, RtlSetThreadWorkOnBehalfTicket, RtlSetCurrentTransaction, RtlSetUmsThreadInformation,
RtlSetExtendedFeaturesMask, RtlSetProcessIsCritical, RtlSetThreadIsCritical, RtlSetUserValueHeap, RtlSetUserFlagsHeap,
RtlSetHeapInformation, RtlSetMemoryStreamSize, RtlSetThreadPoolStartFunc, RtlSetTimeZoneInformation,
RtlSetDynamicTimeZoneInformation, RtlSetFeatureConfigurations, RtlSetSystemBootStatusEx, RtlSetProtectedPolicy.

## Where expectations come from
| Area | Evidence |
| --- | --- |
| Proxied process id, sub-process tag, placeholder modes | Decompiled: each stores into a TEB/PEB slot and returns the previous value; placeholder modes accept 0..3 and return 0xff (no change) otherwise. Sub-process tag slot verified against TEB+0x1720. Values restored at the end. |
| RtlSetThreadWorkOnBehalfTicket | Decompiled: NULL -> STATUS_INVALID_PARAMETER; ticket equal to the cached one (0) -> success without a system call. A made-up non-zero ticket is rejected by the kernel (observed: c000000b); only "failure" is asserted. |
| RtlSetCurrentTransaction | Decompiled: -1 -> FALSE and unchanged; anything else stored in the TEB and TRUE. Verified with RtlGetCurrentTransaction. |
| RtlSetUmsThreadInformation | Decompiled: class 1 with length 8 stores the value at +0x4e8 of the UMS thread record; wrong length STATUS_INFO_LENGTH_MISMATCH, other class STATUS_NOT_SUPPORTED. Tested on a private zeroed buffer (no real UMS thread needed). |
| RtlSetExtendedFeaturesMask | Decompiled: stored mask = (enabled-features & mask) & ~3. Tested on a CONTEXT_EX from InitializeContext with CONTEXT_XSTATE; expectation derived from GetEnabledXStateFeatures. Skipped when no XSTATE context is available. |
| RtlSet*IsCritical | Decompiled: NeedBreaks=TRUE without FLG_ENABLE_SYSTEM_CRIT_BREAKS -> STATUS_UNSUCCESSFUL; otherwise NtSet/QueryInformation. Only FALSE (clearing) is ever requested. Clearing needs SeDebugPrivilege enabled: the test enables it with RtlAdjustPrivilege; where the privilege is not held (standard user) it asserts STATUS_PRIVILEGE_NOT_HELD (c0000061) from the adjust and from both setters. |
| Heap user value / flags | Decompiled and documented (RtlGetUserInfoHeap pair): value stored only for blocks allocated with HEAP_SETTABLE_USER_VALUE; user flag bits are 0x200/0x400/0x800, other bits -> FALSE. Private heap per test. |
| RtlSetHeapInformation | Decompiled: class 0 requires >=4 byte buffer and value 2 (else STATUS_UNSUCCESSFUL), result read back with RtlQueryHeapInformation; class 3 requires version 1 and an 8 byte buffer with zero flags, otherwise STATUS_INVALID_PARAMETER. |
| RtlSetMemoryStreamSize, RtlSetThreadPoolStartFunc | Image-level: both are shared stub bodies (E_NOTIMPL 0x80004001 and "xor eax,eax; ret") sharing an address with other exports; alias with RtlReadMemoryStream asserted. |
| Time zone setters | Decompiled worker validates that the name fields are NUL-terminated before touching the registry, returning STATUS_INVALID_PARAMETER. Only that validation path is tested; the success path rewrites the machine time zone and is deliberately not run. |
| RtlSetFeatureConfigurations / RtlSetSystemBootStatusEx | Decompiled arithmetic checks before any system call: count >= 2^32 -> STATUS_INVALID_PARAMETER, count*32 overflow -> STATUS_INTEGER_OVERFLOW (c0000095); boot status size >= 0x40000000 -> c0000095. The state-changing paths are not run. |
| RtlSetProtectedPolicy | Decompiled: per-GUID table, new policy starts at 0, old value returned, optional old pointer; verified with RtlQueryProtectedPolicy and policies reset to 0 afterwards. |

## Justified uncovered (see report)
RtlSetPortableOperatingSystem, RtlSetImageMitigationPolicy, RtlSetSystemBootStatus, RtlSetProcessDebugInformation, RtlSetUnhandledExceptionFilter.

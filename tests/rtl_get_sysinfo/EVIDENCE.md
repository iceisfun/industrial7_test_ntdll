# RTL system information getters: Windows 10 contracts

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). Reference queried through the corpus explorer
function `/decomp` endpoints (`http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp`);
every expectation was then confirmed by running on a Windows 10 guest (administrator and standard user).
Exports are resolved dynamically with `UDECL`/`UN`; kernel32 wrappers (`UIN`) are used only as
documented cross-checks.

| Export (RVA) | Contract asserted | Source |
| --- | --- | --- |
| RtlGetCurrentPeb (0xfce90) | returns TEB->ProcessEnvironmentBlock, stable | decomp (`gs:[0x60]`), observed |
| RtlGetVersion (0x3e520) | status 0; copies PEB OSMajor/Minor/Build/Platform (offsets 0x118..0x124); size 0x114 leaves the extended fields untouched; size 0x11c/0x124 fills service-pack, suite (`(RtlGetSuiteMask & 0xffef) \| 0x100`) and product type | decomp, observed |
| RtlGetNtVersionNumbers (0xd4a40) | major, minor, build\|0xF0000000; each pointer may be NULL | decomp |
| RtlGetNtProductType (0x3cbf0) | returns TRUE and the SharedUserData `NtProductType` (0x7ffe0264) | decomp |
| RtlGetSuiteMask (0x3cc50) | SharedUserData `SuiteMask` (0x7ffe02d0) | decomp |
| RtlGetNtSystemRoot (0x16bb0) | returns SharedUserData `NtSystemRoot` (0x7ffe0030); equals the Win32 system Windows directory | decomp, observed |
| RtlGetNtGlobalFlags (0x9c820) | PEB `NtGlobalFlag` (0xbc) | decomp |
| RtlGetProductInfo (0x7de30) | matches kernel32 `GetProductInfo`; versions below 6.0 return FALSE and zero the output; newer versions still return TRUE with the installed edition | decomp, observed on Windows 10 (the "newer is rejected" guess was wrong and was replaced) |
| RtlGetCurrentServiceSessionId (0x24850) | 0 for a non-silo process | decomp, observed |
| RtlGetActiveConsoleId (0x83a80) | equals SharedUserData `ActiveConsoleId` (0x7ffe02d8) and `WTSGetActiveConsoleSessionId` | decomp |
| RtlGetConsoleSessionForegroundProcessId (0xfce50) | ULONGLONG from SharedUserData 0x7ffe0338, retried to tolerate a concurrent change | decomp |
| RtlGetSessionProperties (0xe64e0) | NULL output or id -1: 0xC000000D, output untouched; otherwise output 0/1 | decomp |
| RtlGetSystemTimeAndBias (0x9c6b0) | returns SharedUserData system time (bounded by two `GetSystemTimeAsFileTime`), bias equals the active time-zone bias, optional outputs may be NULL | decomp, observed |
| RtlGetSystemTimePrecise | within one tick of `GetSystemTimePreciseAsFileTime` samples, monotonic over 1000 reads | decomp, observed |
| RtlGetInterruptTimePrecise (0x43da0) | returns 100 ns interrupt time and the QPC sample; delta over a 60 ms sleep is in a sane range and consistent with the QPC delta | decomp, observed |
| RtlGetMultiTimePrecise (0xe5b50) | flag 1 = QPC, 4 = precise system time, 2 = hypervisor time (optional); flags 0 returns 0 and reports 0 | decomp, observed |
| RtlGetCurrentProcessorNumber (0xa1cc0), ...Ex (0xa1d00) | group/number inside the active topology; pinned thread reports the pinned processor | decomp, observed |
| RtlGetEnabledExtendedFeatures (0x81c70) | `(XState.EnabledFeatures \| ...) & mask`; mask 0 gives 0, x87+SSE always present, equals kernel32 `GetEnabledXStateFeatures` | decomp |
| RtlGetExtendedContextLength (0x51c00), ...2 (0x51db0) | status 0 and a length that grows with CONTEXT_XSTATE; length equals kernel32 `InitializeContext` query; invalid flags give 0xC000000D with the output untouched | decomp, observed |
| RtlGetExtendedFeaturesMask (0xf5ca0) | takes the CONTEXT_EX of an extended context; returns the XSTATE_AREA_HEADER mask with bits 0 and 1 cleared (set through kernel32 SetXStateFeaturesMask); skipped without AVX | decomp, observed |
| RtlGetLongestNtPathLength (0x85820) | constant 0x10d | decomp |
| RtlGetDeviceFamilyInfoEnum (0x3f890) | version quad (major,minor,build,revision) packed from RtlGetVersion, device family/form factor read from license/registry, every output optional | decomp, observed (family value itself is only noted) |
| RtlGetNativeSystemInformation | same RVA as NtQuerySystemInformation/ZwQuerySystemInformation (alias asserted); class 0 length and 0xC0000004 / 0xC0000003 error statuses | decomp, observed |

Skips: none expected. Version/edition values are compared against sibling APIs, never hard-coded.

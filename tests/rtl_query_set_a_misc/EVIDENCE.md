# RtlQuery* (shared data, time, S-list, bitmaps, modes): Windows 10 contracts

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). Decompilation reference: http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp
(queried for every export below). All expectations were also confirmed by running the exe on a Windows 10 guest
as administrator and as a standard user. Exports are resolved dynamically (UDECL/UN); kernel32 comparison functions
are pinned with t_proc_in.

| Export (RVA) | Source of expectation | Checked |
| --- | --- | --- |
| RtlQueryPerformanceFrequency (0x71250) | decomp: stores the 64-bit value at 0x7ffe0300 (KUSER_SHARED_DATA.QpcFrequency), returns 1 | returns TRUE, equals the shared-data value and kernel32 QueryPerformanceFrequency, stable |
| RtlQueryPerformanceCounter (0x401a0) | decomp: TSC/hypervisor-scaled path or NtQueryPerformanceCounter; returns 1 | TRUE, non-zero, monotonic across Sleep(50), same time base as kernel32 QueryPerformanceCounter, elapsed within 40..2000 ms |
| RtlQueryUnbiasedInterruptTime (0x5ce40) | decomp: NULL -> sets last error from STATUS_INVALID_PARAMETER (87) and returns FALSE; else interrupt time minus bias | TRUE and monotonic, 100 ns delta around Sleep(60), consistent with kernel32 QueryUnbiasedInterruptTime, NULL -> FALSE + ERROR_INVALID_PARAMETER |
| RtlQueryDepthSList (0x6b740) | decomp: returns Header8.Depth | depth tracks push/pop 0..3, equals kernel32 QueryDepthSList |
| RtlQueryElevationFlags (0x81080) | decomp: maps SharedDataFlags (0x7ffe02f0) bits 1/2/3 to flags 1/2/4, status 0 | equals the mapping of the shared-data word, high bits clear |
| RtlQueryValidationRunlevel (0x1020f0) | decomp: result = DWORD at 0x7ffe0258 OR a registry value only when a key argument is given | NULL argument returns exactly the shared-data DWORD |
| RtlQueryFeatureConfigurationChangeStamp (0x101b80) | decomp: returns QWORD at 0x7ffe0710 | equals the shared-data QWORD, non-decreasing |
| RtlQueryThreadProfiling (0xcc080) | decomp: forwards to NtQueryInformationThread; observed on Windows 10 | current thread: status 0 and Enabled FALSE; invalid handle: STATUS_INVALID_HANDLE (0xC0000008) |
| RtlQueryProcessPlaceholderCompatibilityMode (0xff260), RtlQueryThreadPlaceholderCompatibilityMode (0x7ffe0) | decomp: return byte PEB+0x7b0 / TEB+0x280 | equal to those bytes; observed 0 (application default) for an ordinary process |
| RtlQueryTimeZoneInformation (0x57af0), RtlQueryDynamicTimeZoneInformation (0xee670) | decomp: shared worker with structure sizes 0xac / 0x1b0 | status 0; biases agree with kernel32 GetTimeZoneInformation / GetDynamicTimeZoneInformation; key name equals kernel32's; the plain and dynamic queries agree on the leading TIME_ZONE_INFORMATION (names and dates). Display names and dates are NOT compared with kernel32: observed on Windows 10 that kernel32 resolves display names through MUI and differs from the raw ntdll values |
| RtlSetAllBitsEx (0xed450) | decomp: writes ceil(SizeOfBitMap/32) DWORDs of 0xFFFFFFFF, with an 8-byte-aligned fast path and a 4-byte head for buffers at 4 mod 8 | 70 bits sets exactly 3 DWORDs (bits past the size in the last DWORD are also set), aligned and 4-mod-8 buffers, sizes 0/1/32/64/128, neighbours untouched |
| RtlQueryInterfaceMemoryStream (0xd5a70) | decomp: shared stub returning 0x80004001 (E_NOTIMPL) | returns 0x80004001 for NULL and non-NULL arguments; aliases share the address with the other memory-stream exports |

Skips: none expected. Observed-only: none.

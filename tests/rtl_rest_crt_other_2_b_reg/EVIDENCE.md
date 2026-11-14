# rtl_rest_crt_other_2_b_reg

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). Every test was run on the guest in elevated and standard-user mode.
"decomp" = Ghidra decompilation / disassembly of the Windows 10 ntdll record in the reference corpus (evidence only; the guest run is the authority).

| Export | Expectation | Source |
|---|---|---|
| RtlpNtOpenKey (RVA 0x7d780) | clears OBJ_PERMANENT|OBJ_EXCLUSIVE (0x30) in the caller's OBJECT_ATTRIBUTES.Attributes then tail-calls NtOpenKey; missing key STATUS_OBJECT_NAME_NOT_FOUND; bad root handle STATUS_INVALID_HANDLE; NULL OA skips the clearing and the system call rejects it | decomp (`and dword ptr [r8+0x18], 0xffffffcf; jmp`), observed |
| RtlpNtCreateKey (0x107c90) | same attribute clearing; real arguments are (PHANDLE, ACCESS_MASK, OA, ignored, ignored, PULONG Disposition): TitleIndex/Class/Options forced to 0, disposition taken from the sixth argument. New key disposition 1, existing 2 | decomp (stack arg at rsp+0x78 forwarded as Disposition), observed. A seven-argument NtCreateKey-style call faults (STATUS_ACCESS_VIOLATION) because the wrapper does not forward the extra arguments |
| RtlpNtEnumerateSubKey (0x82060) | (HANDLE key, PUNICODE_STRING name, ULONG index): basic-information enumeration copied into the caller's string; Length set to the name length, no terminator; too small -> STATUS_BUFFER_OVERFLOW (0x80000005) with Length = required bytes; past the end STATUS_NO_MORE_ENTRIES; subkeys are returned in sorted order | decomp, observed |
| RtlpNtQueryValueKey (0x7b000) | (HANDLE key, PULONG type, PVOID data, PULONG len) queries the unnamed (default) value (empty value name, partial information); STATUS_OBJECT_NAME_NOT_FOUND from the system call is turned into success with type 0 and length 0; overflow still returns type and required length; NULL data allows a size query; NULL length behaves as a zero-byte buffer (overflow) | decomp+asm (empty UNICODE_STRING on stack, class 2), observed |
| RtlpNtMakeTemporaryKey (0x107cd0) | one-instruction jump to a system call stub; bad handle STATUS_INVALID_HANDLE; success on an owned key handle | observed |
| RtlWriteRegistryValue (0x8aad0) | resolves RelativeTo/path (RTL_REGISTRY_USER = 5) to a key, NtSetValueKey with the name, type, data; replaces existing values and changes type; zero-length data allowed; missing parent STATUS_OBJECT_NAME_NOT_FOUND; invalid RelativeTo STATUS_INVALID_PARAMETER | decomp, observed |
| RtlZeroHeap (0xf6410) | walks a private heap and zeroes free blocks; returns STATUS_SUCCESS; live allocations unchanged; heap remains valid and usable; repeatable | decomp (returns the walk status), observed |
| RtlpConvertCultureNamesToLCIDs (0xf0070) | (PCWSTR multi-sz names, PWSTR *out, ?, flags): at most 4 unique valid cultures; output is a heap-allocated multi-sz of 4-digit LCID strings (RtlConvertLCIDToString radix 16, width 4); invalid/duplicate name, NULL arguments or a non-NULL initial *out give STATUS_INVALID_PARAMETER | decomp, observed (de-DE -> 0407, fr-FR -> 040c; compared case-insensitively) |
| RtlpConvertLCIDsToCultureNames (0xf0280) | inverse: multi-sz of hex LCIDs to a heap-allocated multi-sz of names; same argument validation | decomp, observed |
| RtlpGetDeviceFamilyInfoEnum (0x3f8a0) | each of the three output pointers is independently optional; version quad = major<<48 \| minor<<32 \| build<<16 \| UBR (UBR read from the registry, non-zero on this build) matching RtlGetVersion; device family from the licensing value (3 = desktop here, observed only), form from the registry (0 here, observed only) | decomp, observed. Family/form values are only checked for being written, not for their value |
| RtlpGetSystemDefaultUILanguage (0x3c5b0) | NULL output -> STATUS_INVALID_PARAMETER; otherwise returns the install UI language (equal to GetSystemDefaultUILanguage) | decomp, observed on the en-US guest |
| RtlpCheckDynamicTimeZoneInformation (0x7b5b0) | looks up the zone's registry TZI for the given year; returns TRUE and rewrites the structure when it differs from the registry data, FALSE when equal or when the key name is unknown (structure untouched). Second call on a settled structure returns FALSE. The restoration of a corrupted Bias is only asserted when the first call reports a change; otherwise logged | decomp, observed |

## Skips
- Each registry test skips when the current-user hive or the scratch key cannot be created (never seen).

## Std mode
Standard-user runs executed as a real non-administrator account (verified from the whoami output); no privilege-gated checks exist in these areas.

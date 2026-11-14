# rtl_create_add_delete_a_misc

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), administrator and standard-user runs. Decompilation
(`/api/function/ntdll/<Name>/decomp`) used for validation order/offsets; each value verified on the guest.

## Exports covered (behavioral)
RtlCreateHashTable, RtlCreateHashTableEx, RtlCreateMemoryZone, RtlCreateMemoryBlockLookaside,
RtlCreateEnvironmentEx, RtlCreateProcessParameters, RtlCreateProcessParametersEx,
RtlCreateProcessParametersWithTemplate, RtlCreateUnicodeString, RtlCreateUnicodeStringFromAsciiz,
RtlAddFunctionTable, RtlAddGrowableFunctionTable, RtlAddressInSectionTable, RtlCheckRegistryKey,
RtlCreateRegistryKey, RtlCheckPortableOperatingSystem, RtlCreateActivationContext, RtlAddRefActivationContext,
RtlCreateQueryDebugBuffer, RtlCreateUmsCompletionList, RtlCreateUmsThreadContext, RtlCreateUserFiberShadowStack
(argument check only), RtlAddRefMemoryStream, RtlCreateBootStatusDataFile, RtlCheckBootStatusIntegrity,
RtlCheckSystemBootStatusIntegrity (NULL-argument check only).

## Expected values
| Area | Source |
| --- | --- |
| Hash tables | RTL_DYNAMIC_HASH_TABLE fields (Flags bit0 = allocated by the library, Shift, TableSize, DivisorMask = size-1, NumEntries) from decompilation; sizes must be a power of two in [0x80, 0x800000] (observed: 0x40/0x81/0x180/0x1000000 rejected -> FALSE). Insert/lookup/remove maintain NumEntries. |
| Memory zone | Decompiled: Flags != 0 or Size == 0 -> STATUS_INVALID_PARAMETER; allocation larger than the zone -> STATUS_INSUFFICIENT_RESOURCES (c000009a, observed); blocks are 8-aligned and sequential; reset restarts at the first block. |
| Memory block lookaside | Decompiled argument conditions (flags 0, all sizes non-zero, min <= max); a freed block is recycled by the next same-size allocation. |
| Environment | Flag meanings from decompilation: 1 = ANSI source translated, 2 = OEM (requires 1), 4 = empty environment (cannot be combined with a source: STATUS_INVALID_PARAMETER_MIX c0000030), other bits STATUS_INVALID_PARAMETER_3 (c00000f1); NULL source with flag 1 -> c0000030; NULL source with flags 0 copies the process environment (byte-identical, distinct allocation). |
| Process parameters | RTL_USER_PROCESS_PARAMETERS offsets 0x38 cwd, 0x50 DllPath, 0x60 ImagePath, 0x70 CommandLine, 0x80 Environment, 0xB0.. title/desktop/shell/runtime, 0x3F0 EnvironmentSize. Observed: Flags=0 returns a de-normalized block (flag bit 1 clear), RtlNormalizeProcessParams sets it and relocates buffers inside the block, Flags=1 returns normalized; cwd gets a trailing backslash; CommandLine defaults to the image path; empty/over-long cwd, NULL image, Length > MaximumLength and unknown flag bits -> STATUS_INVALID_PARAMETER. WithTemplate performs a deep copy of all strings and the environment. |
| Unicode string creation | Decompiled: result Length = 2*chars, MaximumLength = Length+2; sources of 0x7FFF characters or more fail (BOOLEAN FALSE); FromAsciiz fails for ANSI strings longer than 0xFFFE bytes. |
| Function tables | Dynamic function table lookup through RtlLookupFunctionEntry: begin inclusive/end exclusive, image base reported = the base passed in, table deletion returns TRUE then FALSE; growable table found after RtlAddGrowableFunctionTable and after RtlGrowFunctionTable adds a second entry; count > max or an empty range would fail-fast on Windows 10 and is not tested. |
| RtlAddressInSectionTable | Decompiled: RtlImageRvaToSection then Base + (Rva - VirtualAddress + PointerToRawData). Sections without file data (.bss) and RVAs in the headers or past the image yield NULL. |
| Registry helpers | RelativeTo constants (0 absolute, 1 services, 2 control, 3 Windows NT\CurrentVersion, 5 user). Missing key -> STATUS_OBJECT_NAME_NOT_FOUND; bad RelativeTo -> STATUS_INVALID_PARAMETER; RtlCreateRegistryKey creates only the leaf (missing parent -> c0000034) and is idempotent. Test keys live in HKCU and are deleted. RtlCheckPortableOperatingSystem: STATUS_NOT_FOUND (c0000225) when the PortableOperatingSystem value does not exist (observed), output left untouched; 0 + FALSE accepted otherwise. |
| Activation contexts | Handle layout from decompilation: refcount at +0, data pointer +0x18, notification routine +0x20, context +0x28. Context built from the data block of one created through CreateActCtxW and a minimal manifest; final release invokes the notification once (reason value is only noted); flags != 0, NULL data, NULL output, extra bytes > 0x10000 -> STATUS_INVALID_PARAMETER; a zeroed block is rejected with c0150003 (not asserted, noted). |
| Debug buffer | Buffer is mapped with ViewBaseClient (+8) pointing at itself and OffsetFree at +0x48; a RtlQueryProcessDebugInformation(modules) call advances OffsetFree. |
| UMS / shadow stack | UMS objects returned non-NULL and deleted with status 0. RtlCreateUserFiberShadowStack: the byte 56..63 of the second argument above 0x40 -> STATUS_INVALID_PARAMETER before any system call (observed-only; no hardware shadow stack needed). |
| RtlAddRefMemoryStream | Body is `xor eax,eax; ret` shared by several unrelated exports (same RVA as RtlReleaseMemoryStream and CsrIdentifyAlertableThread). |
| Boot status | RtlCreateBootStatusDataFile with an explicit private path creates a 0x10800-byte file; RtlCheckBootStatusIntegrity succeeds with TRUE and gives FALSE after one payload byte is changed. RtlCheckSystemBootStatusIntegrity(NULL) -> STATUS_INVALID_PARAMETER; the non-NULL result depends on firmware/boot state and is only noted. |

## Not covered here
RtlCreateTagHeap (return value is uninitialised unless heap tagging is enabled at process creation),
RtlCreateSystemVolumeInformationFolder (rewrites security of the real system folder).

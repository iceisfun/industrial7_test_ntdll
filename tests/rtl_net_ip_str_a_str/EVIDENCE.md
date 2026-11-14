# rtl_net_ip_str_a_str: strings, LUID/SID, bitmap-free helpers, memory copy

Oracle: Windows 10 22H2 ntdll 10.0.19041.2788. Every assertion was run on the guest
(adm and std). Decompilation of each export was read from the corpus explorer
(`/api/function/ntdll/<Name>/decomp`) before writing the expectation; the guest run is the authority.
All exports are resolved dynamically with UDECL/UN.

| Export | Expectation | Source |
| --- | --- | --- |
| RtlInitString | Length=strlen, MaximumLength=len+1, NULL source gives all zero; strings of 0xfffe or more characters saturate at Length 0xfffe / Max 0xffff | decomp (saturating clamp) + guest |
| RtlInitStringEx, RtlInitAnsiStringEx, RtlInitUTF8StringEx | same, but 0xffff or more characters return STATUS_NAME_TOO_LONG (0xC0000106) with the destination zeroed; 0xfffe characters succeed | decomp (length > 0xfffe) + guest |
| RtlInitUTF8String | same layout as RtlInitString (bytes, no validation) | decomp |
| RtlFreeUTF8String | shares the RVA of RtlFreeUnicodeString (decomp); NULL-buffer string unchanged; a heap string from RtlUnicodeStringToUTF8String is freed and the descriptor zeroed (Buffer/Length/MaximumLength) | decomp + guest |
| RtlAnsiCharToUnicodeChar | ASCII char converted, pointer advanced by one | docs + guest (SBCS/ASCII only; no lead-byte locale assumed) |
| RtlAnsiStringToUnicodeSize | (Length*2)+2, uses Length not the NUL | decomp (MultiByteToUnicodeSize + 2) |
| RtlAppendAsciizToString | exact fit succeeds with no NUL, overflow gives STATUS_BUFFER_TOO_SMALL (0xC0000023), NULL/empty append is a no-op success | decomp |
| RtlCompareUnicodeStrings | lengths in characters, ordinal vs case-insensitive, shorter prefix is -1/1 | docs + guest |
| RtlFindUnicodeSubstring | case sensitive/insensitive, first match, needle longer than haystack gives NULL, empty needle matches at start | decomp |
| RtlCompareAltitudes | numeric comparison of the integer (and fractional) parts, not lexical | decomp + guest |
| RtlConvertLCIDToString | base 16/10, zero padding to a minimum width, STATUS_BUFFER_OVERFLOW (0x80000005) when the length argument is 0x200 or more, STATUS_UNSUCCESSFUL (0xC0000001) when the buffer cannot hold digits+NUL | decomp + guest |
| RtlFindClosestEncodableLength | rounds up to 256/65536/4G granularity above 4 GiB; above 0xffffffff00000000 gives 0xC0000001 and output 0 | decomp |
| RtlFindLeastSignificantBit / RtlFindMostSignificantBit | bit index, 0xff (as CCHAR -1) for zero input | decomp |
| RtlEqualWnfChangeStamps | plain ULONG equality | decomp |
| RtlEqualLuid, RtlCopyLuid, RtlCopyLuidAndAttributesArray | field copy / compare, only Count elements written | decomp |
| RtlCopySidAndAttributesArray | SIDs packed back to back, remaining area pointer and size returned, STATUS_BUFFER_TOO_SMALL when a SID does not fit | decomp + guest |
| RtlAllocateAndInitializeSidEx | up to 15 sub-authorities, 16 gives STATUS_INVALID_PARAMETER, output SID layout verified | decomp + guest |
| RtlConvertSidToUnicodeString | "S-1-5-21-1-2-3-500", allocate and fixed-buffer forms, small buffer gives STATUS_BUFFER_OVERFLOW (0x80000005) | guest |
| RtlFindAceByType | by type, with start index in/out parameter, NULL ACL and zero count give NULL | decomp |
| RtlCopySecurityDescriptor | allocates a heap copy of a minimal descriptor and of a 40-byte self-relative descriptor (owner + empty DACL), bytes identical, length preserved | decomp + guest |
| RtlCopyMemory, RtlCopyMappedMemory, RtlCopyMemoryNonTemporal | copy exactly N bytes, zero length no-op, no overrun | docs + guest |

Skips: none. Status values are all NTSTATUS codes asserted exactly; values are
identical for administrator and standard user.

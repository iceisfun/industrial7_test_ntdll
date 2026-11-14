# Rtl security helpers: Windows 10 contracts

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). Function decompilations from the Corpus Explorer
(`http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp`) gave argument order and
validation; values marked "observed" were established on the Windows 10 guest where the decompilation was
ambiguous.

| Export | Source | Checked |
| --- | --- | --- |
| RtlMapGenericMask | decomp 0x37ea0: each of the four generic bits ORs the matching mapping member, then the top four bits are cleared | All four generic bits, combinations, no-generic input unchanged, bits 24-27 (ACCESS_SYSTEM_SECURITY, MAXIMUM_ALLOWED) preserved |
| RtlMapSecurityErrorToNtStatus | decomp 0x1a10, table verified entry by entry on the guest. 0x80090302 and 0x8009030A map to 0xC00000BB (the decompiler's shared "default" labels are ambiguous; observed) | 22 mapped SSPI codes, 17 pass-through values around the table edges |
| RtlLengthSidAsUnicodeString | decomp 0x36d50: `subauthorities*22 + 28`, or `+36` when the identifier authority needs hex; invalid SID 0xC0000078, output untouched | Four SIDs including a hex-authority SID; bound is >= RtlConvertSidToUnicodeString length |
| RtlSidDominates | decomp 0x7bc40: both SIDs must be integrity labels (authority 16), compares the last RID; output cleared first, 0xC000000D otherwise | Equal, higher, lower, non-label either side |
| RtlOwnerAcesPresent | decomp 0xe6bf0 (wrapper): TRUE only when an OWNER RIGHTS (S-1-3-4) ace is present | Empty ACL, ACL without, ACL with |
| RtlMakeSelfRelativeSD | decomp 0x6d290: needed length is `0x14 + owner + group + sacl + dacl`; too-small reports it with 0xC0000023; NULL output 0xC000000D; clears then fills exactly that many bytes; sets SE_SELF_RELATIVE | Size query, short length, NULL output, exact fill with sentinel bytes after, content read back through the Rtl getters, offsets in range, larger buffer identical |
| RtlSelfRelativeToAbsoluteSD2 | decomp 0x88d30: NULL SD 0xC00000EF, NULL length 0xC00000F0, length < 0x14 0xC000000D, not self-relative 0xC00000E7, required size `0x28 + round8(end - 0x14)` reported with 0xC0000023; converts in place | All error paths, size, in-place conversion (flag cleared, pointers inside the buffer, content intact) |
| RtlReplaceSidInSd | decomp 0xe6c00: matches on revision, sub-authority count, identifier authority and sub-authorities, then copies only the sub-authority words (the authority is not copied); counts owner, group and DACL/SACL ace SIDs | No match (different length / authority) leaves count 0, group+ace replacement count 2, owner replacement, repeat finds nothing |
| RtlNewSecurityObject, RtlNewSecurityObjectEx, RtlNewSecurityObjectWithMultipleInheritance | decomp 0x88530 / 0x79c20 / 0x85d10 (thin wrappers of one worker); Windows behaviour observed: defaults come from the token owner, primary group and default DACL; creator DACL replaces default with generic bits mapped; inheritable parent aces are inherited with mapped masks; Everyone as owner 0xC000005A; auto-inherit flag 1 marks inherited aces with INHERITED_ACE and the descriptor SE_DACL_AUTO_INHERITED | Process token queried with TOKEN_QUERY; no privileges required |
| RtlNewInstanceSecurityObject | decomp 0xd6e60: queries the token statistics; if neither descriptor changed and the modified id matches, no descriptor is produced (0 and NULL), otherwise one is built; bad token handle 0xC0000008 | All three branches |
| RtlNewSecurityGrantedAccess | decomp 0xd6f90: maps generics into the remaining-access output; ACCESS_SYSTEM_SECURITY requires an enabled SeSecurityPrivilege (0xC0000061 when not enabled); privilege-set buffer shorter than 0x14 gives 0xC0000023 and the length | Three paths; SeSecurityPrivilege is not enabled in the process token in either mode so the failure is stable |

RtlDeleteSecurityObject is used for cleanup; it does not clear the caller's pointer, so the tests never read it afterwards.
Not covered here: RtlNormalizeSecurityDescriptor (see report).

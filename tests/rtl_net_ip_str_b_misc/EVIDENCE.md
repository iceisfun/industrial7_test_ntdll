# Rtl Is*/Valid* predicates, bit counting, handle table, misc initialisers

Reference: Windows 10 22H2 ntdll 10.0.19041.2788. "Decomp" means the logic read in the decompilation of the 19041
image (argument/validation order), "observed" means measured on the Windows 10 guest. All results were confirmed on
the guest (admin).

| Export | Asserted / source |
| --- | --- |
| RtlNumberOfSetBitsEx, RtlNumberOfClearBitsEx | RTL_BITMAP_EX {u64 size, u64 *buffer}; bits beyond size are not counted; clear = size - set (decomp). |
| RtlNumberOfSetBitsInRange, RtlNumberOfClearBitsInRange | per-range counts across byte/qword boundaries; 0xffffffff for start>=size, start+len>size, len==0 (decomp, observed). |
| RtlNumberOfSetBitsUlongPtr | popcount of 64-bit value (decomp). |
| RtlIsZeroMemory | aligned/unaligned heads and tails, zero length is TRUE (decomp). |
| RtlUpperChar, RtlUpperString | ASCII-only upcase of bytes 'a'..'z' (decomp); RtlUpperString copies min(src.Length, dst.MaximumLength) bytes and sets dst.Length (observed). |
| RtlIsCapabilitySid / RtlIsPackageSid | revision 1, >1 sub-authorities, authority {0,0,0,0,0,15}, first sub-authority 3 (capability) / 2 (package) (decomp). |
| RtlIsValidProcessTrustLabelSid | revision 1, exactly 2 sub-authorities, authority 19 (process trust), rejects {0,x!=0} (decomp). |
| RtlIsElevatedRid | enabled SID_AND_ATTRIBUTES whose last RID is in the administrative list (S-1-5-32-544 true, 545 false); deny-only or integrity-flagged attributes (mask 0x30) rejected; NULL false (decomp, observed). |
| RtlIsParentOfChildAppContainer | AppContainer parent (8 sub-authorities) vs child (12 sub-authorities) with identical hash; different hash, same SID twice and non-AppContainer SIDs false; the argument order is determined empirically and asserted as exactly one order matching (observed). |
| RtlIsCurrentProcess / RtlIsCurrentThread | pseudo handles -1/-2, real handles opened to the current process/thread (true), foreign process/thread and invalid values (false) (decomp: NtCompareObjects). |
| RtlIsProcessorFeaturePresent | equals IsProcessorFeaturePresent for 0..63, false for >=64 (decomp reads KUSER_SHARED_DATA.ProcessorFeatures). |
| RtlIsThreadWithinLoaderCallout, RtlIsCurrentThreadAttachExempt | false outside DllMain / for an ordinary thread (decomp). |
| RtlIsMultiSessionSku, RtlIsMultiUsersInSessionSku, RtlIsStateSeparationEnabled | the latter two equal bits 9 and 10 of KUSER_SHARED_DATA.SharedDataFlags; the SKU-dependent values are only logged (decomp). |
| RtlIsActivationContextActive | true between ActivateActCtx/DeactivateActCtx for the created context, false before and after, false for an arbitrary handle (decomp: walks the TEB activation frame list). |
| RtlIsCloudFilesPlaceholder, RtlIsPartialPlaceholder, RtlIsNonEmptyDirectoryReparsePointAllowed | pure bit/tag tests on attributes (0x400 reparse, 0x40000/0x400000 recall) and reparse tag (0x9000x01a family, bit 28, 0x80000018) (decomp). |
| RtlIsPartialPlaceholderFileHandle / FileInfo | real file handle -> success, FALSE; invalid handle 0xC0000008; info classes 2,3,0x23,0x25,0x26,0x3c,0x3f,0x44,0x46 read FileAttributes at the class-specific offset; other classes < 0x4c 0xC00000BB (not supported), >= 0x4c 0xC0000003 (decomp). |
| RtlIsValidLocaleName | en-US, de-DE valid, case-insensitive; flag bit 1 allowed, other flag bits and NULL invalid; empty name valid (observed); nonsense invalid. |
| RtlValidProcessProtection | exhaustive 0..255 sweep against the set {0x00,0x08,0x12,0x21,0x31,0x41,0x51,0x52,0x61,0x62,0x72,0x81} (decomp). |
| RtlValidateUnicodeString | reserved flags, odd lengths, Length > Maximum, MaximumLength 0xffff, NULL buffer with nonzero length (decomp). |
| RtlValidateCorrelationVector | v1 16-char base, v2 22-char base, dot-separated decimal extension up to 2147483647, malformed cases, NULL (decomp, observed). |
| RtlValidAcl, RtlValidRelativeSecurityDescriptor | built ACL/SD pass; truncated size, bad revision, ACE count overrun, non-self-relative, misaligned/out-of-range owner offset fail (observed). |
| RtlValidateProcessHeaps | TRUE on a healthy process (observed). |
| RtlIsNameInExpression, RtlIsNameInUnUpcasedExpression | `*`, `?`, `<`, `>`, `"` wildcard semantics for 40 cases in both case modes; IgnoreCase requires an already-upcased expression for the first routine, the Un-upcased routine upcases both (decomp: RtlpUpcaseUnicodeStringPrivate). Observed: `*` does not match an empty name and `*.*` does not match a name without a dot. |
| RtlIsNameLegalDOS8Dot3 | 8.3 length/character rules, space reporting, lowercase accepted (upcased through OEM conversion), `.`/`..`/empty reported legal, NULL spaces pointer allowed, names over 12 chars rejected without conversion, OEM output holds the upcased name (decomp, observed). |
| RtlIsTextUnicode | BOM, reverse BOM (flag set, result false), ASCII bytes false, UTF-16 text true, odd length, NULL result pointer; the exact flag word for ambiguous heuristics is only logged (observed). |
| RtlIsNormalizedString | forms C/D on composed and decomposed e-acute, length -1 and counted, empty; NULL pointers, length < -1, form 0 and unknown forms rejected (decomp). |
| RtlIsUntrustedObject | NULL handle 0xC000000D with output preset TRUE, bad handle 0xC0000008, plain event is trusted (observed). |
| RtlInitializeHandleTable, RtlIsValidHandle, RtlIsValidIndexHandle | table header fields (max, entry size, sign bit of size moved to a flag word, five zeroed fields), validity requires range, alignment and bit 0 of the entry (decomp); RtlAllocateHandle/RtlFreeHandle/RtlDestroyHandleTable are used as fixtures. |
| RtlInitializeSidEx | 0..15 sub-authorities written in order, authority copied, 16 -> 0xC000000D (observed). |
| RtlInitializeSListHead | header zeroed and usable with the interlocked list API (decomp). |
| RtlMultipleAllocateHeap / RtlMultipleFreeHeap | count of allocations returned, zero-memory flag, partial result on allocation failure in a fixed-size heap, zero count (decomp). |
| RtlTimeToElapsedTimeFields | day/hour/minute/second/millisecond decomposition, sub-millisecond truncation (decomp). |

Not tested: freeing invalid pointers via RtlMultipleFreeHeap (raises heap corruption), NULL arguments of the
non-Ex string-to-address routines (see the ip area).

Skips: none.

# RTL data structures and memory helpers: Windows 10 contracts

Reference: ntdll 10.0.19041.2788. Decompilation/disassembly came from the corpus explorer; every expectation was
confirmed on a Windows 10 22H2 guest (elevated administrator and standard user).
This historical validation applies to the original table below, not the new
non-volatile expansion described at the end of this file.

| Export (RVA) | Contract asserted | Source |
| --- | --- | --- |
| RtlExpandHashTable (0x886a0) | each call adds one bucket (TableSize +1, Pivot +1); after 128 splits Pivot returns to 0, DivisorMask widens 127 -> 255 and TableSize is 256; all entries remain findable; returns FALSE (table unchanged) while NumEnumerators != 0; NumEntries unchanged | decompilation (field offsets 8/0xc/0x10/0x1c), guest |
| RtlEndEnumerationHashTable (0x81110), RtlEndWeakEnumerationHashTable | decrement NumEnumerators, also when the enumeration ended early; two concurrent enumerators counted | decompilation, guest |
| RtlEndStrongEnumerationHashTable, RtlDebugPrintTimes | both resolve to the same empty routine (identical address) and have no effect: NumEnumerators is unchanged by the call | explorer record (shared 3-byte `ret` body), guest |
| RtlEmptyAtomTable (0x8a7f0), RtlDestroyAtomTable (0x8a730) | Empty(FALSE) removes unpinned atoms and keeps pinned ones (lookup STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034), Empty(TRUE) removes pinned ones too, table reusable; Destroy returns 0 even with pinned atoms | decompilation (flag bit 1 = pinned), guest |
| RtlDestroyHandleTable (0x855d0) | returns 0 for an unused table and for one with committed handles; the committed region is released (VirtualQuery state MEM_FREE) | decompilation (NtFreeVirtualMemory of the committed region), guest |
| RtlDestroyMemoryZone (0x850b0), RtlDestroyMemoryBlockLookaside (0x85050) | return 0 and release the segments: an address handed out earlier is MEM_FREE afterwards | decompilation (segment list freed), guest |
| RtlDestroyProcessParameters (0x7d7a0) | returns 0, frees a process-heap block (HeapSize valid before, heap validates after); RtlDestroyEnvironment is the same routine (same address) | decompilation, guest |
| RtlDestroyQueryDebugBuffer (0xd76d0) | returns 0 and unmaps the section view (MEM_MAPPED before, MEM_FREE after) | decompilation (NtClose/NtUnmapViewOfSection), guest |
| RtlFirstEntrySList (0xa0bf0) | head pointer with the low four bits cleared: NULL when empty, newest pushed entry otherwise, not popped | decompilation, guest |
| RtlFirstFreeAce (0x37710) | walks AceCount entries from ACL+8: free pointer after 0, 1, 2 entries; exact-fit ACL gives the ACL end; AceCount larger than the space returns FALSE with NULL; an entry overrunning the ACL returns TRUE with a NULL pointer | decompilation, guest |
| RtlImageNtHeaderEx (0x32ad0) | NULL output, NULL or -1 base, flag bits above bit 1: STATUS_INVALID_PARAMETER (output cleared where writable); size below 0x40, header not wholly inside the size (boundary e_lfanew+0x18 inclusive), bad MZ/PE signature, e_lfanew >= 0x10000000: STATUS_INVALID_IMAGE_FORMAT (0xC000007B) with output NULL; flag 1 skips the size checks | decompilation, guest |
| RtlImageRvaToSection (0x33aa0) | first section whose [VirtualAddress, VirtualAddress+SizeOfRawData) holds the RVA (raw size, not virtual size); zero raw size matches nothing; image base argument ignored | decompilation, guest |
| RtlIoDecodeMemIoResource (0xf20a0) | descriptor types 1 and 3 return Length with Alignment/Min/Max unscaled; other types scale Length and Alignment by the 0x200 (<<8), 0x400 (<<16), 0x800 (<<32) flags, lowest set flag winning; output pointers optional | decompilation, guest |
| RtlFillMemoryNonTemporal (0xa1bc0) | exact fill of every length 0..4109 tested, all alignments, no write outside the range | decompilation, guest |
| RtlFillNonVolatileMemory (0xfc2b0), RtlFlushNonVolatileMemory (0xfbcb0), RtlFlushNonVolatileMemoryRanges (0xfc360), RtlDrainNonVolatileFlush (0xfbc80) | a token without bit 0 is STATUS_INVALID_PARAMETER and nothing is written; token 1 (valid) and 3 (valid + flush needed) succeed; fills write exactly the range for the tested flag combinations; flush/drain leave data intact | decompilation (token bits, flags), guest. The tokens are synthetic values; no persistent memory is involved |
| RtlFlsAlloc / RtlFlsGetValue / RtlFlsSetValue / RtlFlsFree (0x74860 / 0x52550 / 0x4cdf0 / 0x73670) | index range 1..0xFEF; fresh slot reads 0; set/get round trip; independent slots; Free of a freed slot or invalid index STATUS_INVALID_PARAMETER; callback runs once on Free with the stored value, and not for an empty slot; Get/Set with index 0, 0xFF0, 0x1000, 0xFFFFFFFF STATUS_INVALID_PARAMETER | decompilation (RtlpFlsAlloc/RtlpFlsFree), guest |
| RtlEncodeSystemPointer / RtlDecodeSystemPointer (0x85240 / 0x836c0) | `ror(p ^ cookie, cookie & 63)` with the 32-bit cookie at 0x7FFE0330, and its inverse | decompilation, guest |
| RtlEncodeRemotePointer / RtlDecodeRemotePointer (0xdc8f0 / 0xdc880) | same transform with the target process cookie (ProcessCookie); equals RtlEncodePointer for the current process; failure returns the NtQueryInformationProcess status with bit 28 set (0xD0000008 for an invalid or NULL handle, 0xD0000022 for a handle without query access) and leaves the output untouched | decompilation, guest |

## Skips and notes

No skips on the guest. The non-volatile token values and the descriptor layout are synthetic; the first because no
persistent memory is needed for the helpers' user-mode logic, the second because the function only reads the
documented IO_RESOURCE_DESCRIPTOR fields. `RtlCreateMemoryBlockLookaside` takes SIZE_T size arguments (passing
32-bit values leaves undefined upper register bits and fails with STATUS_COMMITMENT_LIMIT).

## Non-volatile expansion (host-only, not guest-validated)

[V] All seven `/api/function/ntdll/<name>/decomp` listings were read from
the Corpus Explorer; assembly was also checked
for each export. Contracts below are static observations, not fresh runtime results.

| Export / RVA | Verified stock behavior |
| --- | --- |
| RtlGetNonVolatileToken / 0xfc410 | Ignores length; queries current process virtual memory, information class 7, buffer size 0x30. Propagates query failure. If region flags lack 0x20, returns 0xc000000d. Writes token 1 or 3 only on success, selected by RtlpIsFlushRequired. |
| RtlFreeNonVolatileToken / 0xfc3f0 | Bit 0 set: success; otherwise 0xc000000d. No dereference or resource release. Tested in rtl_token_hijack. |
| RtlFlushNonVolatileMemory / 0xfbcb0 | Rejects even tokens before accessing memory. Odd tokens without bit 1 bypass flushing. Otherwise aligns start down to cache-line size and flushes lines below address+length. Flag bit 0 suppresses drain. |
| RtlFlushNonVolatileMemoryRanges / 0xfc360 | Same token checks; reads pairs of pointer and SIZE_T, 16-byte stride. Calls single-range flush with flag bit 0 set, then drains once unless caller flag bit 0 is set. Count zero does not read the array. |
| RtlDrainNonVolatileFlush / 0xfbc80 | Rejects even tokens; otherwise success. Executes SFENCE only if the internal flush-required byte and token bit 1 are both set. |
| RtlWriteNonVolatileMemory / 0xfc490 | Rejects even tokens first. Copies source to destination; flags & 3 == 1 copies then flushes; otherwise bit 1 selects non-temporal copy for lengths >= 8, falling back to copy+flush below 8. With bit 1 clear it just copies. Flag bit 8 suppresses drain only in the flags & 3 == 1 path. |
| RtlFillNonVolatileMemory / 0xfc2b0 | Same flag dispatch and 8-byte threshold as write, but fills the exact requested byte range. |

[V] Instruction anchors: Get at `0xfc43f` (`44 8d 43 06`) selects class 7;
`0xfc44c` (`f6 44 24 3c 20`) tests region bit 0x20; only `0xfc46c`
(`48 89 1f`) writes the output. Drain at `0xfbc9a` is `0f ae f8`
(SFENCE), omitted from the decompilation. Flush at `0xfbcf1` is
`66 0f ae 31` (CLWB), incorrectly rendered as xsaveopt in the decompilation.
Write at `0xfc4d2` and fill at `0xfc2ef` compare length with 8;
`0xfc4fc` / `0xfc317` use `0f ba e1 08` to test flag bit 8.
Ranges at `0xfc3b2` (`4d 8d 76 10`) advances by 16 bytes.

[I] A zero length is not necessarily a no-op for a flush-required token:
an unaligned start rounds down below the end even when length is zero.
Tests therefore use accessible storage rather than assuming NULL/zero is
universally safe for write/fill/flush.

New tests cover ordinary-RAM token failure with untouched output across
four lengths, invalid-token early rejection in a child, and a write/fill
matrix (6 tokens x 9 flags x 9 lengths x 2 offsets). Full destination
comparison checks guards and contents; writes also verify the source unchanged.
Existing range/flush tests remain in place. These checks do not establish
power-failure durability, cache eviction, or fence ordering; successful token
acquisition on persistent memory remains untested.

Validation: cross-build only; new tests NOT RUN on Windows or i7. No guest/QEMU
was launched. No i7 implementation was changed or compared in this corpus task.

# RTL data structures and memory helpers: Windows 10 contracts

Reference: ntdll 10.0.19041.2788. Decompilation/disassembly came from the corpus explorer; every expectation was
confirmed on a Windows 10 22H2 guest (elevated administrator and standard user).

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
| RtlFillNonVolatileMemory (0xfc2b0), RtlFlushNonVolatileMemory (0xfbcb0), RtlFlushNonVolatileMemoryRanges (0xfc360), RtlDrainNonVolatileFlush (0xfbc80) | a token without bit 0 is STATUS_INVALID_PARAMETER and nothing is written; token 1 (valid) and 3 (valid + flush needed) succeed; fills write exactly the range for every flag combination; flush/drain leave data intact | decompilation (token bits, flags), guest. The tokens are synthetic values; no persistent memory is involved |
| RtlFlsAlloc / RtlFlsGetValue / RtlFlsSetValue / RtlFlsFree (0x74860 / 0x52550 / 0x4cdf0 / 0x73670) | index range 1..0xFEF; fresh slot reads 0; set/get round trip; independent slots; Free of a freed slot or invalid index STATUS_INVALID_PARAMETER; callback runs once on Free with the stored value, and not for an empty slot; Get/Set with index 0, 0xFF0, 0x1000, 0xFFFFFFFF STATUS_INVALID_PARAMETER | decompilation (RtlpFlsAlloc/RtlpFlsFree), guest |
| RtlEncodeSystemPointer / RtlDecodeSystemPointer (0x85240 / 0x836c0) | `ror(p ^ cookie, cookie & 63)` with the 32-bit cookie at 0x7FFE0330, and its inverse | decompilation, guest |
| RtlEncodeRemotePointer / RtlDecodeRemotePointer (0xdc8f0 / 0xdc880) | same transform with the target process cookie (ProcessCookie); equals RtlEncodePointer for the current process; failure returns the NtQueryInformationProcess status with bit 28 set (0xD0000008 for an invalid or NULL handle, 0xD0000022 for a handle without query access) and leaves the output untouched | decompilation, guest |

## Skips and notes

No skips on the guest. The non-volatile token values and the descriptor layout are synthetic; the first because no
persistent memory is needed for the helpers' user-mode logic, the second because the function only reads the
documented IO_RESOURCE_DESCRIPTOR fields. `RtlCreateMemoryBlockLookaside` takes SIZE_T size arguments (passing
32-bit values leaves undefined upper register bits and fails with STATUS_COMMITMENT_LIMIT).

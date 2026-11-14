# rtl_net_ip_str_a_obj: bitmaps, handle tables, zones, lookaside, hash tables, contexts, locks

Oracle: Windows 10 22H2 ntdll 10.0.19041.2788, run on the guest in adm and std modes.
Decompilations from the corpus explorer; the guest run is the authority.
Helpers (Create/Destroy variants, enumerate/end) are resolved dynamically beside the exports under test.

| Export | Expectation | Source |
| --- | --- | --- |
| RtlInitializeBitMapEx, RtlFindSetBitsEx, RtlFindClearBitsEx, RtlFindSetBitsAndClearEx | 64-bit size, run search across 64-bit word boundaries, hint wrap, no run gives -1 (ULONG_PTR), AndClear clears found run | decomp + guest |
| RtlCopyBitMap, RtlExtractBitMap | aligned and unaligned offsets, count clamped to the smaller bitmap, surrounding bits preserved | decomp + guest |
| RtlAllocateHandle, RtlFreeHandle | distinct entries and indices, entries aligned, freed entry zeroed and reused LIFO | decomp + guest |
| RtlAllocateMemoryZone, RtlExtendMemoryZone | 8-byte rounding, zero size STATUS_INVALID_PARAMETER, exhaustion gives 0xC000009A (STATUS_INSUFFICIENT_RESOURCES); extend by 0 is invalid, extend then allocate succeeds | decomp + guest |
| RtlAllocateMemoryBlockLookaside, RtlFreeMemoryBlockLookaside, RtlExtendMemoryBlockLookaside | block recycled after free, size above the maximum block is STATUS_INVALID_PARAMETER; the create arguments 3-5 are SIZE_T (5th is read as 64-bit from the stack) | decomp + asm + guest |
| RtlInitBarrier | zeroes the first 16 bytes and stores the thread count at +0x10, NULL gives STATUS_INVALID_PARAMETER | decomp |
| RtlInitEnumerationHashTable, RtlInitWeakEnumerationHashTable, RtlInitStrongEnumerationHashTable | BOOLEAN TRUE, empty table enumerates nothing, five inserted entries are each enumerated exactly once with the matching enumerate/end pair (the strong enumerator must not be used with the weak enumerate routine, which fail-fasts) | decomp + guest |
| RtlAllocateActivationContextStack, RtlFreeActivationContextStack | new stack has no active frame, empty frame-cache list, flags 1; allocating again keeps the existing pointer | decomp + guest |
| RtlFreeThreadActivationContextStack | run on a helper thread: TEB stack pointer non-NULL before and re-initialized (non-NULL) after | decomp + guest |
| RtlInitializeContext | x64: Rcx=parameter, Rip, Rsp, ContextFlags 0x10000b, EFlags 0x200, MxCsr 0x1f80, FP control word 0x27f, filler register values | decomp + guest |
| RtlCopyContext | copies only the requested part, invalid flags fail | guest |
| RtlConvertSRWLockExclusiveToShared | after conversion other readers may acquire, writers may not; lock word returns to zero | decomp + guest |
| RtlConvertExclusiveToShared, RtlConvertSharedToExclusive | RTL_RESOURCE active count and owner fields (+0x44, +0x48) | decomp + guest |
| RtlCopyMemoryStreamTo, RtlCopyOutOfProcessMemoryStreamTo | return E_NOTIMPL (0x80004001), outputs untouched | decomp (shared stub) |

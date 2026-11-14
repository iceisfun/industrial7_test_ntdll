# Rtl data structures, frames, zones, atoms, random: Windows 10 contracts

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788) in the validation guest. Reference queried through the
Corpus Explorer function `/decomp` APIs (`http://docker1.dev.moonlightcompanies.com:8765`) for argument
order and validation; every expectation was also confirmed by running on the guest (administrator mode).
Types that are absent from the SDK headers are declared locally with `UDECL`; 64-bit parameters are declared
64-bit (`SIZE_T`) so no upper register halves are left undefined.

| Export | Source of expectation | Checked |
| --- | --- | --- |
| RtlRealSuccessor, RtlRealPredecessor | decomp 0x65960 / 0x7f2c0 (splay-links walk: right-most-of-left / left-most-of-right, else climb parents) | Hand-built 5-node tree; full in-order walk both directions, NULL at the ends |
| RtlLookupElementGenericTableFull, ...FullAvl | decomp 0xf77d0 / 0x5bbc0: search result code stored through the 4th arg (0 empty, 1 found, 2 insert-left, 3 insert-right), node-or-parent stored through the 3rd, element pointer returned only on a hit | Empty tree, 6 found keys (pointer identity with the insert return value), absent keys below / between / above, drain |
| RtlLookupFirstMatchingElementGenericTableAvl | decomp 0x8a040: walks predecessors while the compare routine returns Equal; RestartKey set to the first match node, cleared when none | Group-only comparison over a `(group, seq)` key: lowest-order element returned, RestartKey set/cleared |
| RtlLookupEntryHashTable | decomp 0x67760 (+ RtlInsertEntryHashTable / RtlCreateHashTable as helpers): returns the entry whose Signature equals the request, NULL otherwise; optional context | 200 entries, every signature found, missing signature NULL, explicit context populated, entry-count field (+0x14), removal |
| RtlPinAtomInAtomTable, RtlLookupAtomInAtomTable | decomp 0xeb090 / 0x4c690: lookup: empty name 0xC0000033, absent 0xC0000034, `#n` integer atoms (>= 0xC000 rejected 0xC000000D), case-insensitive; pin: atom 0 / unknown string atom 0xC0000008, integer atoms succeed, sets the pinned flag (observed through RtlQueryAtomInAtomTable) | Table of cases; delete of an unpinned atom then 0xC0000034 / 0xC0000008 |
| RtlRbInsertNodeEx, RtlRbRemoveNode | Red bit is bit 0 of `ParentValue`, parent pointer in the remaining bits (WDK `RTL_BALANCED_NODE`); behaviour is a standard red-black tree | 400 nodes ascending then pseudo-random, remove every 3rd, then drain via `Min`: after each batch: root black, no red-red, equal black height, in-order sorted, parent links, node count, `Min` is the leftmost node |
| RtlPushFrame, RtlPopFrame | decomp 0x6a4b0 / 0x6b6a0: the frame's second pointer (+8) receives the TEB active-frame slot (+0x17c0) and the slot is set to the frame; pop restores the slot from the frame (frame link untouched) | Two nested frames, cross-checked with RtlGetFrame |
| RtlResetMemoryZone, RtlResetMemoryBlockLookaside | decomp 0xeb240 / 0xeb1e0 (rewinds every segment's allocation pointer; lookaside additionally reinitialises the free lists); creation/allocation helpers used for setup | Allocation addresses are 8-byte rounded and sequential; after a reset the first allocation address repeats; oversize zone request 0xC000009A; create validation 0xC000000D |
| RtlRandom, RtlRandomEx | decomp 0x43ce0: both names share one body; seed update is `(seed * 0x7fffffed + 0x7fffffc3) mod 0x7fffffff` | Seed sequence over 100 iterations equals the formula; both names advance a seed identically; the same RVA; at least 480 of 512 returned values distinct (return value itself is unspecified and not asserted) |
| RtlRunEncodeUnicodeString, RtlRunDecodeUnicodeString | decomp 0xe6f70 / 0xe6f10: first byte `^= seed|0x43`, then each byte `= prev_encoded ^ cur ^ seed`; seed 0 is replaced with a non-zero value derived from the system time | Known-vector encode with seed 0x55; decode round trip; seed 0 gets a non-zero seed that decodes; length 0 and 1 edge cases |
| RtlIoEncodeMemIoResource | decomp 0xf2140 | Types 1 (32-bit only), 3 and 7 encoding at 2^8 / 2^16 / 2^32 scaling, unrepresentable values 0xC0000001, bad type 0xC000000D |
| RtlReadMemoryStream, RtlReadOutOfProcessMemoryStream, RtlRevertMemoryStream, RtlSeekMemoryStream | decomp 0xd5a70: one shared stub body for every memory-stream method, returns E_NOTIMPL (0x80004001) | Return value with two argument sets; shared address |

## Notes
- RtlDeleteSecurityObject-style "pointer cleared after free" is not relied on anywhere in this area.
- RtlProtectHeap, RtlProcessFlsData and RtlPrepareForProcessCloning are not tested here (see the coordinator list).

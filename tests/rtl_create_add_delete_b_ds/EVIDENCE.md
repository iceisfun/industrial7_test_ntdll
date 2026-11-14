# RTL data structures: hash tables, generic tables, splay links, bit runs, SLists

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), x64, run in adm and std modes; every expectation below passed there.
Corpus Explorer decompilations (`/api/function/ntdll/<Name>/decomp`) were used for structure offsets and branch order;
the guest run is the authority. Types are declared locally in the test (not all are in the SDK headers).

| Export | Expectation | Source |
| --- | --- | --- |
| RtlInsertEntryHashTable / RtlRemoveEntryHashTable | Returns TRUE; sets entry Signature; NumEntries +/- 1; NonEmptyBuckets 1 after first insert and 0 after the last removal; a context from RtlLookupEntryHashTable is accepted. Exact bucket sharing is not asserted (bucket selection is internal). | decomp 0x676d0 / 0x7c350; observed |
| RtlEnumerateEntryHashTable | Visits every inserted entry exactly once, then returns NULL; the enumerator is linked into the table (NumEnumerators +1 until RtlEndEnumerationHashTable); enumerator layout is entry (0x18) + ChainHead + BucketIndex (0x28 bytes). Entries with Signature 0 are skipped, so the test uses non-zero signatures. | decomp 0x67850 / 0x67620; observed |
| RtlDeleteHashTable | A table created with a caller-provided header does not free the header (header stays readable, Flags bit 0 clear); an allocated header has Flags bit 0 set. Free of the directory is not observable. | decomp 0x7af50, 0x733c8; observed |
| RtlInterlockedSetBitRun / ClearBitRun | Result equals a bit-by-bit reference for runs inside a word, exactly one word (32), spanning words, zero length and 128 bits; surrounding bits are preserved. | decomp 0xece10 / 0x7a020; observed |
| RtlInsertElementGenericTableFull | Search result enum 0 empty, 1 found, 2 left, 3 right; allocator is called with size + 0x28; found-node insert returns the existing element, NewElement FALSE, no allocation; size overflow (0xFFFFFFF8) returns NULL without calling the allocator; allocator failure returns NULL and NewElement FALSE. | decomp 0x65210; observed |
| RtlInsertElementGenericTableFullAvl | Same shape; allocator size is size + 0x20; overflow 0xFFFFFFF0 returns NULL; NumberGenericTableElements tracks inserts. | decomp 0x5ba90; observed |
| RtlDeleteElementGenericTableAvlEx | Takes the node (user data - 0x20); the free routine receives that node; element count decreases; DeleteCount (+0x40) increases by one per delete; the key is no longer found. | decomp 0x5b830; observed |
| RtlEnumerateGenericTableLikeADirectory | Empty table returns NULL and clears the restart key; with a match routine returning 0 or STATUS_NO_MATCH (0xC0000272) non-matching elements are skipped, NextFlag moves past the restart key, end of table returns NULL; starting key 35 begins at 40. | decomp 0xf7870; observed |
| RtlDelete / RtlDeleteNoSplay | Deterministic hand-built link layouts: single child promoted (parent = self), two children use the in-order predecessor as the new root, leaf removal clears the parent's child pointer and returns the parent, lone root returns NULL (RtlDelete) / root pointer NULL (RtlDeleteNoSplay). | decomp 0x65610 / 0x656b0; observed |
| RtlInterlockedPushEntrySList / PopEntrySList / FlushSList / PushListSList / PushListSListEx | Push and PushList return the previous top; Pop returns the top and decrements the depth; Flush returns the whole chain (top first) and empties the head; depth via RtlQueryDepthSList; empty pop and flush return NULL; PushList adds the supplied count to the depth and links Last->Next to the old top. | decomp 0x69f60, 0xa0c00, 0x701b0, 0xa0cb0, 0xff190; observed |

No skips. Nothing here depends on privilege.

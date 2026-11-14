# RtlTraceDatabase*: Windows 10 contracts

Reference: Corpus Explorer decompilations of RtlTraceDatabaseCreate (rva 0x1027d0), Add (0x102750), Find (0x102a60),
Enumerate (0x102990), Validate (0x102b30), Lock (0x102ae0), Unlock (0x102b10), Destroy (0x102910) and the internals
RtlpTraceDatabaseInternalAdd (0x102c04) / InternalFind (0x102dac) / RtlStackTraceHashFunction (0x102700), ntdll 10.0.19041.2788.
Observed on the Windows 10 22H2 guest (administrator, three runs). The prototypes are the public RTL_TRACE_* ones.

| expectation | source |
|---|---|
| Create with Buckets > 0x100000 returns NULL | Create decompilation: `param_1 < 0x100001` |
| database header: Magic 0xABCDCCCC, Flags = caller flags | 1, Tag | Create decompilation, confirmed by the guest |
| Add with Count > 0x100 returns FALSE and leaves the output untouched | InternalAdd: `param_2 < 0x101` |
| Add stores a copy of the trace in a block: Magic 0xABCDAAAA, UserCount 1, Count, Trace pointer to a copy | InternalAdd decompilation and guest |
| adding an identical trace returns the same block and increments UserCount | InternalAdd found-path |
| Find returns TRUE with the block, FALSE with *Block = NULL; Block may be NULL | InternalFind / Find |
| a custom hash function is called by Add and Find, equal hashes are separated by content | Create stores the hash pointer; InternalFind compares frames |
| Enumerate walks all blocks once, returns FALSE with *Block NULL at the end and for an enum bound to another database | Enumerate decompilation |
| growth over multiple 64 KiB segments (2000 traces of 8 frames) | InternalAdd segment allocation, guest |
| Validate returns TRUE, Destroy returns TRUE | decompilations |
| Lock/Unlock are the database critical section (recursive, blocks other threads) | decompilations (RtlEnterCriticalSection on the database) |

Observed trap, not tested as an assertion: a database created with fewer than 16 buckets faults (integer divide by zero)
on the first Add that stores a new trace (InternalAdd divides by Buckets >> 4), so every test uses at least 16 buckets.
No skips.

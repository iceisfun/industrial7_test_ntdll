# pss_csr_misc_worklist - RtlWow64 cross-process work lists

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), administrator run, 3 tests / 66 checks pass.

These routines are pure lock-free list operations on a caller-provided block, so they are exercised directly.
Layout and behaviour come from decompilation of the five routines and were confirmed by observation (every assertion passed on first run).

* Header word: bits 0-30 offset of first entry, bit 31 heavy-flush request, bits 32-63 sequence (incremented by every successful update, including pops).
* Free list: push stores the previous head offset in the entry (with bit 31 masked) and returns TRUE; pop is LIFO, zeroes the returned entry's link, returns NULL without touching the header when empty; the flush bit is preserved across pushes.
* HeavyFlush: sets bit 31, bumps the sequence, returns TRUE.
* Work list push: links the entry and returns NULL in the out parameter; if a flush is pending the entry is not linked and is handed back in the out parameter (sequence still bumped). Entries with type word 8 whose start equals the head entry's end coalesce: the head entry is handed back for reuse and the new entry spans both ranges.
* PopAll: returns the entries oldest first, resets the header to a bumped sequence with an empty list and no flush, reports the flush bit through the BOOLEAN; on an empty list with no request nothing changes.

std mode: not runnable (guest standard-user logon fails infrastructure-wide); the tests use only private memory.

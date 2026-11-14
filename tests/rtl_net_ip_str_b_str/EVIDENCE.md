# String conversions, GUID strings, string buffers, extended context, RXact, resources

Reference: Windows 10 22H2 ntdll 10.0.19041.2788; checked on the guest (admin). Only ASCII text is converted through
ANSI/OEM so results do not depend on the system code page.

| Export | Asserted / source |
| --- | --- |
| RtlUnicodeStringToAnsiSize/OemSize | WCHAR count + 1 for NUL; these two share one address (decomp: single RVA, also Rtlx aliases). |
| RtlOemStringToUnicodeSize | 2*chars + 2 (decomp). |
| RtlUnicodeStringToCountedOemString, RtlUpcaseUnicodeStringToCountedOemString | allocate mode gives Length == MaximumLength == chars (no NUL); caller buffer exact fit ok, one byte short -> STATUS_BUFFER_OVERFLOW 0x80000005; empty source clears destination; upcase variant uppercases (decomp). |
| RtlUpcaseUnicodeStringToAnsiString / ToOemString | NUL-terminated results (MaximumLength = Length+1), uppercased, no room for NUL -> 0x80000005 (decomp, observed). |
| RtlUpcaseUnicodeToMultiByteN / ToOemN | converted/uppercased length, truncated result 0x80000005 with the number of bytes written, odd byte counts ignore the trailing half char (decomp). |
| RtlUnicodeToCustomCPN / RtlUpcaseUnicodeToCustomCPN | hand-built single-byte CPTABLEINFO (code page 28591 style, identity table, '?' above 255) and a code-page-65001 table which selects the UTF-8 encoder (decomp); overflow 0x80000005, optional result pointer. |
| RtlUnicodeStringToUTF8String | ASCII, 2-/3-/4-byte sequences incl. a surrogate pair, allocated and caller buffers, truncation to Max-1 bytes with STATUS_BUFFER_TOO_SMALL 0xC0000023 (observed; differs from the decompiled constant), zero capacity 0x80000005, empty string (decomp, observed). |
| RtlStringFromGUID / RtlStringFromGUIDEx | `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`, Length 76, MaximumLength 78; caller buffer needs 78 bytes else STATUS_BUFFER_TOO_SMALL 0xC0000023; hex digit case is compared case-insensitively and logged (decomp). |
| RtlMultiAppendUnicodeStringBuffer | appends counted strings after existing content, NUL terminates, MaximumLength = Length+2, keeps the static buffer when it fits, grows to a heap buffer otherwise, total >= 0xffff -> STATUS_NAME_TOO_LONG 0xC0000106 and no change (decomp). |
| RtlInitializeExtendedContext / ...2 | AMD64 context aligned to 16, CONTEXT_EX placed directly after CONTEXT with Legacy/All offsets -sizeof(CONTEXT), no XSTATE area when not requested; invalid flag words rejected (decomp RtlpValidateContextFlags). |
| RtlInitializeRXact | on a throwaway HKCU key: first call STATUS_RXACT_STATE_CREATED 0x40000004, second call 0; invalid root handle fails without writing the context pointer (decomp). |
| RtlInitializeResource | RTL_RESOURCE fields after init (semaphores created, counters zero, debug info set); shared acquire counts up, exclusive acquire sets NumberOfActive -1 and an owner; RtlDeleteResource cleans up (decomp). |

Not covered: RtlInitializeNtUserPfn (hands the NT user function table to the user-mode graphics layer; calling it
replaces process-global state of win32u and can break the test process).

# pss_csr_misc_pss - PssNt* process snapshot routines

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), elevated administrator run; all 7 tests pass (135 checks).

Sources: public PssCaptureSnapshot/PssQuerySnapshot/PssWalkSnapshot documentation for flag and class meaning;
image-level decompilation of the PssNt* routines for validation order and status codes; the remaining values observed on Windows 10.

| Check | Expectation | Source |
|---|---|---|
| Capture flags in mask 0x3ff8000 | STATUS_INVALID_PARAMETER, descriptor stays NULL | decompilation (first test of flags) |
| Flags 0x4000000 | STATUS_INVALID_PARAMETER_MIX (0xC0000030) | decompilation, observed |
| Invalid/NULL process handle | STATUS_INVALID_HANDLE | observed |
| Descriptor NULL (Validate/Free/Query/Walk) | STATUS_INVALID_HANDLE | decompilation, observed. A non-NULL descriptor without the 'PSSD' signature raises an exception and is not tested. |
| Query class 0 (0xF0 bytes) | +8 exit status 0x103, +0x10 PEB, +0x28 pid, +0x30 parent pid, +0x40 creation time (equals GetProcessTimes) | observed, cross-checked with Win32 |
| Query size mismatch | STATUS_INFO_LENGTH_MISMATCH; class > 5 and not 6..9 with wrong length too; negative or 0x7fffffff class STATUS_INVALID_INFO_CLASS | observed + decompilation |
| Query of data not captured | STATUS_NOT_FOUND (0xC0000225) | decompilation, observed |
| Query class 9 (0x28 bytes) with plain flags 0 | elevated administrator: STATUS_NOT_FOUND; standard user (observed on Windows 10 22H2): success, because the descriptor carries internal flag 8 (the decompilation returns NOT_FOUND only without it); mode chosen by TokenElevation | decompilation, observed in both modes |
| Class 5 (threads) | {count, context length}; count equals number of walk entries; context length 0 without thread context flag | observed |
| Thread walk entry (0x88 bytes) | +8 TEB, +0x10 pid, +0x18 tid; ends with STATUS_NO_MORE_ENTRIES (0x8000001A) | observed |
| Aux pages (flag 2) | one page at 0x7ffe0000 (user shared data) | observed |
| VA space (0x800) / handles (0x7c) | query count equals the number of walk entries | observed |
| Walk with NULL entry buffer | observed-only note (0x105); FreeWalkMarker zeroes the marker | decompilation (marker freed) |
| VA clone (flag 1) | class 1 returns a process handle of another process; closed by FreeSnapshot | observed |
| Performance counters (flag 0x40000000) | zero without the flag, nonzero total with it | observed |
| Duplicate local->local | new descriptor, same process data; flag 1 (close source) releases the source descriptor | observed (using the source afterwards faults) |
| Duplicate into another process / FreeRemoteSnapshot | success, second free and bogus pointer give STATUS_PARTIAL_COPY (0x8000000D) | observed |

Skips: none expected. Standard-user mode also passes all 7 tests (135 checks). No privileged operation is used (self capture, own child).

Justified uncovered: none of the 8 PssNt exports; the invalid-signature exception path of PssNtValidateDescriptor is not exercised.

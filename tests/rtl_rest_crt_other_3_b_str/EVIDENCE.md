# CRT string, memory, tokenizer and path exports

Reference: Windows 10 22H2 ntdll 10.0.19041.2788 (administrator and standard user guests).

| Export | Asserted / source |
| --- | --- |
| _wcslwr, _wcsupr, _wcslwr_s, _wcsupr_s | ASCII letters are mapped; code points above 0x7f (Latin-1 0xe9/0xc9, Greek) are left unchanged (observed, surprising versus the Unicode mapping). |
| _wcsnicmp | ASCII case-insensitive, count limit, stops at NUL, sign of the difference; no Latin-1 folding (observed). |
| _wcsset_s, _wcsnset_s | fill to terminator / count, never past the terminator; NULL, size 0, count 0 is valid (decomp 0x8df20). |
| strncpy_s, strncat_s, wcsncpy_s, wcsncat_s | count limits, count 0, exact fit, _TRUNCATE (-1) truncation returns STRUNCATE (80) with terminator (observed, CRT documentation). |
| strtok_s, wcstok_s | leading delimiters skipped, successive calls with NULL and the context pointer, exhaustion returns NULL (observed, CRT documentation). |
| memcpy | all sizes 0..32 and a 70000 byte block with unaligned source and destination (observed). |
| memcpy_s, memmove_s | successful copies, forward/backward overlap for memmove_s, zero count with NULL pointers (observed). Error returns are not driven (invalid-parameter routine). |
| _wmakepath_s | drive colon, directory trailing separator and extension dot are added when missing; empty parts; exact-fit buffer (observed). |
| _wsplitpath_s | drive, directory, file name and extension split; last dot starts the extension; UNC paths have no drive; omitted components with NULL/0; exact-fit buffers (decomp 0x97220, observed). |

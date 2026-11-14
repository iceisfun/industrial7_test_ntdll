# Locale, normalization, NT path and resource-string helpers: Windows 10 contracts

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). Decompilations from the Corpus Explorer
(`http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp`) fixed the validation order;
output values were observed on the Windows 10 guest.

| Export | Source | Checked |
| --- | --- | --- |
| RtlLcidToLocaleName | decomp 0x3b2f0: LCID 0 / 0x1000 gives 0xC00000EF before anything else, NULL output 0xC00000F0, flags other than 0 or 2 gives 0xC00000F1, no buffer without the allocate flag 0xC00000F0, unknown LCID 0xC00000EF, neutral LCIDs only with flag 2 | Seven fixed LCIDs, allocated output, every error path |
| RtlLCIDToCultureName | decomp 0x3b020 (BOOLEAN, falls through to RtlLcidToLocaleName with flag 2) | en-US, de-DE, neutral en, 0, 0x1000, NULL, unknown, too-small buffer |
| RtlLocaleNameToLcid | decomp 0x3ba90: NULL name 0xC00000EF, NULL output 0xC00000F0, flags above 3 0xC00000F1, unknown name 0xC00000EF, neutral names need flag 2; empty name is the invariant locale (0x7F, observed) | Names, case-insensitive match, round trip |
| RtlNormalizeString | decomp 0x80230: form 0 / NULL source / length < -1 / negative output length 0xC000000D; output length is an upper-bound estimate when the buffer is too small (observed: e.g. 3 per input character), so only a lower bound is asserted | NFC, NFD, NFKC, NFKD vectors (composition, singleton, ligature, hangul, canonical reordering), explicit and -1 lengths, error paths |
| RtlNtPathNameToDosPathName | decomp 0xcc4c0: flags must be 0; `\??\` prefix stripped (type 3), `\??\UNC\` replaced by `\\` (type 2); other names are classified (4 absolute drive / UNC / device, 1 relative); type output cleared first | Table of prefix cases, classification cases, error paths, long name stripped in place |
| RtlNtdllName | data export: a pointer to the wide string `ntdll.dll` (observed layout) | String compare |
| RtlReplaceSystemDirectoryInPath | decomp 0x87110 + helper 0x871bc: machine id 1 = System32, 0x14c = SysWOW64, 0x1c4 = SysARM32, 0x3a64 = SyCHPE32, others 0xC000000D (target checked first); identical ids return 0 without examining anything; first case-insensitive occurrence replaced; flag nonzero requires `\Name\` delimiters | Directory swap in both directions, ARM and CHPE names, case-insensitive match, first occurrence only, flag variants, errors |
| RtlLoadString | decomp 0x46fa0: NULL module / NULL output / flags above 1 0xC000000D, flags 1 with extra pointers 0xC00000BB; success: string id mapped to block `(id>>4)+1`, entry `id & 15` | First string found in user32 compared with LoadStringW; missing block fails |

The loader-image mode (flags 1) and the extra output parameters are not exercised beyond the 0xC00000BB check.

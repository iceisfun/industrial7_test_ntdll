# RTL path and atom getters: Windows 10 contracts

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). Decompilation from the corpus explorer
(`/api/function/ntdll/<Name>/decomp`) was used for argument validation order; the Windows 10 guest run
(administrator and standard user) is the authority.

| Export (RVA) | Contract asserted | Source |
| --- | --- | --- |
| RtlGetFullPathName_UEx (0x1d800) | `(Name, BufferBytes, Buffer, FilePart, &BytesNeeded)`: success writes the normalized path (dot segments, duplicate separators collapsed) and its byte length (no NUL); a trailing separator gives a NULL file part; when the buffer is too small the status is still 0 and the output is the required size **including** the NUL (observed); empty name returns 0xC0000033 and zero length | decomp, observed |
| RtlGetFullPathName_UstrEx (0x1d890) | static buffer used when large enough (`StringUsed` = static string, `FilePartPrefixCch` set, path type 2 for `C:\`); too small static buffer with a dynamic string: dynamic buffer allocated and returned in `StringUsed`; no dynamic string: 0xC0000023 and the required size (the unnormalized input length plus NUL); dynamic string without `StringUsed`: 0xC000000D; empty input 0xC0000033. The path type pointer is dereferenced unconditionally and must be non-NULL | decomp (offset `*param_7`), observed access violation with NULL (not asserted) |
| RtlGetLengthWithoutTrailingPathSeperators (0x85a70) | flags must be 0, both pointers required (0xC000000D, length zeroed); trailing `\` and `/` stripped; counts in WCHARs | decomp |
| RtlGetLengthWithoutLastFullDosOrNtPathElement (0x778b0) | WCHAR length of the parent including one trailing separator (`C:\a\b` -> 5, `C:\a` -> 3, `C:\` -> 0, `\\?\C:\a\b` -> 9); empty string 0; nonzero flags or NULL pointers 0xC000000D | decomp (RtlpGetLengthWithoutLastPathElement), observed |
| RtlGetSearchPath (0x83a30) | status 0, cached pointer (second call identical) containing the system directory | decomp, observed |
| RtlGetExePath (0x823b0) | application directory first, then `.`, then system directories; with `NoDefaultCurrentDirectoryInExePath` set the bare-name result omits the current directory | decomp, observed |
| RtlGetIntegerAtom (0x4c910) | `MAKEINTATOM` values 1..0xBFFF pass through, 0 maps to 0xC000, >= 0xC000 rejected; `#n` strings accepted when all digits (n in 1..49152 literal, other values clamp to 0xC000), non-digits and `#` alone rejected; the atom output is optional and untouched on failure | decomp, observed |

Skips: none.

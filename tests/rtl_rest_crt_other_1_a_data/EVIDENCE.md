# Digests, NLS data, prefix tables, bitmaps, access helpers, code-page and CM resource helpers

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). Every test passes on the guest in administrator and
standard-user modes. Function behavior was read from the decompilation of the pinned module
(`/api/function/ntdll/<Name>/decomp`) and then confirmed by running on the guest.

| Export | Expectation | Source |
| --- | --- | --- |
| MD5Init / MD5Update / MD5Final | Context layout `{ULONG i[2]; ULONG buf[4]; UCHAR in[64]; UCHAR digest[16]}`; Init zeroes the bit count and loads the RFC 1321 constants; Final writes the digest at +0x58 and wipes the input block. Vectors: RFC 1321 test suite plus the "quick brown fox" string and one million 'a'. Split updates, a zero-length update and an unaligned source give the same digest. The bit count after Final includes padding, so it is not asserted. | RFC 1321; decomp MD5Init 0x7d720, MD5Update 0x5bef0, MD5Final 0x5be20 |
| MD4Init / MD4Update / MD4Final | Layout `{ULONG buf[4]; ULONG i[2]; UCHAR in[64]; UCHAR digest[16]}` (state first, unlike MD5). Vectors from RFC 1320. | RFC 1320; decomp MD4Init 0x10fe50, MD4Final 0x10fd80 |
| A_SHAInit / A_SHAUpdate / A_SHAFinal | SHA-1: layout `{UCHAR buffer[64]; ULONG state[5]; ULONG countHi; ULONG countLo}`; Update advances the byte count; Final writes 20 big-endian bytes, wipes the buffer and re-arms the state to the initial vector (a second message can be hashed without Init). Vectors from FIPS 180 plus million 'a'. | FIPS 180-4; decomp A_SHAInit 0x410b0, A_SHAFinal 0x40280 |
| NlsAnsiCodePage, NlsMbCodePageTag, NlsMbOemCodePageTag | Data exports: the ANSI code page equals GetACP(); the DBCS tags are TRUE exactly when the ANSI/OEM code page has MaxCharSize > 1 (GetCPInfo). Skipped for a UTF-8 ACP. | Observed on Windows 10; name-based public meaning |
| PfxInitialize / PfxInsertPrefix / PfxFindPrefix / PfxRemovePrefix | Table `{USHORT code=0x200; USHORT nameLength=0; PVOID next=table}` after Init; entries are 0x30 bytes, `NameLength` is the character count with the leading backslash counted as a component (so "\\a" is 2 and "\\a\\b" is 3), the prefix pointer is stored at +0x28. Insert returns FALSE for a duplicate prefix; Find returns the entry with the longest matching prefix on a component boundary, case sensitive, NULL otherwise; Remove unlinks. | decomp PfxInitialize 0xe60e0, PfxInsertPrefix 0xe6100, PfxFindPrefix 0xe6000, PfxRemovePrefix 0xe6220; NameLength values observed on the guest |
| RtlAreBitsClearEx, RtlClearAllBitsEx, RtlClearBitEx, RtlClearBitsEx | 64-bit bitmap `{ULONG64 SizeOfBitMap; PULONG64 Buffer}`. Clear single bits, ranges inside a word, across a word boundary and over several words; AreBitsClear is FALSE for start >= size, run past the end and zero length. ClearAllBits clears whole 32-bit units (ceil(size/32)*4 bytes; for 200 bits, 28 bytes, so the last four bytes of a 32-byte buffer are untouched). | decomp 0xeb830, 0xeb8f0, 0xeb920, 0xeb930 |
| RtlClearBit | 32-bit bitmap clear of one bit, idempotent. | decomp 0x9c7d0 |
| RtlAreAllAccessesGranted / RtlAreAnyAccessesGranted | `(desired & ~granted) == 0` and `(desired & granted) != 0`. | decomp 0x7c340, 0xe63a0 |
| RtlAreLongPathsEnabled | Returns bit 7 of PEB byte 3 (long-path-aware flag); asserted equal to that PEB bit. | decomp 0x752b0 |
| RtlCustomCPToUnicodeN | CodePage 65001 in the table header selects the UTF-8 path (an output buffer that is too small is reported as STATUS_BUFFER_OVERFLOW 0x80000005); otherwise the single-byte `MultiByteTable` is used. Output count is `bytes written`, truncation reports 0x80000005 with the partial count. | decomp 0xe5190 |
| RtlConsoleMultiByteToUnicodeN | Single-byte ACP path: SpecialChar is set when any input byte is below 0x20; truncation to the output size is reported through the byte count with status 0. Skipped for a UTF-8 ACP. | decomp 0xe5020 |
| RtlCmEncodeMemIoResource / RtlCmDecodeMemIoResource | Type 1 (port) and 3 (memory) store a 32-bit length; larger memory lengths use type 7 with a scale flag (0x200 = 2^8, 0x400 = 2^16, 0x800 = 2^32) and fail with STATUS_UNSUCCESSFUL (0xC0000001) when not a multiple of the scale; port lengths above 32 bits and unsupported types give STATUS_INVALID_PARAMETER (0xC000000D). Decode reverses the scaling and returns the start address through the optional pointer. | decomp 0xf1f00, 0xf1e90 |

Notes: all digest vectors and the million-'a' values are public published reference values.
Skips: UTF-8 ACP guests (not present in the validation guest). Nothing is observed-only except the
Pfx `NameLength` numbers.

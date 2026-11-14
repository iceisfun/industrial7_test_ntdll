# CRT math, wide ctype and jump exports

Reference: Windows 10 22H2 ntdll 10.0.19041.2788 (administrator and standard user guests).

| Export | Asserted / source |
| --- | --- |
| sin, cos, tan, atan, atan2 | exact values at 0, relative tolerance 1e-12 elsewhere, quadrants and signed zeros for atan2, infinities, NaN results (C99 Annex F / observed). |
| sqrt, pow, log | exact squares, special values (negative -> NaN, pow(0,-1) -> inf, overflow/underflow, log(0) -> -inf), tolerance for transcendental results (observed). |
| ceil, floor, fabs | exact, negative zero, huge and fractional values at the 2^51 boundary, infinities, NaN (observed). |
| iswalnum, iswalpha, iswascii, iswdigit, iswgraph, iswlower, iswprint, iswspace, iswxdigit | whole ASCII range against the ctype definition. iswprint is built from the BLANK|PUNCT|ALPHA|DIGIT bits so TAB is "printable"; 0xb2 is a digit, 0xa0 is a space (observed). |
| iswctype | table lookup for code points below 0x100, mask bits _UPPER 1, _LOWER 2, _DIGIT 4, _SPACE 8, _PUNCT 0x10, _CONTROL 0x20, _BLANK 0x40, _HEX 0x80, _ALPHA 0x100; returns 0 at and above 0x100 (decomp RVA 0x8fcb0). |
| towlower, towupper | ASCII and Latin-1 mapping; towupper also maps above Latin-1 (0x3b1 -> 0x391, 0xff -> 0x178, 0x101 -> 0x100) while towlower(0x391) is unchanged (observed). |
| longjmp (with _setjmp) | _setjmp with a zero frame followed by longjmp restores the registers and returns the supplied value, 0 becomes 1 (observed; longjmp RVA 0x8ffc0 validates the buffer then restores via __longjmp_internal). |

# CRT number/string conversion exports

Reference: Windows 10 22H2 ntdll 10.0.19041.2788, run on the guest as administrator and as a standard user.
Only ASCII text is converted through the multibyte routines so results do not depend on the ANSI code page.

| Export | Asserted / source |
| --- | --- |
| _ultoa, _ultow | radix 2..36, lower-case digits, returns the destination, no write past the terminator (observed). |
| _ultoa_s, _ultow_s | return 0, exact-fit buffer (strlen+1) succeeds and nothing beyond is touched (observed). Undersized buffers are not driven: they enter the invalid-parameter routine. |
| _wcstoi64, _wcstoui64 | whitespace/sign skipping, base 0 prefix detection (0x, leading 0), bases 2/16/36, endptr (start when no digits), clamping to the 64-bit limits, unsigned negation of "-1" (observed). |
| _wtoi, _wtol, _wtoi64 | whitespace, sign, trailing junk, empty string, 32/64-bit extremes (observed). |
| wcstol, wcstoul, strtol, strtoul | as above for 32-bit; overflow clamps to LONG_MAX/LONG_MIN/ULONG_MAX and sets errno to 34 (ERANGE); success leaves errno untouched (observed). |
| atoi, atol | whitespace, sign, junk, empty (observed). They are separate routines (distinct addresses), so no alias is asserted. |
| mbstowcs | length query with NULL destination; truncation returns the requested count without terminator; exact-fit leaves no terminator (observed). |
| wcstombs | decompilation: converts the source including its terminator and returns bytes written minus one. Hence a truncated conversion of "world" into 3 bytes returns 2 with three bytes written, 5 bytes returns 4, 6 bytes returns 5 and terminates; NULL destination returns the length (decomp RVA 0x92460, confirmed on the guest). |

Not driven: invalid-parameter paths of the *_s functions.

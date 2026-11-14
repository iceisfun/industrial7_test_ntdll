# RTL strings, names, addresses and messages: Windows 10 contracts

Reference: ntdll 10.0.19041.2788. Decompilation and disassembly were read from the corpus explorer
(function `/decomp` and `/asm`); every expectation was then confirmed on a Windows 10 22H2 guest (elevated
administrator and standard user). Where the guest result differs from a first reading of the decompilation the
guest result is what is asserted; those cases are listed under "Observed".

## Sources per export

| Export (RVA) | Contract asserted | Source |
| --- | --- | --- |
| RtlEthernetAddressToStringA/W (0xfbdd0 / 0xfbe40) | `%02X-%02X-%02X-%02X-%02X-%02X`, 17 characters, returns a pointer to the terminating NUL | decompilation (sprintf_s format), guest |
| RtlEthernetStringToAddressA/W (0xfbeb0 / 0xfbff0) | exactly two hex digits per group, `-` or `:` separators, six groups; trailing text is accepted and reported through the terminator pointer; 1 or 3 digits, 5 or 7 groups, trailing separator, non-hex: STATUS_INVALID_PARAMETER and the output is not written | decompilation, guest |
| RtlGUIDFromString (0x69a90) | `{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}` scanned over `Length` characters, hex case-insensitive, any mismatch STATUS_INVALID_PARAMETER | decompilation, guest |
| RtlInt64ToUnicodeString (0xeda30) | unsigned conversion in base 2..16 (0 means 10), upper-case digits, terminator written when it fits; unsupported base STATUS_INVALID_PARAMETER with the string untouched; too small buffer STATUS_BUFFER_OVERFLOW | decompilation (calls RtlLargeIntegerToChar and RtlAnsiStringToUnicodeString), guest |
| RtlDowncaseUnicodeString (0x7bd70) | per-character NLS lower casing, `Length` copied, no terminator; STATUS_BUFFER_OVERFLOW (0x80000005) when `MaximumLength` is below the source length, destination untouched; allocate mode returns a heap buffer freed with RtlFreeUnicodeString | decompilation, guest |
| RtlEraseUnicodeString (0x85c80) | zeroes `MaximumLength` bytes and sets `Length` to 0; no effect when Buffer is NULL or MaximumLength is 0 | decompilation, guest |
| RtlDoesNameContainWildCards (0xfb460) | only the last path component (after the final backslash) is scanned; `* ? < > "` are wildcards; `Length` bounds the scan | decompilation (character class table), guest |
| RtlDoesFileExists_U (0x85c20) | attribute query by DOS path: file, directory and open-exclusive file exist, wildcards and missing paths do not | decompilation (wrapper over RtlDoesFileExists_UEx), guest |
| RtlExpandEnvironmentStrings (0x15630) | lengths in characters, `ReturnLength` includes the terminator and is reported even when the destination is too small (STATUS_BUFFER_TOO_SMALL); unknown variables and unmatched `%` copied verbatim; names case-insensitive; NULL environment means the process block | decompilation, guest |
| RtlIdnToAscii / RtlIdnToUnicode / RtlIdnToNameprepUnicode (0xd0c0 / 0xc6f0 / 0xfee90) | punycode conversion (`bücher.de` <-> `xn--bcher-kva.de`), NUL-terminated input with length -1, output length includes the terminator, size query with a NULL destination and `*DstLen` 0, STATUS_BUFFER_TOO_SMALL, undefined flag bits / NULL source / NULL length / negative length STATUS_INVALID_PARAMETER | decompilation of the workers (RtlpNameprepAsciiWorker, RtlpIdnToUnicodeWorker), guest |
| RtlDnsHostNameToComputerName (0x60b30) | first label up-cased and converted to the OEM code page, at most 15 characters (longer labels are truncated), empty first label or empty input STATUS_INVALID_COMPUTER_NAME (0xC0000122), caller-buffer and allocate modes | decompilation, guest |
| RtlFormatMessage / RtlFormatMessageEx (0xfc550 / 0x65d40) | `%n` inserts (string and `!printf!` forms), `%%`, `%n` CRLF, `%r`, `%t`, `%b`, `%.`, `%!`, `%0`, source line breaks (CRLF, or a space when a width is given), ignore-inserts mode, `ReturnLength` in bytes including the terminator, STATUS_BUFFER_OVERFLOW on a short buffer, trailing `%` STATUS_INVALID_PARAMETER; Ex with a NULL context behaves like the plain form (the plain export is a wrapper) | decompilation, guest |
| RtlIncrementCorrelationVector (0x838d0) | increments the last dotted component in place; version 1 vectors may grow to 63 characters and version 2 vectors to 127, otherwise STATUS_BUFFER_OVERFLOW with the vector unchanged; unknown version or no separator STATUS_BUFFER_OVERFLOW | decompilation, boundaries found on the guest |
| RtlDeriveCapabilitySidsFromName (0x1fd40) | group SID S-1-5-32-h0..h7 and capability SID S-1-15-3-1024-h0..h7 where h is SHA-256 of the upper-cased UTF-16LE name (the test carries its own SHA-256); the twelve legacy capability names map to S-1-15-3-1..12; NULL arguments fast-fail and are not tested | decompilation (RtlUpcaseUnicodeString, SHA256Update/Final, legacy name table), guest |

## Observed (guest differs from, or adds to, the decompilation)

* RtlDnsHostNameToComputerName truncates a 16 character first label to the first 15 characters and succeeds; only an
  empty first label fails.
* RtlIdnToNameprepUnicode leaves pure ASCII upper case unchanged (`Example.COM` stays as is, a NOTE only); non-ASCII
  input such as `BÜCHER.DE` is case-folded.
* RtlIdnToAscii with a NULL destination and `*DstLen` 0 returns success and the required size (17).
* Correlation vector limits are 63 and 127 characters (probed on the guest).

## Skips and status codes

No skips. Status codes used: 0, 0x80000005 (BUFFER_OVERFLOW), 0xC000000D (INVALID_PARAMETER), 0xC0000023
(BUFFER_TOO_SMALL), 0xC0000122 (INVALID_COMPUTER_NAME). Nothing depends on privilege or locale: the OEM conversion
cases use ASCII only, the IDN cases use U+00FC/U+00DC.

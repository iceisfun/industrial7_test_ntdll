# rtl_numeric evidence

Reference read on 2026-10-31: Windows 10 x64 corpus, ntdll reference image.
Corpus instructions: http://docker1.dev.moonlightcompanies.com:8765/SKILL.md
All corpus requests were serial, with exponential retry on HTTP 503. Tests are
independently written; Wine observations are not expectation sources.

## Verified implementation branches

The following URLs were actually read (the `/docs` sibling was also read for
each function). RVA identifies the implementation, not necessarily an export.

| API and decomp URL | Verified branch/contract exercised |
| --- | --- |
| [RtlCharToInteger, 0x75b60](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCharToInteger/decomp) | Bases 0/2/8/10/16; initial whitespace and sign; lowercase auto-prefixes; digit range checks stop scanning; unsigned 32-bit accumulation wraps; invalid base returns C000000D before writing output. |
| [RtlUnicodeStringToInteger, 0x755d0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlUnicodeStringToInteger/decomp) | Rejects zero/odd byte Length; scans a counted UTF-16 buffer; embedded NUL stops; same digit/base/sign branches; invalid base and invalid length go through a common output write of zero and C000000D. |
| [RtlIntegerToChar, 0x163a0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlIntegerToChar/decomp) | Uppercase digit alphabet; unsigned ULONG; base zero means decimal; insufficient capacity returns 80000005 without copying; exact digit capacity succeeds without NUL, larger capacity appends NUL. |
| [RtlIntegerToUnicodeString, 0x164a0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlIntegerToUnicodeString/decomp) | Calls IntegerToChar with a 33-byte temporary buffer then nonallocating AnsiStringToUnicodeString. Invalid base returns before changing the destination. |
| [RtlAnsiStringToUnicodeString, 0x19580](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAnsiStringToUnicodeString/decomp) | ASCII formatting output is converted into caller memory; sets byte Length before checking MaximumLength against Length+2; too-small buffer returns 80000005 without copying. Sufficient buffer appends UTF-16 NUL. |
| [RtlLargeIntegerToChar, 0x1010](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlLargeIntegerToChar/decomp) | Unsigned 64-bit interpretation (including high bit); same base validation, uppercase alphabet, capacity and termination branches. |
| [abs/labs, 0x8e410](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/abs/decomp) | Same entry RVA, signed 32-bit sign-mask absolute value. Only representable results tested; INT_MIN deliberately omitted. [labs URL](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/labs/decomp) also read. |

Full documentation bodies actually read:

- http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/winternl/nf-winternl-rtlchartointeger.md
- http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/wdm/nf-wdm-rtlunicodestringtointeger.md
- http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/wdm/nf-wdm-rtlintegertounicodestring.md

The Unicode parser documentation independently specifies empty-string failure
and the prefix/sign/termination rules. The formatter documentation lists valid
bases and STATUS_BUFFER_OVERFLOW. The corpus `/docs` match for `abs` is an HLSL
page: this is a false semantic match and was NOT used as a CRT contract.

## x64 export gaps

Actually queried:

- http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntdll/exports?q=swap — total 0.
- http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntdll/exports?q=divide — total 0.
- http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntdll/exports?q=mul — 22 entries, none of the legacy integer multiply routines.
- http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntdll/exports?q=abs — `abs` and `labs` both RVA 582672.

`/docs` and `/decomp` queries returned symbol-not-found for RtlUshortByteSwap,
RtlUlongByteSwap, RtlUlonglongByteSwap, _byteswap_ushort, _byteswap_ulong,
_byteswap_uint64, RtlEnlargedIntegerMultiply, RtlEnlargedUnsignedMultiply,
RtlExtendedIntegerMultiply and RtlExtendedLargeIntegerDivide. The three
Rtl byte-swap probes REQUIRE the names and skip; they do not call undocumented
unexpected exports or pretend to test compiler intrinsics. Corpus
`/api/docs/for-symbol?name=RtlUshortByteSwap&limit=2` and corresponding Ulong/
Ulonglong queries identify driver macro documentation, not x64 ntdll exports.

RtlExtendedMagicDivide exists internally at 0x7adc0, but the export query finds
no divide exports. Its decompilation was read, but it is not called by address.
`fabs` decompilation was also read; floating-point control/exception branches
are out of scope. Arithmetic coverage therefore uses exported `abs`/`labs`.

## Build and smoke

`make build/rtl_numeric.exe` succeeds without warnings. Objdump import inspection
shows only KERNEL32.dll and msvcrt.dll, no static ntdll imports. Every ntdll call
uses UDECL+UN and a preceding REQUIRE; only bounded caller-owned buffers used.

Command: `TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_numeric.exe > /tmp/opencode/ntdll_rtl_numeric.log 2>&1`

Final log line: `SUMMARY tests=71 failed=2 skipped=3 checks_pass=449 checks_fail=12`.
Exit code 1. The 3 skips are unavailable byte-swap exports. Remaining failures:

- `rtl_numeric_unicode_invalid_lengths`: Wine returns success for zero/odd
  lengths, and returns 1 for a 3-byte length. Windows decomp rejects both.
- `rtl_numeric_invalid_bases`: Wine leaves Unicode output at 0x12345678 for
  each of 9 invalid bases; Windows decomp writes zero. Status checks pass.

Initial NTSTATUS comparisons accidentally mixed signed/unsigned widths in
EXPECT_EQ; fixed by casting expected error constants to NTSTATUS and rerun.
No Wine-specific suppression was added. Native Windows execution remains
unperformed; malformed negative widths, non-ASCII locale behavior, and legacy
nonexported arithmetic are intentionally not asserted.

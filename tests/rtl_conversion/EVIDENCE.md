# Windows conversion contracts

Authority: Windows 10 corpus at
`http://docker1.dev.moonlightcompanies.com:8765`, queried serially on 2026-10-31
after `/SKILL.md`. For each API below read both
`/api/function/ntdll/<Name>/decomp` and `/docs`. Docs listings are discovery;
hard assertions use the actual Windows implementation. Scratch responses live
in `/tmp/opencode/ntdll_strings_corpus/`, not needed for builds.

## APIs and inspected branches

- `RtlMultiByteToUnicodeN`: clamps output to capacity/2 units, writes optional
  byte count, no terminator, returns success even with truncation.
- `RtlUnicodeToMultiByteN`: analogous byte-output clamp, success on truncation.
- `RtlOemToUnicodeN`: capacity/2 versus input bytes; insufficient capacity
  returns 0x80000005, count reports actual output. Odd capacity rounds down.
- `RtlUnicodeToOemN`: capacity bytes versus input UTF-16 units; insufficient
  capacity returns 0x80000005, count reports actual output.
- `RtlMultiByteToUnicodeSize`, `RtlUnicodeToMultiByteSize`: counted sizes,
  embedded NUL retained, no implicit termination. Tests constrain ANSI/OEM
  input to ASCII to avoid active-code-page assumptions.
- `RtlAnsiStringToUnicodeString`, `RtlOemStringToUnicodeString`: set output
  Length to required data bytes before capacity validation, require two more
  bytes for termination; short buffer returns 0x80000005 without copying.
  Allocation maximum includes terminator; successful output is terminated.
- `RtlUnicodeStringToAnsiString`: reserves one byte for termination; on short
  nonzero capacity changes Length to MaximumLength-1, converts that prefix and
  terminates, returning 0x80000005. Zero capacity returns without copying,
  after setting required Length.
- `RtlUnicodeStringToOemString`: unlike ANSI, short capacity returns
  0x80000005 without partial copying and retains required data Length.
- `RtlFreeUnicodeString`, `RtlFreeAnsiString`: free and zero non-NULL allocated
  descriptor. `RtlFreeOemString`: frees buffer but does not zero descriptor;
  tests never reuse/double-free that dangling descriptor.
- `RtlUTF8ToUnicodeN`: NULL destination with count queries required bytes;
  counted ASCII/NUL, 2/3-byte UTF-8 and supplementary pairs; insufficient
  capacity returns 0xc0000023 with actual written bytes. Incomplete final
  sequence emits U+FFFD and 0x107.
- `RtlUnicodeToUTF8N`: NULL destination queries size; explicit UTF-8 arithmetic
  for 1/2/3/4-byte sequences and surrogate pairs. A nonfitting next character
  is not partially emitted; returns 0xc0000023 and written byte count. Odd
  source byte count returns 0xc00000f3 before touching output/count. Lone
  surrogate emits EF BF BD with status 0x107.

## Assembly corroboration of Wine differences

Also read `/asm` for `RtlOemToUnicodeN`, `RtlUnicodeToOemN`, and
`RtlUnicodeStringToOemString`:

- OEM decode VA 0x18006118e: `cmp r11d,edx; sbb eax,eax; and eax,0x80000005`
  compares output-unit capacity against original input bytes (SBCS branch).
- OEM encode VA 0x1800610e4: same instructions compare output-byte capacity
  against source-unit count (SBCS branch).
- OEM descriptor VA 0x180060cea compares required data Length with maximum;
  `jae 0x1800bdeba` returns 0x80000005 without conversion.

## Validation and gaps

`make build/rtl_conversion.exe` succeeds without warnings. Run:

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_conversion.exe > /tmp/opencode/ntdll_rtl_conversion.log 2>&1
```

Wine: 71 tests, 8 failed, 0 skipped; 291 passing checks, 9 failing checks.
Seven raw OEM truncation tests return Wine success instead of Windows overflow.
One OEM descriptor exact-data-capacity test truncates/copies under Wine,
instead of preserving required Length and untouched buffer. These verified
deviations remain hard failures.

No native Windows execution was available. DBCS/high-byte ANSI/OEM mappings,
active-UTF8 process setup, full invalid-UTF8 taxonomy and supplementary decode
truncation within the surrogate pair are not asserted. No global NLS state is
changed; no allocation failures are forced. NTSTATUS is checked rather than
Win32 last-error (these APIs have no last-error contract).

# Windows string contracts

Authority: Windows 10 corpus, ntdll 19041 family, queried 2026-10-31 at
`http://docker1.dev.moonlightcompanies.com:8765` after reading `/SKILL.md`.
For every API below, queried `/api/function/ntdll/<Name>/decomp` and `/docs`,
serially. Docs indexes are discovery only; assertions below use the actual
Windows decompiled implementation, not Wine. Scratch responses are in
`/tmp/opencode/ntdll_strings_corpus/` (not required to build).

## APIs and inspected branches

- `RtlInitAnsiString`: NULL zeroes lengths; non-NULL aliases source, scans to
  first NUL, clamps length to 0xfffe, maximum is length+1.
- `RtlInitUnicodeString`: equivalent byte lengths, clamp 0xfffc, maximum+2.
- `RtlInitUnicodeStringEx`: clears descriptor lengths before scan; length
  above 0x7ffe characters returns 0xc0000106 while retaining source pointer.
- `RtlCopyString`: min(source Length, destination MaximumLength), no terminator;
  NULL source clears only Length.
- `RtlCopyUnicodeString`: same minimum, terminator only if two bytes remain;
  NULL source clears Length without writing the buffer.
- `RtlAppendStringToString`, `RtlAppendUnicodeStringToString`: empty source
  bypasses copying; capacity below combined lengths returns 0xc0000023 without
  mutation. Exact data capacity succeeds. ANSI never terminates; Unicode
  terminates when combined Length+2 fits, except the empty-source bypass.
- `RtlAppendUnicodeToString`: counts a terminated source; same capacity
  comparison, but even empty non-NULL input reaches optional terminator store.
- `RtlCompareString`, `RtlCompareUnicodeString`: mismatch returns unsigned
  character subtraction; common-prefix return is byte-count difference for
  ANSI, character-count difference for Unicode. Case-insensitive ASCII uses
  uppercase. Lengths, not embedded NUL, delimit comparison.
- `RtlEqualString`, `RtlEqualUnicodeString`: lengths must match; compare all
  counted elements, optional uppercase folding.
- `RtlPrefixString`, `RtlPrefixUnicodeString`: first length must not exceed
  second; empty prefix succeeds; optional case folding.
- `RtlFindCharInUnicodeString`: output is zeroed before flag validation;
  flags outside 7 return 0xc000000d; bit 0 reverse, bit 1 complement,
  bit 2 case-insensitive; not-found 0xc0000225. Forward offsets include the
  matched character (index+1)*2; reverse offsets are index*2.
- `RtlUpcaseUnicodeChar`, `RtlDowncaseUnicodeChar`: explicit ASCII ranges;
  non-ASCII mapping depends on NLS tables and is not asserted.
- `RtlUpcaseUnicodeString`: short nonallocating buffer returns 0x80000005
  before changing Length/data; successful conversion copies counted units,
  sets Length and does not add a terminator. Allocation maximum equals Length.
- `RtlHashUnicodeString`: algorithm 0/1 uses h*0x1003f+character, modulo 32
  bits; optional uppercase; writes output zero before rejecting algorithm>=2.
- `RtlDuplicateUnicodeString`: rejects flags outside 3 or exactly 2;
  flag 1 adds termination; empty source allocates only for flags 3;
  otherwise maximum equals source bytes plus requested terminator.
- `RtlFreeUnicodeString` (same entry as `RtlFreeAnsiString`): non-NULL
  allocation freed, descriptor's first eight bytes and pointer cleared.

Additional `/asm` queries: `RtlFindCharInUnicodeString` and
`RtlInitUnicodeStringEx` (objdump flavor), confirming flag test/output ordering
and initial zero stores. `RtlHashUnicodeString/asm` returned HTTP 404 (also
objdump flavor); its decompilation is available and is the hash authority.

## Validation and uncertainties

`make build/rtl_strings.exe` succeeds without warnings. Run only with:

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_strings.exe > /tmp/opencode/ntdll_rtl_strings.log 2>&1
```

Wine: 60 tests, 4 failed, 0 skipped; 558 passing checks, 7 failing checks.
Retained Windows-verified deviations:

- Invalid hash algorithm leaves Wine output sentinel instead of Windows zero.
- Find flag 4 fails to find ASCII case-insensitive match; flag 8 returns
  not-found instead of invalid-parameter; both leave Wine output sentinel.
- Oversize InitUnicodeStringEx leaves Wine's earlier lengths instead of zero.

No native Windows execution was available. No locale-specific non-ASCII case
tables, maximum ANSI scan, malformed descriptor matrices, or allocation-failure
injection is covered. No arbitrary pointer inputs or exhausted resources.

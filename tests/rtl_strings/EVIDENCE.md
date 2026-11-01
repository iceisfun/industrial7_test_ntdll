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

Initial writer run: Wine 60 tests, 4 failed, 0 skipped; 558 passing checks,
7 failing checks.
Retained Windows-verified deviations:

- Invalid hash algorithm leaves Wine output sentinel instead of Windows zero.
- Find flag 4 fails to find ASCII case-insensitive match; flag 8 returns
  not-found instead of invalid-parameter; both leave Wine output sentinel.
- Oversize InitUnicodeStringEx leaves Wine's earlier lengths instead of zero.

No native Windows execution was available. No locale-specific non-ASCII case
tables, maximum ANSI scan, malformed descriptor matrices, or allocation-failure
injection is covered. No arbitrary pointer inputs or exhausted resources.

## Independent adversarial review (2026-10-31)

Read both original smoke logs, both test sources, `common/t.h`, `common/t.c`,
the Makefile and `tools/wine_run.sh`. Independently fetched fresh corpus bodies,
serially, after reading `/SKILL.md`; did not rely on the writer's saved bodies.
Review scratch responses: `/tmp/opencode/ntdll_review_corpus/`.
No reference implementation was copied into tests.

Every original failing expectation is retained, with this independent authority:

| Failing test suffix | Windows authority and exact expectation | Final failing checks |
| --- | --- | ---: |
| `hash_invalid` | `RtlHashUnicodeString` decomp, RVA `0x1ccb0`: `*param_4 = 0` precedes `if (param_3 < 2)`; rejected algorithm returns `0xc000000d`. Wine returns that status but leaves `0x55555555`. `/asm?flavor=objdump` independently returned HTTP 404; no assembly claim is made. | 1 |
| `find_invalid_flags` | RVA `0x1d390` decomp and asm: VA `0x18001d3ca` clears output, `0x18001d3ce` tests `0xfffffff8`, `0x1800aec51` returns `0xc000000d`. Wine returns `0xc0000225`, leaves `0x5555`. | 2 |
| `find_case` | Same body: flag 4 branches at `0x18001d4b8` into downcasing both set and input (`0x1800aeab8`, `0x1800aeae2`). `a` matches `A`; forward offset is `(index+1)*2 = 2` at index 0. Wine returns not-found and leaves `0x5555`. | 2 |
| `init_large_boundaries` | `RtlInitUnicodeStringEx`, RVA `0x1c270`: VA `0x18001c273` clears lengths and `0x18001c276` retains source before scan; `cmp rax,0x7ffe; ja` at `0x18001c28d` rejects 32767 and 32768 characters. Both rejected calls must leave zero lengths, not Wine's `0xfffc/0xfffe`. | 4 |

These are Windows-corpus-correct Wine divergences, not expected failures or
native-Windows execution results. Original seven failed checks remain covered;
two additional checks exercise the previously missing first-invalid 32767 length.

Other independently read bodies: `RtlCopyUnicodeString`,
`RtlAppendUnicodeToString`, `RtlUpcaseUnicodeString`, and
`RtlDuplicateUnicodeString`. Added empty/multiple find sets, complement of an
empty set, NULL terminated append source (success without terminating), and
in-place uppercase. Uppercase loops read/write the same indexed unit, permitting
the in-place case. Copy/append/uppercase now check the entire untouched tail,
not only its first element. Uppercase checks successful allocation is non-NULL,
maximum equals six bytes when allocating, and caller-owned buffer identity;
invalid duplicate flags must preserve the initially empty destination.
Allocated uppercase/duplicate outputs must not alias caller/source storage;
cleanup explicitly avoids freeing those aliases after a nonfatal assertion.
Duplicate content reads also require sufficient reported allocation capacity.
The first expanded run exposed the old uppercase initializer's zero-filled
second half; it is now fully initialized to the sentinel before tail checks.

Safety audit: `CHECK`/`EXPECT_EQ` are nonfatal (`common/t.h:58-62`);
`t_skip` only sets a flag (`common/t.c:57`). All export prerequisites here use
`REQUIRE`, which explicitly returns, including from helper wrappers. There are
no raw `t_skip` calls, pointer-valued garbage inputs, unchecked resource setup,
or API-produced lengths used as array indices. Caller capacities fit the real
backing arrays. Hash recurrence deliberately uses unsigned 32-bit wraparound;
the long init input is a static, terminated 32769-unit array. Allocation success
is status/pointer guarded before content access; frees require their exports.
No original failing expectation was found incorrect.

Final `make build/rtl_strings.exe build/rtl_conversion.exe` succeeded without
warnings. Final command (exit 1, expected conformance failures, no exceptions):

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_strings.exe > /tmp/opencode/ntdll_review_rtl_strings.log 2>&1
```

`/tmp/opencode/ntdll_review_rtl_strings.log:141`:
`SUMMARY tests=65 failed=4 skipped=0 checks_pass=984 checks_fail=9`.
Failure details are lines 17, 46-53, 130-133. All five added tests pass.
Remaining limitations above still apply; no native Windows host was available.

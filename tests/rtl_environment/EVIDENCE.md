# rtl_environment evidence

## Authority and isolation

46 focused tests. Every environment is explicitly allocated by
RtlCreateEnvironment(FALSE), passed by address to setters, and destroyed through
RtlDestroyEnvironment. No test uses NULL as the environment argument to a query,
setter or expansion; no process/global environment is changed or inherited.
Variables have the `rtl_environment_` prefix and live only in their private
blocks. Two-block testing checks isolation. All exports resolve through
UDECL/UN and REQUIRE; prerequisites are guarded because CHECK is nonfatal.

Reference instructions read:
<http://docker1.dev.moonlightcompanies.com:8765/SKILL.md>

## Windows 10 x64 contracts checked

Prefix all paths with `http://docker1.dev.moonlightcompanies.com:8765`.
Requests were serialized.

| URL | Contract / branches used |
| --- | --- |
| `/api/function/ntdll/RtlCreateEnvironment/decomp` | RVA 0x4dee0: FALSE delegates to CreateEnvironmentEx with flag 4 (empty allocation), not a host snapshot. |
| `/api/function/ntdll/RtlCreateEnvironmentEx/decomp` | RVA 0x4df50: empty path allocates four bytes and zeroes the DWORD; success assigns block and returns zero. |
| `/api/function/ntdll/RtlDestroyEnvironment/decomp` | RVA 0x7d7a0: frees through process heap and returns zero. |
| `/api/function/ntdll/RtlSetEnvironmentVariable/decomp` | RVA 0x4df00: UNICODE_STRING byte lengths become WCHAR counts; NULL value means deletion, non-NULL zero-length value means empty variable. |
| `/api/function/ntdll/RtlSetEnvironmentVar/decomp` | RVA 0x4e160: compares names case-insensitively; insertion, same-size update, shrink, grow/reallocation and deletion move surviving entries and update explicit caller block pointers. |
| `/api/function/ntdll/RtlQueryEnvironmentVariable_U/decomp` | RVA 0x4de70: passes MaximumLength/2 as capacity; success Length is payload bytes; on 0xc0000023 subtracts one from underlying required WCHAR count before assigning Length. |
| `/api/function/ntdll/RtlQueryEnvironmentVariable/decomp` | RVA 0x157e0: explicit block enters RtlpScanEnvironment; empty block returns 0xc0000100. No process-environment cache is used for these independent blocks. |
| `/api/function/ntdll/RtlpScanEnvironment/decomp` | RVA 0x161d0: ASCII names folded to uppercase; exact name must end at '='; success requires `value_chars < capacity_chars`, copies payload and writes NUL. Otherwise returns 0xc0000023 and required count includes NUL. Missing name returns 0xc0000100. |
| `/api/function/ntdll/RtlExpandEnvironmentStrings_U/decomp` | RVA 0x76e00: source Length and destination MaximumLength are divided by two. Success destination Length excludes NUL. Required length includes NUL even on short buffer; failed calls do not assign destination Length. Optional required pointer may be NULL. |
| `/api/function/ntdll/RtlExpandEnvironmentStrings/decomp` | RVA 0x15630: paired nonempty percent names are queried once; unknown/unpaired/empty-percent references are literal; substituted values are not recursively parsed. Accumulates full required size despite insufficient capacity, including one final terminator. |

`/api/function/ntdll/<export>/docs` was queried for the five public entry points.
No exact usable environment API documentation was returned; assertions are
based on the implementation branches above, not on Win32 environment APIs or
third-party tests. No source code was copied from another implementation.

Tests cover empty values, deletion at first/middle/last entry, longer/shorter/
same-length replacement, ASCII case-insensitive names, Unicode values, literal
equals/percent values, independent blocks, and query capacities 0/1/2/exact-1/
exact payload/exact terminated/spare including odd byte capacity. Expansion
covers affixes, adjacent and repeated substitutions, literal syntax, empty and
nonrecursive substitutions, required byte count, undersized buffers and optional
required pointer. Sentinel checks stay within the actual allocated arrays.

## Initial build / Wine triage (before review)

`make build/rtl_environment.exe` succeeded without compiler warnings.

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_environment.exe >/tmp/opencode/ntdll_rtl_environment.log 2>&1
```

Exit 1, summary:
`SUMMARY tests=45 failed=3 skipped=0 checks_pass=604 checks_fail=6`

42 tests pass. Three query tests fail under Wine: zero-capacity empty value,
exact payload capacity, and odd capacity equal to payload plus one byte. Wine
accepts them without a complete WCHAR terminator; Windows RtlpScanEnvironment
requires `value_chars < capacity_chars`. Each produces a status mismatch and a
terminator mismatch. These Windows-backed assertions are retained. No exceptions
were logged, and no tests were skipped.

## Gaps

Native Windows execution remains outstanding. No fixed OS version/build is
assumed; version APIs are outside this area's implemented coverage. Pseudo
environment names, Unicode name case mapping (NLS-dependent), process-global
environment APIs and host environment contents are deliberately not asserted.
Invalid names whose decompilation loses the returned status into an unresolved
stack temporary are not tested without further disassembly evidence.

## Adversarial review

Read the original smoke log and all source in this area, plus
`/home/iceisfun/test_pattern/docs/WRITING_TESTS.md` and `docs/SAFETY.md` in the
same pattern repository. Re-read every environment `/decomp` endpoint listed
above, and queried RtlQueryEnvironmentVariable_U `/docs` (zero matches).
Additional `/asm` queries: RtlpScanEnvironment and RtlQueryEnvironmentVariable_U.
Requests were serial, with 503 retry handling. `/api/modules/ntdll` identifies
the reference DLL as `10.0.19041.2788`, PDB key
`76C7BBFD419865CA30108FE0023CF0401`. These are static implementation checks,
not a native Windows execution claim or a promise for every Windows release.

### Exact retained failure triage

RtlQueryEnvironmentVariable_U 0x4de90 shifts MaximumLength right by one before
passing capacity to the underlying API. RtlQueryEnvironmentVariable enters
RtlpScanEnvironment for our explicit private, nonempty blocks, without using the
process environment cache. RtlpScanEnvironment 0x16330..0x16333 performs
`cmp rcx, rax; jae 0x16374`: payload length **greater than or equal to** WCHAR
capacity fails. At 0x1637e..0x1638b it returns `0xc0000023` with required count
including NUL. The `_U` wrapper 0x4dec6 subtracts one and 0x4deb9 doubles it,
so the reported Length remains the payload byte count.

| Test | Payload WCHARs / capacity WCHARs | Wine / Windows expectation |
| --- | --- | --- |
| rtl_environment_query_empty_zero | 0 / 0 | success / `0xc0000023` |
| rtl_environment_query_exact_payload | 5 / 5 | success / `0xc0000023` |
| rtl_environment_query_odd_capacity | 5 / floor(11/2)=5 | success / `0xc0000023` |
| rtl_environment_query_one_char | 5 / 1 | Both return `0xc0000023`; Wine leaves `buffer[0]=0xa5a5`, Windows writes zero. |
| rtl_environment_query_short | 5 / 4 | Both return `0xc0000023`; Wine leaves `buffer[0]=0xa5a5`, Windows writes zero. |

The final two are newly exposed, verified output-contract differences:
0x16374 compares capacity to one, 0x16378 skips the write only below one, and
0x1637a writes zero to the first WCHAR. This is also explicit in `/decomp`:
`if (param_5 != 0) { *param_4 = 0; }` after the insufficient-capacity branch.
All five differences remain hard failures; no Wine-compatible alternative is
accepted. Old terminator mismatches following Wine's unexpected success were
removed: the Windows path is failure, and no full WCHAR terminator fits within
the declared capacities of those three tests. Their status checks remain.

### Fixes, coverage and safety

- `re_expect` no longer trusts returned Length as a memcmp size or index: content
  and terminator checks use bounded expected size. A broken implementation's
  oversized Length therefore fails without making the test itself read outside
  the actual buffer. Query/expansion helpers explicitly bound capacities and
  expected payload lengths before calls.
- Byte sentinels now start at the exact declared byte capacity and the following
  byte, rather than rounding odd capacities upward and missing a one-byte
  overrun. Guards reserve both sentinel bytes in the actual backing arrays.
- Added explicit non-NULL allocation checks to independent-block tests, avoiding
  a vacuous pass if success is incorrectly returned with a NULL block.
- Added `query_name_boundary`: a name that is only a prefix is missing, then
  short and long names coexist and retain separate values. Verified by the
  scan's exact name-end-at-'=' check and setter's name-length comparison.
- No setter, query or expansion targets the process environment; every test
  creates an empty private block and destroys its current pointer after any
  setter reallocation. No process-global isolation child is necessary. No
  threads, waits, child processes or persistent resources are created. Arrays
  hold 128/512 WCHARs and the largest value is 300 WCHARs; there is no stress
  allocation, malformed block, or invalid-pointer test.
- No hard assertion was added for unresolved invalid-name status, Unicode name
  folding, host environment contents, or pseudo-variable behavior. Native
  Windows execution is still outstanding.

### Reviewed build and smoke

`make build/rtl_compression.exe build/rtl_environment.exe` succeeded without
warnings. Required sandbox command, exit **1**:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_environment.exe >/tmp/opencode/ntdll_review_environment.log 2>&1
```

Log line 99:
`SUMMARY tests=46 failed=5 skipped=0 checks_pass=711 checks_fail=5`.
41 passed; all five failures are individually Windows-backed above. The new
name-boundary test passes at lines 93-94. No exceptions or skipped tests.

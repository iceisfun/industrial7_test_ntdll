# rtl_environment evidence

## Authority and isolation

45 focused tests. Every environment is explicitly allocated by
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

## Build / Wine triage

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

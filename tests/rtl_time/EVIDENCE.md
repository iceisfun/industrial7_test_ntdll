# rtl_time evidence

Reference read on 2026-10-31: Windows 10 x64 corpus. Instructions:
http://docker1.dev.moonlightcompanies.com:8765/SKILL.md
Requests were serial with exponential HTTP 503 retry. Independently written
tests; Wine is a smoke environment, not a behavior oracle.

## Verified implementations

Each `/docs` sibling below was read as well as the linked decompilation.

| API / decomp URL | Verified contract/branches |
| --- | --- |
| [RtlTimeFieldsToTime, 0x5b060](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlTimeFieldsToTime/decomp) | Wrapper calls RtlpTimeFieldsToTime with no local-time bias argument. |
| [RtlpTimeFieldsToTime, 0x5b070](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpTimeFieldsToTime/decomp) | Uses process leap-second data if enabled; otherwise NoLeapSeconds helper. Validation failure returns before caller output write. |
| [RtlpTimeFieldsToTimeNoLeapSeconds, 0x5b174](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpTimeFieldsToTimeNoLeapSeconds/decomp) | Positive month/day; year 1601–30827 inclusive; month <=12; Gregorian divisible-by-400 or divisible-by-4-but-not-100 rule selects days-per-month. Day-1 must be less than month length. Unsigned comparisons reject negative time components and values >=24/60/60/1000. Writes output only on success. Weekday not read. |
| [RtlTimeToTimeFields, 0x5b390](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlTimeToTimeFields/decomp) | Wrapper calls RtlpTimeToTimeFields without a local-time bias argument. |
| [RtlpTimeToTimeFields, 0x5b3a0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpTimeToTimeFields/decomp) | Leap-second table and process flags can modify normal calendar conversion. |
| [RtlpTimeToTimeFieldsNoLeapSeconds, 0x5b498](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpTimeToTimeFieldsNoLeapSeconds/decomp) | Truncates 100ns ticks to milliseconds, divides into days/time components, Gregorian year/month decomposition; weekday is (days+1) modulo 7. |
| [RtlSecondsSince1970ToTime, 0x87dd0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSecondsSince1970ToTime/decomp) | Zero-extends ULONG seconds, adds epoch seconds, multiplies by 10,000,000. |
| [RtlSecondsSince1980ToTime, 0xe5dd0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSecondsSince1980ToTime/decomp) | Same arithmetic with 1980 epoch. |
| [RtlTimeToSecondsSince1970, 0x7ad80](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlTimeToSecondsSince1970/decomp) | Magic division by 10,000,000 precedes epoch subtraction. Only writes ULONG output when upper 32 bits of difference are zero. Otherwise returns FALSE, leaves output untouched. |
| [RtlTimeToSecondsSince1980, 0x7ac50](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlTimeToSecondsSince1980/decomp) | Same truncation/range/output branches with 1980 epoch. |
| [RtlSystemTimeToLocalTime, 0x7d590](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSystemTimeToLocalTime/decomp) | Queries system information and subtracts bias on success. Only logged, no timezone expectation. |
| [RtlLocalTimeToSystemTime, 0xe5d60](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlLocalTimeToSystemTime/decomp) | Queries system information and adds bias on success. Only logged. |

## Documentation bodies read

Prefix `http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/`:

- `windows-driver-docs-ddi/wdm/ns-wdm-time_fields.md`: Year >=1601; fields/ranges; Sunday=0.
- `windows-driver-docs-ddi/wdm/nf-wdm-rtltimefieldstotime.md`: TRUE on conversion, ignores Weekday.
- `windows-driver-docs-ddi/wdm/nf-wdm-rtltimetotimefields.md`: absolute time in 100ns units, no return value.
- `windows-driver-docs-ddi/ntifs/nf-ntifs-rtlsecondssince1970totime.md`: epoch basis start of 1601, elapsed 1970 seconds.
- `windows-driver-docs-ddi/ntifs/nf-ntifs-rtlsecondssince1980totime.md`: analogous 1980 epoch.
- `sdk-api/winternl/nf-winternl-rtltimetosecondssince1970.md`: TRUE/FALSE, dynamic linking, approximate timeframe. Exact upper boundary comes from decomp, not its approximate year prose.
- `windows-driver-docs-ddi/ntifs/nf-ntifs-rtltimetosecondssince1980.md`: approximate valid range, TRUE on representable input.

Some DDI pages are marked kernel-context/partial by the corpus. User-mode
branches above were checked directly rather than importing kernel semantics.

## Deterministic vectors and uncertainty

Epoch constants independently computed using Python datetime differences from
1601-01-01: 1970 = 116444736000000000 ticks, 1980 = 119600064000000000 ticks.
Historical date constants and weekdays were also computed before coding.
Conversions use caller-owned 16-byte TIME_FIELDS-compatible storage and
LARGE_INTEGERs; no clock/timezone changes or allocations.

Modern calendar dates use field round trips and Gregorian weekday expectations,
not fixed tick offsets, because the Windows helper has leap-second branches.
Exact calendar tick checks use historical dates through 1970, before inserted
leap seconds. Second=60 is deliberately not rejected universally; second=61
is the safe invalid vector. Custom/administratively modified historical leap
tables have not been tested. Negative absolute time, extreme years and
timezone/DST policy are not hard-asserted. Epoch-second arithmetic does not
consult those calendar leap tables in the verified implementations.

## Initial build and smoke (superseded by review below)

`make build/rtl_time.exe` succeeds without warnings. Objdump imports show only
KERNEL32.dll and msvcrt.dll; ntdll is not statically imported. Every tested API
uses UDECL+UN and REQUIRE before calls.

Command: `TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_time.exe > /tmp/opencode/ntdll_rtl_time.log 2>&1`

Final log: `SUMMARY tests=76 failed=3 skipped=0 checks_pass=298 checks_fail=6`.
Exit code 1. Failed tests: `rtl_time_invalid_nonleap`,
`rtl_time_invalid_century1900`, `rtl_time_invalid_century2100`. Wine accepts
February 29 for 2023/1900/2100 and writes a result. The Windows helper's
Gregorian leap predicate and month-length comparison reject all three, so
these Windows-supported checks remain hard failures rather than Wine skips.
The other 73 tests pass. Local-time status/bias is logged only. Native Windows
execution and leap-second-enabled machine execution remain outstanding.

## Adversarial review, 2026-10-31

Re-read the corpus instructions, original smoke log, calendar wrappers and both
leap-aware helpers, NoLeapSeconds helpers, epoch-second routines, timezone
converters, TIME_FIELDS and TimeFieldsToTime documentation. All corpus requests
were serial with HTTP 503 retry. No third-party implementation/test was copied.

### Exact retained-failure classifications

[NoLeapSeconds assembly](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpTimeFieldsToTimeNoLeapSeconds/asm)
confirms the decompiler's leap predicate at VA 0x18005b1f4–0x18005b227:
divisible by 400, or divisible by 4 but not 100. The normal month table at RVA
0x12e528 was independently read using
`/api/bytes/ntdll?rva=0x12e528&len=26`; its first three USHORTs are 0,31,59.
Thus February has exactly 59-31=28 days for these non-leap years. The comparison
at 0x18005b255 followed by **jge** at 0x18005b257 rejects day-1 >= month length.
The failure branch at 0x18005b37c zeros AL without reaching the only caller-output
store at 0x18005b331. The leap-aware wrapper validates through this helper into
local storage before any caller-output store, so enabling leap seconds does not
make these invalid dates valid.

| Failed test | Evidence / Wine observation |
| --- | --- |
| `rtl_time_invalid_nonleap` | 2023 is not divisible by 4: reject February 29, preserve sentinel. Wine returns TRUE and writes 0x1d94bd0c4224000, exactly 2023-03-01 (review log lines 104–107). |
| `rtl_time_invalid_century1900` | 1900 is divisible by 100, not 400: same rejection. Wine writes 0x14f6598c43f8000, exactly 1900-03-01 (lines 100–103). |
| `rtl_time_invalid_century2100` | 2100 is divisible by 100, not 400: same rejection. Wine writes 0x22f9fc03dc34000, exactly 2100-03-01 (lines 96–99). |
| `rtl_time_invalid_above_maximum_year` (new) | 0x18005b1d0 forms Year-0x641; 0x18005b1d7 compares it with 0x722a; **ja** rejects larger unsigned differences. Maximum Year=1601+29226=30827, so 30828 fails unchanged. Wine returns TRUE and writes 0x7fff35f4f06c8000 (lines 128–131). |
| `rtl_time_invalid_short_maximum_year` (new) | Same unsigned bound rejects 32767. Wine returns TRUE and writes 0x887d13de97f34000 (lines 124–127), setting the sign bit rather than rejecting the year. |

All five are retained hard **Wine/Windows-image divergences**, not revised to
Wine expectations. The three March-1 values and all existing historical tick
constants/weekdays were independently recomputed with Python datetime; the
upper-year limit was expanded directly from the assembly constants. The docs
only say Year >=1601: this upper bound is specifically an image-backed contract,
not a general documentation claim.

### Safety and missed scope

Added both upper-year rejections and a guarded output-extent test covering the
8-byte LARGE_INTEGER and all eight 16-bit TIME_FIELDS fields. Valid/invalid date
helpers now check input immutability. Initialized the void epoch-conversion
output before calling, avoiding an indeterminate read if an implementation
fails to write. Initialized submillisecond output as well. Timezone calls remain
configuration observations, but now verify preservation of their initialized
outputs on failure; success status, bias, and round trip are not pass criteria.

Every dependency has REQUIRE before invocation. The nonfatal TRUE check in
calendar conversion has an explicit `if (!ok) return` before reverse conversion;
the extent test does likewise. Error-output checks do not drive later unsafe
operations. No handles, heap allocations, files, clock/timezone modifications,
or test-owned persistent state need cleanup.

Unsigned ULONG seconds (including 0x80000000 and 0xffffffff) are zero-extended
before multiplying; the tested sums fit signed 64-bit. Reverse conversion divides
absolute ticks before epoch subtraction, so first-tick/fractional/max-fraction
expectations are intentional. [1970 assembly](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlTimeToSecondsSince1970/asm)
at 0x18007ad99–0x18007adab subtracts epoch, checks the high 32 bits, and writes
only on success. The 1980 decomp confirms the same contract. Exact historical
ticks stop before leap insertion; modern round trips do not assume fixed tick
offsets. Second=60, negative absolute times, extreme valid-year round trips, and
administratively modified leap tables remain unasserted.

### Reviewed build and smoke

Build: `TMPDIR=/tmp/opencode TP_TIMEOUT=120 make build/rtl_numeric.exe build/rtl_time.exe`
completed without warnings. Rechecked imports: only KERNEL32.dll and msvcrt.dll,
no static ntdll import. `common/modules.h` resolves UN only from ntdll.dll.

`TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_time.exe > /tmp/opencode/ntdll_review_time.log 2>&1`

Exit **1**, final line (172):
`SUMMARY tests=79 failed=5 skipped=0 checks_pass=354 checks_fail=10`.
74 tests pass, including one timezone observation registration; 5 fail as
classified above. There are 78 deterministic behavior-test registrations, not
79 timezone-independent behavior claims. No Wine suppression was added.

Log SHA-256: `d8a7b427e56bc359363473f2d8dbd852f620e53cfcedde6c1696e12c6af694c6`.
Native Windows and leap-second-enabled execution were not available/run; static
corpus evidence is not a substitute for those outstanding native baselines.

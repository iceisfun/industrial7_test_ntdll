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
| [RtlpTimeFieldsToTimeNoLeapSeconds, 0x5b174](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpTimeFieldsToTimeNoLeapSeconds/decomp) | Positive month/day; year at least 1601; month <=12; Gregorian divisible-by-400 or divisible-by-4-but-not-100 rule selects days-per-month. Day-1 must be less than month length. Unsigned comparisons reject negative time components and values >=24/60/60/1000. Writes output only on success. Weekday not read. |
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

## Build and smoke

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

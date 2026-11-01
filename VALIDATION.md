# Validation on Windows 10

VERIFIED: the full corpus was run on genuine Windows 10 22H2 x64 (build 19045, ntdll 10.0.19041.2788), once as a standard user and once elevated, after the two fixes below.

| Mode | tests | failed | skipped | checks passed | checks failed |
|---|---|---|---|---|---|
| standard user | 2188 | 0 | 2 | 88573 | 0 |
| administrator | 2188 | 0 | 1 | 88587 | 0 |

Skips: `harness_checks_exception_probe` (runs only in an isolated child; both modes) and `nt_thread_critical_flag_clear` (standard user only; needs SeDebugPrivilege).

Repeated runs gave identical per-test results (no flaky tests observed).

Before the fixes, one test failed in each mode or both:

- `nt_sync_delay_zero_returns`: a zero-length `NtDelayExecution` returned `STATUS_NO_YIELD_PERFORMED` (0x40000024), a success-class status. The test now accepts 0 or 0x40000024.
- `nt_thread_critical_flag_clear`: failed as a standard user with `STATUS_PRIVILEGE_NOT_HELD` (0xC0000061). It now skips on exactly that status; the full check still runs when elevated, where it passed.

Limits: only build 19045 was available as a baseline; other Windows 10 builds and locales are UNVERIFIED. One run per mode was done after the fixes.

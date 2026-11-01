# CRT string contracts

Reference inspected 2026-10-31: Windows 10 corpus at
<http://docker1.dev.moonlightcompanies.com:8765/SKILL.md> (19041 family).
Requests were sequential, with retry handling for HTTP 503. Decompiled bodies were
read, not copied into the tests. Windows is the authority; no Windows execution
was available in this session.

## Length and copy/append

| Inspected Windows bodies | Contract used |
| --- | --- |
| [strlen](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strlen/decomp), [wcslen](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcslen/decomp) | Stop at the first zero; exclude it from the length. Wide length counts 16-bit units, not Unicode scalar values. |
| [strnlen](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strnlen/decomp), [wcsnlen](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcsnlen/decomp) | Counter starts at zero; `_MaxCount == 0` skips reads. Return the smaller of bound and first-zero index; a bounded unterminated array is valid. |
| [strcpy](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strcpy/decomp), [wcscpy](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcscpy/decomp) | Copy through the zero, return original destination, do not write after it. |
| [strncpy](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strncpy/decomp), [wcsncpy](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcsncpy/decomp) | Zero count does no writes. Copy exactly count units; after early zero, pad the remaining count with zeros. No implicit extra terminator on truncation. Return destination. |
| [strcat](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strcat/decomp), [wcscat](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcscat/decomp) | Find destination zero, then copy source including zero; return original destination. |
| [strncat](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strncat/decomp), [wcsncat](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcsncat/decomp) | Append at most count nonzero units and terminate. Zero count preserves the valid destination string. Narrow zero-count branch returns immediately; wide branch rewrites the existing terminator. |

Tests use distinct source/destination arrays and elementwise output oracles.
Padding surrounds writable regions; no copy/append overlap is used. Narrow
sources are padded local arrays, not page-end probes of optimized word readers.

## Comparison and search

| Inspected Windows bodies | Contract used |
| --- | --- |
| [strcmp](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strcmp/decomp), [wcscmp](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcscmp/decomp) | First unequal unsigned byte/unit determines ordering; stop at zero. Only the result sign is asserted. |
| [strncmp](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strncmp/decomp), [wcsncmp](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcsncmp/decomp) | Zero count returns zero; differences outside count or after a shared zero are ignored. Return magnitudes differ between implementations, so use sign only. |
| [_stricmp](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/_stricmp/decomp), [__ascii_stricmp](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/__ascii_stricmp/decomp), [_wcsicmp](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/_wcsicmp/decomp) | Narrow alias `_strcmpi` delegates to ASCII comparison. Only A-Z are folded by adding 0x20; wide body has the same A-Z range check. Punctuation is not folded. |
| [strchr](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strchr/decomp), [wcschr](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcschr/decomp) | First match, including the terminator when searching for zero; otherwise NULL. |
| [strrchr](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strrchr/decomp), [wcsrchr](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcsrchr/decomp) | Scan to the terminator and search backward, including index zero; return the last match or NULL. |
| [strstr](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strstr/decomp), [wcsstr](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcsstr/decomp) | Empty needle returns original haystack, even when haystack is empty. Nonempty needle uses first exact case-sensitive match; restart after a partial mismatch. |
| [strspn](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strspn/decomp), [wcsspn](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcsspn/decomp) | Length of initial run belonging to the control set; empty set/string gives zero. |
| [strcspn](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strcspn/decomp), [wcscspn](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcscspn/decomp) | Length before first member of control set or zero terminator. |
| [strpbrk](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strpbrk/decomp), [wcspbrk](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcspbrk/decomp) | First string position belonging to set, not first set character; empty set/string or no match returns NULL. |

## Secure success paths only

Read [strcpy_s](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strcpy_s/decomp),
[wcscpy_s](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcscpy_s/decomp),
[strcat_s](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strcat_s/decomp), and
[wcscat_s](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcscat_s/decomp).
Valid non-NULL operands with capacity including the final zero return zero.
Wide capacity is in words. Success returns immediately after copying the zero;
tail elements remain unchanged. Tests include exact capacity, capacity one for
empty strings, and roomy buffers.

Actual validation branches: NULL destination or zero capacity invokes
`_invalid_parameter`; NULL source clears destination then invokes it. Copy or
append exhaustion clears destination and invokes it (0x22 on the returning
path); unterminated append destination also invokes it (0x16). None of these
invalid branches is exercised in-process. No handler installation or child
invalid-parameter tests are included.

[strcpy_s docs lookup](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strcpy_s/docs)
returned `total: 0`. Contracts above come from the binary, not a claimed docs
match. Other secure functions, locale-sensitive behavior, and invalid pointers
are intentionally outside this area. CRT functions do not have a Win32
GetLastError result contract here; no such assertion is invented.

## Build and smoke evidence

`make build/crt_strings.exe` succeeds without warnings after cleanup.
Separately compiling `strings.c` with `-O1 -Wall -Icommon -c` and inspecting
`x86_64-w64-mingw32-nm -u` yields only `t_check`, `t_proc_in`, `t_register`,
and `t_skip`: no direct host CRT calls or compiler-lowered CRT references in
the test object. Every export is typed with the headers and pinned with
`UIN("ntdll.dll", ...)`; every call is guarded by REQUIRE.

Smoke command (exit 1):

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/crt_strings.exe > /tmp/opencode/ntdll_crt_strings.log 2>&1
SUMMARY tests=175 failed=2 skipped=0 checks_pass=735 checks_fail=2
```

Failures are `crt_strings_strstr_both_empty` and
`crt_strings_wcsstr_both_empty`: Wine returns NULL rather than the haystack.
These assertions remain hard checks because the Windows assembly confirms them:

- [strstr assembly](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/strstr/asm):
  `0x180091549 cmp byte ptr [rdx], r11b`; empty-needle fallthrough at
  `0x18009154e mov rax, rcx; ret`.
- [wcsstr assembly](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/wcsstr/asm):
  `0x180092139 cmp word ptr [rdx], r11w`; empty-needle fallthrough at
  `0x18009213f mov rax, rcx; ret`.

No Wine-specific expectation or waiver was added. Windows runtime validation of
all 175 cases remains outstanding.

## Independent adversarial review (2026-10-31)

Re-read the original smoke log and both search functions' `/asm`, `/decomp`,
and `/docs` sequentially, retrying HTTP 503 if encountered. The empty-needle
branches quoted above are unchanged: neither reads the haystack before returning
it. **Classification: two Wine implementation divergences, not bad expectations.**
The hard checks remain; there are no permissive Wine branches.

The `strstr/docs` lookup misleadingly labels SHLWAPI `StrStrA`/`StrStrW` pages
as exact matches through case-insensitive symbol matching. Those are not ntdll
CRT documentation and were not used as authority. `wcsstr/docs` has `total: 0`.
Local review responses: `/tmp/opencode/review_{strstr,wcsstr}_{asm,decomp,docs}.txt`.

Added six focused cases (three per width): matches after a haystack NUL must be
ignored, a needle stops at its embedded NUL, and a partial match exhausting the
haystack must fail. These follow the decompiled first-zero/partial-match loops,
not Wine behavior. Fixed `%p` diagnostics to pass actual `void *` arguments.

Audit found no direct API-under-test calls, overlap UB, output-length-driven
reads, or missing prerequisite guards: returned pointers are compared but never
dereferenced, fixed oracle lengths fit their arrays, and secure capacities include
the zero. All secure calls remain valid-input-only; no handler can be triggered
by an intentionally invalid test. Zero-count cases assert pointer/side-effect
contracts and are not vacuous. Shared macro cases are parameterized coverage,
not repeated identical inputs for a count target.

Review build: `make build/crt_strings.exe build/crt_algorithms.exe`, no warnings.
Separate `-O1 -Wall -Icommon -c` compilation and `x86_64-w64-mingw32-nm -u`
again show only `t_check`, `t_proc_in`, `t_register`, and `t_skip`.

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/crt_strings.exe > /tmp/opencode/ntdll_review_strings.log 2>&1
SUMMARY tests=181 failed=2 skipped=0 checks_pass=741 checks_fail=2
```

Exit 1; exactly the same `strstr_both_empty` and `wcsstr_both_empty` failures
(log lines 85-86 and 154-155). All six additions pass. Windows runtime execution
remains unavailable; page-boundary read detection and invalid-handler recovery
remain outside this suite.

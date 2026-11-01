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

Initial writer run: Wine 71 tests, 8 failed, 0 skipped; 291 passing checks,
9 failing checks.
Seven raw OEM truncation tests return Wine success instead of Windows overflow.
One OEM descriptor exact-data-capacity test truncates/copies under Wine,
instead of preserving required Length and untouched buffer. These verified
deviations remain hard failures.

No native Windows execution was available. DBCS/high-byte ANSI/OEM mappings,
active-UTF8 process setup, full invalid-UTF8 taxonomy and supplementary decode
truncation within the surrogate pair are not asserted. No global NLS state is
changed; no allocation failures are forced. NTSTATUS is checked rather than
Win32 last-error (these APIs have no last-error contract).

## Independent adversarial review (2026-10-31)

Independently read original logs, sources and the harness, then fetched fresh
corpus decompilation and objdump assembly serially after `/SKILL.md`.
Scratch: `/tmp/opencode/ntdll_review_corpus/`. No reference code was copied.
Every original failed check was verified directly against Windows, not against
the writer's interpretation or Wine:

| Failing test suffix | Capacity / required output | Independent Windows authority | Final failing checks |
| --- | --- | --- | ---: |
| `raw_oem_zero` | 0 / 8 bytes | `RtlOemToUnicodeN`, RVA `0x61110` | 1 |
| `raw_oem_one` | 1 / 8 bytes | same | 1 |
| `raw_oem_short` | 6 / 8 bytes | same | 1 |
| `raw_oem_odd` | 7 / 8 bytes | same | 1 |
| `raw_to_oem_zero` | 0 / 4 bytes | `RtlUnicodeToOemN`, RVA `0x61070` | 1 |
| `raw_to_oem_one` | 1 / 4 bytes | same | 1 |
| `raw_to_oem_short` | 3 / 4 bytes | same | 1 |
| `descriptor_to_oem_exact_data` | 3 / 4 bytes including terminator | `RtlUnicodeStringToOemString`, RVA `0x60cb0` | 4 |

For each of the four raw decode failures, VA `0x180061144` shifts capacity
right one, and `0x18006118e` executes `cmp r11d,edx; sbb eax,eax;
and eax,0x80000005`. Capacity units 0, 0, 3, 3 are each below four source
bytes: expected overflow. For the three encode failures, source bytes are
shifted at `0x1800610a0`; the same instruction sequence at `0x1800610e4`
compares byte capacities 0, 1, 3 against four source units: expected overflow.
Both decompilations also report actual copied counts, with no terminator.
Wine's data/count/tail checks pass but statuses are success, not overflow.
ASCII has no lead bytes in the DBCS branches either; their remaining-capacity
versus remaining-input comparisons produce overflow for these inputs. The UTF8
branches translate `STATUS_BUFFER_TOO_SMALL` to overflow as well.

For the descriptor case, `0x180060cdf` computes required data length 3;
`0x180060ce2` stores it; `0x180060cea` compares it to MaximumLength and
`jae 0x1800bdeba` returns `0x80000005` before conversion. Thus Length stays
3 and the entire buffer is untouched. Wine returns the expected overflow but
sets Length 2 and writes bytes 0..2 to `61 00 00`; all four final failures are
this verified divergence. The original single-byte no-copy assertion was
replaced by checks of every untouched byte (not duplicated).

Also independently fetched/read `RtlAnsiStringToUnicodeString`,
`RtlOemStringToUnicodeString`, `RtlUnicodeStringToAnsiString`, `RtlFreeOemString`,
`RtlUTF8ToUnicodeN`, and `RtlUnicodeToUTF8N`. Added four empty allocating
descriptor cases (allocated terminated output), four empty UTF conversion/size
cases, and two NULL UTF source cases: both UTF bodies reject NULL source with
`0xc00000f2` before modifying count/output, even for zero input bytes. All ten
added tests pass. Raw and descriptor cases now check full untouched tails;
nonallocating descriptors must retain caller buffer identity. Allocated content
access checks non-NULL and sufficient reported capacity. The partial ANSI
conversion assertion is only entered on success or the expected overflow, not
on an arbitrary failure. OEM free intentionally does not reuse its dangling
descriptor; its Windows body at RVA `0x8ab70` only frees, without clearing.
Allocated descriptors must not alias the actual source or local destination;
cleanup explicitly avoids freeing either alias after a nonfatal assertion.

Safety audit: all function prerequisites use returning `REQUIRE`, not bare
nonreturning `t_skip`; all statuses are checked. Counts returned by the DLL are
compared, never trusted as array indexes or read lengths. Expected copy sizes
are bounded by real local arrays, no exhausted-resource/garbage-pointer tests
are present, and all allocated outputs have a required matching free export.
No original failing expectation was found incorrect. Harness details and
cross-area audit are also recorded in `../rtl_strings/EVIDENCE.md`.

Final build succeeded without warnings. Smoke command exited 1 because of the
classified conformance failures, with no exceptions:

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_conversion.exe > /tmp/opencode/ntdll_review_rtl_conversion.log 2>&1
```

`/tmp/opencode/ntdll_review_rtl_conversion.log:175`:
`SUMMARY tests=81 failed=8 skipped=0 checks_pass=1282 checks_fail=11`.
Failure details: lines 71-74, 123, 126, 129, 150, 153, 156, 159.
All failures remain hard Windows-corpus-verified Wine divergences. Native
Windows execution and the previously listed NLS/malformed-input gaps remain
unavailable/uncovered; no cross-version claim is made.

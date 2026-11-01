# rtl_hash Windows evidence

Reference: Windows 10 x64 `ntdll.dll` 10.0.19041.2788, PDB key
`76C7BBFD419865CA30108FE0023CF0401` (`tools/reference_module.json`).
Queried 2026-10-31 with sequential requests, retrying HTTP 503.
Base: <http://docker1.dev.moonlightcompanies.com:8765>.
Paths below are relative to that server. No Windows execution was performed.

## Exact CRC signatures, not interchangeable routines

Inspected `/api/function/ntdll/<name>/decomp` for RtlComputeCrc32, RtlCrc32,
RtlCrc64 and RtlpComputeCrcInternal, and `/asm` for RtlCrc32 and RtlCrc64.

| Export | RVA | Public signature used by tests |
|---|---|---|
| RtlComputeCrc32 | 0x58990 | ULONG (ULONG seed, const void *buffer, ULONG length) |
| RtlCrc32 | 0x7ea00 | ULONG (const void *buffer, SIZE_T length, ULONG seed) |
| RtlCrc64 | 0xf63f0 | ULONGLONG (const void *buffer, SIZE_T length, ULONGLONG seed) |

RtlCrc32 assembly starts `mov r8d,r8d`, installs descriptor in r9 and
tail-jumps to 0x7ea20. RtlCrc64 installs a different descriptor and tail-jumps
to the same helper, without truncating r8. The helper reads input through rcx,
consumes rdx bytes, XORs r8 with descriptor+0x20 before updating, and XORs
again on return. **Ghidra's wrapper `void` signatures are wrong**: the helper
returns a 64-bit value, propagated by the tail jumps. CRC32 descriptor and
tables restrict that result to 32 bits.

RtlComputeCrc32 explicitly complements the input seed, updates each byte via
a DWORD table, then complements the result. It uses the IEEE polynomial,
not the Castagnoli polynomial used by RtlCrc32.

## Image-backed polynomials and seed convention

Actual descriptor and lookup bytes:

- `/api/search?q=RtlCrc32Table&module=ntdll&limit=5` -> RVA 0x127250.
- `/api/bytes/ntdll?rva=0x127450&len=4` -> `2083b8ed`:
  RtlComputeCrc32 table[128] = 0xedb88320.
- `/api/bytes/ntdll?rva=0x11d7d0&len=40`: RtlCrc32 descriptor,
  byte table VA 0x18012ce40; XOR mask 0x00000000ffffffff.
- `/api/bytes/ntdll?rva=0x12ce40&len=1032`: QWORD table[1] =
  0xf26b8303; table[128] = 0x82f63b78 (reflected Castagnoli polynomial).
- `/api/bytes/ntdll?rva=0x11e628&len=40`: RtlCrc64 descriptor,
  byte table VA 0x18013ca90; XOR mask 0xffffffffffffffff.
- `/api/bytes/ntdll?rva=0x13ca90&len=1032`: QWORD table[1] =
  0x7f6ef0c830358979; table[128] = 0x9a6c9329ac4bc9b5.

The CRC64 polynomial is not the common ECMA reflected 0xc96c5795d7870f42;
tests deliberately retain the image's polynomial. Fixed zero-seed vectors:

| Input | ComputeCrc32 | Crc32 | Crc64 |
|---|---|---|---|
| empty | 0 | 0 | 0 |
| a | e8b7be43 | c1d04330 | 8c2f8445b4cbfc3c |
| abc | 352441c2 | 364b3fb7 | 05e5cabb3fc1faeb |
| 123456789 | cbf43926 | e3069283 | ae8b14860a799888 |
| The quick brown fox jumps over the lazy dog | 414fa339 | 22620404 | d76c54054954c143 |
| bytes 0 through 255 | 29058c73 | 9c44184b | ff71e21279d9966e |

Vectors were computed with an independent bit-at-a-time recurrence from the
verified image polynomials and masks. The test's compact recurrence also
checks seeded lengths 0, 7, 8, 31, 32, 63, 64, 65, 255, 512, aligned and
unaligned starts, every possible two-chunk split, unchanged source, and
Win32 error preservation. These hit the helper's initial alignment peel,
32-byte block division, >63-byte interleaved path and byte tail. No lookup
tables or implementations were copied from third-party code.

## RtlUniform

`/api/function/ntdll/RtlUniform/decomp` (RVA 0x74b20) takes a pointer to
ULONG, reads/writes exactly that ULONG and returns the updated value. Its
64-bit multiply/add followed by reciprocal reduction implements
`(seed * 0x7fffffed + 0x7fffffc3) % 0x7fffffff`.
Eight starting seeds, including 0, modulus boundaries and all bits set, each
test 16 updates, output/state equality and Win32 error preservation. No
statistical or unpredictability claims are made.

`/api/docs/page/sdk-api/winternl/nf-winternl-rtluniform.md` independently
documents in/out Seed and Lehmer generation; its range statement is broader
than the implementation's strict modulus bound, so the exact recurrence
comes from the binary, not that range statement.

## Validation and gaps

Build: `make build/rtl_hash.exe`.
Smoke: `TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_hash.exe`.
Log: `/tmp/opencode/ntdll_rtl_hash.log`:
`SUMMARY tests=56 failed=0 skipped=32 checks_pass=1625 checks_fail=0`.
All 32 skips are missing RtlCrc32/RtlCrc64 exports in the smoke Wine; those
tests still require a Windows run. Windows expectations were not weakened.

A_SHA*, MD4 and MD5 were not added: their exact context layouts were not
verified in this pass. RtlRandom/RtlRandomEx were excluded to avoid shared
global state. No invalid input pointers, exhaustion, or product cryptography
changes. All buffers are bounded local arrays or read-only literal vectors.

## Adversarial review (2026-10-31)

Re-queried Windows module metadata, CRC wrapper assembly, ComputeCrc32 and
shared-helper decompilation, both descriptors and both complete 256-entry
QWORD byte tables (`len=2048` at 0x12ce40 / 0x13ca90). Independently
regenerating all entries with reflected 0x82f63b78 / 0x9a6c9329ac4bc9b5
matched all 512 image entries. Re-fetched IEEE table[128] at 0x127450.
Descriptor+0x18 also contains the respective polynomial and +0x20 the
initial/final XOR mask. All fixed string and binary vectors were recomputed
independently and matched. Argument order, 32/64-bit seed width, return width,
and extension by feeding the previous finalized CRC agree with the inspected
Windows implementation. Review responses are retained under
`/tmp/opencode/ntdll_review_corpus/`.

Added one 65-byte unaligned all-bits-set seed case per CRC, including a full
64-bit seed for Crc64. Every two-chunk split now checks Win32 error
preservation too, including the empty-prefix and empty-suffix calls. These
are bounded local fixtures; no null/invalid buffer probes were added.
REQUIRE returns from the helper on a missing export; there is no fallthrough
after the harness's nonfatal t_skip. No SHA or unverified context was invoked.

RtlUniform's complete assembly at 0x74b20..0x74b60 only reads/writes the
caller-provided seed; there are no calls or global-memory accesses in that
inspected implementation. Its reciprocal reduction was compared with the
modulus expression for the eight fixture seeds plus 10,000 reproducible
32-bit samples (not exhaustive). The SDK Seed in/out description was also
re-fetched. This supports this build's seeded sequence, not a claim about
process-global randomness or other Windows versions; RtlRandom/Ex remain
out of scope.

Build succeeded without diagnostics in `/tmp/opencode/ntdll_review_build.log`.
Smoke used only
`TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_hash.exe`.
`/tmp/opencode/ntdll_review_hash.log:154` records:
`SUMMARY tests=59 failed=0 skipped=34 checks_pass=2808 checks_fail=0`.
The runner exited 0. All 34 skips explicitly report missing exports:
17 RtlCrc32 and 17 RtlCrc64. These are unavailable in this Wine smoke,
not optional in the reference image and not evidence of Windows execution.
`/api/modules/ntdll/exports?q=RtlCrc&limit=10` confirms both reference
exports, ordinals 831 / 832 at RVAs 0x7ea00 / 0xf63f0, without forwarders.
Their tests still need an actual Windows run; expectations were not weakened.

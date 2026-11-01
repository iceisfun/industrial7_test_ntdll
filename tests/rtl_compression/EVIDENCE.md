# rtl_compression evidence

## Authority and scope

45 focused tests. Windows 10 x64 corpus is the authority; Wine is only a
development smoke test. All calls use dynamically resolved UDECL/UN pointers
with REQUIRE. Only LZNT1 streams produced by RtlCompressBuffer are decompressed;
invalid-format tests stop in the documented format-validation branch, before
their input could be interpreted. Buffers are bounded (largest array 16 KiB),
workspace requests are capped at 1 MiB, and allocations are freed on every path.

Reference service:
<http://docker1.dev.moonlightcompanies.com:8765/SKILL.md>

The following URLs were queried serially. Prefix each path below with
`http://docker1.dev.moonlightcompanies.com:8765`.

## Windows branches checked

| URL | Contract used |
| --- | --- |
| `/api/function/ntdll/RtlGetCompressionWorkSpaceSize/decomp` | Low format byte <2 returns 0xc000000d; >=5 returns 0xc000025f; otherwise dispatches with high engine byte. Invalid format leaves outputs alone. |
| `/api/function/ntdll/RtlCompressBuffer/decomp` | Same format rejection before dispatch. |
| `/api/function/ntdll/RtlDecompressBuffer/decomp` | Same format validation; engine bits are not passed to the decompressor. |
| `/api/function/ntdll/RtlDecompressBufferEx/decomp` | Same format validation, forwards caller workspace. |
| `/api/function/ntdll/RtlDecompressFragment/decomp` | Same format validation, forwards offset and workspace. |
| `/api/function/ntdll/RtlCompressWorkSpaceSizeLZNT1/decomp` | RVA 0x85cd0: standard compression workspace 0x10020, maximum 0x20, fragment 0x1000; other engines return 0xc00000bb without assigning outputs. |
| `/api/function/ntdll/RtlCompressBufferLZNT1/decomp` | RVA 0x10c8b0: accepts standard/maximum engines; loops in 4096-byte chunks; final size excludes optional zero terminator; returns 0x117 iff every chunk reports all zeros. |
| `/api/function/ntdll/LZNT1CompressChunk/decomp` | RVA 0x10c434: bounded compressed/uncompressed fallback, 0xc0000023 when neither fits; final return `~-(uint)(local_res10 != 0) & 0x117` corroborates the all-zero status. |
| `/api/function/ntdll/RtlDecompressBufferLZNT1/decomp` | RVA 0x10c9c0: reconstructs chunk data and reports actual byte count. |
| `/api/function/ntdll/RtlDecompressFragmentLZNT1/decomp` | RVA 0x10cb50: skips full 4096-byte chunks, uses workspace for partial compressed chunks, copies requested offset/range. |

`/api/function/ntdll/<export>/docs` was queried for all five public exports.
The returned compression pages are kernel-context contracts (partial matches
for user-mode ntdll), so implementation-specific expectations above are also
backed by the ntdll decompilation. Full pages read:

- `/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-rtlgetcompressionworkspacesize.md`
- `/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-rtlcompressbuffer.md`
- `/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-rtldecompressbuffer.md`
- `/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-rtldecompressbufferex.md`
- `/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-rtldecompressfragment.md`

Docs supply format/engine definitions, valid chunk sizes 512/1024/2048/4096,
workspace ownership, roundtrip and fragment semantics. The tests do not assert
compressed byte encodings or a fixed compression ratio. Exact compressed-size
testing derives size from an initial compression using the same implementation.

## Initial build and smoke results (before review)

`make build/rtl_compression.exe` succeeded without compiler warnings.

Executed only through the required sandbox:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_compression.exe >/tmp/opencode/ntdll_rtl_compression.log 2>&1
```

Exit 1; log summary:
`SUMMARY tests=43 failed=4 skipped=7 checks_pass=807 checks_fail=5`

- Wine reports workspace 0x10 for both standard and maximum, instead of
  Windows 0x10020/0x20 (two failed tests).
- Wine accepts HIBER and returns workspace 0x10, instead of rejecting it with
  0xc00000bb (one failed test, two failed checks).
- Wine returns success instead of STATUS_BUFFER_ALL_ZEROS (one failed test).
- Seven tests skip because Wine lacks RtlDecompressBufferEx.
- The other 32 tests pass; no exceptions were logged.

Expectations are not weakened to accommodate Wine.

## Remaining uncertainty / gaps

No native Windows execution was available. XPRESS and XPRESS_HUFF valid-stream
coverage is not included; LZNT1 is the common documented format across all five
exports. Malformed streams, huge allocations, unsupported chunk sizes and
NULL required pointers are intentionally excluded. Decompressor undersized-buffer
behavior is not generalized from the DDI page: the Windows LZNT1 implementation
has chunk-dependent truncation paths, so partial-output tests use the explicit
fragment API instead.

## Adversarial review

Reviewed the area's source and the original smoke log above against
`/home/iceisfun/test_pattern/docs/WRITING_TESTS.md` and `docs/SAFETY.md` in that
same pattern repository. Reference API requests were made one at a time, with
503 retry handling. Re-read every compression `/decomp` endpoint listed above,
all five full DDI pages, and the workspace `/docs` endpoint. Additional `/asm`
queries: RtlCompressWorkSpaceSizeLZNT1, RtlCompressBufferLZNT1,
LZNT1CompressChunk. `/api/modules/ntdll` reports version `10.0.19041.2788`,
PDB key `76C7BBFD419865CA30108FE0023CF0401`; the surrounding corpus OS build
must not be confused with this DLL version. DDI pages remain partial,
kernel-context contracts; the user-mode branches supply the hard expectations.

### Exact retained failure triage

| Test | Wine / Windows expectation | Verified Windows branch |
| --- | --- | --- |
| rtl_compression_workspace_standard | `c=0x10` / `0x10020` | RVA 0x85cf0 writes `0x10020` for engine zero. |
| rtl_compression_workspace_maximum | `c=0x10` / `0x20` | RVA 0x85cda compares engine with `0x100`; 0x85cdf writes `0x20`. |
| rtl_compression_workspace_hiber | success / `0xc00000bb` | RVA 0x85cdd branches for engine other than zero or `0x100`; 0x85cf8 returns `0xc00000bb` before output writes. |
| rtl_compression_roundtrip_zeros | success / `0x117` | LZNT1CompressChunk 0x10c6bf..0x10c6ce uses `neg; sbb; not; and 0x117`, yielding `0x117` for a zero literal accumulator. RtlCompressBufferLZNT1 0x10c94c preserves the all-zero flag only for that status; 0x10c981..0x10c988 returns `0x117` when it remains set. The DDI page also specifies STATUS_BUFFER_ALL_ZEROS. |

Removed the secondary HIBER workspace-size check after an unexpected success:
it incorrectly applied the standard-engine size to an engine Windows rejects.
The status mismatch remains a hard failure. Error-output sentinels are still
checked when the returned status matches the verified error path.

### Safety and added coverage

- No malformed streams: decompression consumes only matching-compressor output;
  invalid formats 0, 1 and 5 return in the public dispatch wrappers before any
  stream or the small dummy workspace is accessed.
- Actual input/output capacities are 12288/16384/12289 bytes for roundtrips,
  4096/8192/8192 for compression boundaries, and 32/64 for invalid dispatch.
  Output sentinels are in backing storage, not beyond its end; runtime guards
  reject oversized workspace requests and allocation failures before use.
  Boundary tests explicitly fail on an invalid workspace size before returning,
  rather than silently passing without a compression call.
- Exact compressed bytes are compared only between repeated calls using the
  same input, engine and workspace, never against a presumed Windows encoding.
  Final decompressed size is checked independently before the content check.
- Added `fragment_zero_capacity` and `fragment_end`, both with a valid generated
  two-chunk stream. RtlDecompressFragmentLZNT1's partial-chunk branch copies zero
  bytes for capacity zero; its full-chunk skip path assigns final size zero at
  EOF. These are implementation-verified boundaries, not malformed-stream tests.
- No process-global mutation, children, threads, waits or handle leaks occur.
  Workspaces are freed on both success and failure paths. Native execution and
  XPRESS coverage remain outstanding; no native success is inferred from Wine.

### Reviewed build and smoke

`make build/rtl_compression.exe build/rtl_environment.exe` succeeded without
warnings. Required sandbox command (exit **1**, expected retained differences):

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_compression.exe >/tmp/opencode/ntdll_review_compression.log 2>&1
```

Log line 103:
`SUMMARY tests=45 failed=4 skipped=7 checks_pass=829 checks_fail=4`.
34 passed, four failed as individually triaged above, seven skipped for missing
RtlDecompressBufferEx. Added tests pass at log lines 8-11. No exception output.

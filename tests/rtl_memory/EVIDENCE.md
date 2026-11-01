# RTL memory evidence

Authority: Windows corpus, not Wine. Service instructions:
http://docker1.dev.moonlightcompanies.com:8765/SKILL.md . Queries were sequential
with HTTP 503 retry handling. Windows execution was not available.

## Compare

- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCompareMemory/docs
  identifies the exact RtlCompareMemory documentation.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCompareMemory/decomp
  RVA 0xa19d0: length < 8 / differing alignment takes byte comparison; otherwise
  qword comparison is followed by byte refinement. Return is the matching prefix
  length (`plVar5 - param_2`), not a memcmp ordering result or total equal bytes.
  Covers empty, equal, first/last/middle mismatch, qword boundaries and unaligned
  starts. Both argument orders must yield the same prefix length.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCompareMemoryUlong/docs
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCompareMemoryUlong/decomp
  RVA 0xa1a50: word count is `param_2 >> 2`; mismatch reduces the count to the
  leading equal ULONGs; return is `uVar2 * 4`. Therefore a 3-byte length returns
  zero, and a 7-byte length compares only the first ULONG. Inputs are ULONG
  aligned and all bytes are backed by valid storage.

## Fill, zero, overlap-safe move

- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFillMemory/decomp
  RVA 0xfc290 delegates to `memset(destination,(uint)byte_value,length)`.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlZeroMemory/decomp
  RVA 0x87e00 delegates to `memset(destination,0,length)`.
  Tests check the whole array, including untouched prefix/suffix sentinels, for
  zero/one/odd/vector-sized ranges and high-bit byte values.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlMoveMemory/docs
  includes exact user-mode `win32/DevNotes/rtlmovememory.md` documentation.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlMoveMemory/decomp
  shared memory-copy body includes forward/backward paths with source loads
  before overlapping stores. Tests compare against an independent immutable
  pre-call snapshot, not against another invocation of the function. Covers
  empty, self, disjoint, adjacent, and both overlap directions at byte/vector/
  larger distances. Full-buffer comparison checks no stores outside destination.

The Compare/CompareUlong/Fill/Zero/Move implementations have no LastError stores
or error-reporting calls on these bounded paths; sentinel LastError checks are
confined to these APIs, not generalized to all ntdll routines.

## Excluded ULONG fill

- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFillMemoryUlong/decomp
  returned HTTP 404, as did its function docs endpoint.
- http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntdll/exports?q=RtlFillMemory
  returned only RtlFillMemory and RtlFillMemoryNonTemporal; no ULONG variant.
- http://docker1.dev.moonlightcompanies.com:8765/api/docs/for-symbol?name=RtlFillMemoryUlong&limit=3
- http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-rtlfillmemoryulong.md
  documents repeated ULONG pattern, ULONG-aligned destination and length a
  multiple of sizeof(ULONG). This is a **kernel** contract (NtosKrnl.exe), not
  proof of an ntdll user-mode export. Review removed the declaration and test:
  Wine exporting it does not establish Windows export availability or a Windows
  user-mode contract. It is not counted as ntdll coverage. Missing supported
  exports elsewhere still use REQUIRE and report SKIP, not a crash or failure.

## Pointer transformations

- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlEncodePointer/decomp
  RVA 0x71f40 XORs pointer with process cookie then rotates right.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlDecodePointer/decomp
  RVA 0x69f20 applies the inverse rotate then XORs the same cookie.
  Their docs endpoints returned no matched pages. Test only both round-trip
  compositions and repeated encoding stability, using NULL and actual local
  buffer addresses. Never dereference transformed values, assume encoded NULL
  is nonzero, assert a particular cookie, or assume cross-process equivalence.

## Writer runtime validation (before review)

`make build/rtl_memory.exe` succeeded without warnings. Executed only:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_memory.exe
```

Log `/tmp/opencode/ntdll_rtl_memory.log` ends with
`tests=48 failed=0 skipped=0 checks_pass=129 checks_fail=0`.
Wine exposed the optional ULONG fill export. No observed differences required
triage changes. All tested memory fits in fixed stack arrays; no global settings
  or child isolation are needed. Native Windows execution remained a gap.

## Adversarial review of writer commit 1e948cf

- Re-read the harness, WRITING_TESTS.md, and docs/SAFETY.md. Queries were made
  one at a time with bounded retry on HTTP 503. Reference responses are saved
  locally in `/tmp/opencode/ntdll_review_reference/`.
- Rechecked `/api/function/ntdll/<name>/decomp` and `/docs` for CompareMemory,
  CompareMemoryUlong, FillMemory, ZeroMemory, MoveMemory, EncodePointer, and
  DecodePointer (all names prefixed Rtl). Reconfirmed both ULONG-fill endpoints
  return 404 and the filtered exports endpoint lists only RtlFillMemory and
  RtlFillMemoryNonTemporal. No reference implementation code was copied.
- Added all 64 relative alignment pairs with a mismatch at every position of a
  65-byte range, plus a mismatch just outside the limit. Windows CompareMemory
  RVA 0xa19d0 selects its byte-only path when `(left ^ right) & 7` is nonzero;
  the old tests used matching relative alignments only. Expected prefix lengths
  come from constructed inputs, not a second API call.
- Added page-sized fill/zero, disjoint move, and overlapping moves in both
  directions at one-byte and 3072-byte distances. Entire destination backing
  arrays are checked against independent expected bytes/snapshots, including
  both untouched boundaries. Maximum move extent is 8193 bytes in an 8448-byte
  array; no invalid-pointer or resource-exhaustion tests were introduced.
  Move input bytes mix high index bits to avoid the old byte pattern's 256-byte
  period making page-distance copies observationally indistinguishable from a
  no-op. Checked all concrete COMP/FILL/MOVE vector extents against array sizes.
- Made the pointer test's aligned input explicitly 8-byte aligned. Pointer
  tests still check only stable inverse compositions: they do not independently
  establish the process-cookie value or exact encoded representation. This is
  a remaining coverage limitation, not proof of the Windows cookie algorithm.

Review build: `make build/rtl_heap.exe build/rtl_memory.exe` succeeded with no
warnings. Review smoke, exit 0:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_memory.exe
SUMMARY tests=55 failed=0 skipped=0 checks_pass=4349 checks_fail=0
```

Log: `/tmp/opencode/ntdll_review_rtl_memory.log` (summary line 112).
Net test change: 48 -> 55 (eight added, unexported ULONG fill removed).
No native Windows execution was available; Wine is only a compatibility smoke.

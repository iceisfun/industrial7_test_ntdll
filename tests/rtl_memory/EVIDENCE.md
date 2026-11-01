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

## Optional ULONG fill: explicit evidence gap

- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFillMemoryUlong/decomp
  returned HTTP 404, as did its function docs endpoint.
- http://docker1.dev.moonlightcompanies.com:8765/api/modules/ntdll/exports?q=RtlFillMemory
  returned only RtlFillMemory and RtlFillMemoryNonTemporal; no ULONG variant.
- http://docker1.dev.moonlightcompanies.com:8765/api/docs/for-symbol?name=RtlFillMemoryUlong&limit=3
- http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-rtlfillmemoryulong.md
  documents repeated ULONG pattern, ULONG-aligned destination and length a
  multiple of sizeof(ULONG). This is a **kernel** contract (NtosKrnl.exe), not
  proof of an ntdll user-mode export. The optional test uses only those valid
  arguments and REQUIRE skips when the export is absent. Wine exporting it does
  not establish Windows export availability or a Windows user-mode contract.

## Pointer transformations

- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlEncodePointer/decomp
  RVA 0x71f40 XORs pointer with process cookie then rotates right.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlDecodePointer/decomp
  RVA 0x69f20 applies the inverse rotate then XORs the same cookie.
  Their docs endpoints returned no matched pages. Test only both round-trip
  compositions and repeated encoding stability, using NULL and actual local
  buffer addresses. Never dereference transformed values, assume encoded NULL
  is nonzero, assert a particular cookie, or assume cross-process equivalence.

## Runtime validation

`make build/rtl_memory.exe` succeeded without warnings. Executed only:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_memory.exe
```

Log `/tmp/opencode/ntdll_rtl_memory.log` ends with
`tests=48 failed=0 skipped=0 checks_pass=129 checks_fail=0`.
Wine exposed the optional ULONG fill export. No observed differences required
triage changes. All tested memory fits in fixed stack arrays; no global settings
or child isolation are needed. Native Windows runs and optional ULONG-fill
user-mode implementation evidence remain gaps.

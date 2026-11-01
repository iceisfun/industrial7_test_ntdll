# rtl_bitmap — Windows 10 contract evidence

Authority: Windows 10 22H2 reference corpus, queried 2026-10-31. Read
<http://docker1.dev.moonlightcompanies.com:8765/SKILL.md> first. Requests were
serialized, with retry on HTTP 503. No external test implementations used.
The API's DDI pages describe kernel-mode routines (`contract: partial` for
ntdll); the user-mode ntdll implementation below is the hard-assertion authority.

## Retrieved implementation branches

Links are the actual `/decomp` requests. The matching `/docs` endpoint was also
retrieved for every listed function, except RtlTestBit which was read separately
after discovering RtlCheckBit is not a corpus function.

| Function / implementation URL | RVA | Branch or contract used |
|---|---:|---|
| [RtlInitializeBitMap](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInitializeBitMap/decomp) | 0x7b330 | Writes size at offset 0 and buffer pointer at offset 8 only. |
| [RtlSetBits](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSetBits/decomp) | 0x489e0 | `if (param_3 != 0)`; byte masks at first/last byte, full interior bytes set to 0xff. |
| [RtlClearBits](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlClearBits/decomp) | 0x4b7e0 | Same length guard, inverse masks and zero interior bytes. |
| [RtlSetAllBits](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSetAllBits/decomp) | 0x7b120 | Rounds storage to `(size >> 5) + ((size & 31) != 0)` ULONGs. |
| [RtlClearAllBits](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlClearAllBits/decomp) | 0x77f00 | `memset(buffer,0,((size>>5)+((size&31)!=0))*4)`. |
| [RtlTestBit](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlTestBit/decomp) | 0x855b0 | Reads byte `buffer[index >> 3]`, shifts by `index & 7`, returns low bit != 0. |
| [RtlAreBitsSet](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAreBitsSet/decomp) | 0x7af10 | Requires start < size; one-bit shortcut; length >= 2 requires length <= size-start; zero length and invalid range return FALSE. |
| [RtlAreBitsClear](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAreBitsClear/decomp) | 0xeb770 | Same range guards, masked bits must all be zero. |
| [RtlFindClearBits](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFindClearBits/decomp) | 0x85f50 | Hint >= size becomes 0; length branches `<64`, `64..127`, `>127`; no candidate gives 0xffffffff; nonzero hint permits restart. |
| [RtlFindSetBits](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFindSetBits/decomp) | 0x89ae0 | Set-bit search, same hint normalization and failure sentinel. |
| [RtlFindClearBitsAndSet](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFindClearBitsAndSet/decomp) | 0x486b0 | Only invokes RtlSetBits if result != 0xffffffff. |
| [RtlFindSetBitsAndClear](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFindSetBitsAndClear/decomp) | 0xec3c0 | Only invokes RtlClearBits if result != 0xffffffff. |
| [RtlNumberOfSetBits](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlNumberOfSetBits/decomp) | 0x76fb0 | Masks the last partial byte before counting; unused storage bits excluded. |
| [RtlNumberOfClearBits](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlNumberOfClearBits/decomp) | 0xecfa0 | `return *param_1 - RtlNumberOfSetBits(param_1)`. |
| [RtlFindNextForwardRunClear](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFindNextForwardRunClear/decomp) | 0x85e20 | Skips set bits then counts clear bits to next set bit/size; from >= size writes from and returns 0. |
| [RtlFindLastBackwardRunClear](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFindLastBackwardRunClear/decomp) | 0x525c0 | Scans backward from inclusive from; writes first clear index and returns run length. From >= size writes from and returns 0. |
| [RtlFindLongestRunClear](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFindLongestRunClear/decomp) | 0xec380 | Calls RtlFindClearRuns with capacity 1 and longest TRUE. |
| [RtlFindClearRuns](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFindClearRuns/decomp) | 0xec0a0 | Masks tail to set bits; FALSE stops at capacity; TRUE inserts runs by descending length and keeps longest at capacity. |

RVA values were checked against the response headers.

### Actual excerpts supporting the less obvious checks

Initialize (`0x7b330`):
```c
*param_1 = param_3;
*(undefined8 *)(param_1 + 2) = param_2;
```

AreBitsSet (`0x7af10`):
```c
if (param_2 < *param_1) {
  if (param_3 < 2) {
    if (param_3 == 1) { /* read one bit */ }
  }
  else if (param_3 <= *param_1 - param_2) { /* masked range */ }
}
return false;
```

FindClearBits hint / empty request (`0x85f50`):
```c
uVar11 = -(uint)(param_3 < *param_1) & param_3;
if (param_2 == 0) return (ulonglong *)(ulonglong)(uVar11 & 0xfffffff8);
```
Zero-length searches are not currently asserted; all search lengths are positive.

FindSetBitsAndClear mutation gate (`0xec3c0`):
```c
if (uVar9 != 0xffffffff) {
  RtlClearBits((longlong)param_1,uVar9,param_2);
}
return uVar9;
```

Forward run out-of-range branch (`0x85e20`):
```c
else { *param_3 = param_2; uVar5 = 0; }
return uVar5;
```
Backward run out-of-range branch (`0x525c0`):
```c
else { *param_3 = param_2; iVar5 = 0; }
return iVar5;
```
These writes are implementation evidence, even though the DDI documentation
calls the failure output meaningless. Wine's unchanged output is not substituted.

## Documentation URLs and prototype checks

Exact DDI pages were retrieved through
`http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/wdm/nf-wdm-<lowercase-function>.md`
for all supported functions except RtlTestBit (its `/docs` match was retrieved).
Examples of actual requests:

- <http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAreBitsClear/docs>
- <http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/wdm/nf-wdm-rtlarebitsclear.md>
  returns FALSE if length is zero, range is invalid, or any bit is set.
- <http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/wdm/nf-wdm-rtlfindclearbits.md>
  returns starting index or 0xffffffff.
- <http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlTestBit/docs>
  matches `wdm/nf-wdm-rtltestbit.md`; BOOLEAN return is required because upper
  return-register bytes in the decompilation are not a ULONG result.

`RtlCheckBit/decomp`, `RtlCheckBit/docs`, `RtlFindFirstRunClear/decomp`, and
`RtlFindFirstRunClear/docs` returned HTTP 404. No guessed prototypes for these
names are invoked. RtlTestBit covers bit checks; forward search covers first-run
semantics using from=0.

## Safety and remaining gaps

- 41 independently registered tests, with bounded vectors; bitmap <=257 bits.
- Backing buffers include extra initialized words for rounded implementation
  reads, outer guards, and model comparisons for exact range writes.
- No out-of-range mutations or bit reads; only predicates/searches with verified
  logical-failure paths receive invalid ranges or oversized requests.
- Pure bitmap routines have no documented LastError result; no fabricated
  error-code contract is asserted.
- Windows execution is still required; Wine is smoke only. Unverified tie-breaking,
  zero-length search return alignment, and empty-run output variants are not hard
  assertions. Single-bit set/clear exports and extended bitmap APIs remain gaps.

## Build and Wine smoke result

`make build/rtl_bitmap.exe` succeeds with the configured x64 MinGW compiler.
Run exactly:
```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_bitmap.exe >/tmp/opencode/ntdll_rtl_bitmap.log 2>&1
```
Observed summary (exit 1):
```text
SUMMARY tests=41 failed=2 skipped=1 checks_pass=1748 checks_fail=12
```
The failures are `rtl_bitmap_backward_run_boundaries` (all five successful-run
vectors return 0 and leave start=999, and the out-of-range vector leaves start
unchanged) and `rtl_bitmap_forward_run_boundaries` (only from=size leaves start
unchanged). RtlTestBit is missing and correctly skipped. The decompilation's
verified Windows return/output expectations remain hard checks, not Wine-derived
expectations. No native Windows run was available.

# RTL heap evidence

Authority: Windows 10 corpus advertised as 22H2 / build 19041.2965, not Wine.
Read the service instructions at
http://docker1.dev.moonlightcompanies.com:8765/SKILL.md .
All queries were sequential, with retry handling for HTTP 503. No Windows
execution was available; the runtime results below are compatibility checks only.

## Creation, allocation, cleanup

- http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-rtlcreateheap.md
  documents HEAP_GROWABLE when HeapBase is NULL, optional reserve/commit sizes,
  page rounding, and private single-thread-only HEAP_NO_SERIALIZE access.
  Tests exercise default, reserve-only, commit-only, both, and non-page sizes;
  they do not inspect undocumented actual reservation sizes.
- http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-rtlallocateheap.md
  documents successful allocation and HEAP_ZERO_MEMORY / HEAP_NO_SERIALIZE.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAllocateHeap/decomp
  RVA 0x2a9a0 dispatches to the NT or segment-heap implementation by signature.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpAllocateHeapInternal/decomp
  uses `param_3 & 8` for the zero flag, `memset(...,0,...)` on zeroed allocation;
  normalizes zero requested size internally (`if (param_2 != 0)` selects the
  requested size, otherwise the minimum allocation). The zero-size test never
  dereferences the returned block.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFreeHeap/decomp
  RVA 0x24760 explicitly returns 1 when the block argument is NULL, before
  inspecting the heap. Tests still supply a valid private heap.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlDestroyHeap/decomp
  successful NT-heap cleanup ends in `return ...0x0`; tests never reuse a
  destroyed heap. No process heap is destroyed.

## Size and validation

- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSizeHeap/decomp
  RVA 0x24160 computes logical size from block size minus unused bytes
  (`uVar12 * 0x10 - ...`), with separate virtual and segment paths. Requested
  size is checked, not rounded usable capacity. Only live owned blocks enter it.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlValidateHeap/decomp
  RVA 0x5e190: NULL block selects RtlpValidateHeap; a live block selects
  RtlpValidateHeapEntry. Segment path checks RtlpHpSizeHeap against -1. Tests
  validate intact heaps/blocks only and never manufacture corrupt metadata.

## Reallocation flags and preserved contents

- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlReAllocateHeap/decomp
  RVA 0x23640 routes ordinary private heaps to RtlpReAllocateHeapInternal.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpReAllocateHeapInternal/decomp
  calls RtlpReAllocateHeap with merged flags.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpReAllocateHeap/decomp
  the LFH path rejects `param_2 & 0x10` before allocating a replacement;
  replacement success copies min(old,new) bytes and only then frees old memory.
  The growth branch `local_118 < param_4`, with `local_res10 & 8`, calls
  `memset(old_address + old_size,0,new_size - old_size)`.
- http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/heapapi/nf-heapapi-heaprealloc.md
  documents the corresponding Win32 flags: ZERO_MEMORY only zeros new bytes,
  IN_PLACE_ONLY forbids movement, and failure leaves the original block valid.
  This is supporting wrapper documentation, not an exact RtlReAllocateHeap doc.
  Tests allow either result for in-place requests, checking pointer identity on
  success and original logical size/content on failure. They do not require
  particular fragmentation, LFH activation, or allocation addresses.

## Enumeration

- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlGetProcessHeaps/decomp
  RVA 0xf24a0 constructs end = buffer + capacity * 8 and enumerates heaps.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlGetProcessHeapsCallback/decomp
  RVA 0xf2520 increments the count unconditionally, but stores only while
  current < end. This supports capacity-zero query/no-write checks and checking
  a live private heap in a sufficiently large bounded inventory.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlWalkHeap/decomp
  RVA 0xf3390 delegates to RtlpWalkHeapInternal.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpWalkHeapInternal/decomp
  RVA 0x2560 dispatches ordinary heaps to RtlpWalkHeap.
- http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpWalkHeap/decomp
  writes address at entry+0, SIZE_T size at entry+8, flags at entry+0x12;
  reaching the virtual-list head selects `0x8000001a` (STATUS_NO_MORE_ENTRIES).
  Tests pass zeroed aligned oversized entry storage and inspect only the first
  two fields. Enumeration is bounded to 4096 calls with no concurrent heap
  users or mutations, and never dereferences returned free/region addresses.

## Validation and limits

`make build/rtl_heap.exe` succeeded without warnings. Executed only:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_heap.exe
```

Log: `/tmp/opencode/ntdll_rtl_heap.log`, final summary:
`tests=42 failed=0 skipped=0 checks_pass=313 checks_fail=0`.
One observation: in-place 17 -> 65536 was unavailable; preservation checks passed.
No expectation was weakened to match Wine.

Largest requested block is 262144 bytes; no OOM, bogus pointers, invalid flag
combinations, heap corruption, or irreversible global heap settings are used.
All cleanup exports are required before acquisition. Dependent calls are guarded
after allocation checks. No LastError guarantees are inferred for the heap
dispatchers: successful pointer/BOOLEAN/size returns and walk NTSTATUS are the
tested contracts. Missing exact docs for Size/Validate/Walk/GetProcessHeaps are
covered by the cited implementation branches, not by Wine behavior. Windows
execution, alternate segment/debug heap configurations, and cross-thread heap
serialization remain untested.

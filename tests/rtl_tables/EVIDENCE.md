# rtl_tables — Windows 10 contract evidence

Authority: Windows 10 22H2 reference corpus, queried 2026-10-31 after reading
<http://docker1.dev.moonlightcompanies.com:8765/SKILL.md>. All corpus requests were
serialized with HTTP 503 retry. No external test implementations used.

## Prototype and layout verification before testing splay tables

Local installed declaration reference:
`/usr/share/mingw-w64/include/ddk/ntddk.h`, lines 2683–2772 (enum, callback
types, layouts), 4777–4861 (splay functions), and 5014–5118 (AVL functions).
These declarations were read before defining local types and UDECLs. All calls
use dynamic UN resolution and REQUIRE; no ntdll import library is linked.

The corpus's exact initialization DDI pages independently spell out the callback
prototypes, CompareRoutine result ordering, signed CLONG allocation size, and
allocation/free ownership:

- <http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntddk/nf-ntddk-rtlinitializegenerictable.md>
- <http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntddk/nf-ntddk-rtlinitializegenerictableavl.md>

Actual callback excerpts (same shapes with RTL_AVL_TABLE for AVL):
```c
RTL_GENERIC_COMPARE_RESULTS (*PRTL_GENERIC_COMPARE_ROUTINE)(
    struct _RTL_GENERIC_TABLE *Table, PVOID FirstStruct, PVOID SecondStruct);
PVOID (*PRTL_GENERIC_ALLOCATE_ROUTINE)(
    struct _RTL_GENERIC_TABLE *Table, CLONG ByteSize);
VOID (*PRTL_GENERIC_FREE_ROUTINE)(
    struct _RTL_GENERIC_TABLE *Table, PVOID Buffer);
```
The pages specify GenericLessThan, GenericGreaterThan, GenericEqual; local enum
values match the installed header's order 0,1,2. x64 WINAPI matches NTAPI.

The user-mode initializer bodies verify layout: splay stores Compare/Allocate/
Free/Context at offsets 0x28/0x30/0x38/0x40; AVL zeroes 0x68 bytes and stores
callbacks/context at 0x48/0x50/0x58/0x60. Tests use real typed table pointers and
typed callbacks, never cast one table implementation into the other.

DDI pages are kernel-context (`contract: partial` for user-mode ntdll). The
user-mode implementations below decide conflicts, particularly AVL index order.

## Retrieved implementation branches and URLs

Each function's `/decomp` and corresponding `/docs` were retrieved. Exact DDI
pages from each `/docs` result were also read. Links below are actual decomp URLs.

| Function | RVA | Observed branch / expected contract |
|---|---:|---|
| [RtlInitializeGenericTable](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInitializeGenericTable/decomp) | 0x7da20 | NULL root, self-linked insertion list, count/cache zero, callbacks/context saved. |
| [RtlInitializeGenericTableAvl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInitializeGenericTableAvl/decomp) | 0x7ddd0 | `memset(table,0,0x68)`; root parent points to table itself. |
| [RtlInsertElementGenericTable](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInsertElementGenericTable/decomp) | 0x651a0 | FindNodeOrParent then RtlInsertElementGenericTableFull. |
| [RtlInsertElementGenericTableAvl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInsertElementGenericTableAvl/decomp) | 0x5ba20 | FindNodeOrParent then FullAvl. |
| [RtlInsertElementGenericTableFull](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInsertElementGenericTableFull/decomp) | 0x65210 | Found=1 bypasses allocation/copy; new node adds 0x28 overhead; failure returns NULL and clears optional NewElement. |
| [RtlInsertElementGenericTableFullAvl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInsertElementGenericTableFullAvl/decomp) | 0x5ba90 | Found=1 bypasses allocation/copy; new node adds 0x20 overhead; failure returns NULL and clears optional NewElement. |
| [RtlLookupElementGenericTable](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlLookupElementGenericTable/decomp) | 0x65320 | Found=1 splays node and returns node+0x28; otherwise NULL. |
| [RtlLookupElementGenericTableAvl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlLookupElementGenericTableAvl/decomp) | 0x5bc00 | Found=1 returns node+0x20; otherwise NULL. |
| [RtlDeleteElementGenericTable](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlDeleteElementGenericTable/decomp) | 0x65110 | Found=1 deletes links, decrements count, resets index cache, calls FreeRoutine on allocation base, returns TRUE; miss FALSE. |
| [RtlDeleteElementGenericTableAvl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlDeleteElementGenericTableAvl/decomp) | 0x5b7f0 | Calls AvlEx only for found=1; returns found==1. DDI confirms deletion ownership/free callback. |
| [RtlEnumerateGenericTable](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlEnumerateGenericTable/decomp) | 0x650a0 | TRUE finds leftmost; FALSE real successor; splays returned node; NULL at end/empty. |
| [RtlEnumerateGenericTableAvl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlEnumerateGenericTableAvl/decomp) | 0x64a10 | TRUE clears internal restart pointer at 0x38; delegates to WithoutSplayingAvl. |
| [RtlEnumerateGenericTableWithoutSplaying](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlEnumerateGenericTableWithoutSplaying/decomp) | 0x65900 | NULL caller cursor means leftmost; otherwise successor; updates only caller's cursor. |
| [RtlEnumerateGenericTableWithoutSplayingAvl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlEnumerateGenericTableWithoutSplayingAvl/decomp) | 0x64a30 | Empty count returns NULL; caller cursor walks leftmost/successor. |
| [RtlNumberGenericTableElements](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlNumberGenericTableElements/decomp) | 0x83a20 | Reads ULONG count at 0x24. |
| [RtlNumberGenericTableElementsAvl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlNumberGenericTableElementsAvl/decomp) | 0x81ad0 | Reads ULONG count at 0x2c. |
| [RtlGetElementGenericTable](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlGetElementGenericTable/decomp) | 0x7e790 | Rejects index UINT_MAX or index+1 > count; walks insertion list using cached index. |
| [RtlGetElementGenericTableAvl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlGetElementGenericTableAvl/decomp) | 0xf79a0 | Same rejection; walks leftmost then RealSuccessor/RealPredecessor: sorted order, NOT insertion order. |
| [RtlIsGenericTableEmpty](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlIsGenericTableEmpty/decomp) | 0x792f0 | `return *param_1 == 0` (root NULL). |
| [RtlIsGenericTableEmptyAvl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlIsGenericTableEmptyAvl/decomp) | 0x85400 | `return *(int *)(param_1 + 0x2c) == 0` (count zero). |

### Exact failure/copy excerpts

Splay Full (`0x65210`), after allocation failure:
```c
if (param_4 != (undefined1 *)0x0) { *param_4 = 0; }
puVar4 = (undefined8 *)0x0;
```
On success:
```c
RtlCopyMemory(puVar4 + 5,param_2,(ulonglong)param_3);
/* ... */
if (param_4 != (undefined1 *)0x0) { *param_4 = param_6 != 1; }
```

AVL Full (`0x5ba90`):
```c
if ((param_3 + 0x20 < param_3) || (/* allocation */ plVar2 == NULL)) {
  if (param_4 != NULL) { *param_4 = 0; }
  return NULL;
}
/* ... */
RtlCopyMemory(plVar2 + 4,param_2,(ulonglong)param_3);
```
Allocation failures in tests are one explicitly rejected small callback request,
not resource exhaustion; no overflow-sized request is made.

### Documentation conflict: AVL get-element order

<http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntddk/nf-ntddk-rtlgetelementgenerictableavl.md>
says “Ith element inserted”. The actual user-mode implementation instead starts
at leftmost and walks RealSuccessor, proving sorted order for the corpus build.
The test asserts sorted AVL order, insertion splay order; it does not duplicate
the DDI prose error.

## Test scope, lifetime and gaps

Originally 48 focused registered tests: 24 contracts exercised independently against each
implementation. Mixed insertion vectors force left/right navigation and indexed
cache movement. Data keys, payload, and trailing bytes are independently checked.
All tables are stack-local, accessed synchronously, with live callback/context
storage for the complete lifetime of all operations. Caller source modification
does not change copied table data; live element pointers survive other inserts.
No freed element or stale enumeration cursor is dereferenced.

Allocation callback registry records real base pointers; frees must correspond
to an outstanding allocation. Cleanup deletes all recorded keys, checks count=0
and successful allocations=frees, then frees any remaining allocations defensively.
All prerequisite checks happen before allocation and propagate explicit returns.
No garbage pointers, duplicate frees, or resource exhaustion are used.

Remaining: native Windows execution, large-tree depth invariants, Full/FullAvl
public entry points, directory/matching enumeration, standalone RtlSplay links,
and concurrent synchronization (not part of this table contract) are untested.
Callbacks may affect LastError, and these APIs expose no LastError contract;
results, out-flags, contents, counts, callback effects and cleanup are checked.

Original Wine-specific safety gates (narrowed by the review below) do not change Windows assertions: this Wine build's
AVL deletion export aborts as unimplemented, so AVL tests skip before allocation.
Splay NULL allocator callback crashes in Wine, so those two cases also skip
before allocating. The initial smoke observed those failures; they are not
evidence that the valid Windows failure cases are unsupported.

## Build and Wine smoke result

`make build/rtl_tables.exe` succeeds with the configured x64 MinGW compiler.
Run exactly:
```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_tables.exe >/tmp/opencode/ntdll_rtl_tables.log 2>&1
```
Final observed summary (exit 0):
```text
SUMMARY tests=48 failed=0 skipped=26 checks_pass=1526 checks_fail=0
```
22 splay tests execute successfully. 24 AVL tests skip because Wine's exported
deletion routine aborts, and two splay allocation-failure tests skip because
Wine crashes on the valid NULL callback result.

Initial exploratory smoke, before those safety gates, recorded two splay
allocation-failure exceptions `0xc0000005`. A later narrowed-prerequisite run
exposed the AVL issue directly and terminated before any summary:
```text
wine: Call from 00006FFFFFF30BA8 to unimplemented function ntdll.dll.RtlDeleteElementGenericTableAvl, aborting
```
Several additional AVL exports were absent (EnumerateGenericTableAvl,
GetElementGenericTableAvl, IsGenericTableEmptyAvl). These are emulator limitations,
not changes to the verified Windows contracts. Windows execution, especially all
AVL and callback-rejection cases, remains required.

## Adversarial review (2026-10-31; supersedes original smoke classification)

Reviewed writer `b86174a874357b89`, original smoke, harness nonfatal checks,
README safety rules, and HANDOFF. Re-fetched initialization, Full insertion,
AVL index `/decomp` and `/docs`, both initializer DDI pages, and initializer/
Full insertion `/asm` serially with HTTP 503 retry. No dependencies added.

### Findings and fixes

- **Overbroad AVL skip fixed.** Only deletion and cases that insert (including
  cleanup) retain the emulator safety guard. Safe initialize, empty lookup,
  empty enumeration and empty indexing now reach their own prerequisites.
  Removed the empty-predicate prerequisite from initialization and registered
  independent empty-predicate tests for both implementations: **50 tests** total.
  This exposes the real Wine initializer no-op as **one failure / five checks**,
  rather than silently skipping Windows-correct callback/context/root assertions.
- Wine source `wine/dlls/ntdll/ntdll.spec:620` marks AVL deletion `@ stub` (the
  original log observed its abort). `rtl.c:1583–1587` has a no-op initializer;
  `1613–1616` has a **void** insertion stub, not the Windows pointer-returning
  function. Calling it as a successful insertion risks dereferencing a meaningless
  return. Hence allocating cases remain skipped before allocation. Empty lookup
  is safe (`1621–1624`, returns NULL) and executes; a smoke pass of that test does
  not establish a functioning AVL tree. Missing enumeration/index/empty exports
  now report their exact REQUIRE failures instead of a blanket deletion reason.
- **Allocator rejection is supported by this Windows image.** Splay Full tests
  RAX at `0x6525a` and branches on NULL to `0xbf153`, clears optional NewElement
  at `0xbf158`, and returns NULL. AVL Full tests RAX at `0x5bae0`, branches to
  `0xbc7ea`, clears the flag at `0xbc7ef`, and zeros EAX at `0xbc7f2`. Both
  branches precede link/count mutation. These are bounded rejected requests,
  not overflow or exhaustion. Windows assertions remain intact. Wine
  `rtl.c:589–590` passes NULL directly to RtlInitializeSplayLinks, supporting
  the existing two explicit splay crash guards and the original fault log.
- Callback/structure audit: initializer assembly verifies splay offsets
  0x28/0x30/0x38/0x40 and AVL 0x48/0x50/0x58/0x60, with AVL memset size 0x68.
  `/api/types/ntdll/_RTL_AVL_TABLE` confirms the full 104-byte layout and gives
  AllocateRoutine as `void* (*)(_RTL_AVL_TABLE*, unsigned long)`. Corrected
  A_ALLOC to ULONG to match this exact user-mode PDB, rather than the DDI's
  CLONG prose. Small positive request values have identical x64 ABI; the shared
  allocator's signed conversion is bounded to these small requests. The splay
  type endpoint returned 404; its offsets were verified in assembly instead.
  Compare enum ordering and callback table parameters agree with the DDI pages.
- AVL indexed sorted order remains correct: decomp at 0xf79a0 walks leftmost,
  RealSuccessor/RealPredecessor, despite DDI's insertion-order wording.
- All prerequisites precede allocation and propagate through ready=0; every
  direct t_skip has an explicit return. Seed failure goes to cleanup. Cleanup
  uses recorded keys, no optional enumeration, then verifies count/free totals
  and releases only still-owned bases. Earlier deletes leave keys recorded but
  lookup avoids deleting them twice. A failed deletion is reported and residual
  allocations are freed only after all API calls, so no later table traversal
  uses those freed bases. No fail-path defect was found for conforming Windows.

### Review validation

`make build/rtl_bitmap.exe build/rtl_tables.exe` succeeded without warnings.
```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_tables.exe >/tmp/opencode/ntdll_review_tables.log 2>&1
```
Exit **1**, complete summary at log line 132:
```text
SUMMARY tests=50 failed=1 skipped=25 checks_pass=1537 checks_fail=5
```
24 passes (23 splay, one AVL empty lookup). Five failures at log lines 74–78
are the Windows-verified AVL context, root-parent, compare, allocate and free
initialization stores. Skips: 20 unsafe AVL insertion/deletion cases, three
missing AVL exports, two unsafe splay callback-rejection cases. This is improved
visibility, not a regression caused by weakening expected behavior. No native
Windows run was available; the remaining 25 skipped branches need it. Wine
safety gates are emulator-wide rather than version-probed, so later Wine
implementations should revisit them using their actual stub/NULL handling.

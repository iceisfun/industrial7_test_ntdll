# CRT memory, algorithms, and ASCII contracts

Reference inspected 2026-10-31: Windows 10 corpus described by
<http://docker1.dev.moonlightcompanies.com:8765/SKILL.md>. Corpus HTTP requests
were made one at a time with retry handling for 503. Bodies were read for
contracts, not copied. No Windows runtime execution was available.

## Memory

| Inspected Windows body | Contract and branches tested |
| --- | --- |
| [memchr](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/memchr/decomp) | Count-zero returns NULL; compare `(char)_Val` through count bytes, including embedded zero; return first match. Tests cover excluded end, repeated byte, and low-byte conversion. |
| [memcmp](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/memcmp/decomp) | Count-zero returns zero; first unequal unsigned byte sets sign. Body has byte alignment, 8-byte, and 32-byte loops. Tests place mismatches at first/last/boundary positions and reverse operands; compare signs, not exact magnitudes. |
| [memcpy](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/memcpy/decomp), [memmove](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/memmove/decomp) | Same reference entry, RVA 0xa3e80 (`RtlCopyMemory` / `RtlMoveMemory` aliases). Return original destination, zero count does no writes. Size branches: below 8, below 17, below 33, then vector-block copy. Explicit source-before-destination overlap branch copies backward. `memcpy` tests use separate arrays ONLY, despite aliasing; overlap is tested only through `memmove`. |
| [memset](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/memset/decomp) | Return destination; repeat low byte of value for exactly count bytes. Branches below 8, through 78, above 78, then 128-byte blocks. Include 78/79/80, 127/128/129, negative value, and 0x1234 low-byte behavior. |

All operations use valid buffers, including count-zero cases. Memory helpers
check the entire destination array (both surrounding regions included), return
pointer identity, and source preservation for disjoint copies. Overlap expected
results are computed from a saved pre-call snapshot, not from a second memmove.
Counts are at most 255, array sizes at most 512. No inaccessible-memory probes,
page-guard tests, stress cases, or overlap through memcpy are used.

## Sorting and searching callbacks

- [qsort decompilation](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/qsort/decomp):
  validation rejects NULL base with nonzero count, zero width, and NULL
  comparator via `_invalid_parameter`. Count 0/1 skips sorting/callbacks.
  Above 8 elements selects the partition path; at most 8 uses the smaller sort.
  Callback receives `(left, right)` and its sign controls ordering.
- [qsort_s decompilation](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/qsort_s/decomp):
  same validation and count gating. Small-sort guarded indirect dispatch is
  explicitly `(_Context, puVar6, puVar8)`, confirming the three-argument callback
  for the tested count range. Tests include descending context, duplicate/all
  equal input, sorted input, and zero/singleton callback suppression.
- [bsearch decompilation](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/bsearch/decomp):
  comparator receives `(key, candidate)`. Zero count returns NULL without
  comparison; singleton compares directly. Odd/even counts choose their
  respective midpoint and sign selects the next half. Same invalid-parameter
  validation as sorting. Keys below, above, between, at endpoints, and at odd/
  even midpoint are tested, with pointer identity checked.
- [bsearch_s decompilation](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/bsearch_s/decomp)
  elides the third comparator parameter. The
  [assembly](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/bsearch_s/asm)
  settles it: `0x18008ef29 mov rcx,[rsp+0x78]` loads context,
  `0x18008ef36 mov rdx,r13` loads key, `0x18008ef47 mov r8,r14`
  loads candidate, then `0x18008ef4a call [rsp+0x70]` invokes comparator.
  Singleton repeats the three-register setup at 0x18008ef77..0x18008ef82.

All exported pointers use SDK-typed `UIN("ntdll.dll", ...)` and REQUIRE.
Callbacks are explicitly `__cdecl`, and the secure callbacks check exact context
identity before dereferencing it. Context direction changes ordering, not just
an incidental callback counter. Tests avoid exact callback counts except the
verified zero-callback count-0/1 sorting and count-0 searching paths.
Sorts check order AND multiplicities, with surrounding sentinels; searches check
key and array preservation. Invalid validation branches are not called.

### Reference uncertainty

[qsort_s assembly](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/qsort_s/asm),
[address/capstone request](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/0x90570/asm?flavor=capstone),
and [objdump request](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/qsort_s/asm?flavor=objdump)
returned HTTP 404. Its partition-path decompilation omits some callback arguments.
Therefore secure-sort tests deliberately stay at count <= 8, where the full
three-argument dispatch is visible. Ordinary qsort also covers 9, 17, and 32.
Larger secure-sort partitions, large element widths, search duplicate-selection
policy, and invalid-parameter-handler recovery remain gaps.

## ASCII character classes and case conversion

Read each class body:
[isalnum](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/isalnum/decomp),
[isalpha](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/isalpha/decomp),
[iscntrl](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/iscntrl/decomp),
[isdigit](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/isdigit/decomp),
[isgraph](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/isgraph/decomp),
[islower](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/islower/decomp),
[isprint](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/isprint/decomp),
[ispunct](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/ispunct/decomp),
[isspace](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/isspace/decomp),
[isupper](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/isupper/decomp),
[isxdigit](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/isxdigit/decomp).
Each indexes the shared ushort table using the low byte (special-casing -1)
and returns a masked value, NOT a normalized boolean. Tests assert only truth
or falsity for every ASCII value 0..127, split into controls, printable, and DEL.

Actual reference data was checked rather than assuming the table contents:

- [Pointer bytes at RVA 0x166150](http://docker1.dev.moonlightcompanies.com:8765/api/bytes/ntdll?rva=0x166150&len=8)
  are `a04f128001000000`, little-endian VA 0x180124fa0, hence RVA 0x124fa0.
- [First 128 table entries](http://docker1.dev.moonlightcompanies.com:8765/api/bytes/ntdll?rva=0x124fa0&len=256)
  were decoded as 128 little-endian ushorts. A Python check compared all entries
  against the test's ASCII predicates for each class's actual mask. All 11 x 128
  combinations matched. Masks read from the bodies: 0x107, 0x103, 0x20, 4,
  0x117, 2, 0x157, 0x10, 8, 1, 0x80 respectively.
- [__pctype_func](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/__pctype_func/decomp)
  returns `_pctype`.
- [tolower](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/tolower/decomp)
  adds 0x20 only when table bit 1 is set.
- [toupper](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/toupper/decomp)
  calls `RtlAnsiCharToUnicodeChar` then `RtlUpcaseUnicodeToMultiByteN` rather than
  using a simple C-locale arithmetic implementation. Tests restrict it to ASCII
  letters and unchanged ASCII controls/digits/punctuation/DEL. Non-ASCII/codepage
  behavior and EOF conversion are deliberately not asserted.

No locale state is changed. No math tests were added; abs/labs remain owned by
rtl_numeric. CRT operations here do not use GetLastError as their result channel.

## Build and smoke

`make build/crt_algorithms.exe` succeeds without warnings after removing
redundant declarations (the secure prototypes are supplied by MinGW's
`sec_api/stdlib_s.h`, lines 15 and 51). A separate `-O1 -Wall -Icommon -c`
compile plus `x86_64-w64-mingw32-nm -u` reports only `t_check`, `t_proc_in`,
`t_register`, and `t_skip`, confirming no direct CRT or compiler-lowered CRT
references in the test object.

Smoke command, exit 0:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/crt_algorithms.exe > /tmp/opencode/ntdll_crt_algorithms.log 2>&1
SUMMARY tests=155 failed=0 skipped=0 checks_pass=42505 checks_fail=0
```

This is only Wine smoke validation. Windows execution remains outstanding.

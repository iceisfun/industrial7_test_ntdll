# ldr_image evidence

Authority: Windows 10 x64 corpus, queried serially through
http://docker1.dev.moonlightcompanies.com:8765/SKILL.md . Windows execution
has not been available; Wine is only a development smoke test.

## Loader contracts

All URLs below have the prefix
`http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/`.

- `LdrGetDllHandle/decomp` (RVA 0x16870) delegates to
  `LdrGetDllHandleEx/decomp` (0x168a0) with flag 1. The latter skips the
  increment when `(flags & 1) != 0` and writes the module base on successful lookup.
  The tests only query already-loaded ntdll/kernel32, including case and
  extension variants. They never unload a borrowed handle.
  `LdrpFindLoadedDll/decomp` (0x1db20) calls
  `LdrpPreprocessDllName/decomp` (0x1a360), which appends the default
  extension when no dot appears in the final component.
  `LdrpFindLoadedDllByName/decomp` (0x2113c) uppercases ASCII lowercase
  letters while computing the lookup hash.
- `LdrGetProcedureAddress/decomp` (0x81bd0) delegates to
  `LdrGetProcedureAddressForCaller/decomp` (0x2fdc0). Its name preparation
  branch computes Length+1 and copies exactly Length bytes plus a new NUL
  when MaximumLength is insufficient or Buffer[Length] is not NUL. This
  supports counted, deliberately non-NUL-terminated names backed by valid
  local storage. Original bytes must remain unchanged.
- `LdrpGetProcedureAddress/decomp` (0x321c0) compares export names bytewise
  and returns 0xc000007a when no name matches. Missing/wrong-case exports
  check this status. Failure output pointer is logged, not asserted: the
  outer decompilation's stack-relative final store is difficult to interpret.
- `LdrLoadDll/decomp` (0x16a10) maps NULL characteristics to zero and writes
  the returned module base only after successful loading.
  `LdrUnloadDll/decomp` (0xfbf0) finds the loaded entry and decrements its
  load count. Four tests acquire one/two references to known system modules,
  then unload precisely the references they acquired, in reverse order.
  No manual loader-lock acquisition, application DLL initialization, search
  path modification, invalid handle, or unloading of borrowed references.

## PE parsing contracts

- `RtlImageNtHeader/decomp` (0x35bd0) calls
  `RtlImageNtHeaderEx/decomp` (0x32ad0), flags=1, with a zeroed output.
  Ex validates DOS 0x5a4d and NT 0x4550 signatures and locates the NT
  header at e_lfanew. The tests corrupt only these signatures within a
  fully readable allocation; relocated e_lfanew remains in bounds.
- `RtlImageDirectoryEntryToData/decomp` (0x7d9d0) returns NULL on a
  negative helper status. `RtlpImageDirectoryEntryToDataEx/decomp`
  (0x32920), PE32+ branch: rejects directory >= NumberOfRvaAndSizes;
  returns before writing Size for a zero RVA; otherwise writes directory
  size before mapping. Mapped view and header RVAs return base+RVA.
  Raw section RVAs use RtlAddressInSectionTable; gaps yield NULL but
  preserve the already-written directory size. Tests distinguish these
  output contracts using 0xdeadbeef.
- `RtlImageRvaToVa/decomp` (0x86970) and
  `RtlImageRvaToSection/decomp` (0x33aa0): section membership uses
  VirtualAddress <= RVA < VirtualAddress+SizeOfRawData, not VirtualSize.
  Result is base+PointerToRawData+(RVA-VirtualAddress). A supplied cache
  is searched again when empty or outside its raw interval, and updated
  on success. Tests cover both endpoints, virtual-only tail, gap, second
  section, empty cache, and a cache miss pointing at another valid section.

Fixture: aligned 16-KiB zeroed local buffer; PE32+ header at 0x80;
two raw sections [0x1000,0x1200) -> 0x400 and [0x2000,0x2400) -> 0x600.
Mapped and raw return addresses are checked without dereferencing returned
unvalidated pointers. One additional header test uses the loaded ntdll image.

## Documentation coverage and gaps

Queried `/docs` for LdrGetDllHandle, LdrGetProcedureAddress, LdrLoadDll,
LdrUnloadDll, RtlImageNtHeader, RtlImageDirectoryEntryToData, RtlImageRvaToVa:
all returned total=0. Expectations therefore derive from the concrete
decompiled branches, not an invented documentation contract. No ordinal
lookup, forwarded export policy, malformed offset probing, PE32, or
version-specific failure-output contract is claimed. Low-bit tagged bases
were added during review below.

## Development validation

`make build/ldr_image.exe` succeeds without compiler warnings.
Run only via:
`TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/ldr_image.exe >/tmp/opencode/ntdll_ldr_image.log 2>&1`

Initial smoke result: 40 tests, 2 failed, 0 skipped, 88 checks passed,
6 checks failed. Both failures are the counted-name successful-lookup
contract: Wine returns 0xc000007a for `NtClose` and `RtlImageNtHeader`
when MaximumLength=Length and Buffer[Length]='!'. The Windows branch
explicitly makes a terminated copy in this case, so these assertions are
retained rather than weakened to Wine behavior. Native Windows confirmation
remains outstanding.

## Adversarial review

Reviewed writer commit `4597e40`; all reference HTTP requests were serial
(503 retries supported; none needed). Re-read the wrapper decompilation,
`LdrGetProcedureAddressForCaller/asm`, and the exact export records from
`/api/modules/ntdll/exports?q=NtClose` and `?q=RtlImageNtHeader`.
The records name `NtClose` at RVA 0x9d230 (ordinal 262) and
`RtlImageNtHeader` at RVA 0x35bd0 (ordinal 1126), neither forwarded.

Both retained failures are verified separately:

| Test | Name / Length / MaximumLength | Windows expectation | Wine result |
|---|---|---|---|
| `ldr_image_proc_counted_close` | `NtClose` / 7 / 7 | success, matching export address | 0xc000007a, NULL |
| `ldr_image_proc_counted_header` | `RtlImageNtHeader` / 16 / 16 | success, matching export address | 0xc000007a, NULL |

In both cases Buffer[Length]='!'. At VA 0x18002fe3e-0x18002fe4a,
assembly loads Length and MaximumLength, computes Length+1, then uses
unsigned `jb 0x18002fe5d` when MaximumLength is smaller. Both names take
the stack-copy branch at 0x18002fe9f; 0x18002fea3-0x18002fead copies
exactly Length bytes, and 0x18002feb7 writes the new terminator. This
independently confirms the decompilation's polarity and exact boundary.
Each Wine test fails three checks (status, address equality, non-NULL),
not three independent behavioral differences. No expectation was weakened.

Fixes and additional scope:
- Zero the entire export-name buffer before inserting the non-NUL marker,
  so even an implementation incorrectly scanning beyond Length encounters
  a deterministic terminator inside the fixture.
- Check every load output for NULL before breaking; previously a successful
  status with NULL could pass without recording a failure. Unload still
  applies only to successful, non-NULL references acquired by this test.
- Add tagged-base raw section/header cases, based on the reread
  `RtlpImageDirectoryEntryToDataEx/decomp` at 0x32920: it clears low two
  bits and forces raw interpretation when bit 0 is set.
- Add a valid section-cache hit and an RVA in headers (not a section),
  based on reread `RtlImageRvaToVa` / `RtlImageRvaToSection` branches.

Bounds review: the 8-byte-aligned 0x4000-byte fixture contains the DOS,
NT, optional and two section headers, including the relocated header copy.
All synthetic RVAs, raw translations, cache pointers, and directory indices
used for memory access remain in that fixture. Rejected index 16 is checked
against count 16 before table access; the out-of-count case uses count 0.
Returned addresses are compared, never parsed/dereferenced. The real loaded
ntdll DOS header is read only after a non-NULL module check. The PE32+
fixture intentionally matches this repository's x86_64-only Makefile;
PE32 and ARM64 are not validated. No arbitrary invalid offsets are probed.
`common/t.h:75` explicitly returns after nonfatal `t_skip`; no bare
`t_skip` calls exist in this area. No global state changes or new resources.

Review validation:
- `make build/ldr_image.exe build/rtl_path.exe`: success, no warnings.
- `TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/ldr_image.exe >/tmp/opencode/ntdll_review_ldr_image.log 2>&1`
  exited **1**, with exactly the two retained failures above.
- `/tmp/opencode/ntdll_review_ldr_image.log:98`:
  `SUMMARY tests=44 failed=2 skipped=0 checks_pass=95 checks_fail=6`.
- `git diff --check -- tests/ldr_image tests/rtl_path`: success.

No native Windows execution or alternate-architecture run was available;
the retained differences are static Windows evidence plus Wine smoke, not
a claim of a successful native baseline. Ordinals, PE32, forwarded-export
policy, and malformed offsets remain scope gaps.

# nt_vm evidence

## Scope and authority

52 focused tests; native x64, dynamically resolved ntdll exports. Only this
process's small private allocations (normally 1–3 pages) and unnamed pagefile
sections are changed. No executable pages, physical-memory sections, files,
privileges, or system-wide state. Each successful fixture is guarded before use;
views are unmapped and allocations/handles released independently of CHECK results.

Reference corpus: Windows 10 22H2 build 19041.2965. Read
[corpus instructions](http://docker1.dev.moonlightcompanies.com:8765/SKILL.md).
Requests were sequential, with retries for HTTP 503. API docs label the DDI
Nt/Zw pages **partial** for ntdll because of kernel/user context differences.
Only common memory semantics are used; no kernel-only handles or PreviousMode
assumptions are transferred into the tests.

## Documentation read

- [NtAllocateVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-ntallocatevirtualmemory.md): RegionSize is rounded up to page size and cannot be zero; reserve/commit protections and successful NTSTATUS.
- [NtFreeVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-ntfreevirtualmemory.md): decommit preserves reservation, recommitted pages are zeroed, zero-size release frees the allocation. The documented nonzero-release restriction was NOT turned into a hard check: the actual service has a range-release path.
- [NtQueryVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-ntqueryvirtualmemory.md): MemoryBasicInformation describes state, allocation base, protection and type.
- [NtCreateSection](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-ntcreatesection.md): NULL file handle is pagefile backing, MaximumSize rounds to a page.
- [ZwMapViewOfSection](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/wdm/nf-wdm-zwmapviewofsection.md): zero ViewSize maps the remaining section, nonzero sizes round up, compatible readonly/readwrite views, multiple concurrent views. User callers use NtMapViewOfSection.
- [ZwUnmapViewOfSection](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/wdm/nf-wdm-zwunmapviewofsection.md): any address inside a view identifies the whole view for unmapping.
- [NtQuerySection](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/win32/DevNotes/ntquerysection.md): user-mode full contract; SECTION_BASIC_INFORMATION layout, MaximumSize and SEC_COMMIT.

## Actual routines inspected

All links below return decompiled C, unless `/asm` is specified. Decompiler
parameter recovery is not treated as an ABI declaration.

- [ntdll NtReadVirtualMemory stub](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/NtReadVirtualMemory/asm), RVA 0x9d830, syscall 0x3f; [NtWriteVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/NtWriteVirtualMemory/asm), RVA 0x9d790, syscall 0x3a. These stubs do not implement the memory contract.
- [NtAllocateVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtAllocateVirtualMemory/decomp), RVA 0x67d390: rejects `AllocationType & 0x44000`; outputs are copied back only for nonnegative status. [MiAllocateVirtualMemoryPrepare](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/MiAllocateVirtualMemoryPrepare/decomp) inspected for validation context. Negative allocation tests assert failure and unchanged base/size rather than guess an exact status.
- [NtFreeVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtFreeVirtualMemory/decomp), RVA 0x624b20, delegates to [MmFreeVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/MmFreeVirtualMemory/decomp), RVA 0x624bf0. The first condition rejects both/neither release/decommit bits with `-0x3fffff0e`, i.e. STATUS_INVALID_PARAMETER_4 (0xc00000f2). Range rounding and MiDecommitRegion / MiFreeVadRange paths are distinct.
- [NtProtectVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtProtectVirtualMemory/decomp), RVA 0x67ba90: invalid protection mask gives 0xc0000045; zero RegionSize gives 0xc00000f1 before handle lookup. [MmProtectVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/MmProtectVirtualMemory/decomp) aligns the first address with `& ~0xfff` and last address with `| 0xfff`, writes rounded size and prior protection. Tests never dereference noaccess pages.
- [NtQueryVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQueryVirtualMemory/decomp) delegates to [MmQueryVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/MmQueryVirtualMemory/decomp), RVA 0x621f60. Class 0 requires at least 0x30 bytes; [short-buffer helper](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/FUN_1407f7e41/decomp) returns 0xc0000004. Invalid class returns 0xc0000003.
- [NtReadVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtReadVirtualMemory/decomp) and [NtWriteVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtWriteVirtualMemory/decomp) delegate to [MiReadWriteVirtualMemory](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/MiReadWriteVirtualMemory/decomp), RVA 0x678ee0. Zero count bypasses copying and returns success/count zero; optional count pointer is checked; ordinary copying uses MmCopyVirtualMemory. All pointers in these tests address owned readable/writable storage, including cross-page copies.
- [NtCreateSection](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtCreateSection/decomp) and [NtMapViewOfSection](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtMapViewOfSection/decomp), RVA 0x621590: mapping initializes parameters and writes view size/base only after successful mapping. The latter's split cleanup is not inferred from its incomplete recovered return type.
- [NtQuerySection](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQuerySection/decomp), RVA 0x6cc110: class 0 requires 0x18 bytes; short buffer returns 0xc0000004, unknown class 0xc0000003, success writes ReturnLength 0x18.

## Smoke validation and gaps

Built with `make build/nt_vm.exe` without compiler diagnostics. Ran only:

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_vm.exe >/tmp/opencode/ntdll_nt_vm.log 2>&1
```

Initial writer smoke: **51 tests, 3 failed, 0 skipped, 433 passing checks, 3 failing checks**;
exit 1, no exception/timeout. Retained Windows-specific expectations:

| Test | Wine | Windows service branch |
|---|---|---|
| section invalid class | 0xc0000002 | 0xc0000003 |
| conflicting free types | 0xc000000d | 0xc00000f2 |
| protect zero size | success | 0xc00000f1 |

These are smoke differences, not Windows-baselined results. No Windows execution
was available. Internal section construction, page-fault zeroing and
MmCopyVirtualMemory were not exhaustively traced; valid-call assertions rely on
the documented allocation/view semantics in addition to inspected service paths.
No arbitrary bad pointers, use-after-free reads, guard faults, exhaustion or
remote-process memory operations are included.

## Adversarial review (2026-10-31)

Reviewed the writer's 51 tests and `/tmp/opencode/ntdll_nt_vm.log` against the
actual corpus again, one API request at a time, retrying 503. This is **static
Windows implementation verification, not execution on Windows**. The harness's
CHECK/EXPECT_EQ are nonfatal (`common/t.h:58-75`).

### Failure triage and validation order

The `/api/syscalls?q=<name>` mappings independently connect ntdll services
NtFreeVirtualMemory (0x1e), NtProtectVirtualMemory (0x50), and NtQuerySection
(0x51) to the kernel routines cited above. User-mode buffers here are owned,
fully backed and naturally aligned; probes occur before the section class/size
checks and before free's internal flag validation. No kernel-only Zw assumptions
or invalid-pointer shortcuts are used.

- **Section invalid class:** `/asm` confirms RVA 0x81439e loads 0xc0000003;
  0x6cc196 checks length only after selecting a recognized class. Added a zero-
  length/invalid-class case to lock that precedence. Both failure paths leave
  output bytes and ReturnLength unchanged; 0x6cc226 writes ReturnLength only on
  success. The user-mode NtQuerySection doc was re-read, not a kernel substitute.
- **Conflicting MEM_RELEASE|MEM_DECOMMIT:** NtFreeVirtualMemory captures inputs,
  calls MmFreeVirtualMemory and copies back only on success. Mm's initial
  `(FreeType & 0xc000) == 0xc000` branch returns `-0x3fffff0e`, computed as
  0xc00000f2. Retained the exact status, added unchanged base/size checks.
- **Zero protect size:** `/asm` at 0x67bbd0 tests size and branches to the
  0xc00000f1 return at 0x8087e1. Invalid protection is rejected earlier, at
  0x80878a (0xc0000045). These early failures do not copy back base/size/old
  protection. Added sentinel checks. Wine additionally changes OldProtection
  to PAGE_NOACCESS (1) for invalid protection; this is a newly exposed output
  discrepancy, not grounds to weaken the expectation.

The MmFreeVirtualMemory `/asm` request returned HTTP 404 (`no listing available`,
capstone not importable / objdump unavailable); its validation and output checks
are supported by the service/helper decompilations, not a claimed assembly read.

### Safety fixes

- Validate allocation size before returning fixtures; guard commit/recommit
  output address/length before zero-fill indexing. Reset recommit inputs to the
  owned page rather than reusing possibly malformed decommit outputs.
- Guard section view lengths before scanning or indexing a second shared view;
  report a successful NULL second-view pointer as a failure.
- Keep the section handle live for final cleanup when early CloseHandle fails;
  retry interior unmap failure with the original view base. If conflicting free
  unexpectedly succeeds, query the original allocation and release a surviving
  owned reservation rather than unconditionally leaking it or double-freeing it.
- Initialize query buffers so a broken successful implementation cannot cause
  reads of indeterminate fixture fields. These guards do not promise recovery
  from arbitrary corruption or from an OS refusing every cleanup operation.

### Review smoke

Built only `build/nt_vm.exe` and `build/nt_process.exe` with
`TMPDIR=/tmp/opencode make build/nt_vm.exe build/nt_process.exe`, without compiler
diagnostics. VM run:

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_vm.exe > /tmp/opencode/ntdll_review_vm.log 2>&1
```

**52 tests, 5 failed, 0 skipped; 489 passing checks, 5 failing checks; exit 1.**
No exception/timeout. Failures: the original three, the added invalid-class-before-
length test (same Wine 0xc0000002), and invalid-protection OldProtection sentinel
(Wine 1 instead of untouched 0xa5a5a5a5). Every retained assertion has the Windows
branch evidence above. No native run was performed; valid allocation/page-fault
semantics and internal section construction remain non-exhaustive as stated above.

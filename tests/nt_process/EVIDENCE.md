# nt_process evidence

## Scope and authority

47 focused tests. All process/thread handles refer to this process or its calling
thread. Only safe read-only process/thread/system information classes are queried.
Handles are duplicated/closed, but no process or thread is killed, suspended,
created, modified or debugged; no privileges or security policy are changed.
System information is limited to Basic (0), TimeOfDay (3), Exception (33).
Environment-dependent priorities, parent IDs, affinity and debug-port values are
notes, not hard expected constants. No kernel pointers returned by queries are
dereferenced.

Read [corpus instructions](http://docker1.dev.moonlightcompanies.com:8765/SKILL.md)
and queried serially, retrying HTTP 503. Corpus target is Windows 10 22H2 build
19041.2965. DDI pages are partial context matches for ntdll; user-mode pages and
actual Nt service branches provide the relevant contracts. Decompiled signatures
are not used as prototypes.

## Documentation read

- [NtQueryInformationProcess](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/winternl/nf-winternl-ntqueryinformationprocess.md): BasicInformation PID/PEB/exit status, DebugPort pointer-size result, Wow64Information pointer-size result (zero in native x64), ImageFileName UNICODE_STRING plus in-buffer string and sizing protocol.
- [NtQueryInformationThread](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/winternl/nf-winternl-ntqueryinformationthread.md): start address and I/O-pending queries, optional ReturnLength. ThreadBasicInformation layout/length additionally checked against the actual kernel branch below.
- [NtQuerySystemInformation](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/winternl/nf-winternl-ntquerysysteminformation.md): SystemBasicInformation public reserved layout and processor count; opaque TimeOfDay and 16-byte ExceptionInformation. No assertion on reserved contents or specific hardware counts.
- [NtOpenProcess](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntddk/nf-ntddk-ntopenprocess.md): ClientId identifies the process; object attributes initialized with no object name; requested query rights.
- [NtOpenThread](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/win32/DevNotes/ntopenthread.md): caller thread ClientId, query access and native status.
- [ZwDuplicateObject](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-zwduplicateobject.md): same-access duplication versus requested rights, object attributes, source/target process handles. No source-close option is tested.
- [NtQueryObject](http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/sdk-api/winternl/nf-winternl-ntqueryobject.md): PUBLIC_OBJECT_BASIC_INFORMATION (56 bytes), PUBLIC_OBJECT_TYPE_INFORMATION prefix containing a counted type name; optional length protocol.

## Actual service paths inspected

- [NtQueryInformationProcess](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQueryInformationProcess/decomp), RVA 0x636b80: class 0 accepts exactly 0x30 (basic) or 0x40 (extended), otherwise 0xc0000004; it writes ExitStatus/PEB/affinity/priority/PID/parent PID. Tests use only the 0x30 ABI and deliberately avoid treating arbitrary larger buffers as valid. Classes 7, 0x1a and 0x1b were read for scalar/image sizing paths.
- [NtQueryInformationThread](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQueryInformationThread/decomp), RVA 0x5f1760, probes user buffers then enters [FUN_1405f18a7](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/FUN_1405f18a7/decomp), RVA 0x5f18a7. The basic branch requires 0x30 and writes exit status/TEB/CLIENT_ID/affinity/priorities, optional ReturnLength 0x30. Case 9 requires 8 bytes and returns Win32 start address; case 0x10 requires 4 and returns pending-I/O boolean. Short sizes return 0xc0000004. Tests allocate full output storage even when advertising short sizes, so a permissive implementation cannot overrun the fixture.
- [NtQuerySystemInformation](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQuerySystemInformation/decomp), RVA 0x607ee0, delegates to [ExpQuerySystemInformation](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/ExpQuerySystemInformation/decomp), RVA 0x608060. Case 0 requires exactly 0x40, mismatch writes required size 0x40. Case 3 accepts the 0x30 fixture. Case 0x21 accepts at least 0x10 and writes four ULONG counters. No system process/handle enumeration, kernel address list or security-state query is used.
- [NtOpenProcess](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtOpenProcess/decomp) delegates to [PsOpenProcess](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/PsOpenProcess/decomp); [NtOpenThread](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtOpenThread/decomp) delegates to [PsOpenThread](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/PsOpenThread/decomp). Own PID/TID and valid OBJECT_ATTRIBUTES avoid invalid-ID and privilege-dependent cases.
- [NtDuplicateObject](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtDuplicateObject/decomp), RVA 0x5face0: source/target process handle access is PROCESS_DUP_HANDLE (0x40), result comes from [ObDuplicateObject](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/ObDuplicateObject/decomp). That routine handles same-access and supplied attributes separately before handle creation. [PspProcessOpen](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/PspProcessOpen/decomp), RVA 0x6b3310, adds 0x1000 when query-information bit 0x400 is requested; [PspThreadOpen](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/PspThreadOpen/decomp), RVA 0x6b3250, adds 0x800 for bit 0x40. Reduced-right tests therefore check required query access and absence of terminate access, not an incorrectly exact mask.
- [NtQueryObject](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQueryObject/decomp), RVA 0x634be0: basic class requires exactly 0x38; short-size branch dereferences and returns 0xc0000004 BEFORE common ReturnLength assignment. The test verifies a length sentinel stays zero in this case, rather than incorrectly applying the docs' general sizing description. Success builds Attributes from handle information, then GrantedAccess/counts, and reports 0x38. Class 2 delegates to ObQueryTypeInfo; only TypeName is interpreted, with bounds checked before comparing its contents.

## Smoke validation and gaps

Built with `make build/nt_process.exe` without compiler diagnostics. Ran only:

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_process.exe >/tmp/opencode/ntdll_nt_process.log 2>&1
```

Initial writer smoke: **45 tests, 6 failed, 0 skipped, 232 passing checks, 6 failing checks**;
exit 1, no exceptions or timeout. Differences retained against inspected Windows
branches:

| Test(s) | Wine | Windows expectation |
|---|---|---|
| duplicated inheritable handle | basic Attributes lacks bit 2 | OBJ_INHERIT bit 2 |
| system ExceptionInformation | 0xc0000003 | success with 16-byte buffer |
| thread start address, 7-byte advertised buffer | success | 0xc0000004 |
| thread basic, advertised 0/1/47 bytes | success | 0xc0000004 |

Wine is a smoke runner, not a baseline oracle. No Windows execution was available;
in particular the inheritable-handle result needs native confirmation. Type-name
strings and self pseudo-handle behavior are standard object-manager contracts;
the internal ObQueryTypeInfo and pseudo-handle resolution implementations were
not exhaustively traced. RtlCreateUserThread was intentionally omitted: no thread
creation is necessary to meet safe current-thread query coverage, and an untested
creation/timeout cleanup path would add risk. No child process was needed.

## Adversarial review (2026-10-31)

Re-read all 45 writer tests, the harness (nonfatal assertions), and
`/tmp/opencode/ntdll_nt_process.log`. Sequential corpus requests, retrying 503,
independently verified all six original failing tests against actual Windows
services. **No native Windows execution occurred.** The original statement that
inheritable handles need native confirmation remains a runtime-baseline gap, not
a reason to accept Wine's missing basic Attributes flag.

### Actual failure paths, not generic docs

The syscall API maps NtQueryInformationThread 0x25 to ntoskrnl RVA 0x5f1760,
NtQuerySystemInformation 0x36 to 0x607ee0, and NtDuplicateObject 0x3c to 0x5face0.
The ntdll stubs do not implement these contracts. Thread's user-mode entry checks
alignment (4 bytes for our 7/47-byte calls), address range and optional length
pointer before entering the class dispatch. Full-size aligned fixtures back all
advertised short sizes, including zero; none relies on a bad pointer.

- **ThreadBasicInformation sizes 0/1/47:** helper `/asm` at 0x5f1b33 compares
  size with 0x30 and `jne` targets 0x7ef715, which loads 0xc0000004. This returns
  before data/ReturnLength writes. Retained all three; added size 49, backed by
  a 64-byte aligned fixture, plus unchanged-buffer/length checks. Successful
  queries also check a 16-byte tail canary.
- **Thread start address size 7:** helper `/asm` at 0x7eeac4 compares with 8,
  `jne` reaches the same 0xc0000004 return. Only the successful branch writes
  the pointer and ReturnLength (0x7eeb17 / 0x7eeb1f). Added unchanged-output
  checks; no docs-based assumption that a short query writes required length.
- **SystemExceptionInformation (33):** ExpQuerySystemInformation `/decomp`
  case 0x21 and `/asm` 0x6094e7-0x60955c require at least 16, report 16 for a
  short buffer, and write four ULONG counters for success. Retained success
  expectation and added a 15-byte short-size query. Counts are opaque and never
  compared to environment-specific values. TimeOfDay similarly remains opaque;
  only the inspected 48-byte protocol is checked.
- **Inheritable duplicate:** NtDuplicateObject passes the supplied attributes
  to ObDuplicateObject separately from options. ObDuplicateObject `/decomp`
  preserves supplied attributes unless option bit 4 (DUPLICATE_SAME_ATTRIBUTES)
  is set; our inheritable case passes options zero and attributes 2. `/asm`
  0x67801b-0x67802a confirms this option branch. NtQueryObject `/decomp` class 0
  copies HandleAttributes from ObReferenceObjectByHandle's handle information
  into the first ULONG, without removing OBJ_INHERIT. Retained the exact bit-2
  expectation. Added class-4 (two BOOLEAN handle flags) queries to every duplicate
  case: **Wine reports Inherit=1 correctly there while basic Attributes is 0**.
  Thus the observed failure is the basic-info representation, not evidence that
  the test's attribute argument is wrong.

User-mode NtQueryInformationThread/SystemInformation and the partial-context
ZwDuplicateObject DDI page were re-read. The short-buffer ReturnLength statements
in general documentation do not override actual early-return branches. Requests
for NtQueryObject `/asm` (including explicit objdump) returned HTTP 404:
`no listing available`, capstone not importable / objdump unavailable. Its flag
representation is verified from `/decomp`, not claimed as assembly-verified.

### Additional output-state findings and safety

- ProcessBasicInformation invalid sizes 0/1/47/49 now verify ReturnLength stays
  untouched (initialized zero). `/decomp` returns immediately for sizes other
  than 0x30/0x40; `/asm` 0x637124-0x637128 branches straight to the 0xc0000004
  return at 0x63a69c, before length output. Wine writes 48 on these failures.
  The 0x40 extended ABI is deliberately **not** classified as an invalid length;
  it is not exercised by this basic-only fixture.
- Initialize process/thread/object/name query outputs before interpreting them;
  keep counted strings bounded and never dereference PEB/TEB/debug pointers.
  The I/O-pending note masks the unused upper ULONG of its pointer-sized fixture.
- Class sizes/statuses above target the inspected Windows 10 implementation;
  this is not a cross-version claim for arbitrary future information classes.
  Native x64 is intentional. Priorities, affinity, parent/debug-port values and
  actual processor/counter values remain notes rather than fixed host constants.
  Handle cleanup remains after checks; no fixture owns a handle at any REQUIRE
  return, and no close-source duplication or process/thread creation is used.

### Review smoke

Built only `build/nt_vm.exe` and `build/nt_process.exe` with
`TMPDIR=/tmp/opencode make build/nt_vm.exe build/nt_process.exe`, without compiler
diagnostics. Process run:

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_process.exe > /tmp/opencode/ntdll_review_process.log 2>&1
```

**47 tests, 12 failed, 0 skipped; 258 passing checks, 21 failing checks; exit 1.**
No exception/timeout. Exact triage:

| Failing tests | Wine observation | Inspected Windows expectation |
|---|---|---|
| inheritable duplicate | basic Attributes 0; class-4 Inherit 1 | basic OBJ_INHERIT 2; class-4 Inherit 1 |
| exception 16-byte query | 0xc0000003 | success, ReturnLength 16 |
| exception 15-byte query (new) | 0xc0000003, ReturnLength 0 | 0xc0000004, ReturnLength 16 |
| thread start address 7 bytes | success, ReturnLength 7, partial pointer overwrite | 0xc0000004; outputs untouched |
| thread basic 0/1/47/49 bytes (49 new) | success; nonzero sizes overwrite output/length | 0xc0000004; outputs untouched |
| process basic 0/1/47/49 bytes | expected mismatch status, but ReturnLength 48 | mismatch status; ReturnLength untouched |

All original six failures remain. Six additional failing tests expose the same
missing class/strict sizing and newly checked output-state differences; none is
converted into a permissive alternative. Remaining doubts: no native Windows
baseline, and no exhaustive ObQueryTypeInfo / object reference implementation
trace. These limitations are unchanged; no Wine-only claim is labeled Windows-
executed or universally version-independent.

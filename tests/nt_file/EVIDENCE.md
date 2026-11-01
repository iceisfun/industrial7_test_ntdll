# nt_file Windows evidence

Reference queried 2026-10-31: Windows 10 22H2 corpus, ntdll 19041.2788,
ntoskrnl 19041.2965. No third-party implementation is an assertion oracle.

API base: <http://docker1.dev.moonlightcompanies.com:8765/api>.
For every native API used, `/function/ntdll/<name>`, `/decomp`, and `/docs`
were queried serially. Native Nt decompilations are syscall wrappers: the
decompiler's apparent constant return is **not** the API's return contract.

## Contracts checked

* [NtCreateFile](https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntcreatefile):
  CreateDisposition describes open/open-if, overwrite/overwrite-if, supersede,
  and fail-if-existing create. IoStatusBlock.Information lists FILE_OPENED,
  FILE_OVERWRITTEN and FILE_SUPERSEDED. Existing-file create is the bounded
  STATUS_OBJECT_NAME_COLLISION (0xc0000035) case, not an invalid pointer probe.
* [NtOpenFile](https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntopenfile):
  success returns a handle; the DDI page describes it as the open-only subset
  of NtCreateFile. Each access vector includes SYNCHRONIZE for synchronous I/O.
* [NtReadFile](https://learn.microsoft.com/windows/win32/DevNotes/ntreadfile)
  explicitly describes its user-mode relationship to ZwReadFile, byte counts,
  explicit offsets, and synchronous completion. Tests check data and byte count
  for ten bounded length/offset vectors.
* [NtWriteFile](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile):
  Information is bytes written; writes extend EOF. Event/APC/key are NULL.
* [NtQueryInformationFile](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile):
  basic, standard, position, internal, name and all classes have the documented
  structures. Standard information for a fresh non-directory has zero EOF and
  no pending deletion; synchronous initial position is zero. Returned byte
  count is bounded by the supplied buffer. No timestamps or IDs are fixed.
* [NtSetInformationFile](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile):
  FileEndOfFileInformation can extend or truncate; FILE_WRITE_DATA is required.
  Tests set six lengths from zero through 65536 and query the resulting EOF.
* [NtQueryDirectoryFile](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerydirectoryfile):
  ReturnSingleEntry and a literal private filename constrain the scan to one
  object. Names/directory/full-directory classes return a bounded result;
  exhaustion is STATUS_NO_MORE_FILES (0x80000006) on the ordinary local scratch
  filesystem. The page calls this an appropriate status "such as
  STATUS_NO_MORE_FILES"; other filesystems may require revisiting that precise
  exhaustion assertion. No ordering or timestamps are asserted.
* [NtQueryVolumeInformationFile](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvolumeinformationfile):
  size, device, attributes and volume are documented classes; successful
  Information is bytes returned. Capacity, filesystem name and serial are not
  asserted. Exotic filesystems can return appropriate errors; no live Windows
  filesystem coverage was available here.
* [ZwFlushBuffersFile](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwflushbuffersfile):
  explicitly says use NtFlushBuffersFile from user mode and that flushing is
  synchronous. Empty and written private handles must complete successfully.

These DDI pages explicitly distinguish user Nt calls from kernel Zw calls.
Kernel-only IRQL, kernel-handle and PreviousMode rules are not imported into
the user-mode tests.

## Actual kernel service cross-checks

`/syscalls?q=<name>` resolves the following services; each service `/decomp`
was read, rather than assuming a kernel Zw alias was the same function:

| User service | Number | ntoskrnl RVA | Relevant branch |
|---|---|---|---|
| NtCreateFile | 0x55 | 0x5fbcf0 | delegates to IopCreateFile |
| NtOpenFile | 0x33 | 0x5fbc80 | delegates to IopCreateFile |
| NtReadFile | 0x06 | 0x5f9240 | references FILE_READ_DATA; synchronous flag chooses lock/wait path; fast completion admits 0xc0000011 EOF |
| NtQueryInformationFile | 0x11 | 0x5fb1c0 | class 0xe on synchronous handle copies current position and reports 8 bytes |
| NtQueryDirectoryFile | 0x35 | 0x6c5e40 | service dispatch, not a user-mode wrapper contract |

Example reproducible URL:
<http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/0x5fb1c0/decomp>.

`RtlDosPathNameToNtPathName_U` at ntdll RVA 0x17310 returns whether
`RtlpDosPathNameToRelativeNtPathName_U` returned a nonnegative status.
The converted allocation is released with dynamically resolved
RtlFreeUnicodeString. These are fixture prerequisites, not independent string
conformance assertions.

## Safety and validation

44 registered tests. Every scratch leaf has nt_file/PID/test identity under
t_tmpdir; create-new avoids overwriting a preexisting object. Cleanup deletes
only successfully created fixtures. Every native export and Win32 fixture
export is dynamically resolved and REQUIRE-guarded. Failed prerequisites skip;
nonfatal failed checks never permit dependent buffer use.
Win32 fixture helpers are explicitly pinned to kernel32 with REQUIRE/UIN, so
the suite does not depend on kernel32 being in the native export search list.

Maximum file length is 65536; no asynchronous handles, callbacks, raw devices,
unbounded scans, or global changes. Build: `make build/nt_file.exe`.

Wine smoke only (not Windows evidence):
`TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_file.exe >/tmp/opencode/ntdll_nt_file.log 2>&1`
reported `tests=44 failed=0 skipped=0 checks_pass=218 checks_fail=0`.
Native Windows execution remains unperformed.

## Adversarial review (2026-10-31)

Reviewed `common/t.h` and `common/t.c`, plus the test-pattern writing and safety
rules. `CHECK` and `t_skip` are nonfatal: prerequisite exits and cleanup were
checked explicitly. Scope remained this directory and `tests/nt_registry`.

Findings/fixes:

* Failed scratch-path conversion now frees any converted path allocation.
  Cleanup checks NtClose as well as DeleteFileW, and clears fixture ownership.
* File-standard/position parsing now requires the expected returned byte count.
  Compile-time checks pin the x64 IO_STATUS_BLOCK size/Information offset to
  16/8 and FILE_STANDARD_INFORMATION size/Directory offset to 24/21.
* Directory buffers explicitly have eight-byte alignment; an unsuccessful
  initial query no longer cascades into an exhaustion assertion.
* Added five position-buffer vectors (0, 1, 7, 8, 9 bytes) and one invalid-class
  case. These use valid aligned backing storage, check bytes beyond the passed
  length, and never assume IOSB contents on rejected requests.

Independent Windows authority re-checks, requested serially with 503 retries:

* `/function/ntdll/NtQueryInformationFile/asm`: RVA 0x9d270 loads service 0x11
  then executes syscall; it does not implement argument validation.
* `/function/ntoskrnl/NtQueryInformationFile/decomp` and `/asm`: RVA 0x5fb1c0
  calls IopValidateQueryInformationParameters; synchronous class 14 writes eight
  position bytes and sets IOSB.Status/Information to 0/8.
* `/function/ntoskrnl/IopValidateQueryInformationParameters/decomp` and `/asm`:
  RVA 0x5fbb50 validates **nonzero PreviousMode**, so this is the user-mode
  branch, not a Zw KernelMode assumption. At 0x5fbb63 the class is compared with
  0x4c, using unsigned `jae` for rejection; invalid class returns 0xc0000003.
  At 0x5fbb8a the supplied length is compared with the minimum, using unsigned
  `jb` for 0xc0000004. `/bytes/ntoskrnl?rva=0x9874d0&len=76` gives class-14
  minimum byte **8** at RVA 0x9874de. Thus 0/1/7 reject and 8/9 succeed.
* `/types/ntoskrnl/_IO_STATUS_BLOCK` and `/_FILE_STANDARD_INFORMATION` confirm
  the layout checks. `/function/ntoskrnl/NtQueryInformationFile/docs` and
  `/NtQueryDirectoryFile/docs` were read with their linked DDI contracts; the
  kernel/user Nt/Zw context caveat is retained.

Validation: `make build/nt_file.exe build/nt_registry.exe` completed without
compiler diagnostics. Only the permitted sandbox wrapper was used:

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_file.exe > /tmp/opencode/ntdll_review_nt_file.log 2>&1
```

Log line 102: `SUMMARY tests=50 failed=0 skipped=0 checks_pass=383 checks_fail=0`.
This supersedes the earlier 44-test smoke count, not Windows authority.

Remaining gaps: no native Windows run, asynchronous coverage, or filesystem
matrix. Synchronous I/O can block inside the kernel; the executable runner's
120-second timeout bounds the run, not individual syscalls. Existing volume and
directory expectations still require ordinary scratch-filesystem support.
The shared harness creates/removes a PID-named temp directory without an
ownership marker (`common/t.c:93-119`); that preexisting-directory/reparse-point
safety limitation was identified but not changed outside the owned directories.

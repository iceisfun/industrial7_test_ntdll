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

# nt_other_1_a_file evidence

Oracle: Windows 10 22H2 guest; adm and std. All values observed unless a source is named.

* NtDeleteFile: opens with delete-on-close, so the status is that of the open. Missing leaf STATUS_OBJECT_NAME_NOT_FOUND, missing parent
  STATUS_OBJECT_PATH_NOT_FOUND, read-only file STATUS_CANNOT_DELETE (0xC0000121), open without FILE_SHARE_DELETE STATUS_SHARING_VIOLATION,
  non-empty directory returns 0 but the directory survives (the delete fails silently at close), NULL attributes STATUS_INVALID_PARAMETER,
  empty name STATUS_OBJECT_PATH_SYNTAX_BAD (0xC000003B). Root-directory-relative deletion works.
* NtFlushBuffersFileEx: flags 0/1/2/4 succeed with Information 0; undefined bits are ignored for a file; a parameter length without a block
  gives STATUS_INVALID_PARAMETER; read-only handle STATUS_ACCESS_DENIED; NULL IO_STATUS_BLOCK STATUS_ACCESS_VIOLATION.
* NtDeviceIoControlFile: IOCTL_STORAGE_GET_DEVICE_NUMBER (documented storage IOCTL, FILE_ANY_ACCESS) on a zero-access volume handle returns 12 bytes,
  device type FILE_DEVICE_DISK; output 11 bytes or none STATUS_BUFFER_TOO_SMALL; unknown code STATUS_INVALID_DEVICE_REQUEST. A file-system control
  code sent through the device-control service is rejected: STATUS_INVALID_PARAMETER on an NTFS file, STATUS_INVALID_DEVICE_REQUEST on pipe and NUL handles.
  The volume checks are skipped (noted) if the volume cannot be opened.
* NtCopyFileChunk: copies 16 bytes between two local files, Information 16, content verified; zero length succeeds; invalid handles STATUS_INVALID_HANDLE.
* NtAreMappedFilesTheSame: two addresses in one image or the same address -> 0; images of different files STATUS_NOT_SAME_DEVICE (0xC00000D4);
  private memory vs image STATUS_CONFLICTING_ADDRESSES (0xC0000018); NULL / unmapped STATUS_INVALID_ADDRESS (0xC0000141); data-file views
  (even of the same section) STATUS_NOT_SAME_DEVICE.
* NtExtendSection: needs SECTION_EXTEND_SIZE; file-backed section 0x4000 -> 0x8000 returns 0, grows the file to 0x8000 and returns the new size;
  a smaller request returns the unchanged size; pagefile-backed section STATUS_SECTION_NOT_EXTENDED (0xC0000087). ntoskrnl NtExtendSection
  references the handle with access 0x10 (SECTION_EXTEND_SIZE) then calls MmExtendSection.
* NtAllocateVirtualMemoryEx: plain allocations, 4 MiB alignment requirement via MEM_ADDRESS_REQUIREMENTS, address-range bounds, reserve then commit;
  alignment 0x30000 or 0x1000 STATUS_INVALID_PARAMETER, extended-parameter type 0 or 0xFF and count without array STATUS_INVALID_PARAMETER, zero size
  STATUS_INVALID_PARAMETER, protection 3 STATUS_INVALID_PAGE_PROTECTION (0xC0000045), NULL process STATUS_INVALID_HANDLE, NULL base pointer STATUS_ACCESS_VIOLATION.
* NtAllocateUserPhysicalPages / Ex: STATUS_PRIVILEGE_NOT_HELD (SeLockMemoryPrivilege is not in either token); NULL process STATUS_INVALID_HANDLE.
  Skipped with a reason if the token does hold the privilege.

Cleanup: scratch files live in the per-process temporary directory; views, sections and memory are released.

# nt_other_3_a_file evidence

Exports covered (Nt names; Zw aliases checked in `other3a_file_nt_zw_aliases`): NtReadFile,
NtReadFileScatter, NtLockFile (NtUnlockFile used for cleanup/verification), NtFsControlFile,
NtNotifyChangeDirectoryFile, NtNotifyChangeDirectoryFileEx.

## Authority

All values observed on Windows 10 22H2 (ntdll 10.0.19041.2788) in the guest, elevated and standard
user, identical in both. The ntdll entry points are syscall thunks. Scenario design follows the
public documentation of ReadFile, ReadFileScatter, LockFileEx, DeviceIoControl, FSCTL_* and
ReadDirectoryChangesW/ReadDirectoryChangesExW.

## State used

Files and directories under the per-process scratch directory (`t_tmpdir()`), a private named pipe
`\\.\pipe\other3a_peek` (one instance), unnamed events. Handles are created with kernel32 for
fixture purposes only; all assertions are on ntdll calls.

## Observed contracts

- NtReadFile (synchronous handle): NULL ByteOffset uses and advances the file position; an explicit
  offset is honoured and moves the position; offset low 0xFFFFFFFE/high -1 (FILE_USE_FILE_POINTER_POSITION)
  continues from the position; Information is the number of bytes (short at EOF); reading at or
  after EOF gives STATUS_END_OF_FILE 0xC0000011 with Information 0; length 0 succeeds; negative
  offset other than the specials gives 0xC000000D; no FILE_READ_DATA access gives 0xC0000022; a
  directory handle gives 0xC0000010 (STATUS_INVALID_DEVICE_REQUEST); invalid handle 0xC0000008.
  On an overlapped handle a read at EOF returns STATUS_PENDING and completes with EOF through the
  event (so the test accepts either at call time and asserts the completed IO_STATUS_BLOCK).
- NtReadFileScatter (overlapped + FILE_FLAG_NO_BUFFERING handle): two page segments plus a NULL
  terminator are filled in segment order, Information 8192, untouched page unchanged. Length not a
  sector multiple, missing ByteOffset, unaligned offset, and a buffered synchronous handle all give 0xC000000D.
- NtLockFile: exclusive lock conflicts across handles with 0xC0000055 (STATUS_LOCK_NOT_GRANTED, fail
  immediately); shared locks coexist; a read through someone else's exclusive lock gives
  0xC0000054 (STATUS_FILE_LOCK_CONFLICT); locking past EOF works; NtUnlockFile needs an exact range
  and key match (0xC000007E STATUS_RANGE_NOT_LOCKED); a handle without data access gives 0xC0000022.
- NtFsControlFile: FSCTL_GET_COMPRESSION returns a USHORT (0) with Information 2 on NTFS, an output
  buffer shorter than 2 gives 0xC000000D; FSCTL_GET_REPARSE_POINT on a plain file gives 0xC0000275
  (skipped with the observed status when the volume cannot do it); sparse + FSCTL_QUERY_ALLOCATED_RANGES
  reports a range covering the written byte; FSCTL_PIPE_PEEK returns the 16-byte header plus
  available data (state 3 = connected) and a buffer smaller than the header gives 0xC000000D;
  invalid/NULL handle 0xC0000008.
- NtNotifyChangeDirectoryFile: request is STATUS_PENDING; a created file completes it with Status 0,
  Information = 12 + name bytes, Action 1; closing the directory handle completes pending requests with
  STATUS_NOTIFY_CLEANUP 0x10B; a too-small buffer completes with STATUS_NOTIFY_ENUM_DIR 0x10C
  Information 0; WatchTree TRUE reports "sub\name", FALSE ignores subtree changes; filter 0 and unknown
  bits give 0xC000000D; a non-directory handle gives 0xC000000D; invalid handle 0xC0000008.
- NtNotifyChangeDirectoryFileEx: class 1 matches the plain call, class 2 returns
  FILE_NOTIFY_EXTENDED_INFORMATION (name length at 0x50, name at 0x54, total 0x54 + name bytes).
  Observed but not asserted: out-of-range class values are accepted at call time.

## Skips

Volume-dependent FSCTLs (compression state, reparse query, sparse) skip with the observed status
if the scratch volume does not implement them.

# nt_other_1_b_io: file, notification and object natives, Windows 10 22H2 (ntdll 10.0.19041.2788)

Stub decompilations only; expectations come from the Win32 documentation of the wrappers (DeviceIoControl, LockFileEx,
ReadFileScatter, ReadDirectoryChangesW, RegNotifyChangeKeyValue) and runs on the guest (adm and std).

| Export | Checked | Source |
| --- | --- | --- |
| NtFsControlFile | FSCTL_GET_COMPRESSION on a file: status 0, Information 2, value 0; 1-byte output C000000D; NULL output with length 0 C00000E8; unknown code C0000010; invalid and NULL handle C0000008; event signalled. FSCTL_PIPE_PEEK on an anonymous pipe: header 16 bytes, state 3, available count, data not consumed; header-only buffer 80000005 with Information 16; 8-byte buffer C000000D. | docs + observed |
| NtLockFile | exclusive/shared lock, conflicting lock from other handle and the same handle `STATUS_LOCK_NOT_GRANTED` (C0000055), non-overlapping lock granted, ReadFile in a locked range fails with ERROR_LOCK_VIOLATION, unlock with wrong length or key `STATUS_RANGE_NOT_LOCKED` (C000007E), lock beyond EOF, no-data-access handle C0000022, bad/NULL handle C0000008. NtUnlockFile used as helper. | docs + observed |
| NtReadFileScatter | NO_BUFFERING+OVERLAPPED handle: two-page read via event, Information 8192, content check; read crossing EOF Information 4096; read at EOF `STATUS_END_OF_FILE` (C0000011); length 100 and offset 100 C000000D; handle lacking NO_BUFFERING/OVERLAPPED C000000D; bad handle C0000008. | docs + observed |
| NtNotifyChangeDirectoryFile | pending (103) on an async directory handle, FILE_ACTION_ADDED / REMOVED record with name and Information, completion event, filter 0 or 0x80000000 C000000D, cancel gives C0000120, bad handle C0000008. | docs + observed |
| NtNotifyChangeDirectoryFileEx | class 1 record as above; class 2 delivered a record of the same size as class 1 on the guest (observed only, not asserted); filter 0 C000000D; bad handle C0000008. Invalid class values are not rejected (not asserted). | observed |
| NtNotifyChangeKey | async watch pending (103); value set completes a LAST_SET watch with `STATUS_NOTIFY_ENUM_DIR` (10C); subtree NAME watch fires on child creation; ATTRIBUTES watch does not fire on value set; deleting+closing the key completes with `STATUS_NOTIFY_CLEANUP` (10B); bad handle C0000008. Each scenario uses a fresh key because changes made between two notify calls are reported immediately by the next call. | observed |
| NtFlushKey | scratch key and the user root: 0 twice; bad/NULL handle C0000008; process pseudo handle C0000024. | observed |
| NtMakeTemporaryObject / NtMakePermanentObject | temporary: 0 repeatedly, also without DELETE access on an unnamed event; permanent: `STATUS_PRIVILEGE_NOT_HELD` (C0000061) for admin and standard users alike, and the privilege is checked before the handle (invalid handle also C0000061). | observed |

Skips: none. Observed-only: NtNotifyChangeDirectoryFileEx class handling, NtMakeTemporaryObject without DELETE.

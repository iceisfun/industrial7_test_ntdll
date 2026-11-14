# nt_create_open_a_io: NtCreateMailslotFile, NtCreateNamedPipeFile

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788) in the elevated guest. Both exports are thin syscall stubs
(see `/api/function/ntdll/NtCreateMailslotFile/asm`); the validation lives in the kernel and the npfs/msfs
drivers, so every expected status below is **observed on Windows 10** unless a documentation source is given.
The Win32 wrappers (`CreateMailslot`, `CreateNamedPipe`) map to these calls, which is how the public
documentation constrains them (message mode needs message read mode, instances are 1..255 or unlimited).

| Test | Check | Source |
| --- | --- | --- |
| mailslot_create_and_message_roundtrip | success, `IoStatus.Information == FILE_CREATED (2)`; client `WriteFile` of 5 bytes is seen by `GetMailslotInfo` as 1 message / 5 bytes; one `ReadFile` returns the message; a write larger than the maximum message size fails | observed + CreateMailslot docs |
| mailslot_create_collision_and_reuse | second server handle for a live name is `STATUS_OBJECT_NAME_COLLISION` (0xC0000035); the name is free again after the last server handle is closed | observed |
| mailslot_parameter_variants | no read timeout, quota 0x1000, max message 0 and 0xFFFFFFFF are all accepted | observed |
| mailslot_invalid_arguments | NULL ObjectAttributes -> `STATUS_INVALID_PARAMETER`; NULL IO_STATUS_BLOCK -> `STATUS_ACCESS_VIOLATION` returned (not raised) | observed |
| pipe_create_and_data_roundtrip | duplex byte pipe, disposition FILE_CREATE gives `Information == FILE_CREATED`; client `CreateFile` on `\\.\pipe\name` connects; bytes move in both directions | observed + CreateNamedPipe docs |
| pipe_second_instance_dispositions | FILE_OPEN on a missing name is `STATUS_OBJECT_NAME_NOT_FOUND`; FILE_OPEN_IF creates (Information 2) then opens a further instance (Information `FILE_OPENED` 1); FILE_CREATE on an existing pipe is `STATUS_ACCESS_DENIED` | observed |
| pipe_message_mode_creation | message type + message read mode with unlimited instances (0xFFFFFFFF) is accepted; byte type with message read mode is `STATUS_INVALID_PARAMETER` | observed |
| pipe_invalid_arguments | read mode 2, completion mode 2, zero instances, FILE_SUPERSEDE, ShareAccess 0 and 7, NULL default timeout, NULL ObjectAttributes -> `STATUS_INVALID_PARAMETER`; NULL IO_STATUS_BLOCK -> `STATUS_ACCESS_VIOLATION` | observed |

Not asserted because they are unstable or underdetermined: whether a second instance may differ in
MaxInstances/type from the first (Windows 10 accepted it), quota defaults, handle values.
All names are `\Device\Mailslot\oa_ms*_<pid>_<n>` / `\Device\NamedPipe\oa_np*_<pid>_<n>`; every handle is closed.
The Zw twins of these two exports are not in this group.
No skips are expected; std-user behaviour is the same API surface (no privilege is involved).

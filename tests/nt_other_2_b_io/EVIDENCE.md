# nt_other_2_b_io evidence

Oracle: Windows 10 22H2 (ntdll 10.0.19041) x64, adm and std. The Corpus Explorer decompilation of each export is a
bare syscall stub, so status codes were established on the Windows 10 guest (and are explained below). Nothing
privileged is ever enabled; every privileged service is called with invalid or inert arguments and only the
"rejected, nothing changed" outcome is asserted.

| Test | Expected values and source |
|---|---|
| delete_file | Open handle without FILE_SHARE_DELETE -> STATUS_SHARING_VIOLATION 0xC0000043; delete ok -> name gone; second delete -> STATUS_OBJECT_NAME_NOT_FOUND; share-delete handle allows delete; read-only file -> STATUS_CANNOT_DELETE 0xC0000121; non-empty directory: the service returns success or STATUS_DIRECTORY_NOT_EMPTY and the directory remains (delete-on-close fails silently); NULL attributes -> STATUS_INVALID_PARAMETER. |
| flush_buffers | Writable handle -> 0 with IoStatus.Status 0 and Information 0; read-only handle -> STATUS_ACCESS_DENIED; bad handles -> STATUS_INVALID_HANDLE; NULL io block -> access violation. FlushBuffersFileEx flags 0 and 1 (data only) succeed; unknown flag 0x80 is accepted (logged only). |
| device_io_control | FSCTL (device type 9) codes are rejected by ZwDeviceIoControlFile with STATUS_INVALID_PARAMETER and the output untouched; invalid / type-mismatched handles; success path is IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS (0x560000) on the system volume opened with zero access: NumberOfDiskExtents >= 1 and Information == 8 + 24 * count. Short-buffer statuses depend on the storage stack and are logged only. Skips when the volume cannot be opened or has no such ioctl. |
| copy_file_chunk | 1024 bytes copied from offset 0 to offset 0: status 0, Information 1024, destination content verified; NULL source / destination handles -> STATUS_INVALID_HANDLE. |
| extend_section | Pagefile-backed section -> STATUS_SECTION_NOT_EXTENDED 0xC0000087; NULL -> invalid handle; event -> type mismatch; NULL size -> access violation. |
| cancel_io_idle | Idle synchronous handle: CancelIoFile -> 0 / Information 0; CancelIoFileEx -> STATUS_NOT_FOUND 0xC0000225 (also in IoStatus); CancelSynchronousIoFile on an idle current thread -> STATUS_NOT_FOUND; bad handles -> invalid handle. |
| registry_enum_delete | Layout of KEY_BASIC / KEY_VALUE_BASIC / PARTIAL information; ReturnLength is the full size even when the buffer is too small; zero-length buffer -> STATUS_BUFFER_TOO_SMALL, partial buffer -> STATUS_BUFFER_OVERFLOW 0x80000005, index past the end -> STATUS_NO_MORE_ENTRIES 0x8000001A, class 99 -> STATUS_INVALID_PARAMETER; value delete is case-insensitive, missing -> STATUS_OBJECT_NAME_NOT_FOUND; key delete with subkeys -> STATUS_CANNOT_DELETE 0xC0000121; enumerating a deleted key -> STATUS_KEY_DELETED 0xC000017C; read-only handle -> STATUS_ACCESS_DENIED; repeat ZwDeleteKey on a deleted key returns 0 (observed). All under a per-process key in the current user's hive, removed at the end. |
| registry_compact_compress | Both fail with STATUS_PRIVILEGE_NOT_HELD 0xC0000061 before touching any argument (the privilege is never enabled). |
| commit_transaction | Bad/NULL/event handles; a fresh KTM transaction commits (0), a second commit -> STATUS_TRANSACTION_ALREADY_COMMITTED 0xC0190016; CommitComplete/CommitEnlistment on a transaction handle -> type mismatch. |
| commit_registry_transaction | Registry transaction: flags 1 -> STATUS_INVALID_PARAMETER, flags 0 -> 0, second commit -> STATUS_TRANSACTION_NOT_ACTIVE 0xC0190003. |
| enumerate_transaction_object | NULL root with type 0 -> STATUS_NO_MORE_ENTRIES; junk -> invalid handle; zero-length buffer -> STATUS_INVALID_PARAMETER (observed). |
| connect_port | Absolute missing names -> STATUS_OBJECT_NAME_NOT_FOUND; relative name -> STATUS_OBJECT_PATH_SYNTAX_BAD 0xC000003B. ZwCompleteConnectPort returns 0 for any handle value in user mode (observed, a no-op). |
| debug_services | Invalid/type-mismatched handles; on a fresh debug object ZwDebugContinue -> STATUS_INVALID_PARAMETER (no matching event, and for a continue status that is not a DBG_ code). The process is never attached to. |
| wnf_deletes | Unregistered or zero state names -> STATUS_INVALID_PARAMETER; NULL name -> access violation. |
| private_namespace | NULL/junk -> invalid handle; event -> type mismatch. |
| audit_alarm | Observed: both audit-alarm services return 0 with no audit privilege held and arbitrary arguments. |
| boot_driver_entries | Boot/driver entry and firmware-variable services fail with an error status without SeSystemEnvironmentPrivilege (observed STATUS_NOT_IMPLEMENTED 0xC0000002 on the guest; other firmware types may report STATUS_PRIVILEGE_NOT_HELD) - only "error severity" is asserted. NtFilterBootOption (0x80430006) is logged only. |
| last_known_good | STATUS_PRIVILEGE_NOT_HELD with the privilege not enabled; no state changed. |
| physical_pages | SeLockMemoryPrivilege not enabled -> STATUS_PRIVILEGE_NOT_HELD; bad process handle -> STATUS_INVALID_HANDLE. |
| signing_and_counters | NtCompareSigningLevels: equal or greater first level -> 0, lower -> STATUS_INVALID_IMAGE_HASH 0xC0000428 (observed). Auxiliary-counter conversion: STATUS_NOT_SUPPORTED on hardware without one -> skip with that reason, otherwise 0. |
| assign_job | Suspended child (re-launch of this exe) assigned to a fresh job (IsProcessInJob verifies); re-assignment to the same job -> 0 (observed); bad handles / type mismatches on either argument. Child terminated at the end. |

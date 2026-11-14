# nt_other_3_a_key evidence

Exports covered (Zw aliases checked in `other3a_key_nt_zw_aliases`): NtFlushKey,
NtNotifyChangeKey, NtNotifyChangeMultipleKeys.

## Authority

Observed on Windows 10 22H2 (ntdll 10.0.19041.2788), elevated and standard user, identical.
Scenarios follow the public RegFlushKey / RegNotifyChangeKeyValue documentation.

## State used

One volatile subkey per test below the current user's key (created via
RtlFormatCurrentUserKeyPath, never touching an existing key; skipped if the name already exists or
the hive root is not writable), deleted at the end of each test.

## Observed contracts

- NtFlushKey: success on a writable key, repeatable, success even on a KEY_READ handle; invalid or
  NULL handle 0xC0000008; event handle 0xC0000024 (STATUS_OBJECT_TYPE_MISMATCH).
- NtNotifyChangeKey (asynchronous form): the request returns STATUS_PENDING and completes the event;
  the final IO_STATUS_BLOCK.Status is STATUS_NOTIFY_ENUM_DIR 0x10C with Information 0 (no
  change record is delivered); a NAME-only filter ignores value writes but fires on subkey creation;
  WatchSubtree FALSE ignores a child key's value change, TRUE reports it; closing the last handle
  completes the request with STATUS_NOTIFY_CLEANUP 0x10B; invalid handle 0xC0000008, event 0xC0000024.
  Observed but not asserted: a filter of 0 is accepted. Changes made while no request is pending are
  remembered and complete the next request immediately, so every scenario uses its own key.
- NtNotifyChangeMultipleKeys: with no slave array it behaves like NtNotifyChangeKey; an existing
  slave key (Count 1) gives 0xC000000D, a missing one 0xC0000034, Count 1 with a NULL array 0xC000000D.
  The reason an existing slave is refused is observed only.

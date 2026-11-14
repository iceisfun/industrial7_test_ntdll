# nt_other_1_b_misc: handle validation and privilege gates, Windows 10 22H2 (ntdll 10.0.19041.2788)

All exports here are plain syscall stubs in the decompilation; only side-effect-free calls are made (invalid handles,
wrong object types, missing privileges, nonexistent hive/driver). Values observed on the guest in adm mode.

| Export | Checked | Source |
| --- | --- | --- |
| NtListenPort | invalid and NULL handle C0000008; process pseudo handle `STATUS_OBJECT_TYPE_MISMATCH` (C0000024). | observed |
| NtPrepareEnlistment, NtPrePrepareEnlistment, NtPrepareComplete, NtPrePrepareComplete, NtReadOnlyEnlistment, NtRecoverEnlistment, NtPropagationComplete, NtPropagationFailed, NtRecoverResourceManager, NtGetNotificationResourceManager | invalid handle C0000008; for three of them a wrong-type handle C0000024. No transaction objects are created (they need the KTM). | observed |
| NtLockRegistryKey | privilege check precedes handle lookup: an invalid handle returns `STATUS_PRIVILEGE_NOT_HELD` (C0000061). | observed |
| NtGetDevicePowerState | invalid and NULL handle C0000008. | observed |
| NtGetCachedSigningLevel | invalid handle C0000008; kernel32.dll: status 0 on the guest (flags 0x42, level 0xc observed, only `level <= 0xf` asserted). | observed |
| NtLoadKey, NtLoadKey2, NtLoadKeyEx | SeRestorePrivilege not enabled (held-but-disabled counts as not enabled, as in an elevated admin token) -> C0000061; if enabled, a nonexistent hive file gives `STATUS_OBJECT_NAME_NOT_FOUND` (C0000034). The enabled branch was not exercised on the guest. | observed |
| NtLoadDriver | SeLoadDriverPrivilege not enabled -> C0000061; enabled branch expects C0000034 (not exercised). | observed |
| NtLockProductActivationKeys | status 0, safe-mode output 0 (version output not written). | observed |

Skips: none. Uncovered exports are listed with reasons in the report.

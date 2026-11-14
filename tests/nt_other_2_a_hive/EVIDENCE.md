# nt_other_2_a_hive: key rename, save, restore, merge, replace, unload

Oracle: Windows 10 22H2 guest. All keys are throwaway children of the current user's root (found through
RtlOpenCurrentUser) with the process id in their names; hive files live in the scratch directory and are
temporarily loaded below `\Registry\User` and unloaded again. Values are public docs (RegSaveKeyEx,
RegRestoreKey, RegUnLoadKey) plus **observed on Windows 10**. Each test first disables SeBackup/SeRestore so the
result does not depend on test order.

| Export | Expectation | Source |
| --- | --- | --- |
| NtRenameKey | New name visible, old name `STATUS_OBJECT_NAME_NOT_FOUND`, value survives and the open handle stays valid; sibling collision `STATUS_CANNOT_DELETE` (0xC0000121); name containing a backslash `STATUS_INVALID_PARAMETER`; read-only handle `STATUS_ACCESS_DENIED` | (obs) |
| NtSaveKey / NtSaveKeyEx | Privilege disabled `STATUS_PRIVILEGE_NOT_HELD`; with SeBackupPrivilege the file begins with `regf` and is at least 4 KiB; formats 1 and 2 accepted; 0, 4, 5, 6, 99 -> `STATUS_INVALID_PARAMETER` | RegSaveKeyEx docs; (obs) |
| NtRestoreKey | Privilege disabled `STATUS_PRIVILEGE_NOT_HELD`; restored value readable in the destination; invalid handles | RegRestoreKey docs; (obs) |
| NtSaveMergedKeys | Two ordinary subkeys are refused with `STATUS_INVALID_PARAMETER`; invalid handles | (obs) |
| NtReplaceKey | Not a hive root and missing file: never succeeds; privilege denial or access violation for a missing backup attribute; invalid handle (privilege held) | (obs) |
| NtUnloadKey / 2 / Ex | Privilege disabled `STATUS_PRIVILEGE_NOT_HELD`; non-hive name `STATUS_INVALID_PARAMETER`; loaded hive unloads (0) and disappears; open handle blocks flag 0 with `STATUS_CANNOT_DELETE`; REG_FORCE_UNLOAD (1) succeeds and the stale handle reports `STATUS_HIVE_UNLOADED` (0xC0000425); NtUnloadKeyEx event is not required to be signaled for an immediate unload | RegUnLoadKey docs; (obs) |

Standard users hold neither privilege: the denial assertions run, and the success paths t_skip with the exact
RtlAdjustPrivilege status.

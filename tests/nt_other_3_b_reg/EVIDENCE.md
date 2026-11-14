# Zw-named registry services: Windows 10 contracts

Oracle: Windows 10 22H2 x64. Scratch keys live under `HKCU\Software\ntdllt_<pid>_<tag>` and are deleted by each test; hive files are
created in the per-process scratch directory. Backup/restore operations need SeBackupPrivilege/SeRestorePrivilege: the elevated
administrator enables them for the duration of the test; a standard user token lacks them, so the tests assert 0xc0000061 and skip.
Loaded hives use the private name `\Registry\Machine\ntdllt_hive_<pid>` and are always unloaded.

| Export | Expectation | Source |
| --- | --- | --- |
| ZwRenameKey | rename keeps values, old name gone, new name opens; collision with a sibling (also case-insensitively) -> 0xc0000121; name with a separator or empty name -> 0xc000000d; read-only handle -> 0xc0000022; NULL/unused handle -> 0xc0000008; pseudo process handle or event -> 0xc0000024 | obs |
| ZwSaveKey | hive file begins with `regf`, size >= 0x1000; an existing file is overwritten (0); NULL key -> 0xc0000008; NULL file -> 0xc000000d; a file handle as the key -> 0xc0000024 | obs |
| ZwSaveKeyEx | formats 1 and 2 -> 0; format 4 (REG_NO_COMPRESSION) on a non-root key, 0, 3 and 8 -> 0xc000000d with the file left empty | obs |
| ZwRestoreKey | saved values come back, values added later disappear; REG_REFRESH_HIVE on a non-root key -> 0xc000000d; NULL key/file -> 0xc0000008; file handle as key -> 0xc0000024 | obs |
| ZwSaveMergedKeys | two ordinary keys -> 0xc000000d; NULL high or low key -> 0xc0000008; NULL file -> 0xc000000d | obs |
| ZwReplaceKey | non-root key with a missing new file -> 0xc0000034; NULL target handle -> 0xc0000008. No successful replace is attempted: it needs a hive root and takes effect at the next boot | obs |
| ZwUnloadKey / ZwUnloadKey2 | name not loaded -> 0xc000000d; loaded hive with an open handle -> 0xc0000121 and stays loaded; after closing -> 0; REG_FORCE_UNLOAD (1) succeeds with an open handle | obs |
| ZwUnloadKeyEx | with an open handle returns 0x103 (pending) and completes once the last handle closes (polled up to 5 s) | obs |
| ZwRollbackRegistryTransaction | flags 1 -> 0xc000000d; flags 0 -> 0; second rollback -> 0xc0190015; NULL/unused handle -> 0xc0000008; event -> 0xc0000024 | obs |

# ldr_dllpath evidence

Oracle: Windows 10 22H2, ntdll 10.0.19041.2788 in the local guest (elevated and standard user);
decompilation at `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp`. Process-global state that has no getter is exercised in a
child process (`t_run_child`) so it cannot affect other tests.

| Export | Source | Expectation |
| --- | --- | --- |
| LdrSetDllDirectory | decomp 0x7fd20 | returns 1 (TRUE) on success; a semicolon in the string gives 0xC000000D and keeps the old value; empty/NULL-buffer string clears the directory. The directory then shows up in the LdrGetDllPath default search path. |
| LdrGetDllDirectory | decomp 0x7f000 | copies the string; the buffer must hold Length + 2 (NUL): exact fit 0, one wide char short 0xC0000023 with Length = required size and Buffer[0] = 0 |
| LdrAddDllDirectory / LdrRemoveDllDirectory | decomp 0x8b710 / 0x8be20 | existing absolute directory returns a cookie; the directory then appears in the LOAD_LIBRARY_SEARCH_USER_DIRS (0x400) search path and disappears after removal. Relative path 0xC000000D, non-existent directory 0xC0000034 and no cookie is written. |
| LdrSetDefaultDllDirectories | decomp 0x7fce0 | accepted: any non-empty combination of 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000; rejected with 0xC000000D: 0, 0x1, 0x2, 0x4, 0x8, 0x80, 0x100 (alone or combined), 0x8000, 0x10000, 0x80000000. With 0x800 set, an unflagged LdrGetDllPath returns exactly the system directory. Child process. |
| LdrGetDllPath | decomp 0x11450 | flags 0: application directory first, then the system and Windows directories; flags 0x800: exactly the system directory (case differs from GetSystemDirectory, compared case-insensitively); 0x7f9 is an invalid combination (0xC000000D) |
| LdrUpdatePackageSearchPath | decomp 0xdec80 | NULL or empty 0xC000000D; replaces the earlier value; more than 0xFFFD bytes 0xC0000106 (0x7FFF chars) and 0x7FFE chars accepted. Child process. |
| LdrSetMUICacheType | decomp 0x8bfe0 | value must be below 8 and not have both bits 2 and 4 (0xC000000D); the type can be set once: second call 0xC0000001. Child process. |
| LdrFlushAlternateResourceModules | decomp 0x89450 | returns TRUE every time (repeat on an empty cache) |

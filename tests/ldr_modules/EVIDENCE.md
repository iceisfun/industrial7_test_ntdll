# ldr_modules evidence

Oracle: Windows 10 22H2, ntdll 10.0.19041.2788 in the local guest (elevated and standard user).
Contracts were read from `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp` and every expectation confirmed on the guest.
The code-free fixture DLL from `pebuild.h` (see ldr_resource/EVIDENCE.md) is the "extra module"
that is loaded, queried and unloaded; core modules (ntdll, kernel32, the exe) are only read.

| Export | Source | Expectation |
| --- | --- | --- |
| LdrGetDllHandleByName | decomp 0x770b0 | base name or full name (either may be NULL); case-insensitive; no default extension added ("ntdll" is 0xC0000135); missing/empty name 0xC0000135; takes a load reference for non-pinned modules (fixture needs one extra FreeLibrary) |
| LdrGetDllHandleByMapping | decomp 0x74710 | the exact image base resolves (also referenced); an address inside the image has no PE header there: 0xC000007B; NULL 0xC000000D; a mapped image view that is not in the loader list 0xC0000135 |
| LdrGetDllFullName | decomp 0x10240 | copy of the loader full name; too small buffer: 0xC0000023 with Length = bytes that fit (observed: equals MaximumLength); NULL handle is the process image; unknown handle or interior pointer 0xC0000135 |
| LdrDisableThreadCalloutsForDll | decomp 0xef70 | 0 for a loaded module (idempotent); unknown handle/NULL 0xC0000135 |
| LdrIsModuleSxsRedirected | decomp 0xcdfe0 | BOOLEAN in AL (upper bits are undefined): 0 for ordinary and unknown modules |
| LdrQueryProcessModuleInformation | decomp 0x1430 (wrapper of the Ex form) | NULL/0 buffer or any short buffer: 0xC0000004 and the required size (8 + count*0x128); exact buffer: 0. Exe and ntdll entries have the right base, size, ANSI path and file-name offset; a loaded fixture grows the list by one entry (LoadCount 1, ImageSize 0x2000). LoadOrderIndex is not filled by this variant (observed 0xCCCC left from the pre-fill), so it is not asserted. |
| LdrQueryModuleServiceTags | decomp 0xce1d0 | non-service module: 0, count 0, buffer untouched; unknown handle 0xC0000135 |
| LdrGetKnownDllSectionHandle | decomp 0x844b0 | opens the section under \KnownDlls: kernel32.dll returns an image section (NtQuerySection attributes include SEC_IMAGE); case-insensitive; unknown 0xC0000034; the 64-bit flag byte set: 0xC000000D; path with separators 0xC000003A; NULL/empty name 0xC0000024 (observed, the directory object itself is opened) |
| LdrControlFlowGuardEnforced | decomp 0x33520 | result 0 or 1, stable; the test exe is not CFG-enforced but a system policy could change that, so only the range and stability are asserted |
| LdrGetFailureData | decomp 0xcdfd0 | returns the address of a global inside the ntdll image; stable |
| LdrGetProcedureAddressForCaller | decomp 0x2fdc0 | named and by-ordinal resolution equal GetProcAddress; unknown name 0xC0000139 (observed); unknown module 0xC0000135; counted name that is not NUL-terminated is copied (name "Nt" is not an export). |
| LdrRegisterDllNotification / LdrUnregisterDllNotification | decomp 0x84bf0 / 0xce6e0 | flags must be 0, callback and cookie pointer must be non-NULL (0xC000000D). Callback gets reason 1 (loaded) and 2 (unloaded) with FullDllName, BaseDllName, DllBase and SizeOfImage of the loaded module and the registration context; several registrations are all called; unregister twice or of NULL gives 0xC0000135. |
| LdrSetImplicitPathOptions | decomp 0xce670 | options must be non-zero and within bits 8..14 (0x100.. 0x7F00 here); 0 or other bits 0xC000000D; unknown module 0xC0000135 |
| LdrAddRefDll, LdrGetDllHandleEx, LdrFindEntryForAddress, LdrEnumerateLoadedModules, LdrLockLoaderLock, LdrUnlockLoaderLock, LdrGetProcedureAddressEx | existing contracts, see ldr_image/EVIDENCE.md | exercised again against the fixture: entry fields (DllBase, SizeOfImage, BaseDllName), enumeration order, explicit reference needing one more free, lookup without reference (flag 1), lock state 1, procedure lookup in a module without exports (0xC0000139), freed module no longer found (0xC0000135) |

Notes
* NtQuerySection is queried with SectionBasicInformation (class 0): {Base, Attributes, Size}.
* The reference-count test relies on counts of a private fixture, so the shared system DLLs are never unloaded.

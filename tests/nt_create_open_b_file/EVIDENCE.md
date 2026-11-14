# nt_create_open_b_file: ZwCreateFile, ZwOpenFile, mailslot and named pipe creation

Reference queried 2026-11-14: Windows 10 22H2 corpus (ntdll 10.0.19041.2788). The ntdll exports in this
area are syscall stubs (`/api/function/ntdll/<name>/decomp` shows only the service-number load and
`syscall`/`int 2e` dispatch, no argument checks), so every expected value below was **observed on a
real Windows 10 22H2 guest** (adm = elevated administrator, std = standard user) and, where the name
describes a documented contract, cross-checked against public documentation. Nt/Zw pairs share one
RVA: each test asserts `t_proc("NtX") == t_proc("ZwX")` and exercises behavior through the Zw name.
Status codes are written as NTSTATUS values. Tests do not depend on order and clean up what they create.
Object names are made unique per process in the caller's session namespace
(`\BaseNamedObjects` for session 0, `\Sessions\<n>\BaseNamedObjects` otherwise).

Exports: ZwCreateFile, ZwOpenFile, ZwCreateMailslotFile, ZwCreateNamedPipeFile.

| Behavior | Status / value | Source |
|---|---|---|
| Dispositions on an NTFS scratch file | CREATE new: 0, Information FILE_CREATED(2); CREATE existing: STATUS_OBJECT_NAME_COLLISION; OPEN missing C0000034; OPEN existing Information FILE_OPENED(1); OPEN_IF existing FILE_OPENED; OVERWRITE/OVERWRITE_IF existing FILE_OVERWRITTEN(3) and size 0; SUPERSEDE FILE_SUPERSEDED(0) | observed, matches documented FILE_* semantics |
| IO_STATUS_BLOCK.Information on failure paths | **not written** by the object-manager/parse failures here (the pre-fill pattern survives), so it is not asserted | observed |
| Disposition 6 or -1; share bits 0x8; DIRECTORY_FILE together with NON_DIRECTORY_FILE | STATUS_INVALID_PARAMETER | observed |
| File opened with FILE_DIRECTORY_FILE | STATUS_NOT_A_DIRECTORY C0000103; directory opened with FILE_NON_DIRECTORY_FILE: STATUS_FILE_IS_A_DIRECTORY C00000BA | observed |
| Missing parent directory | STATUS_OBJECT_PATH_NOT_FOUND C000003A | observed |
| Exclusive open vs second open | STATUS_SHARING_VIOLATION C0000043; an attribute-only open (FILE_READ_ATTRIBUTES\|SYNCHRONIZE) ignores sharing | observed |
| DELETE_ON_CLOSE | file is gone after the last close | observed |
| ZwOpenFile | share 0x10 or open options 0xFF000000: C000000D; ObjectName NULL: C000003B; NULL IO_STATUS_BLOCK or handle: C0000005; open of `\Device\Null` succeeds | observed |
| Relative open/create with a directory RootDirectory | works; creating in the directory reports FILE_CREATED | observed |
| Mailslot | creation Information FILE_CREATED; GetMailslotInfo reports max message 0x100, a 5-byte message pending; same name again C0000035; oversized writes fail at the client | observed |
| Named pipe | one instance (Max=1): second instance C00000AB (STATUS_INSTANCE_NOT_AVAILABLE) for OPEN_IF and CREATE; client round trip; two instances with Max=2 (first FILE_CREATED, second FILE_OPENED); OPEN of a missing pipe C0000034; MaximumInstances 0 C000000D; read mode message on byte pipe and completion/read mode 2 rejected C000000D; NamedPipeType 2 is accepted (observed only, logged as a note) | observed |

Skips: none.

# nt_create_open_b_obj: namespace and section object create/open

Reference queried 2026-11-14: Windows 10 22H2 corpus (ntdll 10.0.19041.2788). The ntdll exports in this
area are syscall stubs (`/api/function/ntdll/<name>/decomp` shows only the service-number load and
`syscall`/`int 2e` dispatch, no argument checks), so every expected value below was **observed on a
real Windows 10 22H2 guest** (adm = elevated administrator, std = standard user) and, where the name
describes a documented contract, cross-checked against public documentation. Nt/Zw pairs share one
RVA: each test asserts `t_proc("NtX") == t_proc("ZwX")` and exercises behavior through the Zw name.
Status codes are written as NTSTATUS values. Tests do not depend on order and clean up what they create.
Object names are made unique per process in the caller's session namespace
(`\BaseNamedObjects` for session 0, `\Sessions\<n>\BaseNamedObjects` otherwise).

Exports: ZwCreateSymbolicLinkObject, ZwOpenSymbolicLinkObject, ZwOpenDirectoryObject, ZwCreatePrivateNamespace,
ZwOpenPrivateNamespace, ZwCreateSection, ZwCreateSectionEx, ZwOpenSection, ZwCreateJobObject, ZwOpenJobObject.

| Behavior | Status / value | Source |
|---|---|---|
| Symlink create/query | NtQuerySymbolicLinkObject returns target and ret length = target byte length; buffer of 8 bytes gives STATUS_BUFFER_TOO_SMALL C0000023 with the needed length | observed |
| Unnamed symlink | allowed (status 0); NULL target pointer C0000005; empty target C000000D | observed |
| Symlink name collision | C0000035; link vanishes when the last handle closes (not permanent) | observed |
| Lookup through a link | NtOpenEvent on the link name reaches the target event | observed |
| ZwOpenSymbolicLinkObject with OBJ_OPENLINK (0x100) | STATUS_INVALID_PARAMETER | observed |
| Open a directory as a symlink | STATUS_OBJECT_TYPE_MISMATCH | observed |
| ZwOpenDirectoryObject | type name `Directory`; relative open through RootDirectory; `\` and `\Device` open with DIRECTORY_QUERY | observed |
| Private namespace | OA must be unnamed (a named OA gives C0000033 OBJECT_NAME_INVALID); a boundary descriptor made with RtlCreateBoundaryDescriptor + RtlAddSIDToBoundaryDescriptor(Everyone) is accepted; second create with the same descriptor C0000035; NULL descriptor C0000005; open with an unknown boundary descriptor C000003A; NtDeletePrivateNamespace 0 | observed |
| Section create: size 0 or NULL size without a file | STATUS_INVALID_PARAMETER_4 C00000F2; AllocationAttributes 0 or COMMIT\|RESERVE C00000F4 (PARAM_6); protection 3 gives STATUS_INVALID_PAGE_PROTECTION C0000045 | observed |
| Section query | NtQuerySection class 0 returns 24 bytes: Size = requested size, Attributes include SEC_COMMIT | observed |
| Two views (creator handle, opened handle) of one section see the same bytes | observed |
| File-backed section | NULL/0 size takes the file size; SEC_IMAGE over a file without an MZ header gives C000012F | observed |
| ZwCreateSectionEx | extended parameter count 1 with NULL array C000000D; invalid pointer C0000005; size 0 C00000F2 | observed |
| Job object | type name `Job`; collision C0000035; JOB_OBJECT_QUERY open granted exactly; basic accounting query returns 0x30 bytes | observed |

Skips: none.

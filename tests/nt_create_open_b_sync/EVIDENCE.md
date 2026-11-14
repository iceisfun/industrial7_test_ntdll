# nt_create_open_b_sync: synchronization object create/open

Reference queried 2026-11-14: Windows 10 22H2 corpus (ntdll 10.0.19041.2788). The ntdll exports in this
area are syscall stubs (`/api/function/ntdll/<name>/decomp` shows only the service-number load and
`syscall`/`int 2e` dispatch, no argument checks), so every expected value below was **observed on a
real Windows 10 22H2 guest** (adm = elevated administrator, std = standard user) and, where the name
describes a documented contract, cross-checked against public documentation. Nt/Zw pairs share one
RVA: each test asserts `t_proc("NtX") == t_proc("ZwX")` and exercises behavior through the Zw name.
Status codes are written as NTSTATUS values. Tests do not depend on order and clean up what they create.
Object names are made unique per process in the caller's session namespace
(`\BaseNamedObjects` for session 0, `\Sessions\<n>\BaseNamedObjects` otherwise).

Exports: ZwCreateMutant, ZwOpenMutant, ZwCreateSemaphore, ZwOpenSemaphore, ZwOpenEvent, ZwOpenEventPair,
ZwCreateTimer, ZwOpenTimer, ZwCreateTimer2, ZwCreateIRTimer, ZwCreateKeyedEvent, ZwOpenKeyedEvent.

| Behavior | Status / value | Source |
|---|---|---|
| Create named object, new | 0; type name from NtQueryObject(ObjectTypeInformation) is `Mutant`, `Semaphore`, `Timer`, `KeyedEvent` | observed |
| Create with an existing name, no OBJ_OPENIF | STATUS_OBJECT_NAME_COLLISION C0000035 | observed (documented object-manager behavior) |
| Same with OBJ_OPENIF (0x80) | STATUS_OBJECT_NAME_EXISTS 40000000 (success severity), valid handle | observed |
| Open missing name | STATUS_OBJECT_NAME_NOT_FOUND C0000034; missing parent component C000003A (PATH_NOT_FOUND) | observed |
| Open with NULL ObjectAttributes | STATUS_INVALID_PARAMETER C000000D; with OA.Length wrong C000000D | observed |
| Open with OA whose ObjectName is NULL or empty | STATUS_OBJECT_PATH_SYNTAX_BAD C000003B | observed |
| Open with invalid RootDirectory handle | STATUS_INVALID_HANDLE C0000008 | observed |
| NULL or unwritable output handle pointer | STATUS_ACCESS_VIOLATION C0000005 (probed in the service, not an exception) | observed |
| Open an object of another type (event opened as mutant, semaphore, timer) | STATUS_OBJECT_TYPE_MISMATCH C0000024 | observed |
| Mutant InitialOwner=TRUE | NtQueryMutant(class 0): count 0, OwnedByCaller 1, Abandoned 0; unowned: count 1 | observed |
| Semaphore initial/max | NtQuerySemaphore returns 8 bytes {current,limit}. max 0, initial>max, negative values: STATUS_INVALID_PARAMETER | observed |
| Timer type 0/1 accepted; type 2 or -1 | STATUS_INVALID_PARAMETER_4 C00000F2 | observed |
| ZwOpenEvent with access 0 | STATUS_ACCESS_DENIED C0000022; MAXIMUM_ALLOWED gives all event rights; requested subset is the granted mask | observed |
| ZwCreateTimer2(PHANDLE, Reserved1, Reserved2, Attributes, Access) | parameters 2 and 3 must be NULL (C00000F0 / C00000F1 otherwise); attributes 4 and 8 accepted, 1 and 0xF0 give C00000F2; resulting object type name is `IRTimer` | observed |
| ZwCreateIRTimer | access 0 gives C000000D, a nonzero access with a NULL second argument gives C0000005; no success path was found with the three-argument shape, so only the rejection paths are asserted | observed |
| Keyed event: access mask 3 (WAIT\|WAKE) | create/open succeed; open with 0x1F0003 or 0 gives C0000022 (the default DACL does not grant the standard rights); zero-timeout wait/release with no waiter return STATUS_TIMEOUT 00000102 | observed |
| ZwOpenEventPair, NtCreateEventPair | always STATUS_NOT_IMPLEMENTED C0000002, arguments are not examined | observed |

Skips: none. Differences between std and adm: none expected, all objects live in the caller's session namespace.

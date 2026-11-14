# nt_query_info_b_object: object-manager query services

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), x64. Every expectation below was either taken from
public documentation / the native structure layouts, or observed on the Windows 10 guest and then fixed
in the test. Nothing is asserted that was not seen to pass on the guest in elevated-administrator mode
(and, for the unprivileged mode, see "Privilege" below).

Corpus Explorer function records (`/api/function/ntdll/<Name>`): all exports in this area are plain
syscall stubs (`mov eax, <service>; syscall`); Nt and Zw names share one RVA (asserted by `alias_pairs`).
Argument validation therefore lives in the kernel; the status codes below are observed results.

## Exports and expectations

| Export | Behaviour asserted | Source |
| --- | --- | --- |
| NtQueryEvent | class 0 = {EventType, EventState}, 8 bytes, ReturnLength 8; type 0 notification / 1 synchronization; state 0/1. Length != 8 -> STATUS_INFO_LENGTH_MISMATCH; class != 0 -> STATUS_INVALID_INFO_CLASS; NULL / stale handle -> STATUS_INVALID_HANDLE; process pseudo handle / semaphore -> STATUS_OBJECT_TYPE_MISMATCH; handle without EVENT_QUERY_STATE -> STATUS_ACCESS_DENIED | docs (EVENT_BASIC_INFORMATION) + observed |
| NtQueryMutant | {CurrentCount, OwnedByCaller, AbandonedState}, size 8: free = 1, after acquire 0, after recursive acquire -1, owner flag; initially-owned mutex. Class 1 and size mismatches both give STATUS_INFO_LENGTH_MISMATCH (not INVALID_INFO_CLASS, observed) | docs + observed |
| NtQuerySemaphore | {CurrentCount, MaximumCount} 8 bytes; value follows NtReleaseSemaphore; wrong length 4/12 -> mismatch; class 1 -> INVALID_INFO_CLASS | docs + observed |
| NtQueryTimer | {RemainingTime, TimerState}, 16 bytes: armed 1 hour timer reports remaining 35000000000..36000000000 (100 ns), state 0; after a one-shot expiry state 1. RemainingTime of a disarmed timer is a stale value on Windows 10 (observed: a large negative number), so only `<= 0` is asserted | observed |
| NtQuerySection | class 0 = {BaseAddress, Attributes, Size} 24 bytes: pagefile-backed SEC_COMMIT / SEC_RESERVE sections report size and attribute flag, BaseAddress 0; class 1 on a non-image section -> STATUS_SECTION_NOT_IMAGE (0xC0000049); view-only handle (no SECTION_QUERY) -> ACCESS_DENIED | observed |
| NtQuerySymbolicLinkObject | Unnamed link to `\Device\Null`: Length = target bytes, ReturnedLength = Length + 2 (terminating NUL is counted), MaximumLength must be >= Length + 2 else STATUS_BUFFER_TOO_SMALL with the needed size in ReturnedLength; no SYMBOLIC_LINK_QUERY -> ACCESS_DENIED | observed |
| NtQueryObject | class 1 name of an unnamed object has Length 0; class 2 type name "Event"; class 4 handle flags (2 bytes, no inherit/protect); named object in a private directory ends with the leaf name; too-small buffer -> STATUS_INFO_LENGTH_MISMATCH and a nonzero ReturnLength; bad class -> INVALID_INFO_CLASS | observed |
| NtQueryDirectoryObject | private directory with 3 events and 1 symbolic link: all entries returned in one call terminated by a zeroed entry, TypeName "Event" / "SymbolicLink", Context counts entries; ReturnSingleEntry walks 4 entries then STATUS_NO_MORE_ENTRIES (0x8000001A); empty directory -> NO_MORE_ENTRIES; 8 byte buffer -> STATUS_BUFFER_TOO_SMALL; non-directory handle -> TYPE_MISMATCH; no DIRECTORY_QUERY -> ACCESS_DENIED. `\KnownDlls` (readable by standard users) lists `ntdll.dll` with TypeName "Section" (`\ObjectTypes` is not readable by standard users: ACCESS_DENIED observed) | observed |
| NtQuerySecurityObject | unnamed objects have no descriptor: a 20-byte empty self-relative header is returned (Owner = Dacl = 0). Named object (private directory): length 0 -> STATUS_BUFFER_TOO_SMALL with required size; OWNER query returns a valid self-relative descriptor with only the owner offset set; GROUP query likewise; handle without READ_CONTROL -> ACCESS_DENIED | observed |
| NtQueryInformationAtom | class 0 = {UsageCount, Flags, NameLength, Name}; ReturnLength = 6 + name bytes + 2; second NtAddAtom increments usage; buffer 6 -> BUFFER_TOO_SMALL, buffer 5 -> INFO_LENGTH_MISMATCH; class 1 = atom table {count, atoms[]}: buffer smaller than the table -> INFO_LENGTH_MISMATCH and only the count (ReturnLength 4); deleted atom -> STATUS_INVALID_HANDLE; atom 0 -> STATUS_INVALID_PARAMETER. NtAddAtom is denied (0xC0000022) until the process has initialised user32 (window-station atom table), so the test calls GetDesktopWindow and skips if still denied | observed |

## Skips

* `query_information_atom` skips only if NtAddAtom stays STATUS_ACCESS_DENIED after user32 initialisation.

## Privilege

Nothing here needs elevation: all objects are created unnamed or in a private unnamed directory object.

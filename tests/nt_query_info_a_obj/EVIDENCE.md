# nt_query_info_a_obj evidence

Oracle: Windows 10 22H2 guest (ntdll 10.0.19041.2788), elevated administrator and standard user.
All exports here are bare syscall stubs in ntdll (decompilations show only the syscall), so status codes were
observed on the guest; layouts (OBJECT_DIRECTORY_INFORMATION, ATOM_BASIC_INFORMATION, JOBOBJECT_*) come from
public headers.

| Export | Assertions | Source |
|---|---|---|
| NtQueryDirectoryObject | `\KernelObjects`: one bulk call lists the entries, terminated by a zeroed entry, context equals the entry count, LowMemoryCondition is present and is of type SymbolicLink on 19041; the following call is STATUS_NO_MORE_ENTRIES (0x8000001A); single-entry mode with restart visits the same number of entries; an 8 byte buffer is STATUS_BUFFER_TOO_SMALL; a partial buffer returns STATUS_SUCCESS or STATUS_MORE_ENTRIES (0x105) (note); root `\` contains Device (Directory) and ObjectTypes; invalid handle 0xC0000008; event handle STATUS_OBJECT_TYPE_MISMATCH; handle opened with DIRECTORY_TRAVERSE only STATUS_ACCESS_DENIED | observed |
| NtQuerySymbolicLinkObject | an unnamed link created with NtCreateSymbolicLinkObject round-trips its target; UNICODE_STRING.Length excludes the terminator and ReturnedLength includes it (Length + 2); a buffer Length + 1 long is STATUS_BUFFER_TOO_SMALL and reports Length + 2; link opened without SYMBOLIC_LINK_QUERY STATUS_ACCESS_DENIED; directory and event handles STATUS_OBJECT_TYPE_MISMATCH; closed handle STATUS_INVALID_HANDLE; `\??\C:` points into `\Device\`, `\??\NUL` is `\Device\Null` | observed |
| NtQuerySecurityObject | named event (an unnamed object has no descriptor): self-relative descriptor, revision 1, SE_SELF_RELATIVE and SE_DACL_PRESENT set, owner/group/DACL offsets nonzero, SACL offset zero; owner-only is smaller; 8 byte buffer STATUS_BUFFER_TOO_SMALL with LengthNeeded; NULL buffer reports the size; SecurityInformation 0 returns a 20-byte header (note); SACL without ACCESS_SYSTEM_SECURITY STATUS_ACCESS_DENIED (note); handle without READ_CONTROL STATUS_ACCESS_DENIED; pseudo handles -1 and -2 succeed; NULL LengthNeeded STATUS_ACCESS_VIOLATION | observed |
| NtQueryInformationAtom | success path (use count, name, table listing, delete) is implemented but skipped on the guest: the harness process has no window station so NtAddAtom, NtQueryInformationAtom and GlobalAddAtomW all fail with STATUS_ACCESS_DENIED (error 5); the skip is raised only on exactly that status | observed |
| NtQueryInformationJobObject | empty job: accounting class 1 all zero, class 2 reflects kernel32-set ActiveProcessLimit 7 and native priority class 5 (below normal), class 9 extended, class 3 empty list; short buffer STATUS_INFO_LENGTH_MISMATCH; class 0x7777 and 0 STATUS_INVALID_INFO_CLASS; bogus handle STATUS_INVALID_HANDLE; event STATUS_OBJECT_TYPE_MISMATCH; handle with only JOB_OBJECT_SET_ATTRIBUTES STATUS_ACCESS_DENIED | observed |

Nt/Zw alias pairs share an address (asserted by qobj_alias_pairs).

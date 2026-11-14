# nt_create_open_a_objects: object-manager creators and openers

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), elevated guest. All exports here are syscall stubs, so
expected statuses are observed Windows 10 behaviour; where kernel logic explained a result the decompiled
service from the Corpus Explorer is cited. Names live under `\BaseNamedObjects\oa_*_<pid>_<n>` and every
handle is closed.

| Export(s) | Expectation | Evidence |
| --- | --- | --- |
| NtCreateDirectoryObject, NtOpenDirectoryObject | create/open/collide (0xC0000035), object created relative to the directory handle is reachable by full path, non-permanent directory vanishes with its last handle, root `\` opens, missing -> 0xC0000034, NULL handle pointer -> 0xC0000005, unnamed with access 0 succeeds | observed |
| NtCreateDirectoryObjectEx (+ZwCreateDirectoryObjectEx alias) | flags 0 and 1 accepted; flags 2 and 4 -> 0xC00000F3 (parameter 5); shadow handle valid directory ok, bogus handle -> 0xC0000008 | observed |
| NtCreateSymbolicLinkObject, NtOpenSymbolicLinkObject | create/collide, open, `NtQuerySymbolicLinkObject` returns the target and reports 0xC0000023 with the required size, link is temporary, NULL target -> 0xC0000005 | observed |
| NtCreateKeyedEvent, NtOpenKeyedEvent | flags must be 0 (else 0xC00000F2, parameter 4); open with WAIT/WAKE (1,2,3) and MAXIMUM_ALLOWED works, SYNCHRONIZE alone is 0xC0000022 | observed |
| NtCreateJobObject, NtOpenJobObject | collide, open; a limit set through one handle is read back through the other; gone after last close | observed |
| NtCreateJobSet | every argument combination returns 0xC00000BB (STATUS_NOT_SUPPORTED) | observed |
| NtCreateSectionEx, NtOpenSection | named page-file section, two views via two handles share data, `NtQuerySection` size 0x2000, error codes 0xC00000F2 (size), 0xC0000045 (protection 0x1234), 0xC00000F4 (no allocation attribute), 0xC000000D (extended-parameter count without array), 0xC0000008 (bad file handle); SEC_RESERVE and PAGE_EXECUTE_READWRITE accepted | observed |
| NtCreateTimer2, NtCreateIRTimer | Timer2 attribute bits 0, 4, 8 valid; 1, 3, 12, 0x10..0x100 -> 0xC00000F2 (decompiled `ExpExTimerAttributesAreValid`, ntoskrnl NtCreateTimer2 @0x70ab40); OA must be NULL (0xC00000F1), reserved pointer only legal with IR attribute (0xC00000F0); NtCreateIRTimer is `NtCreateTimer2(...,attributes 2,...)` and is refused (0xC000000D without a parameter block, 0xC0000022 with one) | decompilation + observed |
| NtCreateDebugObject | named create/collide, flags 0/1 ok, flag 2 -> 0xC000000D, object type name `DebugObject` | observed |
| NtCreatePort, NtCreateWaitablePort | named/unnamed ok, collide, MaxMessageLength 0x10000 -> 0xC000000D; both produce object type `ALPC Port` on Windows 10 | observed |
| NtCreatePrivateNamespace, NtOpenPrivateNamespace | identified by a boundary descriptor (built with Rtl* helpers); create, open, duplicate create -> 0xC0000035, delete via NtDeletePrivateNamespace, open afterwards -> 0xC000003A; an unrooted object name -> 0xC0000033; junk descriptor -> 0xC000000D; NULL descriptor -> 0xC0000005 | observed |
| NtCreateEventPair, NtOpenEventPair (+Zw alias) | every call returns 0xC0000002 (STATUS_NOT_IMPLEMENTED) on Windows 10 | observed |
| ZwCreateEvent | alias of NtCreateEvent (same entry); behaves as an event: notification event initially signalled, type 2 -> 0xC000000D | observed |
| Zw aliases | CreateCrossVmEvent/Mutant, DebugObject, DirectoryObject(Ex), Enclave, Enlistment, Event, EventPair resolve to the same address as their Nt names | image export table |

Skips: private namespace creation is skipped when the account gets ACCESS_DENIED/PRIVILEGE_NOT_HELD
(not seen on the administrator account). The ALPC/LPC depth is covered by other areas.

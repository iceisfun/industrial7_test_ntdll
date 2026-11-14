# NtSetInformationObject, NtSetSecurityObject, NtSetInformationSymbolicLink, NtSetInformationDebugObject, NtSetInformationJobObject

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), administrator and standard user. Kernel decompilations
read for order and status codes; values confirmed on the guest. Named objects are created in the
session namespace with process-unique names or are unnamed, and every handle is closed.

| Check | Expected | Source |
|---|---|---|
| NtSetInformationObject class 4 {Inherit, ProtectFromClose}, 2 bytes | success; `GetHandleInformation` and NtQueryObject class 4 agree; closing a protected handle gives STATUS_HANDLE_NOT_CLOSABLE (C0000235) | documented, decompilation (ObSetHandleAttributes), observed |
| length 1 / 4 for class 4 | STATUS_INFO_LENGTH_MISMATCH | decompilation (`param_4 != 2`), observed |
| class 0, 0x7fffffff | STATUS_INVALID_INFO_CLASS | decompilation, observed |
| invalid or NULL handle, class 4 | STATUS_ACCESS_DENIED | observed (ObSetHandleAttributes reports an unresolvable handle that way) |
| class 5 (ObjectSessionInformation) | STATUS_PRIVILEGE_NOT_HELD before the handle is looked at; skips if SeTcbPrivilege is enabled | decompilation (SeSinglePrivilegeCheck(SeTcbPrivilege)), observed |
| NtSetSecurityObject DACL on a named event, self-relative SD with one ACE | success; NtQuerySecurityObject returns that single ACE and mask; replaced by a second call | documented, observed |
| unnamed event | set fails with STATUS_NO_SECURITY_ON_OBJECT (C00000D7); query succeeds with a descriptor that has no DACL | observed |
| handle with only READ_CONTROL | STATUS_ACCESS_DENIED | observed |
| OWNER or GROUP information with an SD lacking them | STATUS_INVALID_SECURITY_DESCR (C0000079) | decompilation (owner/group offset zero), observed |
| invalid / NULL handle | STATUS_INVALID_HANDLE | observed |
| NtSetInformationSymbolicLink on an unnamed link (SYMBOLIC_LINK_QUERY\|SET access) | class 0 or 3: STATUS_INVALID_INFO_CLASS; classes 1 and 2 with length != 4: STATUS_INFO_LENGTH_MISMATCH; classes 1 and 2 with length 4: STATUS_PRIVILEGE_NOT_HELD (SeTcbPrivilege) | decompilation, observed |
| symbolic link handle with only QUERY | STATUS_ACCESS_DENIED; event handle STATUS_OBJECT_TYPE_MISMATCH; invalid handle STATUS_INVALID_HANDLE | decompilation (reference with access 2), observed |
| NtSetInformationDebugObject class 1: 0 / 1 | success; ReturnLength written as 0 | decompilation, observed |
| value 2, class 0, class 2 | STATUS_INVALID_PARAMETER | decompilation, observed |
| length 8 | STATUS_INFO_LENGTH_MISMATCH with ReturnLength 4 | decompilation, observed |
| debug handle with DEBUG_READ_EVENT only | STATUS_ACCESS_DENIED; event: STATUS_OBJECT_TYPE_MISMATCH | decompilation (access 4), observed |
| NtSetInformationJobObject: basic limit (2), extended limit (9), UI restrictions (4) | success; NtQueryInformationJobObject returns what was set | documented, observed |
| short buffer, bad class, invalid handle, handle with only JOB_OBJECT_QUERY | STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_HANDLE, STATUS_ACCESS_DENIED | observed |

Not covered here: setting SeTcb-protected classes with the privilege held, and job limits that need processes in the job.

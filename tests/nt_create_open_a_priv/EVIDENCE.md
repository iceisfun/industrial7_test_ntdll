# nt_create_open_a_priv: privileged, platform-dependent and unimplemented creators

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788) in the elevated guest. Syscall stubs only; every status is
**observed on Windows 10**. Destructive successes (forging a token, adding a paging file, creating a memory
partition, writing audit records) are deliberately never reached: those checks assert the
`STATUS_PRIVILEGE_NOT_HELD` (0xC0000061) outcome that an account without the relevant privilege enabled gets.
Administrators do not hold SeCreateTokenPrivilege, SeAuditPrivilege or an enabled SeCreatePagefilePrivilege/
SeLockMemoryPrivilege by default, and no test enables privileges.

| Test | Check | Source |
| --- | --- | --- |
| create_token_needs_create_token_privilege | NtCreateToken / NtCreateTokenEx return 0xC0000061 for NULL, invalid-type and fully populated arguments (the privilege check precedes argument validation) | observed |
| create_lowbox_token_argument_checks | NULL package SID and NULL source token -> 0xC000000D. A successful lowbox creation is not exercised: experiments with valid-looking package SIDs stalled the guest run until it was killed | observed |
| create_paging_file_needs_privilege | 0xC0000061 for valid, swapped min/max and NULL-name calls; the target file must not exist afterwards | observed |
| partition_create_open | NtCreatePartition (parent NULL or current process) -> 0xC0000061; NtOpenPartition unknown name -> 0xC0000034, NULL attributes -> 0xC000000D | observed |
| open_session_object | `\KernelObjects\Session<id>` opens with SESSION_QUERY (1); full access 0x1F0001 -> 0xC0000022; unknown name 0xC0000034; NULL attributes 0xC000000D. Skipped if the session object is absent or inaccessible | observed |
| create_enclave_unsupported_configuration | on the guest (no SGX/VBS enclave support) NtCreateEnclave fails (0xC00000BB observed), and the base address output is untouched; skipped if enclaves are supported | observed |
| create_cross_vm_objects_not_implemented | NtCreateCrossVmEvent / NtCreateCrossVmMutant -> 0xC0000002 | observed |
| wnf_create_temporary_state_name | lifetime 3 (temporary), scope 1 and 2: unique non-zero names; decoded with the public XOR key the version is 1, lifetime 3, scope as requested, permanent bit clear; `NtDeleteWnfStateName` succeeds | observed |
| wnf_create_invalid_arguments | scope 3, 5, 9 and lifetime 4 and 0 -> 0xC000000D; max state size 0x1001 -> 0xC000000D; persistence on a temporary name -> 0xC000000D; NULL security descriptor -> 0xC0000005; lifetimes 1 and 2 -> 0xC0000061 | observed |
| open_object_audit_alarm_needs_audit_privilege | 0xC0000061, generate-on-close output untouched | observed |
| profile_create_buffer_sizing_and_validation | profile objects are created but never started. buffer size = range >> (shift - 2): exact size ok, one ULONG less -> 0xC0000023; shifts 2, 3, 4 ok; 0, 1, 40 -> 0xC000000D; empty affinity -> 0xC000000D; profile source 1 -> 0xC00000BB; bogus process 0xC0000008; NULL buffer 0xC0000005 | observed |
| profile_ex_group_affinity | group count 0 with NULL array ok; count 1 with a group affinity ok; count 1 with NULL array 0xC0000005 | observed |

Skips: profile tests skip on PRIVILEGE_NOT_HELD / ACCESS_DENIED (profiling needs SeProfileSingleProcessPrivilege on
some configurations), the WNF test skips if session-scope names are refused, the session test as noted above.
The Zw twins CreateCrossVmEvent, CreateCrossVmMutant and CreateEnclave are checked for address identity.

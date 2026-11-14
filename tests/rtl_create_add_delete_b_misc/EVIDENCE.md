# Create/delete helpers: security objects, SIDs, registry, privileges, paths, stacks, threads, tables

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), x64. adm: all tests pass. std: all pass except one concrete skip
(rtl_cad_b_release_privilege: the standard account is refused SeIncreaseWorkingSetPrivilege with 0xC0000061).

| Export | Expectation | Source |
| --- | --- | --- |
| RtlCreateVirtualAccountSid | Base sub-authority must be 0x50..0x6f (else 0xC000000D); NULL name or length 0xC000000D; buffer smaller than 32 gives 0xC0000023 and sets length 32; SID is S-1-5-<base>-<5 dwords> where the five dwords are the SHA-1 digest of the upper-cased UTF-16LE name (verified against an in-test SHA-1); case-insensitive; base 80 equals RtlCreateServiceSid. | decomp 0x84130; observed |
| RtlCreateUserSecurityObject / RtlDeleteSecurityObject | Self-relative descriptor is valid, owner and group equal the arguments, DACL has the two requested ACEs in order with the requested types and masks and SID; delete frees it and returns 0. | decomp 0xd69f0 / 0x7d750; observed |
| RtlDeleteBoundaryDescriptor | Descriptor from RtlCreateBoundaryDescriptor (version dword 1), SIDs may be added; delete frees it (no observable effect beyond not crashing, so it is listed as weakly covered). | decomp 0x22e70 |
| RtlDeleteRegistryValue | RTL_REGISTRY_USER (5) relative path: value removed (checked through Win32), repeated delete 0xC0000034, missing value 0xC0000034; RTL_REGISTRY_HANDLE (0x40000000) with an open key handle works the same; unknown relative-to class 0xC000000D. | decomp 0x8bf30; observed |
| RtlOpenCurrentUser | Returns an open key whose name is under \REGISTRY\USER\ and equals the token user SID (or .DEFAULT). | decomp 0x16790; observed |
| RtlRemovePrivileges | Keep-list semantics: all privileges not listed are removed; values outside 2..0x24 give 0xC000000D; listing a privilege the token does not hold returns STATUS_NOT_ALL_ASSIGNED (0x106) without changing the token; after keeping SeChangeNotifyPrivilege (23) the token has exactly that privilege. Runs on a duplicated token only. | decomp 0x88870; observed |
| RtlReleasePrivilege | After RtlAcquirePrivilege(SeIncreaseWorkingSet) the thread token holds it enabled; after release it is gone or disabled; re-acquire works. Skips on 0xC0000061. | decomp 0x80b80; observed |
| RtlReleasePath | RtlGetExePath twice returns the same cached string; releasing one reference leaves the other valid. | decomp 0x11f80; observed |
| RtlReleaseRelativeName | Clears the CurDirRef field (+0x18) of a RTL_RELATIVE_NAME_U; second release is a no-op. | decomp 0x1a320; observed |
| RtlCreateUserStack | Page size 0, alignment 0, alignment smaller than page size, and a page-size value with the high byte above 0x40 give 0xC000000D; success returns StackBase = AllocatedStackBase + 0x100000, committed top, reserved base; RtlFreeUserStack frees the region. | decomp 0x76310; observed |
| RtlCreateUserThread | Suspended thread does not run until NtResumeThread (previous count 1); start routine runs with the parameter in the new thread (client id matches), exit code is the routine's return; invalid process handle 0xC0000008 with the handle output left NULL. | decomp 0x56090; observed |
| RtlReleaseActivationContext | Reference count (first dword of the context) drops by one after an AddRef/Release pair; NULL is ignored. Layout from decomp 0x13570. | observed |
| RtlDeleteUmsCompletionList / RtlDeleteUmsThreadContext | NULL gives 0xC000000D. Create/delete of real objects is exercised, status is recorded only if creation is refused. | decomp 0xf7040 / 0xf70a0 |
| RtlDeleteFunctionTable | Delete of an unregistered table FALSE; registered table is found by RtlLookupFunctionEntry and after delete is not; second delete FALSE. | decomp 0x679f0; observed |
| RtlDeleteGrowableFunctionTable | After delete RtlLookupFunctionEntry no longer finds the entry. | decomp 0x67ec0; observed |
| RtlDeleteAtomFromAtomTable | String atom delete 0; reference counted (two adds, two deletes); second delete 0xC0000008; pinned atom 0x40000019 and still looked up; integer atom 0x1234 returns 0; atom 0 and unallocated string atom 0xC0000008. | decomp 0x4c170; observed |
| RtlLockMemoryStreamRegion / RtlUnlockMemoryStreamRegion / RtlReleaseMemoryStream | Share RVAs with E_NOTIMPL (0x80004001) and `xor eax,eax` stubs: region calls return 0x80004001 regardless of arguments, Release/AddRef return 0 for any pointer. | asm 0xd5a70 / 0x843e0; observed |

Notes: RtlDeleteRegistryValue creates the target key when it does not exist, so the tests always use a fresh key under HKCU and delete it.

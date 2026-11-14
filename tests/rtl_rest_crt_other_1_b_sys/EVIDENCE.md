# RTL process and thread level helpers: Windows 10 contracts

Reference: ntdll 10.0.19041.2788. Decompilation/disassembly came from the corpus explorer; every expectation was
confirmed on a Windows 10 22H2 guest (elevated administrator and standard user).

| Export (RVA) | Contract asserted | Source |
| --- | --- | --- |
| RtlImpersonateSelf (0x773f0), RtlImpersonateSelfEx (0x77400) | duplicates the process token at the requested impersonation level and installs it on the thread; level 1..3 thread tokens report TokenType impersonation and the requested level, level 0 (anonymous) cannot be re-opened (STATUS_BAD_IMPERSONATION_LEVEL 0xC00000A6); level 4 STATUS_BAD_IMPERSONATION_LEVEL (0xC00000A5); Ex with an access mask and no output pointer STATUS_INVALID_PARAMETER_2 (0xC00000F0) without impersonating; Ex returns a handle to the impersonation token when asked; reverted with NtSetInformationThread(ThreadImpersonationToken, NULL), after which NtOpenThreadToken gives STATUS_NO_TOKEN (0xC000007C) | decompilation, guest |
| RtlDefaultNpAcl (0xd6a90) | ACL revision 2 with five allowed ACEs: S-1-5-18 and S-1-5-32-544 (0x10000000), the token owner (0x10000000), S-1-1-0 and S-1-5-7 (0x80000000); validates; allocated from the process heap. The owner is the token owner (Administrators for an elevated token, the user for a standard token). AppContainer tokens add ACEs and are skipped | decompilation, guest |
| RtlDeregisterWait (0x85960), RtlDeregisterWaitEx (0xb5b0) | NULL handle STATUS_INVALID_PARAMETER_1 (0xC00000EF); unsignalled registration deregisters with 0 and never calls back; with INVALID_HANDLE_VALUE blocks until callbacks end; with a completion event or NULL while a callback is running returns STATUS_PENDING (0x103) and the event is signalled when the callback returns; timeout expiry calls back with TimerOrWaitFired TRUE | decompilation, guest |
| RtlExitUserThread (0x54640) | does not return; thread exit code is the argument (including values with the high bits set) | decompilation, guest |
| RtlExitUserProcess (0x5d9d0) | in a child process: exit code is the argument; other threads are terminated and the process ends promptly | decompilation, guest (child processes) |
| RtlDllShutdownInProgress (0x63440) | FALSE while the process runs normally | decompilation, guest |
| RtlAddGrowableFunctionTable / RtlGrowFunctionTable / RtlDeleteGrowableFunctionTable (0x68720 / 0xe0bc0 / 0x67ec0) | only the first `EntryCount` entries are searchable through RtlLookupFunctionEntry (the ImageBase output is the range base); growing makes further entries searchable, same count allowed, end address exclusive; after delete nothing is found | decompilation (count at +0x54), guest |
| RtlInstallFunctionTableCallback (0x68410), RtlDeleteFunctionTable (0x679f0) | identifier low two bits must be 3 and length must fit 31 bits (otherwise FALSE); the callback is called only from lookups with the control PC and context, its return (or NULL) is the lookup result, the range bounds the calls; delete removes it (FALSE when absent) | decompilation, guest |
| RtlDeactivateActivationContext (0x70a40) | cookie from RtlActivateActivationContext (type nibble 1); a zero cookie is ignored; nested activation restores the previous frame; flag 1 (force early deactivation) accepted | decompilation, guest. Out-of-order deactivation raises an exception and is not tested |
| RtlDeactivateActivationContextUnsafeFast (0x197b0) | caller-allocated frame activated with RtlActivateActivationContextUnsafeFast becomes the active context and deactivation restores the previous one; frame storage reusable | decompilation, guest |
| RtlDeregisterSecureMemoryCacheCallback (0xf7ac0), RtlFlushSecureMemoryCache (0xf7b80) | callbacks return BOOLEAN and the flush result is TRUE when any callback returned TRUE; callbacks receive (address, length); a zero length selects the whole allocation region of the address (FALSE and no call for free memory); no callbacks registered FALSE; registrations are reference counted; deregistering an unknown callback FALSE | decompilation (RtlpCallSecureMemoryCallbacks), guest |
| RtlEnableThreadProfiling (0xcbf80), RtlDisableThreadProfiling (0xcbf10) | flags other than 0/1 STATUS_INVALID_PARAMETER_2 (0xC00000F0); counter mask above 16 bits STATUS_INVALID_PARAMETER_3 (0xC00000F1), flags checked first; the output is untouched on error; the success path (and Disable) is exercised when the guest supports it | decompilation, guest |
| RtlFlushHeaps (0x73f80) | no visible effect: heap validates, live allocations keep their contents and sizes | decompilation, guest |
| RtlDisownModuleHeapAllocation (0x7fa60) | returns STATUS_SUCCESS without using its arguments; the block stays an ordinary allocation | decompilation, guest |
| RtlEnableEarlyCriticalSectionEventCreation (0xe8d80) | sets bit 0x10000000 in PEB.NtGlobalFlag and nothing else; idempotent. The effect on critical-section initialisation was not observable (LockSemaphore stays NULL, recorded as a NOTE); the test restores the original flag value | decompilation, guest |
| RtlGuardCheckLongJumpTarget (0x6dec0) | in a process without enforced control flow guard returns 0 and reports the target valid (1); the output pointer is optional | decompilation, guest |
| RtlEnterUmsSchedulingMode (0xf7190), RtlExecuteUmsThread (0xf7270), RtlDequeueUmsCompletionListItems (0xf7100) | argument validation only: version other than 0x100, NULL thread, NULL list or NULL output all STATUS_INVALID_PARAMETER | decompilation, guest |

## Skips

None on the guest. The AppContainer skip in the default-ACL test applies to tokens that are not used in the
standard test modes.

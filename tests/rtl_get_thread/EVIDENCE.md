# RTL thread, TEB, heap, loader and misc getters: Windows 10 contracts

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788); decompilation from the corpus explorer was used to find
validation order and TEB offsets, the guest run (administrator and standard user) confirmed every value.

| Export (RVA) | Contract asserted | Source |
| --- | --- | --- |
| RtlGetThreadErrorMode (0x60730) | per-thread mask in RTL form: FAILCRITICALERRORS 0x10, NOGPFAULTERRORBOX 0x20, NOOPENFILEERRORBOX 0x40 (SetThreadErrorMode translates); a new thread starts at 0 and does not see other threads' values | decomp, observed (initial guess of 1/2/4 was wrong) |
| RtlGetCriticalSectionRecursionCount (0xe8db0) | RecursionCount for the owning thread, 0 for other threads | decomp |
| RtlGetFrame (0xcdbf0) | TEB ActiveFrame (0x17c0), follows RtlPushFrame/RtlPopFrame (used only as fixtures) | decomp |
| RtlGetCurrentTransaction (0x6dbd0) | TEB CurrentTransactionHandle (0x17b8); initially NULL, follows RtlSetCurrentTransaction (a dummy value is stored and cleared again) | decomp |
| RtlGetCallersAddress (0xed9d0) | first output is the return address of the function that called the caller, second is that function's return address (two-deep stack capture) | decomp, observed |
| RtlGetActiveActivationContext (0x6b5d0) | NULL: 0xC000000D; no active context: 0 with NULL output; with an activated manifest context returns that context handle (reference added, released by the test) | decomp, observed |
| RtlGetCurrentUmsThread / RtlGetNextUmsListItem / RtlGetUmsCompletionListEvent (0x589e0 / 0xf7470 / 0xf74a0) | non-UMS thread: 0xC00000BB with NULL output; NULL args 0xC000000D; list head swapped out atomically; completion list event is a duplicated handle for a real kernel32 completion list | decomp, observed |
| RtlGetThreadWorkOnBehalfTicket (0x6b6c0) | flags 0 returns the TEB ticket (0x2b8); flags with bits above 7 or both low bits set: 0xC00000F0; flags 2 queries the thread (status 0) | decomp, observed |
| RtlGetSecurityDescriptorRMControl (0x85a20) | FALSE and 0 without SE_RM_CONTROL_VALID; TRUE and Sbz1 with it; round trip with RtlSetSecurityDescriptorRMControl | decomp |
| RtlGetFunctionTableListHead (0xe0bb0) | stable list head; RtlAddFunctionTable/RtlDeleteFunctionTable add and remove exactly one entry | decomp, observed |
| RtlGetUnloadEventTrace (0xce800) / ...Ex (0xce810) | stable table pointers; entry size 104; an unloaded module appears in the 16-entry trace with its base, size and name; the extended table count stays within 64 | decomp, observed (the extended table is a wrapped ring and is not searched) |
| RtlGetReturnAddressHijackTarget (0xfd810) | address inside ntdll, equals RtlRaiseExceptionForReturnAddressHijack when exported | decomp |
| RtlGetNonVolatileToken (0xfc410) | ordinary memory: 0xC000000D with output untouched; NULL address: 0xC0000141 | decomp, observed |
| RtlGetLocaleFileMappingAddress (0x7c890) | NULL base 0xC00000EF, NULL locale 0xC00000F0, then a stable mapped-section base and locale | decomp, observed |
| RtlGetUserInfoHeap (0x1bc0) | user value and user flags (0x200/0x400/0x800 settable flags) of a block; the user value requires the block to be allocated with HEAP_SETTABLE_USER_VALUE (0x100), otherwise RtlSetUserValueHeap returns FALSE (observed) | decomp, observed |
| RtlGetNextEntryHashTable (0x82370) | after RtlLookupEntryHashTable, enumerates the remaining entries with the same signature exactly once each, then NULL | decomp, observed |

Skips: none expected.

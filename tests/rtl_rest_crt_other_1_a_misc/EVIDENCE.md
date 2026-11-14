# Privileges, AVL trees, locale/time helpers, barriers, API sets, context capture and misc helpers

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788); green in administrator and standard-user modes.
Behavior was derived from the decompilations (`/api/function/ntdll/<Name>/decomp`) and confirmed on the guest.

| Export | Expectation | Source |
| --- | --- | --- |
| RtlAdjustPrivilege | Uses SeShutdown (held by both account types): enable returns 0 and reports the previous state (0 then 1), disable likewise; a privilege not held (SeTcb) gives STATUS_PRIVILEGE_NOT_HELD 0xC0000061 and leaves the output untouched; thread-token mode without impersonation gives STATUS_NO_TOKEN 0xC000007C. The original state is restored. SeTcb held would be noted, not failed. | decomp 0x791e0 |
| RtlAvlInsertNodeEx / RtlAvlRemoveNode | Generic AVL on `RTL_BALANCED_NODE {Left, Right, ParentValue}` (low two bits of ParentValue hold the balance): 300 shuffled inserts, ascending inserts (height of a 128-node ascending tree is 8), ordered removals; after every step the tree is a BST, parent pointers match and subtree heights differ by at most 1. Insert into an empty tree makes the node the root. | decomp 0x68920, 0x68070 |
| RtlCanonicalizeDomainName | Lower-cases and IDNA-normalizes names; IPv4/IPv6 literals are re-formatted ("[::1]" becomes "::1"); an empty name fails. | decomp 0xcf10; outputs observed on the guest |
| RtlCultureNameToLCID | en-US 0x409, de-DE 0x407, ja-JP 0x411, fr-FR 0x40c, case-insensitive; unknown name, empty name, NULL pointers and over-long names return FALSE. | decomp 0x3b850; documented LCIDs |
| RtlCutoverTimeToSystemTime | Year 0: month/week-of-month (1..5, 5 = last)/weekday rules (second Sunday of March 2020 = Mar 8, last Sunday of Oct 2020 = Oct 25, first Thursday of Nov 2020 = Nov 5); with ThisYear FALSE and the month already past the next year is used (Mar 14 2021); week 0 or 6 is rejected. Year != 0: converted verbatim, FALSE when in the past unless ThisYear, FALSE for an invalid month. | decomp 0x5aea0 |
| RtlBarrier / RtlBarrierForDelete | Initialized with kernel32 InitializeSynchronizationBarrier; with three participants over five rounds exactly one call per round returns TRUE (the last arriver). A one-thread barrier always returns TRUE. RtlBarrierForDelete is a separate entry point (calls the posix barrier with flag 0x10000). | decomp 0xed870, 0xed880 |
| ApiSetQueryApiSetPresence(Ex) | Existing contracts report present=TRUE, unknown ones FALSE with status 0; Ex also returns the in-schema flag first. A non-API-set name reports present=FALSE. | decomp 0x76ea0, 0x691b0; observed |
| RtlCaptureContext2 | ContextFlags is rebuilt as 0x10000F, SegCs 0x33, SegSs 0x2B, MxCsr 0x1F80, Rip inside the calling image, Rsp inside the thread stack. | decomp 0xa12c0 |
| RtlCloneMemoryStream, RtlCommitMemoryStream | All IMemoryStream-style Rtl methods are one shared stub returning E_NOTIMPL 0x80004001. Shared-address assertion over 14 exports. | decomp 0xd5a70 |
| RtlDeNormalizeProcessParams | Turns the nine pointer fields (offsets 0x40, 0x58, 0x68, 0x78, 0xB8, 0xC8, 0xD8, 0xE8, 0x418) into offsets from the block base, skips NULLs, clears flag bit 0, is a no-op when not normalized, and returns its argument (NULL stays NULL). | decomp 0xd67a0 |
| RtlContractHashTable | A fresh dynamic hash table is at minimum size (FALSE); after Expand it contracts once (TRUE) and then FALSE again; 20 expands then 20 contracts then FALSE. | decomp 0x87e10 |
| RtlCommitDebugInfo / RtlDeCommitDebugInfo | Bump allocator inside a debug-information buffer (fields at +0x48 next, +0x50 committed end, +0x58 reserved end): sizes round up to 8; sizes above 0xFFFFFFF8 or beyond the reserved limit return NULL; DeCommit only takes back the most recent allocation; growing past the committed end commits memory. | decomp 0xd7410, 0xd76c0 |
| RtlClearThreadWorkOnBehalfTicket | Returns 0 when no ticket is set on the thread. | decomp 0x675b0 |
| RtlAppxIsFileOwnedByTrustedInstaller | System32\kernel32.dll is owned by TrustedInstaller (TRUE); a scratch file is not (FALSE); NULL output pointer gives 0xC000000D; an invalid handle gives STATUS_INVALID_HANDLE 0xC0000008 and leaves the output. | decomp 0xcbda0; observed |

| KiUserInvertedFunctionTable | Data export: `{ULONG Count, MaxCount, Epoch...; entries of 0x18 bytes at +0x10: ExceptionDirectory, ImageBase, ImageSize, SizeOfTable}`; the executable and ntdll are listed with SizeOfImage and the exception directory taken from their PE headers. | observed on the guest |

Skips: none expected. Observed-only: canonicalization outputs, API-set presence of the chosen contract names.

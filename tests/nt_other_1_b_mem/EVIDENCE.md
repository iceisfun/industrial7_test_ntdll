# nt_other_1_b_mem: memory natives, Windows 10 22H2 (ntdll 10.0.19041.2788)

Decompilation of these exports is only the syscall stub (corpus function records, `/decomp`), so argument
validation order is not visible there. Every expected value below was therefore taken from the public
documentation of the Win32 wrappers and then confirmed by running the exe on the Windows 10 guest (adm and std).
Nt/Zw pairs: `alias_pairs` compares the two resolved addresses (same RVA).

| Export | Checked | Source |
| --- | --- | --- |
| NtFlushInstructionCache | status 0 for the pseudo handle, `GetCurrentProcess()`, NULL/0 ("flush all"); an executed `ret` stub afterwards. An invalid handle and a NULL handle also return 0: the process handle is not validated (observed on Win10). | docs + observed |
| NtFlushProcessWriteBuffers / NtFlushWriteBuffer | callable repeatedly; NtFlushWriteBuffer returns 0. | docs (FlushProcessWriteBuffers) + observed |
| NtFlushVirtualMemory | mapped file view: status 0, IoStatus.Status 0, base/size rounded out to page boundaries; data reaches the file; invalid handle `STATUS_INVALID_HANDLE` (C0000008); reserve-only page `STATUS_NOT_MAPPED_DATA` (C0000019). | observed |
| NtLockVirtualMemory | MAP_PROCESS (1): base/size rounded to pages; locking an already-locked page returns the success-class `STATUS_WAS_LOCKED` (40000019); map type 0 or 4 `STATUS_INVALID_PARAMETER`; bad handle C0000008. Unlocked again through NtUnlockVirtualMemory (helper only). | observed |
| NtGetWriteWatch | counts and addresses of dirtied pages, granularity 4096, reset flag (1) clears hits, count clamped to the output array; flags 2 -> `STATUS_INVALID_PARAMETER_2` (C00000F0); size 0 -> `STATUS_INVALID_PARAMETER_4` (C00000F2); region without MEM_WRITE_WATCH -> C00000EF; unaligned base is rounded (0); bad handle C0000008. NtResetWriteWatch used as helper. | observed + docs (GetWriteWatch) |
| NtMapViewOfSectionEx | pagefile section mapped at a new address with offset 0: view size = section size, shared content with a Win32 view, MEM_MAPPED, requested protection; partial view size; offset 4096 -> `STATUS_MAPPED_ALIGNMENT` (C0000220); invalid section or process handle C0000008. Extended parameters NULL/0 only. | observed |

Skips: none. Not covered here: NtFreeUserPhysicalPages, NtMapUserPhysicalPages(Scatter) (AWE needs SeLockMemoryPrivilege).

# nt_other_3_a_mem evidence

Exports covered (Nt names; Zw names share the entry RVA and are alias-checked in
`other3a_nt_zw_aliases`): NtFreeVirtualMemory, NtProtectVirtualMemory, NtFlushVirtualMemory,
NtLockVirtualMemory (with NtUnlockVirtualMemory for cleanup), NtGetWriteWatch (NtResetWriteWatch
for cleanup), NtMapViewOfSection, NtMapViewOfSectionEx, NtFlushInstructionCache,
NtFlushWriteBuffer, NtFlushProcessWriteBuffers.

## Authority

Every status code and output value below was observed on Windows 10 22H2 (ntdll 10.0.19041.2788)
in the guest, in both elevated-administrator and standard-user runs, with identical results.
The ntdll stubs are bare syscall thunks (the Corpus Explorer shows `syscall` with the service
number only), so argument validation order comes from the kernel services; the public
documentation of VirtualFree, VirtualProtect, VirtualLock, GetWriteWatch and MapViewOfFile was
used to choose scenarios, not to fix status codes.

## State used

Private allocations of 1-8 pages and unnamed pagefile-backed sections (16-128 KiB). No files,
no executable pages, no physical memory, no process other than the caller. Every allocation,
view and handle is released at the end of its test.

## Observed contracts

- NtFreeVirtualMemory: MEM_RELEASE with size 0 releases the whole allocation and returns its size;
  MEM_DECOMMIT keeps the reservation and recommitted pages are zero; unaligned decommit ranges
  round outward; neither/both of RELEASE and DECOMMIT, or an unknown high bit, give
  STATUS_INVALID_PARAMETER_4 (0xC00000F2); invalid handle 0xC0000008; releasing an unallocated
  address 0xC00000A0 (STATUS_MEMORY_NOT_ALLOCATED). Observed: unlike VirtualFree, the native service accepts
  MEM_RELEASE with a non-zero size and frees just that page range (test
  `free_release_with_size_releases_a_range`).
- NtProtectVirtualMemory: old protection returned, base/size rounded to pages, PAGE_GUARD modifier
  round-trips; invalid protection 0xC0000045; zero size 0xC00000F1 (parameter 3); reserved-only
  range 0xC000002D (STATUS_NOT_COMMITTED); unallocated range 0xC0000018 (STATUS_CONFLICTING_ADDRESSES).
- NtFlushVirtualMemory: private memory 0xC0000019 (STATUS_NOT_MAPPED_VIEW), pagefile section view
  0xC0000088 (STATUS_NOT_MAPPED_DATA), invalid handle 0xC0000008; size argument untouched on failure.
- NtLockVirtualMemory: MapType 1 (MAP_PROCESS) succeeds without any privilege (identical in the
  standard-user run); the second unlock gives 0xC000002A (STATUS_NOT_LOCKED); MapType 0 or 4 and size 0
  give 0xC000000D. MAP_SYSTEM (2) is intentionally not called (needs SeLockMemoryPrivilege).
- NtGetWriteWatch: with MEM_WRITE_WATCH, written pages are reported in address order with
  granularity 0x1000; flag 1 (reset) clears; array capacity limits the count; invalid flags give
  0xC00000F0 (parameter 2), zero size 0xC00000F2, an empty result array 0xC00000F3, a region not
  allocated with write watch 0xC00000EF.
- NtMapViewOfSection: ViewSize 0 maps the whole section (size rounded), view is MEM_MAPPED,
  second unmap gives 0xC0000019, view larger than the section or offset past the end 0xC000001F
  (STATUS_INVALID_VIEW_SIZE), offset not 64 KiB aligned 0xC0000220 (STATUS_MAPPED_ALIGNMENT), an
  execute protection on a read/write-only section 0xC000004E (STATUS_SECTION_PROTECTION), bad
  protection value 0xC0000045, invalid handles 0xC0000008.
- NtMapViewOfSectionEx: same mapping results with no extended parameters; a non-zero parameter
  count with a NULL array gives 0xC000000D. Two views of one section share data.
- NtFlushInstructionCache: success for a valid range, for NULL/0, and (observed) also for an
  invalid process handle and an unmapped range; i.e. no validation is performed.
- NtFlushWriteBuffer returns STATUS_SUCCESS; NtFlushProcessWriteBuffers returns nothing observable
  and must simply return.

## Skips

None expected. Tests use REQUIRE() only for exports missing from the module.

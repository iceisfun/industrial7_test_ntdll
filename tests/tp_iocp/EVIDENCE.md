# I/O completion ports and wait completion packets

Reference: Windows 10 22H2 ntdll 10.0.19041.2788. All exports here are thin system-call stubs (the Nt and Zw names share one
RVA), so argument validation and results come from the kernel. Every status below was observed on the Windows 10 guest
(administrator and standard user). Public documentation was used only for the semantics of the calls.

| Check | Source |
| --- | --- |
| Nt/Zw pairs resolve to the same entry for all ten exports | decompilation / export table (same RVA) |
| Create (access 0x1F0003), query depth (class 0, ULONG, return length 4), FIFO delivery of key/apc/IoStatus.Status/Information via NtSetIoCompletion + NtRemoveIoCompletion | observed |
| Remove on empty port with zero timeout -> STATUS_TIMEOUT 0x102; relative timeout waits at least ~half the time | observed |
| NULL result handle in create -> 0xC0000005; NULL/closed handle -> 0xC0000008; pseudo handle (-1) and event handle -> 0xC0000024 | observed |
| Query: class 1 -> 0xC0000003; lengths 0/3/8 -> 0xC0000004; NULL return length accepted; NULL buffer -> 0xC0000005 | observed |
| Handle created with only SYNCHRONIZE: set/remove/query -> 0xC0000022 | observed |
| Open of a missing name -> 0xC0000034; NULL ObjectAttributes -> 0xC000000D; an opened handle shares the object (packet set through one handle removed through the other) | observed |
| NtRemoveIoCompletionEx: batches of 3 then 2 in FIFO order with all fields; count 0 -> 0xC000000D; NULL info or NULL returned count -> 0xC0000005; bad handle -> 0xC0000008; alertable timeout -> 0x102. EntriesRemoved on timeout is not asserted (observed non-zero) | observed |
| NtSetIoCompletionEx with a reserve object (NtAllocateReserveObject type 1): packet carries key/apc/status/info, reserve reusable after the packet is removed, second use while queued -> 0xC00000F0; NULL port/reserve -> 0xC0000008; port used as reserve -> 0xC0000024 | observed |
| Wait completion packet: associate with unsignaled event -> 0, AlreadySignaled=0, no packet queued; cancel -> 0; signal -> packet with the given key/apc/status/info; associate while associated -> 0xC00000EF; cancel after delivery -> 0xC0000120; associate with signaled target -> 0 and AlreadySignaled=1 with the packet queued at once; cancel with RemoveSignaledPacket=TRUE removes a queued packet (-> 0, next remove times out); NULL/wrong-type handles -> 0xC0000008 / 0xC0000024; NULL out handle -> 0xC0000005 | observed |

Nothing depends on privilege. Named-object tests use the session's object directory discovered from a named event and skip if
creation is denied.

Review additions: creating a second port with an existing name -> 0xC0000035 (observed, asserted exactly); an alertable
NtRemoveIoCompletionEx wait interrupted by a queued user APC returns 0xC0 (STATUS_USER_APC) and the APC then runs (observed).

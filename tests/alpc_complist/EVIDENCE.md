# ALPC completion lists on a real port

Reference: Windows 10 22H2 ntdll 10.0.19041.2788. The Alpc*CompletionList wrappers are thin: the decompilation
shows each forwards to `NtAlpcSetInformation` (RegisterCompletionList additionally zeroes the user SRW lock at
header+0x140 after success). Their argument validation therefore comes from the kernel and every status below was
observed on the Windows 10 guest (admin and standard user), not derived.

| Check | Source |
| --- | --- |
| Register: list size 0x1000 or concurrency 0 -> 0xC000000D; NULL buffer -> 0xC0000005; pseudo/process handle -> 0xC0000024 | observed |
| Register on a valid listening port with size 0x10000, concurrency 2 succeeds; kernel writes `StartMagic 0xDEADBEEFBAADF00D`, `TotalSize`, list/bitmap/data regions (ordered, inside the buffer, data 64-byte aligned), `AttributeFlags`, `AttributeSize == AlpcGetHeaderSize(flags)`, empty-list state 0x0000FFFFFFFFFFFF | observed; absolute offsets are not asserted, only structure |
| Register again on the same port: same buffer 0xC0000018, different buffer 0xC000071A | observed |
| Adjust concurrency: 3 ok, 0 -> 0xC000000D, before registration 0xC000000D | observed |
| Rundown/Unregister succeed; Unregister is idempotent; Rundown after Unregister -> 0xC000000D; re-register after Unregister works with new flags | observed |
| Completion packet: NtAlpcSetInformation class 2 (associate completion port, `{key, port}`) makes the kernel queue a packet with the registered key for each batch of messages posted into the list; a connection request is delivered through the list (type 0x200a, low byte 10 = connection request) and is then no longer receivable with NtAlpcSendWaitReceivePort; it is accepted from a copy of the list message | observed |
| Packets can be coalesced (fewer packets than messages), so the test requires at least one packet and drains the rest without a count | observed |
| Ring order, per-message data, context attribute (`PortContext` of the communication port, `MessageId`), AlpcGetCompletionListMessageAttributes == attribute pointer returned by AlpcGetMessageFromCompletionList, post/return counters, outstanding count, LastMessageInformation, block reuse after Free | observed, helpers' semantics from decompilation (see alpc_attr/EVIDENCE.md) |
| Worker-thread register/unregister on the kernel-initialised header | decompilation + observed |

The IO completion key (0x77) and the context values (0x4242) are chosen by the test. Nothing depends on privilege.

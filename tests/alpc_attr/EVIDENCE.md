# ALPC message-attribute and completion-list helpers (memory-only)

Reference: Windows 10 22H2 ntdll 10.0.19041.2788. Decompilations from the Windows 10 corpus
(`/api/function/ntdll/<Name>/decomp`) were read for the contracts; the Windows 10 guest run is the authority.
All checks below passed unchanged on Windows 10 (admin and standard user).

| Export | RVA | Contract tested (source: decompilation, confirmed on Windows 10) |
| --- | --- | --- |
| AlpcGetHeaderSize | 0x70460 | 8-byte `ALPC_MESSAGE_ATTRIBUTES` header plus per-attribute sizes: bit31 security 0x18, bit30 data view 0x20, bit29 context 0x20, bit28 handle 0x18, bit27 token 0x18, bit26 direct 8, bit25 work-on-behalf 8. Bits 0-24 ignored. All 128 subsets checked. |
| AlpcInitializeMessageAttribute | 0x703c0 | Always writes the required size to the out parameter; `STATUS_BUFFER_TOO_SMALL` (0xC0000023) if the supplied size is smaller (buffer untouched); otherwise `AllocatedAttributes = flags`, `ValidAttributes = 0`. A NULL buffer is accepted when the size is sufficient. |
| AlpcGetMessageAttribute | 0x70420 | NULL unless exactly one bit is requested and that bit is allocated; otherwise buffer + AlpcGetHeaderSize(allocated bits above the requested bit), i.e. attributes are laid out in descending bit order. `ValidAttributes` is not consulted. |
| AlpcMaxAllowedMessageLength | 0x84a10 | Constant 0xFFFF. |
| AlpcRegisterCompletionListWorkerThread | 0x75240 | Worker count is the top 16 bits of the state qword at header+0x40; increments and returns 1 while the count is <= 0xFFFE, else returns 0; low 48 bits preserved. |
| AlpcUnregisterCompletionListWorkerThread | 0x751e0 | Returns 0 if the count is 0 or the low 24 bits (head index) are not the empty marker 0xFFFFFF; otherwise decrements the count and returns 1. |
| AlpcGetOutstandingCompletionListMessageCount | 0x85db0 | `*(int*)(hdr+0x80) - *(int*)(hdr+0xc0)` (posted minus returned). |
| AlpcGetCompletionListLastMessageInformation | 0xe0970 | Copies hdr+0x48 (last message id) and hdr+0x4c (last callback id) to the two out parameters. |
| AlpcGetCompletionListMessageAttributes | 0xe0990 | NULL when hdr+0x24 (attribute flags) is zero, else the 8-byte-aligned address after `msg + PORT_MESSAGE.TotalLength`. |
| AlpcGetMessageFromCompletionList | 0x10a60 | Pops the message at the head index of the ring (entry count = ListSize/4; list at ListOffset, data at DataOffset); head == tail empties the list (low 48 state bits all ones); a head/tail >= entry count or the empty marker returns NULL; wraps modulo the entry count; state high bits (worker count) preserved; attribute out pointer optional and NULL when no attribute space is configured. |
| AlpcFreeCompletionListMessage | 0x70730 | Message must be 64-byte aligned and its extent (TotalLength, rounded to 8 plus AttributeSize when attributes are configured) must lie inside the data area; clears the covering 64-byte-block bits in the bitmap and increments ReturnCount (hdr+0xc0). Anything else is silently ignored. |

The completion-list tests run against a hand-built header in private memory, using the header layout
(`StartMagic`, `TotalSize`, `ListOffset/Size`, `BitmapOffset/Size`, `DataOffset/Size`, `AttributeFlags/Size`,
state at +0x40, `LastMessageId`/`LastCallbackId` at +0x48/+0x4c, post count +0x80, return count +0xc0, user lock
+0x140) that the kernel-initialised header in the `alpc_complist` area is also checked against.

No skips. No privilege dependence.

# NtAlpc* ports, connections, messages and per-port resources

Reference: Windows 10 22H2 ntdll 10.0.19041.2788. The Nt*/Zw* stubs are bare syscall stubs (no user-mode
validation in the decompilation), so every status code below is the kernel's and was **observed** on the Windows
10 guest, admin and standard user; structure layouts (ALPC_PORT_ATTRIBUTES, PORT_MESSAGE, ALPC_MESSAGE_ATTRIBUTES,
security/view/context attributes) follow the public ntlpcapi definitions. Everything runs inside one process over
a loopback connection on a port named under `\RPC Control` (creatable by standard users), with a server thread
(fixture.h) and the test thread as client. All waits have timeouts.

Statuses: 0xC0000035 name collision, 0xC0000034 name not found, 0xC0000041 port connection refused, 0xC0000037
port disconnected, 0xC0000024 object type mismatch, 0xC0000008 invalid handle, 0xC000000D invalid parameter,
0xC0000004 info length mismatch, 0xC0000005 access violation (bad pointer), 0xC000002F invalid buffer size,
0xC0000022 access denied, 0xC0000023 buffer too small, 0x102 timeout, 0x80000005 buffer overflow,
0xC0000141 invalid address. 0xC0000702 and 0xC0000109 are returned for an unknown message id and for a cancel
that has nothing to cancel; they are asserted as observed numbers.

| Area | What is asserted and where it came from |
| --- | --- |
| Nt/Zw aliases | All 23 Nt/Zw pairs resolve to the same address (export table). |
| Create | named create, duplicate name 0xC0000035, NULL result 0xC0000005, undefined flag bits and MaxMessageLength 0x100000 -> 0xC000000D, failed creates leave no name behind, unnamed ports with NULL attributes. Observed. |
| QueryInformation | class 0 = `{Flags, SequenceNo, PortContext}` 16 bytes; server connection ports carry flag 0x20000; length < 16 -> 0xC0000004; NULL buffer/bad class/NULL handle -> 0xC000000D; pseudo, process and event handles -> 0xC0000024; class 12 = `{SessionId, ProcessId}` of the owner (checked against the real session and pid). Observed. |
| SetInformation | classes 1 and 2 have a fixed size (mismatch 0xC0000004), class 2 with a NULL completion port 0xC000000D, class 0/99 and NULL handle 0xC000000D. Observed. |
| Connect (ALPC_SYNC_CONNECTION 0x20000) | missing port 0xC0000034; no receiver -> timeout 0x102 with output handle untouched; refused connection 0xC0000041; accepted connection returns the handle, the connection-reply data, and the length 0x28+8 in the buffer-length parameter. Without the sync flag the connect returns immediately and the reply arrives later as a message, so the tests always set it. Observed. |
| Accept | the context passed to NtAlpcAcceptConnectPort is reported as PortContext of the new communication port (0x5151) and in the context attribute of each received request; the connection request carries DataLength, data, client pid and a token attribute. Observed. |
| Request/reply | synchronous (flag 0x20000) and asynchronous (separate receive) replies; received type low byte 1; client pid/tid in the header; short receive times out 0x102. Observed. |
| Sender queries | NtAlpcOpenSenderProcess/Thread return handles to the client process and thread (pid/tid compared); NULL message/NULL attributes 0xC0000005; desired access 0 -> 0xC0000022; unknown message 0xC0000702; flags are ignored. Observed. |
| QueryInformationMessage | class 0 = the sender token user SID (compared with the process token's user), class 1 = token modified LUID (compared with TokenStatistics), too-small buffer 0xC0000023 with required length, class 2 0xC000000D, class 3 0xC0000004. Observed. |
| Impersonation | NtAlpcImpersonateClientOfPort fails with 0xC0000022 unless the request was sent with a security attribute (created by NtAlpcCreateSecurityContext); with it, it succeeds (a thread token exists, RevertToSelf afterwards); flags 1 and 8 accepted, 0x10 -> 0xC000000D; unknown message 0xC0000702. Observed. |
| Message size checks | TotalLength beyond the port's MaxMessageLength 0xC000002F; total shorter than the header or data longer than total-header 0xC000000D. Observed. |
| Disconnect | undefined flags 0xC000000D, NULL handle 0xC0000008, wrong object type 0xC0000024; a disconnected port rejects sends with 0xC0000037; closing the client port makes the server receive a port-closed message (type 5). Observed. |
| ConnectPortEx | works with the connection port named through OBJECT_ATTRIBUTES; second client gets a distinct server-side port; missing port 0xC0000034. Observed. |
| Resource reserve / port section / section view / security context | create/delete round trips, double delete 0xC0000008 (views: 0xC0000141), flag/size/NULL-pointer error paths, section created with and without a backing section handle (actual size 0x10000, view readable and writable). Observed. |

Observed-only quirks that are asserted because they were stable across runs: NULL-handle statuses differ by call
(0xC0000008 for most, 0xC000000D for query/set information, delete-resource-reserve and message queries).

Not covered by behaviour: see the coordinator's justified list (NtAlpcImpersonateClientContainerOfPort succeeds
or fails depending on container state, so only its NULL-pointer paths and unknown-message path are asserted).

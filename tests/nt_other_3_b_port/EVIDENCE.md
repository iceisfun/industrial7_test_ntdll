# Zw-named legacy LPC port services: Windows 10 contracts

Oracle: Windows 10 22H2 x64, elevated and standard user. A server thread in the test process owns a connection port in
`\RPC Control` and answers a client in the same process (fixtures: NtCreatePort, NtConnectPort, NtAcceptConnectPort,
NtCompleteConnectPort). Every wait is bounded; the server loop ends on a 5 s receive timeout and the port handle is closed at the end.
Message layout: 40-byte PORT_MESSAGE header (DataLength, TotalLength, Type, DataInfoOffset, ClientId, MessageId, ClientViewSize).

| Export | Expectation | Source |
| --- | --- | --- |
| ZwRequestWaitReplyPort | reply carries Type 2 (LPC_REPLY), DataLength 8, TotalLength 48, non-zero MessageId, payload incremented by the server; works for replies sent with ZwReplyWaitReceivePort(Ex) and with ZwReplyPort | obs |
| ZwReplyWaitReceivePortEx / ZwReplyWaitReceivePort | server receives connection request (Type 10), requests (Type 1), datagrams (Type 3); a 30 ms and a zero timeout on an empty port -> 0x102 | obs |
| ZwRequestPort | datagram delivered with its payload and no reply; TotalLength smaller than the header or smaller than DataLength + header -> 0xc000000d; message above the port maximum -> 0xc000002f | obs |
| ZwReplyPort | answers a request over the communication port; the client sees the reply | obs |
| ZwReplyWaitReplyPort | answers a request and then blocks; when the client end is closed it returns 0xc0000253 | obs |
| ZwSecureConnectPort | second client connects with a NULL required SID; unknown port name -> 0xc0000034 (same for the plain connect) | obs |
| ZwReadRequestData / ZwWriteRequestData | message without data entries -> 0xc000000d; with a NULL or event handle the message check still fires first (0xc000000d) | obs |
| ZwRegisterThreadTerminatePort | client port handle -> 0; NULL and unused handle -> 0xc0000008; event handle -> 0xc0000024 | obs |
| All services | NULL and unused handles -> 0xc0000008, event handle -> 0xc0000024 (request, reply, receive, register services) | obs |

Skip: port creation failure (status in the skip text).

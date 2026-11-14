# nt_other_2_a_lpc: legacy LPC port services

Oracle: Windows 10 22H2 guest. A server thread owns an NtCreatePort port under `\RPC Control`; the client
connects with NtSecureConnectPort. All waits carry timeouts (5 s server receive, 5-8 s joins). Values are
**observed on Windows 10**; message type numbers are the documented LPC constants (request 1, reply 2,
datagram 3, port closed 5, connection request 10).

| Behaviour | Value |
| --- | --- |
| Connect | NtSecureConnectPort returns 0, MaxMessageLength equals the server's 0x100; the server receives type 10, NtAcceptConnectPort and NtCompleteConnectPort return 0 |
| Request/reply | NtRequestWaitReplyPort returns reply type 2 with data incremented bytewise, non-zero MessageId; the first receive uses NtReplyWaitReceivePortEx and later ones NtReplyWaitReceivePort; first reply through NtReplyPort, others through the next NtReplyWaitReceivePortEx |
| Datagram | NtRequestPort delivers type 3 with no reply; port context given at accept (0xABCD) is returned with every request |
| Close | Closing the client delivers type 5 to the server; the next receive times out (0x102, also with a zero timeout) |
| Errors | invalid handle `STATUS_INVALID_HANDLE`, event handle `STATUS_OBJECT_TYPE_MISMATCH` for all message calls; unknown port name `STATUS_OBJECT_NAME_NOT_FOUND`, unknown directory `STATUS_OBJECT_PATH_NOT_FOUND`; accept with a non-connection message `STATUS_REPLY_MESSAGE_MISMATCH` (0xC000021F); stray reply (no outstanding request) 0xC0000702 (observed); NtWriteRequestData with a message lacking a data-info descriptor `STATUS_INVALID_PARAMETER`, checked before the handle |
| NtRegisterThreadTerminatePort | accepts a port handle created by NtCreatePort |

NtCompleteConnectPort (helper) returns 0 for any handle on this build and is therefore not asserted on invalid
handles. NtReplyWaitReplyPort is only covered by argument validation (a callback reply needs a second LPC
connection pattern that is not stable to build).

# Thread pool timers, waits, I/O, job and ALPC completions

Reference: Windows 10 22H2 ntdll 10.0.19041.2788; decompilation of each export and the guest run (admin and standard
user) as the authority. Invalid parameters raise a continuable exception 0xC000000D (TppRaiseInvalidParameter); a vectored
handler counts it and continues.

| Check | Source |
| --- | --- |
| TpSetTimerEx: first set returns 0, replacing a pending timer returns 1, cancelling (NULL due time) returns 1 when set and 0 otherwise; one-shot fires once, periodic fires repeatedly and stops after cancel and TpWaitForTimer; absolute past due time fires at once; NULL timer raises and returns 0 | decompilation (0x126d0), observed |
| TpTimerOutstandingCallbackCount: 0 when idle and after completion, 1 inside the running callback, NULL timer raises and returns 0 | decompilation (0x9bb0), observed |
| TpSetWaitEx: callback result WAIT_OBJECT_0 on signal and WAIT_TIMEOUT on timeout; NULL handle cancels (returns 1 when a wait was pending, 0 otherwise); NULL timeout waits indefinitely; non-NULL reserved argument raises | decompilation (0x11d60), observed |
| TpAllocIoCompletion with an overlapped file: the native callback receives (Instance, Context, OVERLAPPED, IoStatusBlock, Io) with Status 0 and Information = byte count for a write and a read, STATUS_END_OF_FILE (0xC0000011) for a read at EOF; TpStartAsyncIoOperation followed by TpCancelAsyncIoOperation produces no callback and TpWaitForIoCompletion does not block. NULL out / NULL file / NULL callback raise; an event handle gives 0xC0000024 | decompilation (0x75ca0, 0x127e0, 0x78bd0), observed |
| TpAllocJobNotification: NULL out / NULL job / NULL callback raise (0xC000000D); a child assigned to the job produces at least two callbacks carrying the context; wait and release return | decompilation (0x7f510, 0x7f310, 0x7f350), observed |
| TpAllocAlpcCompletion(Ex): NULL out, NULL callback, NULL port raise (0xC000000D); an event handle gives 0xC0000024; a real port gives an object that TpWaitForAlpcCompletion passes and TpReleaseAlpcCompletion frees; a port accepts only one completion association (second allocation 0xC0000048); TpAlpcRegister/UnregisterCompletionList on an object not allocated for a completion list raise | decompilation (0x796b0, 0x79510, 0x79640, 0x796e0), observed |

The job notification count (3 to 5) and the message argument vary with job events and are not asserted exactly. The
TpAllocAlpcCompletionEx status on a port that already carries an association is logged only.

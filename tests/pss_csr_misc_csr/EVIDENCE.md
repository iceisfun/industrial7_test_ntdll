# pss_csr_misc_csr - Csr* client helpers

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), administrator run, 8 tests / 85 checks pass.

Sources: image-level decompilation (capture-buffer layout, rounding, status codes) confirmed by observation on Windows 10.

* CsrGetProcessId: nonzero, stable, and names csrss.exe in the toolhelp process list.
* CsrAllocateCaptureBuffer(n, bytes): block size = (bytes + 0x23 + 11*n) & ~3 at offset 0, pointer count at +0x10 (0), data pointer at +0x18 = base + 0x20 + 8*n... (observed: base+0x30 for n=2), zeroed slots. Limits (n >= 0x10000000, bytes >= 0x7fffffdc, combined overflow) return NULL.
* CsrAllocateMessagePointer: returns length rounded up to 4 (0 for length 0), stores the old data pointer, advances it, records the address of the output pointer variable in the next slot (NULL for length 0) and increments the count.
* CsrCaptureMessageBuffer copies bytes; CsrCaptureMessageString: STRING.Length, MaximumLength = rounded allocation (copy path) or exactly the request (NULL source), terminator written when room remains.
* CsrCaptureMessageMultiUnicodeStringsInPlace: NULL first argument STATUS_INVALID_PARAMETER; allocates the buffer when *pCapture is NULL, repoints each non-NULL UNICODE_STRING into it, NULL entries skipped (count 2 of 3), strings NUL terminated.
* CsrCaptureTimeout: -1 -> NULL; otherwise ms * -10000 (signed 32-bit input).
* CsrSetPriorityClass: STATUS_INVALID_PARAMETER for any input. CsrIdentifyAlertableThread: returns 0 (two-instruction stub, xor eax,eax).
* CsrVerifyRegion: false for NULL, wrap-around and stack addresses; true for the first byte of the PEB ReadOnlySharedMemoryBase region; zero length at the base is false (observed, matches decompilation).
* CsrClientConnectToServer: with no connection info returns 0 and clears the server-to-server flag; info without size is STATUS_INVALID_PARAMETER (nothing is sent).
* CsrClientCallServer: an API number with an unused index (server 1, index 0xFFFF) is refused by the subsystem with STATUS_ILLEGAL_FUNCTION (0xC00000AF), written to the message status (+0x34); the API number is stored at +0x30 and the port-message length word at +0 is 0x600038 for a 0x20-byte payload.
* CsrFreeCaptureBuffer: called on every allocated buffer (no observable result; heap block release).

Skips: none. std mode: not runnable (guest standard-user logon fails infrastructure-wide). The subsystem requires nothing privileged.

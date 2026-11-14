# nt_other_1_a_ctx evidence

NtContinue / NtContinueEx on Windows 10 22H2.

* Round trip: RtlCaptureContext in a function, then NtContinue(ctx, FALSE) / NtContinueEx(ctx, FALSE) from the same function resumes at the capture point (setjmp-like); a
  phase counter proves the second pass. The service does not return on success.
* TestAlert: with FALSE a queued user APC stays pending until an alertable wait (NtDelayExecution returns STATUS_USER_APC); with TRUE the APC runs as part of the
  continue (documented behaviour of the TestAlert parameter).
* Errors (observed): NULL context and an unmapped context pointer STATUS_ACCESS_VIOLATION; a misaligned context pointer STATUS_DATATYPE_MISALIGNMENT (0x80000002).

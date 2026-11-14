# rtl_query_set_b_async

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), standard user and elevated administrator runs. Decompilation (Corpus Explorer, /api/function/ntdll/<Name>/decomp) was consulted for argument validation order; every value below was then confirmed by running on the Windows 10 guest.

## Exports covered (behavioral)
RtlSetThreadPreferredUILanguages, RtlSetThreadPreferredUILanguages2, RtlSetProcessPreferredUILanguages, RtlSetTimer,
RtlSetIoCompletionCallback.

## Where expectations come from
| Area | Evidence |
| --- | --- |
| Preferred UI languages | Decompiled flag validation: unknown bits and name+id (0xc) -> STATUS_INVALID_PARAMETER (process: flags other than 4/8 also invalid; 0 means names). Lists verified with the Get functions (the thread getter appends fallback languages, so only prefix and lower bounds are asserted for the thread list; the process list is exact). NULL or empty list resets. Invalid language tag: STATUS_UNSUCCESSFUL (observed), list unchanged. Ex form returns a snapshot handle restored with RtlRestoreThreadPreferredUILanguages (TRUE). All state reset at the end of each test. |
| RtlSetTimer | Decompiled signature (queue, out handle, callback, context, due ms, period ms, flags). Observed: one-shot fires once with TimerOrWaitFired=TRUE and the given context; periodic fires repeatedly until RtlDeleteTimer(queue, timer, INVALID_HANDLE_VALUE) (blocking delete); a deleted far-future timer never fires. Waits use 5 s timeouts. |
| RtlSetIoCompletionCallback | Decompiled: NULL handle or non-zero flags -> STATUS_INVALID_PARAMETER. Observed: callback invoked as (error code, bytes transferred, OVERLAPPED*) on a threadpool thread for overlapped write and read on the registered file. |

# Zw-named synchronization services: Windows 10 contracts

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), x64, run elevated and as a standard user; both identical.
All behaviour is driven through the `Zw*` export names. `zw_sync_aliases` asserts each `Nt*`/`Zw*` pair resolves to one address.
Object creation helpers (`NtCreateEvent/Semaphore/Mutant/Timer/KeyedEvent`, `NtSetEvent`, `NtAlertThread`, `NtAlertThreadByThreadId`)
are fixtures only. Event type numbers: 0 = notification, 1 = synchronization (auto-reset).

Sources: "doc" = public Microsoft documentation, "obs" = observed on the Windows 10 guest (stable status codes), "decomp" = service
implementation read through the Corpus Explorer. Every value below was confirmed on the guest.

| Export | Expectation | Source |
| --- | --- | --- |
| ZwResetEvent | returns previous state through the optional output (1 then 0); clears state; query-only handle -> 0xc0000022 with output untouched; semaphore handle -> 0xc0000024; NULL and unused handle value -> 0xc0000008; pseudo handle -1 -> 0xc0000024 | obs |
| ZwReleaseSemaphore | previous count output; count 0 or negative -> 0xc000000d; exceeding maximum -> 0xc0000047 and output untouched; no modify access -> 0xc0000022; event -> 0xc0000024 | doc + obs |
| ZwReleaseMutant | not owned -> 0xc0000046; recursion: previous count of a twice-acquired mutant is -1 (count decremented per acquire); release of an initially owned mutant succeeds once | obs |
| ZwWaitForSingleObject | zero timeout -> 0x102 on unsignaled, 0 on signaled; auto-reset consumed; relative timeout waits ~ the interval; absolute time in the past -> 0x102; no SYNCHRONIZE -> 0xc0000022; current process/thread pseudo handles are waitable (unsignaled -> 0x102); alertable wait with pending alert -> 0x101 (alert consumed); non-alertable wait ignores alert | doc + obs |
| ZwWaitForMultipleObjects | WaitAny returns index; WaitAll 0; count 0 or > 64 -> 0xc00000ef (INVALID_PARAMETER_1); wait type other than 0/1 -> 0xc00000f1 (INVALID_PARAMETER_3); invalid handle in the array -> 0xc0000008; 64 handles accepted | obs |
| ZwWaitForMultipleObjects32 | same parameter validation as the 64-bit service; a 32-bit handle array with a small handle value is waited successfully (observed 0) | obs |
| ZwSignalAndWaitForSingleObject | signals event/semaphore/mutant then waits; mutant not owned -> 0xc0000046; unsupported signal type (timer) -> 0xc0000024; bad handles -> 0xc0000008; signal handle without modify access -> 0xc0000022; the signal happens even when the wait times out | doc + obs |
| ZwTestAlert | 0 normally; 0x101 once when an alert is pending (consumed) | doc + obs |
| ZwYieldExecution | 0 (another thread ran) or 0x40000024 (STATUS_NO_YIELD_PERFORMED) | doc |
| ZwWaitForAlertByThreadId | timeout -> 0x102; a pending alert (posted before or during) is consumed once and the wait returns 0x101; invalid thread id for NtAlertThreadByThreadId -> 0xc000000b | obs |
| ZwReleaseKeyedEvent / ZwWaitForKeyedEvent | no partner: 0x102 on timeout; low bit of key set -> 0xc00000ef; NULL handle = default keyed event (times out); unused handle -> 0xc0000008; event handle -> 0xc0000024; two threads pair in either order and both return 0 | obs |
| ZwWaitLowEventPair / ZwWaitHighEventPair | event pairs are not implemented: `NtCreateEventPair` and both wait services return 0xc0000002 for any handle (NULL, unused, event) | obs |

Skips: none expected. The event pair test asserts the not-implemented status rather than skipping.
Hazards avoided: no wait that could block forever (every blocking wait has a timeout), no alert left pending at the end of a test.

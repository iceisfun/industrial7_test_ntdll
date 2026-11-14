# nt_set_info_b_sync: event, event-pair, timer, execution-state and WNF setters

Oracle: Windows 10 22H2 x64 (ntdll 10.0.19041.2788). All exports are syscall stubs in ntdll, so every status
below is the kernel's. Nt/Zw pairs share an address; behaviour is tested through the Nt name and the alias is
asserted with `t_proc("NtX") == t_proc("ZwX")`. "Observed" means: the value was seen on a Windows 10 guest in both
elevated-administrator runs and is asserted as-is; kernel decompilation (ntoskrnl 10.0.19041.2965, Corpus Explorer)
was consulted where noted.

| Export | Expectation | Source |
|---|---|---|
| NtSetEvent | `PreviousState` is 0 then 1 on repeated sets; optional (NULL ok); auto-reset event consumed by one wait; NULL / bad handle STATUS_INVALID_HANDLE; process pseudo handle and mutex STATUS_OBJECT_TYPE_MISMATCH; SYNCHRONIZE-only handle STATUS_ACCESS_DENIED; unwritable PreviousState STATUS_ACCESS_VIOLATION | MS docs for NtSetEvent + observed |
| NtSetEventBoostPriority | success on a synchronization event (wakes one waiter); notification event is STATUS_OBJECT_TYPE_MISMATCH (kernel accepts only synchronization events); access and handle errors as above | observed |
| NtSetHighEventPair, NtSetLowEventPair, NtSetHighWaitLowEventPair, NtSetLowWaitHighEventPair | every call, with any handle argument (NULL, event, pseudo handle), returns STATUS_NOT_IMPLEMENTED (0xC0000002); NtCreateEventPair also returns STATUS_NOT_IMPLEMENTED. Event pairs no longer exist on Windows 10 | observed |
| NtSetTimer | PreviousState is the timer's previous *signal state* (0 when merely armed, 1 once it had fired), not "was armed"; setting clears the signal; negative period STATUS_INVALID_PARAMETER_6 (0xC00000F4, matches the kernel `param_6 < 0` test in NtSetTimer); NULL DueTime STATUS_ACCESS_VIOLATION; wrong type/NULL/SYNCHRONIZE-only handle errors; NtCancelTimer reports the same signal-state notion | observed + ntoskrnl NtSetTimer decompilation |
| NtSetTimerEx | class 0 (coalescable timer info, 0x30 bytes) arms the timer and writes PreviousState; wrong length STATUS_INFO_LENGTH_MISMATCH, bad class STATUS_INVALID_INFO_CLASS | observed |
| NtSetTimer2 | a high-resolution waitable timer (CreateWaitableTimerExW flag 2) is a Timer2 object; a classic timer handle gives STATUS_OBJECT_TYPE_MISMATCH; due time and optional period arm it | observed |
| NtSetIRTimer | in the kernel it is ExpSetTimer2(handle, due, 0, 0), so it accepts the same Timer2 handle; NtCreateIRTimer itself rejects every access mask tried with STATUS_INVALID_PARAMETER for an unprivileged caller (needs a special access check) and is therefore not used | ntoskrnl decompilation + observed |
| NtSetTimerResolution | un-requesting when nothing was requested is STATUS_TIMER_RESOLUTION_NOT_SET (0xC0000245); a 5 ms request yields an actual resolution in [maximum, 50000]; repeated request idempotent; clamped when out of range | docs for NtSetTimerResolution + observed |
| NtSetThreadExecutionState | a new thread starts at ES_CONTINUOUS (0x80000000); the previous state is returned; unknown flag bits (0x40000000) STATUS_INVALID_PARAMETER | observed |
| NtSetWnfProcessNotificationEvent | success with an event handle; NULL is STATUS_INVALID_HANDLE; bad handle, wrong type, SYNCHRONIZE-only handle give INVALID_HANDLE / TYPE_MISMATCH / ACCESS_DENIED | observed |

Skips: none expected. Privileges: none required; std and adm see identical behaviour except the std-mode run could not be
completed because of a guest infrastructure failure (see the group report).

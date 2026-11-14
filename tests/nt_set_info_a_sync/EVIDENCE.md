# NtSetTimerEx, NtSetTimer2, NtSetIRTimer, NtSetTimerResolution, NtSetEventBoostPriority, event pairs, NtSetWnfProcessNotificationEvent

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), administrator and standard user; kernel
decompilations read for validation order. All waits are bounded (5 s).

| Check | Expected | Source |
|---|---|---|
| NtSetTimerEx class 0, 0x30-byte TIMER_SET_COALESCING_INFO, 20 ms due | STATUS_SUCCESS, PreviousState 0, a synchronization timer is then signaled | decompilation (length 0x30, class 0), observed |
| class 1 | STATUS_INVALID_INFO_CLASS (checked first) | decompilation (`return 0xc0000003`), observed |
| length 0x28 or 0x38 | STATUS_INFO_LENGTH_MISMATCH | decompilation (`!= 0x30`), observed |
| Period 0x80000000 | STATUS_INVALID_PARAMETER_3 (C00000F1) | decompilation, observed |
| periodic timer with APC routine, period 20 ms | APC runs repeatedly with the supplied context while the thread sleeps alertably | documented SetWaitableTimer semantics, observed |
| event handle passed as timer | STATUS_OBJECT_TYPE_MISMATCH | decompilation, observed |
| NtSetTimer2 with NULL due time | STATUS_INVALID_PARAMETER_2 (C00000F0), even with an invalid handle | decompilation (`if (param_2 == 0) return 0xc00000f0`), observed |
| NtSetTimer2 on a NtCreateTimer2 timer, 20 ms | success; wait signaled | observed |
| NtSetIRTimer on the same kind of timer | success; wait signaled | decompilation (shares ExpSetTimer2), observed |
| NtCreateIRTimer(NULL id) | STATUS_INVALID_PARAMETER (IR timers need a valid timer id) | decompilation (ExpCheckIRTimerAccess), observed |
| NtSetTimerResolution(10000, TRUE) then (10000, FALSE) | success; actual resolution non-zero and not coarser than the 15.6 ms default; releasing never improves it | documented, observed (actual 10000) |
| NtSetEventBoostPriority: auto-reset event | success, event signaled afterwards when nobody waits; wakes a blocked waiter | decompilation, observed |
| manual-reset event, mutex | STATUS_OBJECT_TYPE_MISMATCH | decompilation (`*object & 0x7f == 0` -> 0xC0000024), observed |
| NtSet{Low,High}EventPair, NtSet{LowWaitHigh,HighWaitLow}EventPair | STATUS_NOT_IMPLEMENTED for any handle | decompilation (services share the not-implemented stub), observed |
| NtSetWnfProcessNotificationEvent: invalid handle, mutex, event, event again | STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH, success, then C0000718 (a process can install the notification event once) | decompilation (compare-exchange on the process context), observed |

The WNF test can only succeed once per process; it is a single test and no other test in the exe calls the service.

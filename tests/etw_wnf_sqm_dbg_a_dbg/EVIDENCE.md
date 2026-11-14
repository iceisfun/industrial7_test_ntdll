# DbgPrint family, break points and DbgUi wrappers: evidence

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788) elevated guest. Decompilations from the Corpus Explorer
(`/api/function/ntdll/<Name>/decomp` and `/asm`) explain the structure; asserted values were observed on the guest.
Status values are NTSTATUS. The test process never has a debugger attached; tests skip if IsDebuggerPresent.

| Export | Expectation and source |
|---|---|
| DbgPrint, DbgPrintEx, DbgPrintReturnControlC | decomps 0x509b0 / 0x50340 / 0xe09d0 call vDbgPrintExWithPrefixInternal; with no debugger every call returns 0 and raises no exception (observed), including out-of-range component ids and level masks. |
| DbgPrompt | decomp 0xe0a20 -> DebugPrompt (0xa0bc0: `mov eax,2; int 2d; int3; ret`). Without a debugger it raises exactly one EXCEPTION_BREAKPOINT (0x80000003) reported at the final `ret`; the test resumes there. The returned value is just eax (observed 2) and is not asserted. |
| DbgQueryDebugFilterState | syscall stub (0xe0a70). Observed: (101,0) is 1, other levels, level >= 32, and unknown components are 0. |
| DbgSetDebugFilterState | syscall stub. Only clearing already-clear levels is attempted (state unchanged); the status is privilege dependent so it is logged, and the follow-up query is asserted unchanged. |
| DbgBreakPoint, DbgUserBreakPoint | asm 0xa0b70/0xa0b80: `int3`. A vectored handler observes one 0x80000003 exception whose ExceptionAddress is the export address, and resumes after it. |
| DbgUiGetThreadDebugObject / SetThreadDebugObject | decomps 0xccb10 / 0xccc00: plain read and write of TEB+0x16a8 (DbgSsReserved[1]). Verified on a private thread against the raw TEB slot. |
| DbgUiConnectToDbg | decomp 0xcc740: creates a debug object only if the slot is empty; second call is a successful no-op returning the same handle. |
| DbgUiWaitStateChange | NtWaitForDebugEvent on the thread's object: no object -> 0xC0000008; empty queue with 50 ms timeout -> STATUS_TIMEOUT (0x102). |
| DbgUiStopDebugging | NtRemoveProcessDebug: process not being debugged -> 0xC0000353 (STATUS_PORT_NOT_SET); after a real attach -> 0, a second call -> 0xC0000353. |
| DbgUiDebugActiveProcess | decomp 0xccaa0: NtDebugActiveProcess then remote break-in. NULL handle -> 0xC0000008 (observed), current-process pseudo handle -> 0xC0000022 (observed). A real attach to a sleeping child returns 0. |
| DbgUiContinue | NtDebugContinue with a client id that has no pending event -> 0xC000000D (observed). |
| DbgUiIssueRemoteBreakin | decomp 0xccb30: creates a thread running DbgUiRemoteBreakin in the target. NULL or invalid pseudo handle -> 0xC0000008, valid child -> 0 and the child survives. |
| DbgUiRemoteBreakin | decomp 0xccba0: with no debugger the thread simply exits with code 0; skipped when a debugger or kernel debugger is enabled (KUSER_SHARED_DATA+0x2d4). |
| DbgUiConvertStateChangeStructure(Ex) | Crafted DBGUI_WAIT_STATE_CHANGE (NewState, CLIENT_ID at +8, union at +0x18): exit-process (5), exit-thread (4), breakpoint (7) and exception (6) states map to the documented DEBUG_EVENT codes, process/thread ids and exit/exception records. States 0, 1 and unknown values return STATUS_UNSUCCESSFUL (0xC0000001) (observed). Ex and non-Ex agree. |
| attach/event/detach cycle | A sleeping child is attached with DbgUiDebugActiveProcess on a worker thread; the first state change is DbgCreateProcessStateChange (3), a create-thread (2) and a breakpoint (7) state follow from the injected break-in thread, each converts to a DEBUG_EVENT with the child's pid, and every event is continued with DBG_CONTINUE before detaching. The debug object and file handles are closed; the child is terminated. |

Nothing in this area needs privileges; DbgSetDebugFilterState is the only call whose status depends on them.

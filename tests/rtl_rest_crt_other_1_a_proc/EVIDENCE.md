# RXact, legacy timers, activation contexts, heap compaction, cross-VM names, import hash, capabilities, cloning

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788); administrator and standard-user runs.

| Export | Expectation | Source |
| --- | --- | --- |
| RtlInitializeRXact, RtlStartRXact, RtlAbortRXact, RtlAddActionToRXact, RtlApplyRXact, RtlApplyRXactNoFlush | On a scratch HKCU key: first RtlInitializeRXact returns STATUS_RXACT_STATE_CREATED 0x40000004; abort with no started transaction and a second start both give STATUS_RXACT_INVALID_STATE 0xC000011C; a queued SetValue (operation 2) is applied by Apply and by ApplyNoFlush (default value of the named subkey is written), and the log is released after apply. | decomp 0x8b570, 0x811b0, 0x80060, 0xe62f0, 0x80030; observed |
| RtlCancelTimer | Tail-calls RtlDeleteTimer without a wait event: cancelling a fired, pending and periodic timer returns a success status; a periodic timer stops firing; a pending timer never fires. | decomp 0x112e90 |
| RtlActivateActivationContext(Ex) | Flags must be 0 (Ex: 0 or 1), cookie pointer required, handle -1 invalid, Ex needs a non-NULL TEB: all give STATUS_INVALID_PARAMETER 0xC000000D and zero the cookie; activation makes the context the active one (RtlGetActiveActivationContext), nested activations unwind in order. RtlDeactivateActivationContext returns nothing. | decomp 0x72360, 0x723b0 |
| RtlActivateActivationContextUnsafeFast | Caller frame (extended, size 0x48): stores the context at +0x18 and makes it active; RtlDeactivateActivationContextUnsafeFast restores the previous one. | decomp 0x19900 |
| RtlCompactHeap | Returns the size of the largest free block (observed >= 128 and non-decreasing after frees); live allocations remain valid. The exact number is only noted. | decomp 0xf2300 |
| RtlConstructCrossVmEventPath / ...MutexPath | One shared implementation; yields `\SharedVmObjects\{second-guid}\{first-guid}`-style names: with one GUID `\SharedVmObjects\{guid}`, with two the second GUID qualifies the first. | decomp 0xf5ae0; observed |
| RtlComputeImportTableHash | Revision 1 gives a deterministic, non-zero, image-specific 16-byte hash (kernel32.dll vs cmd.exe differ); other revisions give STATUS_UNKNOWN_REVISION 0xC0000058 without touching the output; a bad handle gives 0xC0000008; a non-image file fails (status noted only). | decomp 0xe06e0 (partly unreadable), observed |
| RtlCapabilityCheck / RtlCapabilityCheckForSingleSessionSku | A normal (non-AppContainer) token passes any capability (result TRUE, status 0). RtlCapabilityCheck does not validate a NULL result pointer (not tested). The single-session wrapper rejects a NULL result pointer with 0xC000000D and reports FALSE on multi-session SKUs. | decomp 0x3fcd0, 0x88640; observed |
| RtlComputePrivatizedDllName_U | Real name is `<exe dir>\<leaf>` and local-redirection name is `<exe dir>\<exe name>.Local\<leaf>`; a name without extension gets ".DLL"; directory parts of the input are dropped. | decomp 0xd56f0; observed |
| RtlCloneUserProcess | Run in a helper child process: a suspended, handle-inheriting clone returns 0 in the parent with process/thread handles (suspend count 1 on resume) and STATUS_PROCESS_CLONED 0x129 in the clone, which terminates itself with exit code 77; the parent observes that exit code. Skipped (reported) if cloning is unavailable. | observed on the guest |

Not tested (see the report): RtlCompleteProcessCloning (needs a clone context), KiUser* dispatchers, ExpInterlockedPopEntrySList* helpers, RtlAssert, RtlApplicationVerifierStop.

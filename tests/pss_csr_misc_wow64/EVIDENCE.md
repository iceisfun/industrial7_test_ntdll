# pss_csr_misc_wow64 - RtlWow64* and Rtlp WoW64 context helpers (native x64 process)

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), administrator run, 9 tests / 186 checks pass.

Sources: decompilation for algorithms; all concrete values observed on Windows 10.

* GetCurrentMachine 0x8664; GetEquivalentMachineCHPE maps 0x3a64 -> 0x14c, others unchanged.
* GetProcessMachines: current process / real handle -> (process machine 0, native 0x8664); NULL native out pointer accepted; invalid handle STATUS_INVALID_HANDLE and outputs untouched; thread pseudo handle STATUS_OBJECT_TYPE_MISMATCH.
* IsWowGuestMachineSupported: 0x14c true (skipped if the image has no WoW64); 0x1c4, 0x8664, 0xaa64, 0 and junk false with STATUS_SUCCESS.
* GetCpuAreaInfo: results for 0x14c, 0x1c4, 0x8664, 0xaa64 at base 0x10000/0x10001 (alignment 4/8/16), unknown machine STATUS_INVALID_PARAMETER with only the base stored.
* GetSharedInfoProcess: native process -> not-WoW64 byte 0; invalid handle STATUS_INVALID_HANDLE.
* Get/SetThreadContext on a native thread: STATUS_INVALID_PARAMETER; invalid handle STATUS_INVALID_HANDLE.
* GetThreadSelectorEntry: selectors 0, 0x23, 0x2b, 0x53 (base = native TEB + 0x2000, limit 0xfff), other selectors STATUS_UNSUCCESSFUL, wrong length STATUS_INFO_LENGTH_MISMATCH, returned length 8.
* SuspendThread: previous count returned/applied exactly like NtSuspendThread; invalid handles STATUS_INVALID_HANDLE. SuspendProcess: suspend count of a created-suspended child rises 1 -> 2 and returns to 1 after NtResumeProcess.
* RtlWow64CallFunction64 / EnableFsRedirection / EnableFsRedirectionEx share one address and return STATUS_NOT_IMPLEMENTED.
* RtlpWow64CtxFromAmd64, RtlpWow64GetContextOnAmd64, RtlpWow64SetContextOnAmd64: register mapping, constant segments (cs 0x23, ss/ds/es/gs 0x2b, fs 0x53) and EFlags masking (0x3f0dd5 | 0x202) from decompilation, confirmed by observation.

Justified uncovered (not tested): RtlWow64GetCurrentCpuArea (dereferences the WoW64 CPU area of the TEB; a native thread has none and the call faults), RtlWow64GetCurrentMachine's WoW64 branch (needs a 32-bit process), RtlWow64LogMessageInEventLogger (loads the event log API and writes to the system event log), RtlWow64PushCrossProcessWorkOntoWorkList etc. are covered in pss_csr_misc_worklist.

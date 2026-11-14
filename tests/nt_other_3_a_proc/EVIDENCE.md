# nt_other_3_a_proc evidence

Exports covered (all Zw aliases verified in `other3a_proc_nt_zw_aliases`): NtGetNextProcess,
NtGetNextThread, NtGetCurrentProcessorNumber(Ex), NtIsProcessInJob, NtGetContextThread,
NtQueueApcThread(Ex), NtPulseEvent, NtPrivilegeCheck, NtImpersonateAnonymousToken, NtImpersonateThread,
NtMakeTemporaryObject, NtMakePermanentObject, NtPowerInformation, NtIsSystemResumeAutomatic,
NtRaiseException, NtGetNlsSectionPtr, NtIsUILanguageComitted, NtGetMUIRegistryInfo, and (bad-handle /
type-mismatch paths only) NtListenPort and NtImpersonateClientOfPort.

## Authority

Observed on Windows 10 22H2 (ntdll 10.0.19041.2788), elevated and standard user. Decompilation of the
ntdll stubs shows syscall thunks only; behaviour is from the guest.

## State used

The test process only: its own threads, small helper threads, one child process (`o3a_sleeper`,
terminated at the end) for the job test, two unnamed job objects, unnamed events and a mutex, a
duplicated impersonation token. Impersonation is always reverted. NtRaiseException runs in a child
process (`o3a_raise`), the exit code reports the verdict.

## Observed contracts

- NtGetNextProcess: NULL start gives the first process; chaining enumerates until
  STATUS_NO_MORE_ENTRIES 0x8000001A, including the caller; flags 1 = reverse; HandleAttributes OBJ_INHERIT is
  applied to the new handle; invalid handle 0xC0000008; unknown flag 0x80 gives 0xC000000D.
- NtGetNextThread: same chaining for the threads of a process; contains the current and a freshly
  created thread; every non-zero flags value 1..7 gives 0xC000000D.
- NtGetCurrentProcessorNumber(Ex): value below the active processor count; Ex fills group/number with
  reserved 0; pinned to CPU 0 both report 0.
- NtIsProcessInJob: 0x123 STATUS_PROCESS_NOT_IN_JOB / 0x124 STATUS_PROCESS_IN_JOB for a specific job, a different job
  and NULL (any job); invalid handles 0xC0000008. The child is created with CREATE_BREAKAWAY_FROM_JOB first; if
  the harness job forbids it the plain creation is used and assignment failure skips only that part.
- NtGetContextThread: suspended thread, CONTEXT_CONTROL|INTEGER filled (Rip, aligned Rsp, SegCs 0x33,
  EFlags IF set); registers not requested are untouched; handle with only
  THREAD_QUERY_LIMITED_INFORMATION gives 0xC0000022.
- NtQueueApcThread(Ex): the three arguments reach the routine unchanged in an alertable wait; a handle
  without THREAD_SET_CONTEXT gives 0xC0000022; Ex with NULL reserve handle is an ordinary APC; reserve handle
  value 1 (special user APC) is delivered to a running non-waiting thread.
- NtPulseEvent: releases a waiter and leaves a notification event non-signaled; previous state returned
  (0 or 1) and the event ends non-signaled; no EVENT_MODIFY_STATE gives 0xC0000022; mutex 0xC0000024.
- NtPrivilegeCheck: SeChangeNotifyPrivilege (23) passes and gets SE_PRIVILEGE_USED_FOR_ACCESS;
  SeTcbPrivilege (7) fails; any-of/all-necessary semantics; unknown luid and empty set return success with
  Result FALSE; primary tokens are accepted too; invalid handle 0xC0000008.
- NtImpersonateAnonymousToken: after the call the thread token's user is S-1-5-7; reverted by clearing
  ThreadImpersonationToken; a process handle gives 0xC0000024; invalid handle 0xC0000008.
- NtImpersonateThread: token type impersonation, level equals the requested SQOS level; Anonymous level
  makes the token unopenable (0xC00000A6); a client handle without THREAD_DIRECT_IMPERSONATION gives 0xC0000022.
- NtListenPort / NtImpersonateClientOfPort: with a minimal PORT_MESSAGE header (TotalLength 0x28,
  MessageId 1) an invalid handle gives 0xC0000008 and an event handle 0xC0000024 for both. With an all-zero
  header NtImpersonateClientOfPort gives 0xC000000D (message validated before the handle lookup; observed).
  No port is created.
- NtMakeTemporaryObject: success on an unnamed event, 0xC0000022 without DELETE, 0xC0000008 invalid.
  NtMakePermanentObject needs SeCreatePermanentPrivilege (not held by either test account by default):
  0xC0000061; with a bad handle either 0xC0000008 or 0xC0000061 is accepted since the order is not stable here.
- NtPowerInformation: SystemPowerCapabilities (4) 76 bytes, buffer 8 bytes gives 0xC0000023;
  ProcessorInformation (11) one 0x18-byte record per processor with Number = index; SystemExecutionState (16) and
  LastWakeTime (14) succeed; unknown level 0x7fff gives 0xC000000D.
- NtIsSystemResumeAutomatic: FALSE (the guest is not resumed by a timer).
- NtRaiseException: a first-chance continuable exception goes to a vectored handler (code, parameters and
  flags intact); on EXCEPTION_CONTINUE_EXECUTION execution resumes at the supplied context.
- NtGetNlsSectionPtr(11, 1252): success, non-NULL view of at least a page; unknown code page 0xC0000034;
  unknown section type 0xC00000EF.
- NtIsUILanguageComitted: success; skipped with the observed status where the UI language is not committed.
- NtGetMUIRegistryInfo: NULL data returns the required size with success; a full buffer succeeds; a
  one-byte-short size gives 0xC0000023 with the required size.

## Skips

Language-dependent NtIsUILanguageComitted; job assignment failure (nested-job policy) skips the assigned-process part.

## Justified-uncovered (not in this file's tests)

See the group report: kernel-only/system-state/service-connection exports are not called.

## Review additions

- NtImpersonateClientOfPort on a real unnamed port (NtCreatePort, never listened on): 0xC000021F
  (STATUS_REPLY_MESSAGE_MISMATCH) for a well-formed header, 0xC000000D for an all-zero header. NtListenPort is not called
  on a live port because it blocks.
- User pointer faults: NtGetContextThread(NULL context), NtGetNextProcess(NULL output), NtPrivilegeCheck(NULL result or NULL
  set) give 0xC0000005; a NULL token handle gives 0xC0000008.
- NtMakePermanentObject: the privilege check precedes handle lookup; with SeCreatePermanentPrivilege absent (both guest
  accounts) an invalid handle gives 0xC0000061, asserted exactly (0xC0000008 only if the privilege is held).
- NtPowerInformation SystemExecutionState: value 0 observed on the guest; test only asserts it holds EXECUTION_STATE bits
  and that a 2-byte buffer gives 0xC0000023. Capability and processor MHz values are hardware-dependent and not asserted.
- NtPulseEvent: waiter release is driven by repeated pulses rather than a fixed sleep (no timing assumption).

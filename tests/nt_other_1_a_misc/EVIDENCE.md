# nt_other_1_a_misc evidence

Oracle: Windows 10 22H2 guest, adm and std modes. "observed" means the value was measured on the guest; where
a ntoskrnl decompilation was consulted it is named.

* NtDelayExecution: relative negative 100 ns intervals, zero interval returns 0; alertable delay returns STATUS_USER_APC (0xC0)
  after running a queued user APC, STATUS_ALERTED (0x101) when an alert is pending (documented kernel wait semantics, observed).
  A non-alertable delay does not consume an alert or an APC. Unreadable interval pointer: STATUS_ACCESS_VIOLATION (observed).
* NtAlertThread / NtAlertResumeThread: handle needs THREAD_ALERT (STATUS_ACCESS_DENIED otherwise), process handle gives
  STATUS_OBJECT_TYPE_MISMATCH, NULL gives STATUS_INVALID_HANDLE (observed). AlertResume returns the previous suspend count
  (documented). An alert sent to a thread that has not yet started running is lost (observed, hence the test suspends an already
  waiting thread). Alerting a terminated thread whose handle is still open succeeds (observed).
* NtAlertThreadByThreadId / NtWaitForAlertByThreadId (used as the observer): wait ends with STATUS_ALERTED (0x101) when alerted,
  STATUS_TIMEOUT (0x102) otherwise; an alert sent before the wait is remembered once; an id that cannot exist gives
  STATUS_INVALID_CID (0xC000000B). All observed.
* NtClearEvent: clears manual- and auto-reset events, idempotent; needs EVENT_MODIFY_STATE; wrong type STATUS_OBJECT_TYPE_MISMATCH. Observed.
* NtAllocateLocallyUniqueId: strictly increasing, > 1000, shares the sequence with the Win32 AllocateLocallyUniqueId; NULL/bad pointer
  STATUS_ACCESS_VIOLATION (observed).
* NtAllocateUuids: monotonic time, non-zero range, stable sequence and 6-byte node seed (UUID generation rules, observed).
* NtAllocateReserveObject: types 0/1 give objects whose type names are "UserApcReserve" / "IoCompletionReserve"
  (queried with NtQueryObject); other types STATUS_INVALID_PARAMETER; relative name without root directory STATUS_OBJECT_NAME_INVALID. Observed.
* NtCompareObjects: same underlying object through different handles -> 0; different objects or types -> 0xC00001AC
  (STATUS_NOT_SAME_OBJECT); NULL or invalid handle STATUS_INVALID_HANDLE. Observed.
* NtCompareSigningLevels: the rule is not numeric; the exact pairs asserted (0/0, 8/8, 12/12, 14/14, 1/0, 12/8 succeed; 0/1, 8/12, 0x100/1 give
  STATUS_INVALID_IMAGE_HASH 0xC0000428) were measured on the guest and are the only ones asserted.
* NtAssignProcessToJobObject: needs JOB_OBJECT_ASSIGN_PROCESS on the job and PROCESS_SET_QUOTA|PROCESS_TERMINATE on the process (STATUS_ACCESS_DENIED
  otherwise); assigning twice to the same job succeeds; assigning an exited process to another job gives STATUS_ACCESS_DENIED. Observed.
* NtCreateTimer2 (helper) / NtCancelTimer2: cancel of an idle timer succeeds with zeroed or NULL parameters; closed handle STATUS_INVALID_HANDLE; event handle
  STATUS_OBJECT_TYPE_MISMATCH. Observed.
* NtCallbackReturn outside a kernel-to-user callback: STATUS_NO_CALLBACK_ACTIVE (0xC0000258). Observed.
* NtCancelIoFile / NtCancelIoFileEx / NtCancelSynchronousIoFile with nothing pending: 0 (Information 0) / STATUS_NOT_FOUND (0xC0000225); error cases
  as above. Pending-request behaviour is covered in nt_cancel_io.

Skips: none in either mode. Zw aliases are asserted by pointer equality.

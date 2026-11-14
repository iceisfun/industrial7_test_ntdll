# nt_other_1_a_kobj evidence

Oracle: Windows 10 22H2 guest. Observed unless noted.

* KTM: NtCreateTransaction on the default manager; commit 0, second commit or rollback after commit STATUS_TRANSACTION_ALREADY_COMMITTED (0xC0190016), commit after rollback
  STATUS_TRANSACTION_ALREADY_ABORTED (0xC0190015); handles without access STATUS_ACCESS_DENIED; NULL / wrong type STATUS_INVALID_HANDLE / STATUS_OBJECT_TYPE_MISMATCH.
  NtEnumerateTransactionObject on a log-backed manager (created with NtCreateTransactionManager and a log file in the scratch directory): empty manager STATUS_NO_MORE_ENTRIES (0x8000001A),
  manager and resource-manager object types succeed, cursor smaller than 36 bytes, unknown type and NULL cursor STATUS_INVALID_PARAMETER. Creating a transaction with an explicit manager handle
  returned STATUS_INVALID_PARAMETER on the guest in every variant tried, so no per-transaction enumeration or enlistment commit state is asserted. NtCommitEnlistment and NtCommitComplete: NULL and
  bad handle STATUS_INVALID_HANDLE, resource manager / event handle STATUS_OBJECT_TYPE_MISMATCH.
* Registry transactions: NtCreateRegistryTransaction with non-zero flags STATUS_INVALID_PARAMETER; NtCommitRegistryTransaction with flags 1 STATUS_INVALID_PARAMETER; a handle created
  with 0x1F0003 cannot commit (STATUS_ACCESS_DENIED), one created with MAXIMUM_ALLOWED can.
* Legacy LPC: connect to a missing port STATUS_OBJECT_NAME_NOT_FOUND, NULL name STATUS_OBJECT_NAME_INVALID; NtAcceptConnectPort on a message that is not a pending connection
  STATUS_REPLY_MESSAGE_MISMATCH (0xC000021F), NULL request STATUS_ACCESS_VIOLATION; NtCompleteConnectPort performs no handle validation (0 for NULL and event handles).
  The full handshake (NtCreatePort in \RPC Control, NtListenPort returning an LPC_CONNECTION_REQUEST message, NtAcceptConnectPort, NtCompleteConnectPort, NtConnectPort) runs in a child process
  with a timeout.
* Debug objects: attach a suspended child; second attach STATUS_PORT_ALREADY_SET (0xC0000048); the first event is DbgCreateProcessStateChange (3) with the child's ids;
  NtDebugContinue with it succeeds, without a matching event or with an invalid continue status STATUS_INVALID_PARAMETER; attaching without PROCESS_SUSPEND_RESUME, to self, or with
  a bad debug object STATUS_ACCESS_DENIED.
* WNF: NtDeleteWnfStateData/NtDeleteWnfStateName on an invalid name STATUS_INVALID_PARAMETER, NULL/bad pointers STATUS_ACCESS_VIOLATION; for a temporary name created by the test, deleting
  data (even twice) succeeds, deleting the name once succeeds and a second time gives STATUS_OBJECT_NAME_NOT_FOUND.
* Private namespaces: NtDeletePrivateNamespace on a namespace created through CreatePrivateNamespaceW succeeds; the handle is then invalid; NULL STATUS_INVALID_HANDLE, event STATUS_OBJECT_TYPE_MISMATCH.

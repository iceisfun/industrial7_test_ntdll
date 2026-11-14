# nt_other_2_a_misc: rarely used services and window procedure helpers

Oracle: Windows 10 22H2 guest; all values **observed on Windows 10** unless a public document is named.

| Export | Observed behaviour |
| --- | --- |
| NtVdmControl | `STATUS_NOT_IMPLEMENTED` for any service number on a 64-bit process |
| NtTerminateEnclave | Ordinary memory -> `STATUS_CONFLICTING_ADDRESSES` (0xC0000018); NULL -> `STATUS_MEMORY_NOT_ALLOCATED` (0xC00000A0) |
| NtUmsThreadYield | Non-UMS thread `STATUS_NOT_SUPPORTED` (0xC00000BB) |
| NtAcquireProcessActivityReference | `STATUS_ACCESS_DENIED` before any handle lookup (caller check); signature per symbol data, third argument semantics unknown, so only this early failure is asserted |
| NtAcquireCrossVmMutant | `STATUS_OBJECT_TYPE_MISMATCH` for an invalid handle value; observed-only, signature not documented |
| NtRevertContainerImpersonation | `STATUS_UNSUCCESSFUL` when not impersonating |
| NtUnloadDriver | SeLoadDriverPrivilege disabled `STATUS_PRIVILEGE_NOT_HELD`; enabled (administrator) and a service key that does not exist `STATUS_OBJECT_NAME_NOT_FOUND`; standard user: only the denial is asserted |
| NtReplacePartitionUnit | `STATUS_PRIVILEGE_NOT_HELD` |
| NtRegisterProtocolAddressInformation | invalid handle `STATUS_INVALID_HANDLE`, event handle `STATUS_OBJECT_TYPE_MISMATCH` |
| NtTranslateFilePath | `STATUS_NOT_IMPLEMENTED` |
| NtSerializeBoot | `STATUS_PRIVILEGE_NOT_HELD` for administrator and standard token |
| NtSubscribeWnfStateChange / NtUnsubscribeWnfStateChange | Subscribing to an arbitrary state name returns 0 with a changed subscription id; event mask 0 accepted; NULL name `STATUS_ACCESS_VIOLATION`; one unsubscribe by name removes all of the process's subscriptions for it, the next gives `STATUS_OBJECT_NAME_NOT_FOUND` |
| NtdllDefWindowProc_A/W, NtdllDialogWndProc_A/W | Forward to the default window handling: WM_SETTEXT -> 1, WM_GETTEXTLENGTH / WM_GETTEXT -> 5 and the text, ANSI and wide variants agree, truncation to the buffer, WM_NULL -> 0, WM_NCHITTEST on a message window -> HTCLIENT; DialogWndProc WM_NULL -> 0. t_skip when a message-only window cannot be created |

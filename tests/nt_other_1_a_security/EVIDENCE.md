# nt_other_1_a_security evidence

Oracle: Windows 10 22H2 guest, administrator and standard-user runs. Tokens used are duplicates of the caller's token; descriptors are
built privately with Rtl* helpers (owner and group set, DACL granting Everyone two custom rights).

* NtAccessCheck: documented AccessCheck semantics. Allowed rights are returned in GrantedAccess with AccessStatus 0; a missing right gives
  AccessStatus STATUS_ACCESS_DENIED with granted 0 while the call itself returns 0; MAXIMUM_ALLOWED returns the union of granted rights; an earlier
  deny ACE wins. Observed service errors: primary token STATUS_NO_IMPERSONATION_TOKEN, anonymous-level STATUS_BAD_IMPERSONATION_LEVEL, token without
  TOKEN_QUERY STATUS_ACCESS_DENIED, unmapped GENERIC_* in DesiredAccess STATUS_GENERIC_NOT_MAPPED (0xC00000E6), descriptor without owner or NULL
  STATUS_INVALID_SECURITY_DESCR (0xC0000079), PrivilegeSetLength 0 STATUS_BUFFER_TOO_SMALL, NULL mapping/outputs STATUS_ACCESS_VIOLATION.
* NtAccessCheckByType / NtAccessCheckByTypeResultList: without a list identical to NtAccessCheck; with a one-element list the root result; with a
  root plus child list both result entries match for plain ACEs. A first list element not at level 0 and a list count without a list give
  STATUS_INVALID_PARAMETER; the result-list form requires a list.
* NtAdjustPrivilegesToken: disabling/enabling SeChangeNotifyPrivilege returns the previous state and required length (4 + 12 bytes); too small a buffer
  STATUS_BUFFER_TOO_SMALL with the length and no change; unheld privileges (SeTcb, bogus LUID) STATUS_NOT_ALL_ASSIGNED (0x106) while the held entries still
  apply; DisableAll disables everything; neither state nor DisableAll STATUS_INVALID_PARAMETER; handle without TOKEN_ADJUST_PRIVILEGES STATUS_ACCESS_DENIED.
* NtAdjustGroupsToken: ResetToDefault succeeds (also with a state, which is ignored); disabling the mandatory Everyone group STATUS_CANT_DISABLE_MANDATORY;
  a group the token lacks STATUS_NOT_ALL_ASSIGNED; no state and no reset STATUS_INVALID_PARAMETER.
* NtFilterToken: documented CreateRestrictedToken semantics. DISABLE_MAX_PRIVILEGE leaves at most change-notify; deleting a privilege removes it;
  deny-only SID gets SE_GROUP_USE_FOR_DENY_ONLY; restricting SIDs make TokenIsRestricted 1; unknown flag bits and SIDs not in the token are ignored (observed).
  A SANDBOX_INERT-filtered token reports TokenSandBoxInert 0 on this build (recorded as a note, not asserted).
* NtFilterTokenEx and NtAdjustTokenClaimsAndDeviceGroups: STATUS_NOT_IMPLEMENTED (0xC0000002) for every argument combination including NULL handles
  (observed).
* NtCompareTokens: equal for a token and its duplicates including impersonation vs primary; not equal when a SID is deny-only or a privilege was removed or
  restricting SIDs were added; invalid handles STATUS_INVALID_HANDLE, wrong type STATUS_OBJECT_TYPE_MISMATCH, no TOKEN_QUERY STATUS_ACCESS_DENIED, NULL result STATUS_ACCESS_VIOLATION.
* Audit alarm services (NtAccessCheckAndAuditAlarm, ...ByType..., ...ResultList..., ...ByHandle, NtCloseObjectAuditAlarm, NtDeleteObjectAuditAlarm): without
  an impersonation token the access-check variants return STATUS_NO_IMPERSONATION_TOKEN; with one they return STATUS_PRIVILEGE_NOT_HELD because neither token
  holds SeAuditPrivilege; Close/Delete return STATUS_PRIVILEGE_NOT_HELD. The test skips if the token holds SeAuditPrivilege. No audit record can be generated.

Skips: audit test when SeAuditPrivilege is present; change-notify tests when the token lacks that privilege.

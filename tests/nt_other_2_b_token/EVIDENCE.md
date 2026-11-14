# nt_other_2_b_token evidence

Oracle: Windows 10 22H2 (ntdll 10.0.19041) x64; adm and std results identical. The process token is never modified:
all adjustments happen on impersonation-level duplicates opened with TOKEN_ALL_ACCESS.
Corpus decompilation is a bare syscall stub for every export here; documentation plus observation provide values.

| Test | Expected values and source |
|---|---|
| duplicate_token | Impersonation (2) and primary (1) duplicates report the matching TokenType; type 3 -> STATUS_INVALID_PARAMETER; NULL/junk -> STATUS_INVALID_HANDLE; event -> STATUS_OBJECT_TYPE_MISMATCH; source opened without TOKEN_DUPLICATE -> STATUS_ACCESS_DENIED. |
| adjust_privileges | SeChangeNotifyPrivilege (23) is held and enabled by every logon. Disabling returns PreviousState with the old attributes (count 1, ReturnLength 16); re-enabling reports disabled; a no-op change reports count 0; PreviousState too small -> STATUS_BUFFER_TOO_SMALL with ReturnLength 16 and nothing applied; enabling a privilege the token lacks (SeCreateTokenPrivilege, 2) -> STATUS_NOT_ALL_ASSIGNED 0x106; DisableAllPrivileges clears all; NULL NewState without DisableAll -> STATUS_INVALID_PARAMETER; handle without TOKEN_ADJUST_PRIVILEGES -> STATUS_ACCESS_DENIED. |
| adjust_groups | Disabling a mandatory group -> STATUS_CANT_DISABLE_MANDATORY 0xC000005D; group absent from the token -> STATUS_NOT_ALL_ASSIGNED; NULL NewState without reset -> STATUS_INVALID_PARAMETER; the optional-group success path only runs when the token contains an enabled non-mandatory group (it did not on the test guest; a note records that). |
| filter_token | DISABLE_MAX_PRIVILEGE leaves only SeChangeNotifyPrivilege; SidsToDisable turns Everyone into deny-only (SE_GROUP_USE_FOR_DENY_ONLY); PrivilegesToDelete removes the privilege from the new token. Unknown flag 0x100 is accepted (observed, logged only). Bad/NULL handle -> invalid handle, query-only handle -> STATUS_ACCESS_DENIED. |
| filter_token_ex, adjust_claims | Observed: both return STATUS_NOT_IMPLEMENTED 0xC0000002 for every argument combination on this build (the arguments are not inspected). |
| compare_tokens | A token and its duplicate compare equal; a token vs. its restricted-SID filtered copy compare different; NULL output -> access violation; bad handles -> STATUS_INVALID_HANDLE; event -> type mismatch. |

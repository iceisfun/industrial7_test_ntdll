# rtl_create_add_delete_a_acl

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), standard user and elevated administrator runs.
Decompilation consulted for argument-validation order (http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp); every value below was
then confirmed by running on the Windows 10 guest (both modes green, repeated).

## Exports covered (behavioral)
RtlAddAccessAllowedAceEx, RtlAddAccessDeniedAceEx, RtlAddAccessAllowedObjectAce, RtlAddAccessDeniedObjectAce,
RtlAddAuditAccessAce, RtlAddAuditAccessAceEx, RtlAddAuditAccessObjectAce, RtlAddAce, RtlAddCompoundAce,
RtlAddMandatoryAce, RtlAddProcessTrustLabelAce, RtlAddAccessFilterAce, RtlAddScopedPolicyIDAce,
RtlAddResourceAttributeAce, RtlCreateAndSetSD, RtlCreateBoundaryDescriptor, RtlAddSIDToBoundaryDescriptor,
RtlAddIntegrityLabelToBoundaryDescriptor, RtlCreateServiceSid, RtlCheckTokenMembership,
RtlCheckTokenMembershipEx, RtlCheckTokenCapability, RtlCheckSandboxedToken.

## Where expectations come from
| Area | Evidence |
| --- | --- |
| Simple ACE layout (type, flags, size, mask, SID copy, ACL revision = max(old, requested), AceCount) | Decompiled common helper (validate SID -> revision <= 4 -> flag mask -> RtlValidAcl -> RtlFirstFreeAce -> space check) and documented ACE structures in winnt.h. Confirmed on guest. |
| Flag masks | Allowed ACE: bits above 0x1F rejected except 0x20; denied: only low 0x1F; audit: low 0x1F plus 0x40/0x80 (0x20 rejected); object ACEs follow audit rules for type 7. Status STATUS_INVALID_PARAMETER. Confirmed on guest. |
| Status codes | STATUS_INVALID_SID c0000078 (bad SID), STATUS_REVISION_MISMATCH c0000059 (revision > 4, or < 4 for object ACEs, < 3 for compound), STATUS_INVALID_ACL c0000077, STATUS_ALLOTTED_SPACE_EXCEEDED c0000099 (no room), STATUS_BUFFER_TOO_SMALL c0000023 (RtlAddAce), STATUS_INVALID_PARAMETER c000000d. |
| Object ACEs | Layout (type, flags, size, mask, ULONG object flags, optional GUIDs, SID) from winnt.h; with both GUIDs NULL the call degenerates into the plain ACE type, as in the decompiled wrapper. |
| RtlAddAce | List walked by AceSize; insertion index MAXULONG or beyond the end appends; list length that does not end on an ACE boundary -> STATUS_INVALID_PARAMETER; revision raised only. |
| Mandatory / trust label / filter / scoped policy / resource attribute | Decompiled argument checks: label SID must be S-1-16-x (single sub-authority), trust-label SID S-1-19-x-y, filter ACE SID Everyone (S-1-1-0) with an "artx" conditional-expression header and size >= 6, scoped policy SID authority 17 with access mask 0, resource attribute SID Everyone with mask 0 and non-NULL ReturnLength. ReturnLength equals ACL header (8) plus the sum of ACE sizes including the new one; too-small ACL fails with STATUS_ALLOTTED_SPACE_EXCEEDED and still reports the needed size. |
| RtlCreateAndSetSD | RTL_ACE_DATA array {AceType, InheritFlags, AceFlags, Mask, PSID*}; type 0 allowed, 1 denied, 2 audit (SACL), others -> STATUS_INVALID_PARAMETER; zero ACEs gives an absolute SD with a present NULL DACL and no SACL; owner/group pointers are stored, not copied. The SD is one process-heap block. |
| Boundary descriptors | Layout observed from the allocation: dword version=1, item count, total size, flags, then items (type, size incl. 8-byte header, payload) padded to 8 bytes. Bad name (empty, odd length) or flags > 1 return NULL; invalid SIDs return STATUS_INVALID_PARAMETER (not STATUS_INVALID_SID). A descriptor with name + Everyone is accepted by NtCreatePrivateNamespace. |
| RtlCreateServiceSid | SHA-1 of the upper-cased name; S-1-5-80 with 5 sub-authorities (length 32); small buffer -> STATUS_BUFFER_TOO_SMALL with required length written. The five sub-authorities are checked against an independent SHA-1 of the upper-cased UTF-16LE name computed inside the test; determinism and case-insensitivity also asserted. |
| Token checks | RtlCheckTokenMembership(Ex): NULL token uses a duplicate of the process token; result for Everyone TRUE, an absent domain SID FALSE, Administrators compared with advapi32 CheckTokenMembership so the same test is correct for the standard-user and administrator runs. A primary (non-impersonation) handle yields STATUS_BAD_IMPERSONATION_LEVEL (c000005c) and FALSE. Unknown Ex flag bits (4, 0x80000000) give STATUS_INVALID_PARAMETER and clear the output to FALSE (observed). RtlCheckTokenCapability: non-capability SID -> STATUS_INVALID_PARAMETER; a token that is not an app container passes every capability check (TRUE). RtlCheckSandboxedToken: normal process token is not sandboxed. |

## Observed-only / notes
- RtlCheckTokenMembershipEx flags=1 is accepted; only status and the Everyone result are asserted.
- RtlCheckSandboxedToken with an invalid handle is not asserted (an observed TRUE for the current-process pseudo handle is not a stable contract).
- RtlAddResourceAttributeAce: passing AttributeCount > number of attributes reads past the caller's data (access violation), so that case is deliberately not tested.
- No skips on either mode.

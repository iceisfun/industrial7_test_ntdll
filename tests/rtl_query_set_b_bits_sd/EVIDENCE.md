# rtl_query_set_b_bits_sd

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), standard user and elevated administrator runs. Decompilation (Corpus Explorer, /api/function/ntdll/<Name>/decomp) was consulted for argument validation order; every value below was then confirmed by running on the Windows 10 guest.

## Exports covered (behavioral)
RtlSetBit, RtlSetBitEx, RtlSetBitsEx, RtlSetAttributesSecurityDescriptor, RtlSetSecurityDescriptorRMControl,
RtlSetInformationAcl, RtlSetSecurityObject, RtlSetSecurityObjectEx.
(Helpers used as verifiers only: RtlInitializeBitMap(Ex), RtlTestBit(Ex), RtlNumberOfSetBitsEx, RtlGet*SecurityDescriptor, RtlQueryInformationAcl.)

## Where expectations come from
| Area | Evidence |
| --- | --- |
| RtlSetBit / RtlSetBitEx | Decompiled: buffer[idx>>3] |= 1<<(idx&7), no bounds check. Asserted on the raw buffer (32/64-bit word layout) and through RtlTestBit(Ex). Out-of-range indexes are not tested (undefined). |
| RtlSetBitsEx | Decompiled: zero count is a no-op; partial first byte, memset of whole bytes, partial tail. Asserted by comparing every (start,count) pair of a sweep with a bit-by-bit model, plus wide unaligned ranges and RtlNumberOfSetBitsEx. |
| RtlSetAttributesSecurityDescriptor | Decompiled: *Revision = SD revision byte; revision != 1 -> STATUS_UNKNOWN_REVISION (c0000058) after writing the out value; otherwise RtlSetControlSecurityDescriptor(sd, bits & 0x3fc0, bits & 0x3fc0). Observed on Windows 10: the call only ORs bits in (mask equals value), passing 0 never clears; bits outside 0x3fc0 are ignored. |
| RtlSetSecurityDescriptorRMControl | Decompiled: NULL clears SE_RM_CONTROL_VALID (0x4000) and Sbz1; non-NULL sets the flag and stores *RMControl in Sbz1. Read back with RtlGetSecurityDescriptorRMControl (BOOLEAN return). Output cleared to 0 when the flag is absent (observed). |
| RtlSetInformationAcl | Decompiled: ACL revision must be 2..4 (else STATUS_INVALID_PARAMETER); class must be 1 (AclRevisionInformation) else STATUS_INVALID_INFO_CLASS (c0000003); length < 4 -> STATUS_BUFFER_TOO_SMALL; new revision lower than the current -> STATUS_INVALID_PARAMETER; otherwise stored. Revisions above 4 for the new value are not tested (accepted without validation per decompilation; not documented). |
| RtlSetSecurityObject(Ex) | Documented behaviour (modifies the self-relative descriptor the pointer refers to and replaces it with a freshly allocated one). Asserted: DACL_SECURITY_INFORMATION replaces only the DACL (owner untouched, result self-relative), SecurityInformation 0 leaves the object unchanged, NULL token accepted. Ex form with AutoInheritFlags 0 behaves identically. Observed on Windows 10. |

## Skips / notes
- The impersonation-token duplicate in the SetSecurityObject tests is best effort; the semantic checks run either way.

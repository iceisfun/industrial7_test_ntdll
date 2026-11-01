# rtl_security Windows authority

Reference: Windows 10 22H2 x64 corpus, queried 2026-10-31. Read
http://docker1.dev.moonlightcompanies.com:8765/SKILL.md first. Requests were
serial (one API at a time); `/decomp` and `/docs` were fetched for every public
API below. Expectations come from actual implementation branches, not Wine.
All security descriptors, ACLs and SIDs are process-local buffers; none is
installed on a system object. No advapi32 or ntdll static imports.

## SID contracts inspected

Each link is the actual decompilation endpoint read. The corresponding `/docs`
endpoint was also read; implementation evidence takes precedence where the
documentation is reserved/internal or kernel-context only.

| API / RVA | Verified contract |
| --- | --- |
| [RtlInitializeSid 0x400b0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlInitializeSid/decomp) | `param_3 < 0x10`: writes revision 1, count, six authority bytes, returns 0. It does not initialize subauthorities. Count 16 returns `0xc000000d` before writes. |
| [RtlAllocateAndInitializeSid 0x6d920](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAllocateAndInitializeSid/decomp) | `8 < param_2` returns `0xc0000078` before allocation/output. Otherwise allocate `count*4+8`, copy authority and requested subauthorities, publish pointer on success. Zero count skips subauthority writes. |
| [RtlFreeSid 0x751a0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFreeSid/decomp) | Successful RtlFreeHeap makes returned pointer NULL. Only successfully allocated SIDs are freed. |
| [RtlLengthRequiredSid 0x7a0c0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlLengthRequiredSid/decomp) | For tested bounded counts, `count*4+8`. |
| [RtlLengthSid 0x6e1c0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlLengthSid/decomp) | `sid[1]*4+8`. Tested counts 0,1,2,8,15. |
| [RtlValidSid 0x37950](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlValidSid/decomp) | Non-NULL, revision low nibble 1 and count below 16. NULL/revision 2/count 16 reject. Count-16 negative fixture is not dereferenced past its header. |
| [RtlEqualSid 0x38310](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlEqualSid/decomp) | First revision/count word must match, then byte comparison of `count*4+8`. BOOLEAN return interpreted only in low byte. |
| [RtlEqualPrefixSid 0x37de0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlEqualPrefixSid/decomp) | Revision, authority and counts must match. Ordinary SIDs compare all but last subauthority. Tests use count 3 and NT authority, not the special count-11 authority branch. |
| [RtlSubAuthoritySid 0x71600](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSubAuthoritySid/decomp) | Returns base + `(index+2)*4`. Only in-range indices 0..2 tested. |
| [RtlSubAuthorityCountSid 0x752d0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSubAuthorityCountSid/decomp) | Returns base+1. |
| [RtlIdentifierAuthoritySid 0x79500](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlIdentifierAuthoritySid/decomp) | Returns base+2. |
| [RtlCopySid 0x67410](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCopySid/decomp) | Computes source length. Short size returns NTSTATUS `0xc0000023` without writes; sufficient size copies exactly source length and returns 0. This is not a BOOL-returning API on this Windows build. |

## ACL contracts inspected

| API / RVA | Verified contract |
| --- | --- |
| [RtlCreateAcl 0x3a450](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCreateAcl/decomp) | Size below 8 returns `0xc0000023`. Revision 2..4 and size below 0xfffd succeed; size field is `size & 0xfffc`. Revision 1 returns `0xc000000d`. Initializes reserved fields/count to zero. |
| [RtlAddAccessAllowedAce 0x77880](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAddAccessAllowedAce/decomp) | Calls RtlpAddKnownAce with flags 0/type 0. Decompiler labels wrapper void; underlying status is the API's NTSTATUS result. |
| [RtlAddAccessDeniedAce 0x8bca0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAddAccessDeniedAce/decomp) | Same helper, type 1. |
| [RtlpAddKnownAce 0x375c4](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlpAddKnownAce/decomp) | Validates SID/ACL/revision. ACE size `(count+4)*4`; writes type, flags, mask, SID and increments count. Insufficient ACL space returns `0xc0000099`. |
| [RtlGetAce 0x711f0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlGetAce/decomp) | Revision/index checks precede output. Empty index 0 returns `0xc000000d` with output unchanged. Valid index walks ACE sizes from base+8. |
| [RtlDeleteAce 0x78780](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlDeleteAce/decomp) | Invalid/out-of-range index returns `0xc000000d`. Success compacts trailing ACE data and decrements count. First and last deletion tested with distinct masks. |
| [RtlQueryInformationAcl 0x78da0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlQueryInformationAcl/decomp) | Class 1 requires 4 bytes, class 2 requires 12 bytes; short returns `0xc0000023`, other classes return `0xc0000003`. Empty size info is count 0, used 8, remaining size-8. |

## Security descriptor contracts inspected

| API / RVA | Verified contract |
| --- | --- |
| [RtlCreateSecurityDescriptor 0x3c950](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlCreateSecurityDescriptor/decomp) | Revision 1 zeroes all 40 x64 bytes then sets revision. Other revision returns `0xc0000058` before writes. |
| [RtlValidSecurityDescriptor 0x701c0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlValidSecurityDescriptor/decomp) | Requires revision 1; optional owner/group validated as SIDs; present non-NULL ACLs validated. Empty and constructed relative fixture valid. |
| [RtlLengthSecurityDescriptor 0x713f0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlLengthSecurityDescriptor/decomp) | Absolute base length 40, relative base 20; add owner/group SID lengths and aligned lengths of present non-NULL ACLs. Relative test totals `20+16+12+8+8=64`. |
| [RtlSetOwnerSecurityDescriptor 0x38080](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSetOwnerSecurityDescriptor/decomp) | Absolute revision-1 descriptor receives pointer and owner-defaulted bit (bit 0). NULL allowed. |
| [RtlGetOwnerSecurityDescriptor 0x785b0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlGetOwnerSecurityDescriptor/decomp) | Returns pointer or resolves relative offset; defaulted from bit 0. |
| [RtlSetGroupSecurityDescriptor 0x38020](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSetGroupSecurityDescriptor/decomp) | Same pattern for group, defaulted bit 1. |
| [RtlGetGroupSecurityDescriptor 0x79a50](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlGetGroupSecurityDescriptor/decomp) | Group pointer/offset and defaulted bit 1. |
| [RtlSetDaclSecurityDescriptor 0x3c8e0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSetDaclSecurityDescriptor/decomp) | Absent clears present bit only; present sets pointer (NULL accepted) and bit 2, defaulted bit 3 from argument. |
| [RtlGetDaclSecurityDescriptor 0x70d50](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlGetDaclSecurityDescriptor/decomp) | Always writes present output on revision 1. Pointer/defaulted outputs written only in present branch; absent leaves both untouched. |
| [RtlSetSaclSecurityDescriptor 0x67450](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSetSaclSecurityDescriptor/decomp) | Same local-memory behavior, present/defaulted bits 4/5. No system SACL is changed. |
| [RtlGetSaclSecurityDescriptor 0x75c20](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlGetSaclSecurityDescriptor/decomp) | Same present-gated output writes as DACL getter. |
| [RtlGetControlSecurityDescriptor 0x79da0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlGetControlSecurityDescriptor/decomp) | Writes revision and, on revision 1, control. |
| [RtlSetControlSecurityDescriptor 0x7f990](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSetControlSecurityDescriptor/decomp) | Success requires `(mask & 0xc03f)==0 && (bits & ~mask)==0`; stores `(old & ~mask) | bits`. Otherwise `0xc000000d`. Tests set/clear DACL_PROTECTED, reject SELF_RELATIVE and bits outside mask. |
| [RtlAbsoluteToSelfRelativeSD 0x6d270](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlAbsoluteToSelfRelativeSD/decomp) | Short size updates required size and returns `0xc0000023` before output access. NULL with sufficient size returns `0xc000000d`. Exact buffer gets 20-byte header, copied components, offsets, SELF_RELATIVE set. |
| [RtlSelfRelativeToAbsoluteSD 0x6d0b0](http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlSelfRelativeToAbsoluteSD/decomp) | NULL/short absolute header or any short component returns `0xc0000023`, populating all five required lengths. Exact succeeds with caller component pointers, clears SELF_RELATIVE and copies component bytes. |

## Validation and retained Wine differences

Build: `make build/rtl_security.exe` succeeds without warnings after correcting
an initial local macro-parameter naming collision during implementation.
PE imports checked using objdump: KERNEL32.dll and msvcrt.dll only.

Only runtime command used:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_security.exe >/tmp/opencode/ntdll_rtl_security.log 2>&1
```

Observed summary: `tests=69 failed=9 skipped=0 checks_pass=339 checks_fail=10`.
All 9 failures retained against the Windows branches above:

* SID init count 1/15: Wine zeroes first subauthority; Windows leaves it unchanged.
* SID copy exact/short: Wine returns 1/0; Windows returns NTSTATUS 0/BUFFER_TOO_SMALL.
* ACL size 255: Wine preserves 255; Windows stores 252.
* ACL short query/bad class: Wine returns INVALID_PARAMETER for both; Windows
  returns BUFFER_TOO_SMALL / INVALID_INFO_CLASS respectively.
* Absent DACL getter: Wine clears pointer/defaulted; Windows leaves both unchanged
  (two failing assertions in one test). Absent SACL already matches Windows.
* Control bits outside mask: Wine succeeds; Windows rejects INVALID_PARAMETER.

## Gaps / uncertainty

No native Windows execution was available; the corpus implementation is the
authority, with Wine used only for smoke testing. No out-of-range pointer probes,
huge allocation requests, count-11 special prefix SID, object-security mutation,
or malformed relative offsets are tested. Helper wrapper return-type recovery
is imperfect in Ghidra; API typedefs use NTSTATUS and BOOLEAN as appropriate,
not guessed Ghidra `void`/64-bit return types.

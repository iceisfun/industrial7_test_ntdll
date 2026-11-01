# nt_token Windows authority

Reference: Windows 10 22H2 x64 corpus, queried 2026-10-31 after reading
http://docker1.dev.moonlightcompanies.com:8765/SKILL.md. All requests serialized
one API at a time. Public API `/decomp` and `/docs` responses were inspected.
No token setters, privilege changes, process-token assignments or impersonation
calls are used. Duplicates remain unattached and handles are closed. Fresh-thread
tests run in bounded children (35 seconds; worker wait 30 seconds).

## Stubs are not validation evidence

The ntdll implementations below are syscall stubs. Their decompiler's apparent
constant return is NOT the syscall result or a contract:

* http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/NtOpenProcessToken/decomp
  (RVA 0x9f560; service 0x129).
* http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/NtOpenThreadToken/decomp
  (RVA 0x9d4d0; service 0x24).
* http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/NtQueryInformationToken/decomp
  (RVA 0x9d470; service 0x21).
* http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/NtDuplicateToken/decomp
  (RVA 0x9d890; service 0x42).

## Actual kernel service branches inspected

* http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtOpenProcessToken/decomp
  (RVA 0x67e850) delegates to NtOpenProcessTokenEx with attributes zero.
* http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtOpenProcessTokenEx/decomp
  (RVA 0x67e870) reads caller PreviousMode, probes writable output in user mode,
  references process with access 0x1000, opens its primary token with requested
  access and writes output only on successful open. Tests use own pseudo-handle,
  TOKEN_QUERY and/or TOKEN_DUPLICATE; never security/adjustment rights.
* http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtOpenThreadToken/decomp
  (RVA 0x67e090) delegates to NtOpenThreadTokenEx.
* http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtOpenThreadTokenEx/decomp
  (RVA 0x67e0b0) user-mode output probe, thread reference, impersonation flag/token
  checks. No impersonation token returns `0xc000007c` before output assignment.
  Both OpenAsSelf choices are tested on a new thread, not an ambient caller
  whose impersonation state could depend on the test runner.
* http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtDuplicateToken/decomp
  (RVA 0x5e7d20) user-mode branch rejects `1 < TokenType-1U` with
  `0xc000000d`. Captures QoS and references source using access 2
  (TOKEN_DUPLICATE). DesiredAccess zero uses source granted access. Explicit QoS
  selects impersonation level. Successful duplicate/insert publishes handle;
  failure leaves output unchanged. Tests request identification-level QoS,
  primary/unattached impersonation types, EffectiveOnly FALSE/TRUE and access 0.
* http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/NtQueryInformationToken/decomp
  (RVA 0x61d520) user-mode output buffer uses `ProbeForWrite(...,4)` and valid
  ReturnLength probe. Selected classes reference with TOKEN_QUERY (8).
  TokenSource (7), which requires access 0x10, is deliberately not included.

Selected query switch branches (decimal class values):

| Classes | Observed required-size / output branch |
| --- | --- |
| User 1 | Writes required size, checks buffer length, copies SID_AND_ATTRIBUTES and SID into output. |
| Groups 2 / RestrictedSids 11 | Required size includes aligned header, attributes array, SID data. Writes count and copied groups only after size check. |
| Privileges 3 | Computes privilege count/length and converts privileges after size check. |
| Owner 4 / PrimaryGroup 5 | Required length is SID length + 8-byte pointer; output pointer targets copied SID. |
| DefaultDacl 6 | Required length is ACL length + 8-byte pointer; NULL ACL gets NULL pointer. Test sizes are discovered, not hard-coded. |
| Type 8 | Required size 4, output token type. Own process token is primary. |
| Statistics 10 | Required size 0x38 (56), includes type, counts, token/authentication/modified IDs. |
| SessionId 12 | Required size 4, writes session ID. Value logged, not fixed. |
| ElevationType 18 | Required size 4, result depends on token/logon state. Value logged. |
| HasRestrictions 21 | Required size **1**, short iff input length is zero, writes a boolean byte. Not assumed to have Win32 BOOL width. |
| VirtualizationAllowed 23 / Enabled 24 / UIAccess 26 | Required size 4, boolean from token flags. Values logged. |
| IntegrityLevel 25 | Required size SID length + 0x10; copies one SID_AND_ATTRIBUTES. SID checked only after in-buffer bounds validation. No fixed integrity RID. |
| MandatoryPolicy 27 | Required size 4, calls SeQueryMandatoryPolicyToken only when length >=4. Value not fixed. |

Every class test queries size with NULL/zero; checks 1 and exact-1 bytes when
required size >1; queries exact size and checks trailing guard bytes. Buffer
allocations are bounded to 1 MiB. Returned pointers/counts are bounded before
dependent reads. Query/duplicate fixtures gate on successful own-token opens;
policy-denied opens/duplication skip with cleanup, rather than assuming elevation.

## Documentation actually read

The `/docs` mappings for query/duplicate identify kernel-context pages and label
the user-mode match **partial**. They are not treated as interchangeable kernel
Zw contracts: the service's PreviousMode/user-probe branches above were checked.
The pages themselves explicitly discuss using Nt names from user mode.

* http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-ntopenprocesstoken.md
  documents own-process macro, access-token handle lifetime and successful open.
* http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-ntopenthreadtoken.md
  documents OpenAsSelf and STATUS_NO_TOKEN for threads not impersonating.
* http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-ntqueryinformationtoken.md
  explicitly documents STATUS_BUFFER_TOO_SMALL plus required ReturnLength,
  STATUS_ACCESS_DENIED without required rights, structure shapes, four-byte
  alignment, and primary versus impersonation token types. Tests never pass
  NULL ReturnLength or invalid memory. The service computes a pointer-sized
  default-DACL header even for NULL ACL; required size is discovered dynamically.
* http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/windows-driver-docs-ddi/ntifs/nf-ntifs-ntduplicatetoken.md
  documents TOKEN_DUPLICATE requirement, zero DesiredAccess inheriting access,
  QoS level selection, EffectiveOnly, primary/impersonation types and creation
  of a duplicate of the existing token. AuthenticationId equality is checked
  between original/duplicate, not against a machine-specific constant.

## Validation / retained Wine differences

`make build/nt_token.exe` succeeds without warnings. objdump import inspection:
KERNEL32.dll and msvcrt.dll only (no ntdll/advapi32 imports).

Only runtime command used:

```
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_token.exe >/tmp/opencode/ntdll_nt_token.log 2>&1
```

Observed summary: `tests=27 failed=5 skipped=0 checks_pass=485 checks_fail=10`.

Retained failures:

* Invalid duplicate type 0 succeeds under Wine, returning a handle. Windows
  user-mode validation explicitly returns INVALID_PARAMETER before output.
  Unexpected Wine handle is closed (two assertions fail, no token attached).
* RestrictedSids, HasRestrictions, VirtualizationAllowed and MandatoryPolicy
  return STATUS_NOT_IMPLEMENTED (`0xc0000002`) under Wine instead of the Windows
  size-query BUFFER_TOO_SMALL/required length (two assertions per class).
  All four classes have real Windows service switch branches above.

Both fresh-thread child cases return STATUS_NO_TOKEN with NULL handle. Other
query/duplicate tests pass in this Wine run; values are not Windows authority.

## Gaps / uncertainty

No native Windows run was available. An attempted kernel NtQueryInformationToken
`/asm` request returned HTTP 404; its decompilation and documentation were read
successfully. Ghidra recovers that large service as `void` and some common exit
helpers imperfectly, so BUFFER_TOO_SMALL status comes from explicit docs plus
the service's observed size branches, not the apparent decompiler return type.
No linked-token query (it could create another handle), privilege adjustment,
token impersonation/assignment, arbitrary invalid handles/pointers, or system
security operations are included.

## Adversarial review (2026-10-31)

Serially re-fetched the four service implementations, both open-Ex helpers,
their docs mappings, and the four documentation pages linked above. Re-fetched
NtDuplicateToken assembly and NtQueryInformationToken decompilation; query
assembly again returned HTTP 404. Response snapshots are under
`/tmp/opencode/ntdll_review_refs/`. Kernel docs remain partial evidence for these
user-mode calls; their buffer guidance is combined with actual PreviousMode
branches, not substituted for them. In particular, the page's claim of zero
ReturnLength for NULL default DACL is not imposed: the service initializes its
required pointer-header length to 8.

All five original failures were verified and retained:

| Original failing test | Exact service evidence |
| --- | --- |
| duplicate_bad_type | NtDuplicateToken RVA 0x5e7d20, decomp lines 53..62: user PreviousMode checks unsigned `TokenType-1 > 1` before the writable output probe; type zero returns 0xc000000d. Lines 136..137 publish only after successful insertion. Unexpected successful Wine handles are closed. |
| query_restricted_sids | NtQueryInformationToken RVA 0x61d520, case 0xb (lines 326..351): TOKEN_QUERY reference, length = 8 + count*16 + SID bytes; size check before data writes, including count zero. |
| query_has_restrictions | Case 0x15 (lines 594..603): required length 1, zero length takes short path before one-byte boolean store. |
| query_virtualization_allowed | Case 0x17 (lines 631..668): required length 4, short path before token flag extraction/output. |
| query_mandatory_policy | Case 0x1b (lines 686..699): required length 4, only sufficient size invokes SeQueryMandatoryPolicyToken. |

All four unsupported Wine queries still return STATUS_NOT_IMPLEMENTED. None is
privilege-dependent in the checked service branches: each requires TOKEN_QUERY,
not SeSecurityPrivilege/SeTcbPrivilege. Actual contents, elevation, session ID,
integrity RID, optional groups and privileges remain environment-dependent.
Policy-denied fixture opens/duplications still skip, with handles cleaned up.

Added one precedence test: for TokenType with a real handle lacking TOKEN_QUERY,
access denial precedes a zero-length-buffer check and preserves both data and
ReturnLength. This follows the service's early TokenType branch (lines 125..134):
SepReferenceTokenByHandle fails before `*ReturnLength=4`. Wine instead returns
BUFFER_TOO_SMALL and sets length 4 (two assertions fail).

Extended existing query tests to verify short-buffer data preservation and exact
scalar widths (HasRestrictions is one byte, the selected DWORD outputs four).
Boolean values are only constrained to 0/1; policy/session/elevation values are
not fixed. New preservation assertions expose two failures in the existing
privileges test: Wine writes into both short buffers. Windows case 3 (lines
174..193) checks length before SepConvertTokenPrivileges; no output data is
written on its short paths. These are two more retained Wine deviations, not
reasons to weaken the tests. Buffer resets isolate the independent calls.

Layout/prototype audit: compile-time assertions pin TOKEN_USER=16,
TOKEN_GROUPS.Groups offset=8, TOKEN_PRIVILEGES.Privileges offset=4,
LUID_AND_ATTRIBUTES=12, TOKEN_STATISTICS=56, QoS=12. Query service stores/copies
and sizes support those offsets. PDB `_SECURITY_QUALITY_OF_SERVICE` independently
confirms length/level/tracking/effective offsets 0/4/8/9 and size 12; the PDB
TOKEN_STATISTICS lookup returned 404. malloc gives aligned query buffers; count
and pointer ranges are checked before variable-size accesses. Nt* results are
NTSTATUS; EffectiveOnly/OpenAsSelf are BOOLEAN, not pointer-sized integers.
Successful query, allocation, open and duplicate prerequisites are explicitly
gated because CHECK is nonfatal. Closed the worker handle on wait failure too;
that path immediately exits the bounded child, letting process teardown end any
outstanding worker. No impersonation, attachment, token setter or privilege
adjustment was added.

Review validation (build clean; runtime completed with exit 1):

```sh
make build/rtl_security.exe build/nt_token.exe
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_token.exe > /tmp/opencode/ntdll_review_nt_token.log 2>&1
```

`/tmp/opencode/ntdll_review_nt_token.log:76`:
`SUMMARY tests=28 failed=7 skipped=0 checks_pass=518 checks_fail=14`.
Native Windows runtime validation remains outstanding. Query-service assembly
and unavailable PDB types remain limitations; no exact failing-service return
status is inferred from Ghidra's apparent void return alone.

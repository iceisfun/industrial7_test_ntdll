# nt_other_2_a_access: ZwAccessCheck family

Oracle: Windows 10 22H2 guest. Kernel behaviour is not available as decompilation, so values are public
documentation (AccessCheck, AccessCheckByType, AccessCheckByTypeResultList) plus **observed on Windows 10**.

Fixture: hand-built absolute security descriptor (owner and group Everyone S-1-1-0, DACL with one allow ACE for
Everyone, mask 3), generic mapping read=1 write=2 exec=4 all=7, an impersonation-level token duplicated from the
process token, a primary token, and an anonymous-level impersonation token.

| Behaviour | Value | Source |
| --- | --- | --- |
| Granted subset (1, 2, 3) | granted equals desired, AccessStatus 0, call returns 0 | AccessCheck docs |
| Desired bit not in DACL | call returns 0, granted 0, AccessStatus `STATUS_ACCESS_DENIED` | docs; (obs) |
| MAXIMUM_ALLOWED | 0x60003: DACL mask plus READ_CONTROL and WRITE_DAC because the caller's user matches the owner via Everyone | (obs) |
| Generic bits in DesiredAccess | `STATUS_GENERIC_NOT_MAPPED` (0xC00000E6); outputs untouched | docs ("must map generic rights first"); (obs) |
| NULL DACL / empty DACL | all access / none | SD semantics |
| Primary token | `STATUS_NO_IMPERSONATION_TOKEN` (0xC000005C) | docs; (obs) |
| Anonymous-level token | `STATUS_BAD_IMPERSONATION_LEVEL` (0xC00000A5) | docs; (obs) |
| Invalid / NULL / wrong-type token handle | `STATUS_INVALID_HANDLE` / `STATUS_OBJECT_TYPE_MISMATCH` | (obs) |
| SD without owner | `STATUS_INVALID_SECURITY_DESCR` | (obs) |
| ByType, no list | same as plain check; list entry with level != 0 first -> `STATUS_INVALID_PARAMETER` | docs; (obs) |
| ResultList | per-element granted and status arrays filled identically for a non-object ACE | docs; (obs) |
| AndAuditAlarm variants | Without an impersonation token on the thread: `STATUS_NO_IMPERSONATION_TOKEN`; impersonating (NtSetInformationThread class 5) without SeAuditPrivilege: `STATUS_PRIVILEGE_NOT_HELD` (0xC0000061); the ByHandle variant takes the token explicitly and reports the privilege failure directly. Skipped when the token holds SeAuditPrivilege | docs; (obs) |

Nt/Zw alias pairs are asserted by address equality. Success of the AuditAlarm calls (needs SeAuditPrivilege, a
service-level privilege) is not reachable from an ordinary or administrator token.

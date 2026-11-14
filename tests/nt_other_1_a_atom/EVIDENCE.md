# nt_other_1_a_atom evidence

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), observed in a throwaway guest in both elevated-administrator and
standard-user modes. NtAddAtom/NtAddAtomEx/NtFindAtom/NtDeleteAtom are thin syscall stubs, so every status below is the
kernel result observed on the guest. The Win32 global-atom API (documented) was used as an independent cross-check.

| Expectation | Source |
|---|---|
| String atoms are in 0xC000..0xFFFF; same name (case-insensitive) returns the same atom and bumps a reference count; delete decrements | Win32 GlobalAddAtom/GlobalDeleteAtom documentation, plus observed |
| Add returns the atom visible to GlobalFindAtomW / GlobalGetAtomNameW | documented Win32 wrappers |
| Unknown name: STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034); empty name: STATUS_OBJECT_NAME_INVALID (0xC0000033) | observed |
| Name of 255 characters accepted, 256 characters: STATUS_INVALID_PARAMETER (0xC000000D) | observed (Win32 limit is 255 characters) |
| Odd byte length is accepted (trailing byte dropped); NULL name with non-zero length: STATUS_INVALID_PARAMETER | observed |
| "#1234" names denote integer atom 1234 on add and find; delete of an integer atom (0..0xBFFF) is a successful no-op | documented (MAKEINTATOM / "#nnn" convention) and observed |
| Delete of an absent string atom (0xFFFF, or after the last reference is released) and atom 0: STATUS_INVALID_HANDLE (0xC0000008) | observed |
| NtAddAtomEx flags other than 0: STATUS_INVALID_PARAMETER | observed |
| Nt/Zw aliases share one address | export table |

Cleanup: every atom added is deleted again; names are unique per process id and tick count.
Skips: none.

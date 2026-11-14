# RtlIpv4/RtlIpv6 address <-> string conversions

Reference: Windows 10 22H2 ntdll 10.0.19041.2788. Expected values come from the documented behaviour of
`RtlIpv4AddressToString*`, `RtlIpv4StringToAddress*`, `RtlIpv6AddressToString*`, `RtlIpv6StringToAddress*`
(ntdll/ws2 conventions), cross-checked against the decompilation (e.g. `RtlIpv6AddressToStringExA`: formats
`[addr%scope]:port` into a stack buffer, port is byte-swapped from network order, returns STATUS_INVALID_PARAMETER
when `*len` is smaller than the formatted length + NUL and always stores the required length in `*len`) and then
confirmed by running on the Windows 10 guest (admin). Cases not obvious from the decompilation were observed.

Status codes: 0 success, 0xC000000D STATUS_INVALID_PARAMETER (every parse/format failure and NULL argument of the
`*Ex` variants).

| Export | Asserted |
| --- | --- |
| RtlIpv4AddressToStringA/W | dotted decimal for 0.0.0.0, 255.255.255.255 and mixed values; the return value points at the terminating NUL. |
| RtlIpv4AddressToStringExA/W | `a.b.c.d` and `a.b.c.d:port` (port in network byte order, 0 = no port); `*len` counts the NUL; too-small length -> 0xC000000D with the required length written back; NULL address/length/buffer -> 0xC000000D. |
| RtlIpv4StringToAddressA/W | strict mode (decimal, 4 parts, each <= 255) and non-strict mode (1-4 parts, hex `0x`, octal leading `0`, last part fills remaining bytes); terminator points at the first character not consumed (`1.2.3.4xyz`, `1.2.3.4:80`); empty/garbage/empty-part/256 -> 0xC000000D; a fifth part is rejected. NULL arguments are NOT tested: the routine does not validate them and faults on Windows 10 (observed). |
| RtlIpv4StringToAddressExA/W | whole string must be consumed; `:port` is decimal, `0x` hex or leading-0 octal, range 0..65535, returned in network order; trailing junk, empty port, port 65536 rejected; NULL arguments -> 0xC000000D. |
| RtlIpv6AddressToStringA/W | RFC 5952 style: longest zero run compressed (first of equal runs, single zero group not compressed), lower-case hex, `::ffff:a.b.c.d` / `::a.b.c.d` / `::ffff:0:a.b.c.d` dotted forms; return value points at the NUL. |
| RtlIpv6AddressToStringExA/W | `[addr%scope]:port` composition, scope id as unsigned decimal (up to 4294967295), required-length write-back, 0xC000000D on too small/NULL. |
| RtlIpv6StringToAddressA/W | compressed and full forms, embedded IPv4 tail, case-insensitive hex, stops at `%`; `[::1]`, 7 groups, `12345::`, leading/trailing single colon, `g`, empty rejected. Observed: parsing stops at the longest valid prefix, so `1:2:3:4:5:6:7:8:9`, `1::2::3`, `:::` and `1:2:3:4:5:6:7:8::` succeed with the terminator before the surplus text; `::2:3:4:5:6:7:8` yields `::2:3:4:5:6:7` with terminator before `:8`. NULL arguments not tested (not validated, faults). |
| RtlIpv6StringToAddressExA/W | optional `[...]`, `%scope` (decimal), `:port` (decimal, network order); unterminated bracket, trailing junk, bad scope, port 65536 rejected; empty port after `]:` accepted as 0 (observed); NULL arguments -> 0xC000000D. |

The Nt/Zw alias rule does not apply (these are Rtl exports); the test only asserts that the A and W routines are
distinct exports.

Skips: none. Standard-user and administrator runs behave identically (no privileged calls).

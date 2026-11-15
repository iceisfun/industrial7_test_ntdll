# Token cleanup and return-address hijack

[V] Reference listings fetched from the Corpus Explorer using
`/api/function/ntdll/<name>/asm`
and (for token cleanup) `/decomp`. These are static observations, not a
Windows execution result.

## RtlFreeNonVolatileToken

[V] RVA `0xfc3f0`, bytes:

```text
80 e1 01       and cl,1
f6 d9          neg cl
1b c0          sbb eax,eax
f7 d0          not eax
25 0d0000c0    and eax,0xc000000d
c3             ret
```

[V] No memory is accessed. Only bit zero of the token matters: odd values
return zero; even values return `0xc000000d`. In particular 1 and 3 both
succeed. No persistent-memory hardware is required to test this routine.
The pointer-sized declaration represents the opaque token; the decompiler's
byte parameter describes the portion actually consumed, not its public type.
The test covers high bits and invalid addresses to reject implementations
that validate only particular token values or dereference the token.

## RtlRaiseExceptionForReturnAddressHijack

[V] RVA `0xa1d70`: `48 81 ec d0 00 00 00` subtracts `0xd0`
from RSP. At `0xa1d77` it builds an exception record at RSP+0x20:
code `0x80000033`, flags zero, chained record NULL, address NULL,
parameter count zero. At `0xa1d92`, `e8 d9 f2 fa ff` calls
`0x51070`. At `0xa1d97`, `48 81 c4 c8 00 00 00 c3` adds
`0xc8` and returns. The net stack adjustment before RET is **minus 8**.

[V] The callers endpoint (`/callers?depth=1`) returned no edges and
`truncated:false`. This does not prove absence of indirect/kernel callers.

[I] This is a special-entry trampoline, not an ordinary callable C function.
The test supplies an aligned entry RSP and a continuation at entry RSP-8;
its VEH checks the exception and continues execution. A normal C wrapper
with a balanced stack is not equivalent under this entry convention.
Exact kernel reachability and comparison with the i7 implementation remain
outside the evidence collected here; no claim of a verified i7 fix is made.

## Validation

Host cross-build only. Windows execution (including whether the synthetic
frame is sufficient on the reference OS) is NOT RUN, per the task's
host-only restriction. The hijack test is a candidate pending oracle validation;
do not count it as a Windows-validated coverage row yet.

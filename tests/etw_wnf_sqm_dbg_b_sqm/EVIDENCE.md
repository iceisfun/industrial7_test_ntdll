# WinSqm* stubs: Windows 10 contracts

Reference: Corpus Explorer (http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/asm and /decomp), ntdll 10.0.19041.2788. Validated on the Windows 10 22H2 guest (administrator, run three times).

On this build every WinSqm export is a tiny stub (no documentation page exists). Behaviour comes from the disassembly and was confirmed by the guest run:

| group | exports | body | asserted |
|---|---|---|---|
| void | AddToAverageDWORD, AddToStream, AddToStreamEx, EndSession, IncrementDWORD, SetDWORD, SetDWORD64, SetIfMaxDWORD, SetIfMinDWORD, SetString | `ret 0` | no argument memory is written (sentinel buffers, NULL and -1 arguments) |
| zero | CheckEscalationAddToStreamEx, CheckEscalationSetDWORD, CheckEscalationSetDWORD64, CheckEscalationSetString, EventEnabled, EventWrite, GetEscalationRuleStatus, IsOptedIn, IsOptedInEx, StartSqmOptinListener | `xor eax,eax; ret` | full 64-bit return value 0 |
| one | CommonDatapointDelete, CommonDatapointSetDWORD, CommonDatapointSetDWORD64, CommonDatapointSetStreamEx, CommonDatapointSetString, IsSessionDisabled, SetEscalationInfo | `mov eax,1; ret` | return 1 |
| invalid handle | StartSession, StartSessionForPartner | `or rax,-1; ret` | return (HANDLE)-1, GUID argument untouched |
| property | GetInstrumentationProperty | writes 0 to the optional USHORT* (3rd) and ULONG* (4th) outputs when non-NULL, returns 0 | outputs zeroed independently, NULL tolerated |

The exports inside each group share one entry address (same RVA in the corpus); the test asserts this and that the four groups are distinct. Signatures are not documented, so the argument count and types are not asserted; the void group's return register is undefined and is not checked. Everything is observed-only on Windows 10 (decompilation + guest run); nothing is skipped.

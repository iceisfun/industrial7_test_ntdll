# Zw-named system services (privileged, stubbed, version dependent): Windows 10 contracts

Oracle: Windows 10 22H2 x64 in a throwaway guest, run elevated (privileges present but disabled) and as a standard user.
Decompilations of the kernel services (Corpus Explorer, `ntoskrnl` NtShutdownSystem, NtSerializeBoot, NtUmsThreadYield,
NtTranslateFilePath, NtReplacePartitionUnit, NtSystemDebugControl, NtThawRegistry) gave the validation order; the guest run is the authority.
`zw_misc_aliases` asserts the Nt/Zw pair addresses are equal.

| Export | Expectation | Source |
| --- | --- | --- |
| ZwShutdownSystem | only actions above 3 are called (4, 0x100, 0xffffffff) -> 0xc000000d, checked before any privilege test. Actions 0-3 would shut down or reboot the machine and are never issued | decomp + obs |
| ZwSerializeBoot | needs SeTcbPrivilege; the call is only made when the token does not hold that privilege (otherwise skip), then -> 0xc0000061 | decomp + obs |
| ZwVdmControl | 0xc0000002 for any arguments | obs |
| ZwUmsThreadYield | 0xc00000bb for a non-UMS thread | decomp + obs |
| ZwTranslateFilePath | BIOS boot: 0xc0000002 for every argument set; UEFI boot: output type 0 or above 5 -> 0xc000000d (type check) | decomp; the BIOS branch observed |
| ZwStartProfile / ZwStopProfile | NULL and unused handle -> 0xc0000008; process and event handles -> 0xc0000024 | obs |
| ZwReplacePartitionUnit | without SeShutdownPrivilege -> 0xc0000061 (skip); with the privilege enabled, undefined Flags (1, 0x7fffffff) -> 0xc00000f1 before any name is used; privilege disabled again -> 0xc0000061 | decomp + obs |
| ZwUnloadDriver | without SeLoadDriverPrivilege -> 0xc0000061 (skip); with it, a service key that does not exist -> 0xc0000034; disabled again -> 0xc0000061 | obs |
| ZwSystemDebugControl | with no kernel debugger on the system any command fails with 0xc0000354 (debugger inactive) before the arguments are examined and the output length is untouched; any other status (debugger enabled) skips the test | decomp + obs |
| ZwThawRegistry | without SeBackupPrivilege -> 0xc0000061 (skip); with it while nothing is frozen -> 0xc0000189 (twice) | decomp + obs |
| ZwThawTransactions | 0xc0000061 with a default token (no enabled privilege) | obs |
| ZwRegisterProtocolAddressInformation | NULL and unused resource-manager handle -> 0xc0000008; event handle -> 0xc0000024 (valid buffers supplied; NULL buffers raise an access violation status) | obs |
| ZwSubscribeWnfStateChange / ZwUnsubscribeWnfStateChange | see the subscription test: unsubscribe of an unknown name returns 0xc0000034; subscription to a well-formed name succeeds and is removed again | obs |

Privilege handling: privileges are enabled with RtlAdjustPrivilege only for the call under test and restored afterwards. A standard user
token lacks them entirely, so those checks assert 0xc0000061 and then skip with that reason.

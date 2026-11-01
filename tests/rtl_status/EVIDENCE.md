# rtl_status Windows evidence

Reference: Windows 10 x64 `ntdll.dll` 10.0.19041.2788, PDB key
`76C7BBFD419865CA30108FE0023CF0401` (`tools/reference_module.json`).
Queried 2026-10-31, sequential HTTP requests, retrying HTTP 503.
No Windows execution was performed; the Windows oracle here is binary inspection.

Base URL: <http://docker1.dev.moonlightcompanies.com:8765>.
All paths below are relative to it.

## Prototypes and thread error storage

Inspected `/api/function/ntdll/<name>/decomp` for every tested export:

| Export | RVA | Verified behavior |
|---|---|---|
| RtlNtStatusToDosError | 0x50840 | 32-bit status argument/result; stores original status at TEB + 0x1250 before conversion, does not store Win32 error |
| RtlNtStatusToDosErrorNoTeb | 0x759e0 | 32-bit argument/result; identical conversion without TEB write |
| RtlGetLastNtStatus | 0x7c680 | no arguments, reads DWORD at TEB + 0x1250 |
| RtlGetLastWin32Error | 0x19f0 | no arguments, reads DWORD at TEB + 0x68 |
| RtlSetLastWin32Error | 0x507c0 | same entry as RtlRestoreLastWin32Error; takes DWORD, writes TEB + 0x68, not + 0x1250 |
| RtlRestoreLastWin32Error | 0x507c0 | equal-value no-op branch; zero and 997 bypass origin-provider reporting |
| RtlSetLastWin32ErrorAndNtStatusFromNtStatus | 0x507a0 | calls conversion then Win32-error setter, preserving original NTSTATUS |

The decompiler widens RtlNtStatusToDosError's return to 64 bits; the SDK
declaration in `winternl.h` supplies the public ULONG signature via `U()`.
The tests snapshot and restore both fields before reporting assertions. The
thread isolation test runs in a bounded child, with a separate worker thread;
it tests distinct parent/worker status and Win32 values, not undocumented
initial values in a fresh thread. Setters are tested twice to hit equal-value
branches. Origin-provider diagnostics and debugger break configuration are not
enabled or modified.

## Conversion branches and actual mapping table

`/api/function/ntdll/RtlNtStatusToDosErrorNoTeb/decomp` explicitly shows:

- 0 -> 0; 0x103 -> 997.
- Bit 29 set -> original 32-bit status, before facility handling.
- Facility 7 and top byte 0x80/0xc0 -> low 16 bits.
- Top nibble 0xd -> clear bit 28 before table lookup; TEB retains original input.
- Otherwise binary search RtlpRunTable, then 16- or 32-bit RtlpStatusTable entry.

Actual table bytes were fetched, not inferred from status names:

- `/api/bytes/ntdll?rva=0x130400&len=2472`: 309 run records, each
  `{uint32 start; uint8 count; uint8 width; uint16 index;}`.
- `/api/bytes/ntdll?rva=0x12e5e0&len=7712`: status table, indexed in WORDs.
- `/api/symbols/ntdll?near=0x130400&limit=5` identifies both table symbols.

For width 1 the result is WORD[index + status - start]; otherwise it is the
DWORD beginning at WORD[index + 2 * (status - start)]. Decoded entries:

| Status | Result | Run start / count / width / index |
|---|---:|---|
| 0x102 | 1460 | 0xff / 16 / 1 / 8 |
| 0xc0000001, 02, 05, 08, 0d, 0f, 17 | 31, 1, 998, 6, 87, 2, 8 | 0xc0000001 / 28 / 1 / 333 |
| 0xc0000022, 23 | 5, 122 | 0xc000001e / 7 / 1 / 363 |
| 0xc0000034, 35, 3a, 43, 54, 61, 6a, 7b | 2, 183, 3, 32, 33, 1314, 86, 193 | 0xc000002c / 96 / 1 / 384 |
| 0xc000009a, 0xc00000ba, 0xc0000120 | 1450, 5, 995 | 0xc0000097 / 216 / 1 / 502 |
| 0xc0000225 | 1168 | 0xc0000201 / 73 / 1 / 782 |
| 0x80000005, 06 | 234, 18 | 0x80000001 / 7 / 2 / 191 |

## Unmapped fallback and decompiler limitation

The NoTeb decomp loses the return type across its cold helper. Inspecting
`/api/function/ntdll/0xc29f5/asm` verifies comparison with 0xc0010000 and
`movzx eax,dx` for that legacy facility. The other branch calls diagnostic
printing. `/api/bytes/ntdll?rva=0xc2a12&len=40` contains at RVA 0xc2a2f
`b8 3d 01 00 00` (`mov eax,317`) followed by a jump to the normal return
at 0x75a92. Thus the misleading decompiled nonreturning DbgPrint is not
treated as the contract.

All 309 run records were scanned: 0xc0ffffff, 0x4007ffff, and 0xc0080057
match no run. The first also covers normalized 0xd0ffffff. These test the
317 fallback, informational facility 7 not being extracted, and facility 8
not being extracted. 0xc0011234 tests the legacy low-word fallback.

Documentation independently states unmapped status returns
ERROR_MR_MID_NOT_FOUND:
`/api/docs/page/sdk-api/winternl/nf-winternl-rtlntstatustodoserror.md`.

## Validation and gaps

Build: `make build/rtl_status.exe`.
Smoke: `TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_status.exe`.
Log: `/tmp/opencode/ntdll_rtl_status.log`.
`SUMMARY tests=51 failed=0 skipped=0 checks_pass=377 checks_fail=0`.
Wine is a smoke check, not the Windows oracle. No invalid pointers, resource
exhaustion, private TEB layout writes, or process-global error configuration.
The function-level `/asm` query for NoTeb returned HTTP 404; cold-helper asm,
raw bytes and decompilation were available and used instead.

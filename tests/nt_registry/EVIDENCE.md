# nt_registry Windows evidence

Reference queried 2026-10-31: Windows 10 22H2 corpus (ntdll 19041.2788,
ntoskrnl 19041.2965). All requests were serial, with 503 retry handling.
Base: <http://docker1.dev.moonlightcompanies.com:8765/api>.
`/function/ntdll/<name>`, `/decomp`, `/docs` and the matching Microsoft page
were inspected for every registry Nt API used. Nt stubs alone do not establish
kernel validation behavior.

## Microsoft contracts

All links below are DDI pages under
`https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/`.
Each explicitly directs user-mode callers to the Nt name. Only user-applicable
handle access, status, data and buffer contracts are tested; kernel IRQL and
Zw PreviousMode assumptions are excluded.

| Page | Checked contract |
|---|---|
| [ZwCreateKey](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatekey) | Relative ObjectAttributes, REG_OPTION_VOLATILE, REG_CREATED_NEW_KEY disposition; returned private handle |
| [ZwOpenKey](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkey) | Open existing child with KEY_READ; deleted child returns STATUS_OBJECT_NAME_NOT_FOUND |
| [ZwSetValueKey](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-zwsetvaluekey) | Creates/replaces named data; KEY_SET_VALUE required; STATUS_ACCESS_DENIED on query-only handle; byte-counted binary/none/DWORD/QWORD/SZ/EXPAND_SZ/MULTI_SZ/big-endian types |
| [ZwQueryValueKey](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryvaluekey) | Basic/full/partial classes, ResultLength, missing value STATUS_OBJECT_NAME_NOT_FOUND, invalid class STATUS_INVALID_PARAMETER, short buffer STATUS_BUFFER_TOO_SMALL or STATUS_BUFFER_OVERFLOW |
| [ZwDeleteValueKey](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletevaluekey) | Deletes a private value; missing value STATUS_OBJECT_NAME_NOT_FOUND |
| [ZwDeleteKey](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletekey) | Child keys deleted before parent; close all deleted-key handles |
| [ZwEnumerateKey](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratekey) | Basic information NameLength/name; empty and out-of-range index STATUS_NO_MORE_ENTRIES |
| [ZwEnumerateValueKey](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratevaluekey) | Partial data/type/length; out-of-range STATUS_NO_MORE_ENTRIES |
| [ZwQueryKey](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-zwquerykey) | Basic/node/full/name classes, required-length query followed by exact-sized retrieval |

The partial value record has ULONG TitleIndex/Type/DataLength then Data;
successful payload length is checked as 12+DataLength. String data includes
terminating UTF-16 zeros. Default value uses a valid zero-length counted name,
not a NULL UNICODE_STRING pointer. Unicode names/data are explicit UTF-16
code units; no locale-dependent comparison. Zero-byte data is tested only
for binary/none, avoiding malformed string contracts.

15 value-buffer tests vary zero, one, required-1, exact and oversized length
across basic/full/partial classes. Both documented insufficient-buffer statuses
are admitted: the page does not specify the exact header/payload boundary for
each class. ResultLength must stay the required size. These are intentionally
not Wine-derived exact status assertions, nor assertions about untouched bytes
on failure. Enumeration has one private entry, so there is no ordering claim.

## Actual Windows branches

Queries `/syscalls?q=NtQueryValueKey`, `NtSetValueKey`, `NtDeleteKey` mapped
services to ntoskrnl, whose `/decomp` was then read:

* NtQueryValueKey: syscall 0x17, kernel RVA 0x618560.
  `if (4 < param_3)` sets `0xc000000d`. References the key with access 1.
  After CmQueryValueKey, success/0x80000005/0xc0000023 copy ResultLength;
  0xc0000023 does not copy the payload. Tests use class 99 as the bounded
  invalid-class case, with otherwise valid objects and buffers.
  <http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/0x618560/decomp>
* NtSetValueKey: syscall 0x60, kernel RVA 0x66deb0.
  References access 2, handles access-denied/virtualization separately,
  captures user strings/data using PreviousMode, and explicitly sets captured
  data to NULL for zero DataSize. Tests are native x64 private HKCU objects,
  not virtualized machine keys.
  <http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/0x66deb0/decomp>
* NtDeleteKey: syscall 0xd4, kernel RVA 0x701fa0. Read as the actual service,
  not confused with kernel ZwDeleteKey.
  <http://docker1.dev.moonlightcompanies.com:8765/api/function/ntoskrnl/0x701fa0/decomp>

RtlOpenCurrentUser at ntdll 0x16790 was inspected but deliberately **not used**:
its name-not-found branch falls back to a default user hive. Instead
RtlFormatCurrentUserKeyPath (0x36c40) queries the user SID, allocates a string,
and appends that SID to `\REGISTRY\USER\`. NtOpenKey opens that exact HKCU
root prerequisite; no fallback hive is ever mutated. The allocated string is
freed before creating the private child.
<http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/RtlFormatCurrentUserKeyPath/decomp>

## Safety, validation, gaps

40 registered tests. Every top-level private leaf is
`nt_registry_corpus_<PID>_<test>`, created volatile beneath the current user's
root. A preexisting leaf is skipped without modifying/deleting it. All value
and child operations remain beneath that fixture. Root handles are closed;
every private key is deleted and closed even after nonfatal assertions fail.
No machine, policy, system or other-user path is opened. Every API under test
uses UDECL/UN plus REQUIRE; NtClose/RtlFreeUnicodeString use U plus REQUIRE.

Build: `make build/nt_registry.exe`. Smoke command:
`TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_registry.exe >/tmp/opencode/ntdll_nt_registry.log 2>&1`.
Wine is validation only, never the contract oracle. Native Windows execution
is still needed; security callbacks, privilege policies and filesystem/hive
environment variations have not been measured on Windows.

Final ntdll-only module-list build/run reported
`tests=40 failed=0 skipped=0 checks_pass=291 checks_fail=0` (log line 82).
An intermediate rebuild skipped all tests because GetCurrentProcessId was
looked up in the native-only list; pinning this fixture helper to kernel32 via
REQUIRE/UIN fixed that integration issue without changing native expectations.

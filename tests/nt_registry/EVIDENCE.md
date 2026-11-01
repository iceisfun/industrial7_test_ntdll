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

## Adversarial review (2026-10-31)

Reviewed the harness and test-pattern writing/safety rules. All mutations use
the newly created volatile key under the SID-specific HKCU root, or its child;
no machine/default/other-user hive fallback or unscoped deletion was found.
Preexisting top-level keys are closed without deletion. Nonfatal assertions do
not bypass cleanup. Cleanup now checks close statuses and clears ownership.

Findings/fixes:

* Successful basic/full value-buffer queries previously checked only status and
  ResultLength. They now verify type, counted Unicode name, and full-information
  data length/content using the returned DataOffset. Returned lengths/offsets
  are explicitly bounded before dependent reads: failed CHECKs do not suffice
  as guards. Partial information also verifies payload.
* All buffer vectors check the canary beyond the supplied capacity, on success
  and failure. The partial-data offset has a compile-time 12-byte check.
* Added two partial-information header-boundary vectors: 11 and 12 bytes.
  Partial short-buffer statuses are now exact, based on Windows implementation,
  not on the Wine result. Basic/full retain the documented pair of statuses.
* Child enumeration now checks the returned header/name extent before reading
  it, rather than silently omitting checks for a short header. Its buffer has
  explicit eight-byte alignment.

Independent serial Windows corpus re-checks (503 retries enabled):

* `/function/ntdll/NtQueryValueKey/asm` is the service-0x17 syscall stub.
  `/function/ntoskrnl/NtQueryValueKey/decomp` (0x618560) and
  `/CmQueryValueKey/decomp` (0x67a400) lead to CmpQueryKeyValueData.
* `/function/ntoskrnl/CmpQueryKeyValueData/decomp` and `/asm` (0x67ab00):
  class 2 sets required size to data length + 12. At 0x67aba4, `cmp r13d,0xc`
  followed by unsigned `jb` selects 0xc0000023 at 0x67ac42. With the header
  present, 0x67abc2 compares capacity-minus-12 to payload length; unsigned
  `cmovb` selects 0x80000005 if truncated. Thus this seven-byte value needs
  19 bytes: 0/1/11 return SMALL, 12/18 return OVERFLOW, and 19/512 succeed.
  The basic/full field and copy offsets also match the new parsing checks.
* `/function/ntoskrnl/NtQueryKey/decomp` (0x618ff0) and
  `/NtSetValueKey/decomp` (0x66deb0) were read; the latter references access 2,
  consistent with query-only write denial. `/NtQueryValueKey/docs` and
  `/NtOpenKey/docs` flag Zw twins as **partial**, with the PreviousMode caveat;
  the user-mode Nt path remains authoritative. Structure pages
  `wdm/ns-wdm-_key_value_{basic,full,partial}_information.md` were read via
  `/docs/page/windows-driver-docs-ddi/`.

Corpus gaps encountered: NtQueryValueKey kernel `/asm` returned
`no listing available` (capstone/objdump unavailable), and these registry
structure names were absent from the PDB type endpoint. The successful service
decompilation, CmpQueryKeyValueData assembly, and vendored structure docs were
used instead; no unavailable view is claimed as verified.

Validation: build completed without compiler diagnostics, followed only by:

```sh
TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/nt_registry.exe > /tmp/opencode/ntdll_review_nt_registry.log 2>&1
```

Log line 86: `SUMMARY tests=42 failed=0 skipped=0 checks_pass=449 checks_fail=0`.
This supersedes the earlier 40-test smoke count. No native Windows execution or
security-callback/virtualization policy matrix was available. Cleanup failures
are reported, but successful deletion cannot be guaranteed if the implementation
under test rejects its own cleanup calls; no broad recovery deletion is used.

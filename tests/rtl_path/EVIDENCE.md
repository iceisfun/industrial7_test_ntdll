# rtl_path evidence

Authority: Windows 10 x64 corpus, read serially using
http://docker1.dev.moonlightcompanies.com:8765/SKILL.md . Wine results do
not establish Windows behavior. No native Windows run has been performed.

## Concrete decompilation branches

URLs below have prefix
`http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/`.

- `RtlDetermineDosPathNameType_U/decomp`, RVA 0x76290: relative=5;
  second character colon with no following separator=3; colon followed
  by slash/backslash=2; single leading separator=4; two separators=1.
  Two separators followed by dot/question mark plus separator=6; an
  immediately terminated dot/question mark form=7, other suffix=1.
  This syntactic branch does not validate a drive letter, hence `1:\\leaf`
  is intentionally classified as drive-absolute, without using it for I/O.
- `RtlIsDosDeviceName_U/decomp` (0x77150) initializes a Unicode string
  and calls `RtlpIsDosDeviceName_Ustr/decomp` (0x1be90). The helper strips
  colon/trailing spaces/dots, locates the final component, ignores an
  extension for name recognition, compares names case-insensitively, and
  returns byte-length | (byte-offset << 16). It excludes UNC paths,
  rejects COM0 and five-character COM10, and recognizes CONIN$/CONOUT$.
  Eighteen independent vectors exercise these branches and packed fields.
- `RtlDosPathNameToNtPathName_U/decomp` (0x17310) converts helper status
  to BOOLEAN via signed >=0. `_WithStatus/decomp` (0x16be0) returns the
  helper status directly. Both call
  `RtlpDosPathNameToRelativeNtPathName_U/decomp` (0x1a974), then
  `RtlpDosPathNameToRelativeNtPathName/decomp` (0x1af50): absolute drive
  names gain the DOS-devices prefix; UNC names replace their initial two
  separators with the DOS-devices UNC prefix; allocation includes NUL;
  output Length/MaximumLength are byte counts. FilePart is rebased into
  the allocated output. The helper calls full-path normalization for dot
  and parent components. Tests check exact bytes, terminator, allocation
  capacity, file-part pointer identity, and free every allocated string
  dynamically through RtlFreeUnicodeString.
- `RtlpWin32NtNameToNtPathName/decomp` (0x17108): extended `\\?\`
  names append the DOS-devices prefix and the source after its first
  four WCHARs. FilePart scans the allocated output backward. Extended
  names are tested through both Boolean and status entry points.
- `RtlGetFullPathName_U/decomp` (0x813d0),
  `RtlGetFullPathName_UEx/decomp` (0x1d800), and
  `RtlGetFullPathName_Ustr/decomp` (0x1b430): file part is initially NULL;
  supplied byte range is zeroed; insufficient storage returns required
  bytes including NUL. For `C:\leaf`, input/output length=7 WCHARs,
  successful return=14 bytes, minimum capacity=16 bytes. Normalization
  handles slash conversion, dot and parent components, and computes the
  final file-part pointer only when a nonempty final component exists.
  Tests use capacities 0,2,14,16 with a sentinel immediately after the
  advertised range, plus guarded full buffers for deterministic paths.
- `RtlGetCurrentDirectory_U/decomp` (0x5d290): returned success length
  is bytes excluding NUL, while insufficient capacity returns bytes
  including NUL without copying. It strips an internal trailing slash
  except for drive roots. Tests first obtain the current value without
  assuming its spelling, then exercise query/short/exact-without-NUL/
  exact-with-NUL storage and validate byte counts and sentinels.

No current-directory mutation occurs, even temporarily. No files are
created, UNC names are only syntactically converted (no network access),
and no environment, process search state, or host-wide state is changed.
All export pointers are dynamically resolved and REQUIRE-guarded; skips
are followed by explicit returns through REQUIRE.

## Documentation queried/read

`/docs` was queried for every tested public function above. Exact pages:

- http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/win32/DevNotes/rtlisdosdevicename_u.md
  documents the packed device-name offset/length and recognized names.
  Its unrelated parameter prose is erroneous; the concrete signature and
  helper branches, not that prose, establish the input contract.
- http://docker1.dev.moonlightcompanies.com:8765/api/docs/page/win32/DevNotes/rtldospathnametontpathname_u_withstatus.md
  documents PCWSTR input, allocated UNICODE_STRING output, optional
  file-part pointer and reserved PVOID, returning NTSTATUS.

Other tested APIs returned no exact documentation from `/docs`; their
contracts above are grounded in the decompilation. Failure allocation
outputs, long-path policy, per-drive environment state, null input,
device-name filesystem existence checks, relative-name handle ownership,
and directory mutation are deliberately outside this corpus area.

## Development validation

`make build/rtl_path.exe` succeeds without compiler warnings.
Run only via:
`TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_path.exe >/tmp/opencode/ntdll_rtl_path.log 2>&1`

Observed summary: 66 tests, 0 failed, 0 skipped, 191 checks passed,
0 checks failed. This is smoke evidence only; native Windows 10 execution
is still needed to validate all hard expectations against the target OS.

## Adversarial review

Reviewed writer commit `1e9d002`. The original log has no failures to
reclassify (`/tmp/opencode/ntdll_rtl_path.log:134`). Reference requests
were serial (503 retries supported; none needed).

Fixes:
- Replace unbounded comparisons of implementation-produced full paths and
  file parts with fixed-length comparisons, including the expected NUL.
  FilePart must match the exact expected address, and output Length and
  MaximumLength must support the read. Address comparison uses integer
  arithmetic so a bad returned length cannot cause out-of-object pointer
  arithmetic while checking a mismatching FilePart.
- Initialize output buffers before use. Current-directory output must have
  an in-range, even byte count and a NUL at that count before lstrlenW.
- Increase current-directory storage to the counted Unicode string range
  (32768 WCHARs), avoiding a host-dependent 511-character assumption.
  The second buffer has one extra WCHAR for the sentinel: previously a
  successful 1022-byte name made capacity 1024 and accessed small[512]
  outside the old 512-WCHAR buffer in the exact-capacity test.

Added two successful extended-path vectors: `\\?\C:\alpha\.\file`
and `\\?\C:\alpha\..\file` preserve the literal dot/parent components,
through Boolean/status entry points respectively. Re-read
`RtlpWin32NtNameToNtPathName/decomp` (RVA 0x17108): it appends the prefix
and source after four WCHARs directly with RtlAppendUnicodeStringToString,
then scans backward for FilePart, without full-path normalization.
This distinguishes extended syntax from the existing normalized DOS cases.

Re-read `RtlGetCurrentDirectory_U/decomp` (0x5d290): root paths require
length+2 capacity; nonroots copy their internal trailing separator and
replace it with NUL, returning the shortened byte count. Both cases give
the existing required=returned_length+2 contract. No cwd mutation was
introduced. Literal C: and UNC inputs are lexical fixtures, not host-path
assumptions or filesystem/network probes. Allocated conversion strings
remain freed via RtlFreeUnicodeString, including failure cleanup when a
buffer is returned. Export guards use `common/t.h:75`, which explicitly
returns after nonfatal `t_skip`; there are no bare skip calls in this area.

Review validation:
- `make build/ldr_image.exe build/rtl_path.exe`: success, no warnings.
- `TMPDIR=/tmp/opencode TP_TIMEOUT=120 tools/wine_run.sh build/rtl_path.exe >/tmp/opencode/ntdll_review_rtl_path.log 2>&1`
  exited **0**.
- `/tmp/opencode/ntdll_review_rtl_path.log:138`:
  `SUMMARY tests=68 failed=0 skipped=0 checks_pass=215 checks_fail=0`.
- Exact retained failure list: **none**.
- `git diff --check -- tests/ldr_image tests/rtl_path`: success.

Native Windows execution remains unavailable. Relative/per-drive state,
invalid-input allocation outputs, long-path conversion policy and
relative-name handle ownership remain untested; the larger cwd buffers
remove a test-side limit but do not constitute a long-cwd runtime baseline.

# User-mode ETW provider side: evidence

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), run elevated and as a standard user.
Decompilations come from the Corpus Explorer (`/api/function/ntdll/<Name>/decomp`), used to choose argument-validation
order and status codes; every asserted value was then confirmed on the Windows 10 guest.
All return values are Win32 error codes (ULONG), not NTSTATUS. No trace session is created, so every provider
stays disabled and writes are no-ops.

| Export | Source of expectation |
|---|---|
| EtwEventRegister / EtwEventUnregister | decomp 0x42ec0: NULL callback with non-NULL context returns 87 before any work and does not touch last-error; other failures come from EtwNotificationRegister (NULL guid/handle -> 87, last-error set). Unregister of 0, tag-less, odd or already-freed handles -> 6. Handle layout (16-bit tag in bits 48..63, 8-byte aligned pointer) from the decomp and observed. |
| EtwNotificationRegister / EtwNotificationUnregister | decomp 0x43080 / 0x503e0; Unregister's second argument returns the registration's context pointer (observed, matches decomp `*param_2 = reg[7]`). |
| EtwEventEnabled / EtwEventProviderEnabled | decomp 0x50d50 / 0x74aa0: invalid or stale handles and NULL descriptor give FALSE; a provider with no session is FALSE. |
| EtwEventWrite, WriteTransfer, WriteEx, WriteFull | thin wrappers over EtwpEventWriteFull. Observed: disabled provider -> 0; handle 0 -> 6. |
| EtwEventWriteString | decomp 0x110640: handle checks (6) precede NULL-string check (87), which precedes the enabled check (0). |
| EtwEventWriteStartScenario / EndScenario | decomp 0x89e00 / 0x4ec20: NULL descriptor 87, then EtwEventEnabled false -> 6. |
| EtwEventWriteNoRegistration | decomp 0x609e0: NULL provider or descriptor 87; with no session the kernel refuses with 4212 (observed on Win10; ERROR_WMI_ALREADY_DISABLED); this single value is observed only. |
| EtwEventSetInformation | decomp 0x42b30: class switch (0: length must be 0; 2: non-NULL buffer, length 3..0xffff; 3: non-NULL, length 1; everything else 50) evaluated before the handle. Length 0x10000 and 0xffffffff -> 87 (the 0xffff upper bound reads memory so is not exercised; observed ERROR_NOACCESS 998 on a short buffer). Class 0/len 0 and class 3/len 1 on a valid registration succeed (observed 0). |
| EtwEventActivityIdControl | decomp 0x5b6e0: per-thread GUID in the TEB; 1 get, 2 set, 4 swap, 3 create (kernel), 5 create+set returning the previous id; NULL pointer and unknown codes -> 87. Observed on Win10: CREATE_SET returns 0 and the old id, then the current id is a new non-zero GUID. A new thread starts with the zero GUID. |
| EtwCreateTraceInstanceId | decomp 0x110960: pure memory operation. Structure `{LONG counter; ULONG pid}`, instance info `{PVOID reg; ULONG id}`. Counter pre-incremented, 0 skipped on wrap, pid mismatch -> 87 with the handle field still stored. |
| EtwEnumerateProcessRegGuids | decomp 0x110540: NULL buffer with non-zero size -> 87. The needed size from a zero-size query counts every registration (duplicates included); with a buffer the GUIDs are de-duplicated against the entries already stored (observed: 16 registrations vs 12 unique GUIDs in a fresh process). Insufficient buffer returns 122 (the decompiler shows a one-byte return; the test masks to the low byte). |
| EtwGetTraceEnableFlags / Level / LoggerHandle | decomp 0x81480 / 0x81440 / 0x81400: handle bits 32..63 flags, 16..23 level, low 16 bits logger id (must be below the maximum logger count or 0xffff); invalid -> 0 / -1 and last-error 6; NULL header 87; BufferSize <= 0x2f gives 24. |
| EtwLogTraceEvent, EtwTraceEventInstance | decomp 0x4fb90 / 0x1109c0: argument validation only (NULL, header size below 0x38, NULL instance registration, continuation payload not a multiple of 16 or over 0x100) -> 87. The successful path needs a live session and is not exercised. |
| EtwRegisterTraceGuidsW / A | decomp 0x42a50: NULL callback, NULL guid, NULL handle, count over 0x10000 -> 87 with last-error 87. A control-GUID-only registration succeeds on Win10 (observed) and is released with EtwNotificationUnregister. A is a wrapper of W. |
| EtwCheckCoverage | decomp 0x85ba0: consults PEB+0x7a0; with no sampler it returns FALSE and leaves the result slot alone. Skipped if the field is non-NULL. |
| EtwSetMark, EtwTraceMessage, EtwReplyNotification | thin NtTraceEvent/NtTraceControl wrappers (decomps 0x8a8c0, 0x506b0, 0x19a0). Logger handle 0 -> 6 and a zeroed notification header -> 87 are observed on Win10 only. |
| EtwProcessPrivateLoggerRequest | decomp 0x559a0: request size under 0xf8 -> 0x1071 (4209); a zero-filled 0xf8 request returns 0 with the error embedded in the reply (observed). |

## Not covered

EtwDeliverDataBlock, EtwSendNotification and EtwRegisterSecurityProvider need a live trace session, the ETW service or SeTcb and could change system tracing state; see the group report.

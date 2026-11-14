# CRT formatted I/O and debug print exports

Reference: Windows 10 22H2 ntdll 10.0.19041.2788 (administrator and standard user guests).

| Export | Asserted / source |
| --- | --- |
| sprintf, sprintf_s | d i u x X o c s %% flags (- + space 0 #), width, precision, `*`, h/l/I64 sizes, %ls/%S; return value is the length; sprintf_s exact fit (observed). |
| swprintf, swprintf_s | `swprintf` is the two-argument form (decomp RVA 0x8d8f0, alias of _swprintf); %s is a wide string, %hs narrow; return values (observed). |
| vsprintf, vsprintf_s, vswprintf_s | same formatting through a va_list (observed). |
| _vswprintf | three-argument form (buffer, format, va_list); the four-argument signature in the decompilation listing is wrong: calling it that way faults (observed). |
| _vsnprintf, _vsnwprintf | count semantics: fits -> length with terminator; exactly count -> length, no terminator; over -> -1 with count characters written (observed). |
| _vsnprintf_s, _vsnwprintf_s | count below size cuts at count and returns -1 with a terminator; _TRUNCATE cuts at size-1 and returns -1; fits -> length (decomp 0x96c20, observed). |
| _vscprintf, _vscwprintf | length without writing (observed). |
| sscanf, sscanf_s, swscanf_s | d i u x o c s [set], widths, `*` suppression, %n not counted, I64/h sizes, match failure returns the converted count; empty narrow input returns -1 but empty wide input returns 0 (observed). |
| vDbgPrintEx, vDbgPrintExWithPrefix | return STATUS_SUCCESS for a normal component/level, no debugger attached (observed). Output goes to the debugger only. |

Not driven: floating point conversions, %n (not supported: the count is not stored), bounded variants without _TRUNCATE on overflow and NULL arguments (invalid-parameter routine).

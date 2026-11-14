# rtl_net_ip_str_a_path: DOS path conversion, search path, 8.3 names, name equality, correlation vectors

Oracle: Windows 10 22H2 ntdll 10.0.19041.2788, run on the guest in adm and std modes.
Decompilations read from the corpus explorer; the guest run is the authority. Exports are resolved dynamically.

| Export | Expectation | Source |
| --- | --- | --- |
| RtlDosSearchPath_U | returns full-path byte length, FilePart points at the leaf in the output buffer, extension appended only when the name has none, not found gives 0, too-small buffer returns the required size including NUL and writes an empty string | docs + guest |
| RtlDosPathNameToRelativeNtPathName_U / _WithStatus | `\??\C:\...` result, FilePart, ".." collapsed, UNC maps to `\??\UNC\...`, empty string fails (BOOLEAN FALSE / negative status; WithStatus gives STATUS_OBJECT_NAME_INVALID 0xC0000033), NULL input negative | guest |
| RtlDosLongPathNameToNtPathName_U_WithStatus, RtlDosLongPathNameToRelativeNtPathName_U_WithStatus | paths longer than MAX_PATH (about 1000 characters) succeed, FilePart is the leaf | guest |
| RtlGenerate8dot3Name | LONGFI~1.TXT then LONGFI~2.TXT with the same context, MYFILE~1.DOC (spaces dropped), NOEXTE~1 (no extension, 16 bytes), long extension cut (ABC~1.LO prefix, 18 bytes: observed) | decomp + guest |
| RtlEqualComputerName / RtlEqualDomainName | case-insensitive (OEM canonicalization), different or too long names FALSE | decomp |
| RtlInitializeCorrelationVector / RtlExtendCorrelationVector | version 1: 16 base64 characters then ".0" (length 18); version 2: 22 characters then ".0" (length 24); versions 0 and 3 and NULL GUID give STATUS_INVALID_PARAMETER; extend appends ".0" and returns STATUS_BUFFER_OVERFLOW (0x80000005) when full | decomp |
| RtlConvertDeviceFamilyInfoToString | success writes NUL-terminated names starting "Windows."; sizes in bytes; small buffers give STATUS_BUFFER_TOO_SMALL (0xC0000023) and return required sizes | decomp + guest |
| RtlFindExportedRoutineByName | same address as GetProcAddress, case sensitive, unknown names NULL | docs + guest |

Fixtures use a throwaway file created in the per-process temp directory.

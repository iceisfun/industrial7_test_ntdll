# rtl_query_set_b_env

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788), standard user and elevated administrator runs. Decompilation (Corpus Explorer, /api/function/ntdll/<Name>/decomp) was consulted for argument validation order; every value below was then confirmed by running on the Windows 10 guest.

## Exports covered (behavioral)
RtlSetCurrentDirectory_U, RtlSetEnvironmentVar, RtlSetCurrentEnvironment, RtlSetEnvironmentStrings,
RtlSetSearchPathMode, RtlSetThreadErrorMode.

## Where expectations come from
| Area | Evidence |
| --- | --- |
| RtlSetCurrentDirectory_U | Decompiled (full path, device-name check, open directory). Success verified via GetCurrentDirectoryW and RtlGetCurrentDirectory_U (no trailing backslash, byte length returned). Relative paths ("sub", "..") resolve against the current directory. Errors observed on Windows 10: missing directory STATUS_OBJECT_NAME_NOT_FOUND (c0000034), a file STATUS_NOT_A_DIRECTORY (c0000103), DOS device name "NUL" STATUS_NOT_A_DIRECTORY; the directory is unchanged after each failure. The original directory is restored. |
| RtlSetEnvironmentVar | Decompiled validation: name length 0 or first char NUL -> failure; embedded NUL or '=' (after the first character) in the name and embedded NUL in the value -> STATUS_INVALID_PARAMETER. Environment pointer NULL = process block (cross-checked with GetEnvironmentVariableW/SetEnvironmentVariableW); a private block from RtlCreateEnvironment is used for the add/replace/delete cases, verified with RtlQueryEnvironmentVariable_U (case-insensitive lookup, length-bounded names, empty values, delete via NULL value, STATUS_VARIABLE_NOT_FOUND c0000100, STATUS_BUFFER_TOO_SMALL with required length). Deleting an absent variable succeeds (observed). |
| RtlSetCurrentEnvironment | Decompiled: swaps the PEB process-parameters environment pointer and returns the old block through the second argument. Test installs an empty private block, checks visibility through GetEnvironmentVariableW, and swaps back (the block returned equals the one installed). |
| RtlSetEnvironmentStrings | Decompiled: copies the given block (byte length) into the current environment, reallocating when it is larger. Test saves the whole environment, replaces it with small and large blocks, and restores it. |
| RtlSetSearchPathMode | Decompiled flag logic: valid = ENABLE_SAFE (1) alone or DISABLE_SAFE (0x10000) alone, optionally with PERMANENT (0x8000, not used here as it cannot be undone); everything else STATUS_INVALID_PARAMETER. |
| RtlSetThreadErrorMode | Decompiled: bits other than 0x10/0x20/0x40 -> STATUS_INVALID_PARAMETER_1 (c00000ef) and old value untouched; old value pointer optional; value readable with RtlGetThreadErrorMode. |

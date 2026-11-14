# ETW user-mode helpers, NtTraceControl/NtTraceEvent, WNF update: Windows 10 contracts

Reference: Corpus Explorer (http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp, /asm), ntdll 10.0.19041.2788. The Nt/Zw trace and WNF exports are syscall
stubs; their status codes are observed on the Windows 10 22H2 guest (administrator, three runs). The standard-user guest
mode could not be exercised during this work (the guest launcher failed with "The user name or password is incorrect"
for every area), so the privilege-sensitive checks tolerate STATUS_ACCESS_DENIED by skipping on exactly that status.

| export | expectation | source |
|---|---|---|
| Zw aliases | NtTraceControl/ZwTraceControl, NtTraceEvent/ZwTraceEvent, NtUpdateWnfStateData/ZwUpdateWnfStateData share an address | corpus alias data (same entry RVA) |
| NtTraceControl | codes 0, 0x2c-0x2f and -1 -> STATUS_INVALID_DEVICE_REQUEST; 0xfff -> STATUS_INVALID_PARAMETER; codes 1-7 with a 64-byte zero input -> STATUS_INVALID_BUFFER_SIZE; codes 0x27, 0x2a, 0x2b succeed with ReturnLength 8, 4, 4 (64-byte zero input) | observed only |
| NtTraceEvent | invalid handle/flags combinations -> STATUS_INVALID_PARAMETER | observed only |
| EtwUnregisterTraceGuids | decompilation 0x50380: error from EtwNotificationUnregister, else frees the registration; 0/bogus handle and double unregister -> ERROR_INVALID_HANDLE (6), valid -> 0 | decompilation + guest |
| EtwTraceMessageVa | decompilation 0x506e0: kernel logger path returns the DOS error of NtTraceEvent; an unknown logger handle -> ERROR_INVALID_HANDLE | decompilation + guest |
| EtwWriteUMSecurityEvent | decompilation 0x7bf50: NULL guid -> 0x57; otherwise NtTraceEvent result mapped; non-security callers (even administrators) get ERROR_ACCESS_DENIED | decompilation + guest |
| EtwpGetCpuSpeed | decompilation 0x57400: reads ~MHz of HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0; test compares with RegGetValue; STATUS_OBJECT_NAME_NOT_FOUND skips | decompilation + guest |
| EtwpCreateEtwThread | decompilation 0x56020: RtlCreateUserThread(suspended) + NtResumeThread, returns the thread handle; start routine runs with the parameter | decompilation + guest |
| RtlWnfCompareChangeStamp | decompilation 0xde940: unsigned compare returning -1/0/1 | decompilation + guest |
| RtlWnfDllUnloadCallback | decompilation 0x85b60: finds the module by handle (STATUS_DLL_NOT_FOUND otherwise) and drops one load reference; the module unloads when the count reaches zero. Skips if no candidate DLL is free of earlier loads | decompilation + guest |
| NtUpdateWnfStateData | fresh temporary user-scope name: stamp 0, then each successful update increments the stamp and replaces the data; CheckStamp=1 with a stale MatchingChangeStamp -> STATUS_UNSUCCESSFUL; data > maximum size (0x1000 at creation) -> STATUS_INVALID_PARAMETER; length 0 with NULL buffer succeeds; non-zero length with NULL buffer or a NULL state name -> STATUS_ACCESS_VIOLATION (reported by the syscall, not raised); malformed name -> STATUS_INVALID_PARAMETER; deleted name -> STATUS_OBJECT_NAME_NOT_FOUND | observed only; state is created/deleted with NtCreateWnfStateName/NtDeleteWnfStateName and verified with NtQueryWnfStateData; skips if the name cannot be created |

Observed-only values (not documented): scope value 3 is rejected by NtCreateWnfStateName with STATUS_INVALID_PARAMETER, hence scope 2 (user) is used.

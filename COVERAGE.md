# Coverage

Which `ntdll.dll` exports the tests refer to, per area. The list is name-based: an export is listed under an area when the area's sources call it (directly, through a typed pointer, or through a table of names). It says nothing about how deeply the behaviour is verified. `export_surface` additionally checks the whole export table (names, ordinals, forwarders) of Windows 10 22H2 build 19045 without calling each function.

Reference: ntdll.dll 10.0.19041.2788, 2433 exports (2432 named). Exports referenced by at least one area: 550.

| Area | Exports referenced |
|---|---:|
| `core_smoke` | 1 |
| `crt_algorithms` | 22 |
| `crt_strings` | 34 |
| `export_surface` | 0 |
| `harness_checks` | 5 |
| `ldr_image` | 26 |
| `nt_file` | 29 |
| `nt_process` | 14 |
| `nt_registry` | 28 |
| `nt_sync` | 42 |
| `nt_thread` | 22 |
| `nt_token` | 25 |
| `nt_vm` | 17 |
| `rtl_bitmap` | 27 |
| `rtl_compression` | 8 |
| `rtl_context` | 29 |
| `rtl_conversion` | 17 |
| `rtl_environment` | 8 |
| `rtl_hash` | 8 |
| `rtl_heap` | 18 |
| `rtl_memory` | 14 |
| `rtl_netaddr` | 20 |
| `rtl_numeric` | 11 |
| `rtl_path` | 9 |
| `rtl_path_ext` | 20 |
| `rtl_security` | 51 |
| `rtl_slist` | 9 |
| `rtl_status` | 7 |
| `rtl_strings` | 24 |
| `rtl_strings_ext` | 22 |
| `rtl_sync` | 41 |
| `rtl_tables` | 42 |
| `rtl_threadpool` | 20 |
| `rtl_time` | 23 |

## core_smoke

`atoi`

## crt_algorithms

`bsearch`, `bsearch_s`, `isalnum`, `isalpha`, `iscntrl`, `isdigit`, `isgraph`, `islower`, `isprint`, `ispunct`, `isspace`, `isupper`, `isxdigit`, `memchr`, `memcmp`, `memcpy`, `memmove`, `memset`, `qsort`, `qsort_s`, `tolower`, `toupper`

## crt_strings

`_stricmp`, `_wcsicmp`, `strcat`, `strcat_s`, `strchr`, `strcmp`, `strcpy`, `strcpy_s`, `strcspn`, `strlen`, `strncat`, `strncmp`, `strncpy`, `strnlen`, `strpbrk`, `strrchr`, `strspn`, `strstr`, `wcscat`, `wcscat_s`, `wcschr`, `wcscmp`, `wcscpy`, `wcscpy_s`, `wcscspn`, `wcslen`, `wcsncat`, `wcsncmp`, `wcsncpy`, `wcsnlen`, `wcspbrk`, `wcsrchr`, `wcsspn`, `wcsstr`

## harness_checks

`NtClose`, `atoi`, `strcmp`, `strlen`, `strncmp`

## ldr_image

`LdrAddRefDll`, `LdrEnumerateLoadedModules`, `LdrFindEntryForAddress`, `LdrGetDllHandle`, `LdrGetDllHandleEx`, `LdrGetProcedureAddress`, `LdrGetProcedureAddressEx`, `LdrLoadDll`, `LdrLockLoaderLock`, `LdrUnloadDll`, `LdrUnlockLoaderLock`, `NtClose`, `RtlAllocateHeap`, `RtlImageDirectoryEntryToData`, `RtlImageNtHeader`, `RtlImageNtHeaderEx`, `RtlImageRvaToSection`, `RtlImageRvaToVa`, `RtlInitUnicodeString`, `RtlPcToFileHeader`, `_wcsnicmp`, `memmove`, `memset`, `strcmp`, `strcpy`, `strlen`

## nt_file

`NtCancelIoFile`, `NtClose`, `NtCreateFile`, `NtDeleteFile`, `NtDeviceIoControlFile`, `NtFlushBuffersFile`, `NtFsControlFile`, `NtLockFile`, `NtOpenFile`, `NtQueryAttributesFile`, `NtQueryDirectoryFile`, `NtQueryFullAttributesFile`, `NtQueryInformationFile`, `NtQueryVolumeInformationFile`, `NtReadFile`, `NtSetInformationFile`, `NtSetVolumeInformationFile`, `NtUnlockFile`, `NtWriteFile`, `RtlDosPathNameToNtPathName_U`, `RtlFreeUnicodeString`, `memcmp`, `memcpy`, `memset`, `strchr`, `strcpy`, `strlen`, `wcslen`, `wcsrchr`

## nt_process

`NtDuplicateObject`, `NtOpenProcess`, `NtOpenThread`, `NtQueryInformationProcess`, `NtQueryInformationThread`, `NtQueryObject`, `NtQuerySystemInformation`, `NtQuerySystemTime`, `_wcsnicmp`, `memcmp`, `memcpy`, `memset`, `strrchr`, `wcslen`

## nt_registry

`NtClose`, `NtCreateKey`, `NtDeleteKey`, `NtDeleteValueKey`, `NtEnumerateKey`, `NtEnumerateValueKey`, `NtFlushKey`, `NtNotifyChangeKey`, `NtOpenKey`, `NtQueryKey`, `NtQueryMultipleValueKey`, `NtQueryValueKey`, `NtSetValueKey`, `RtlCheckRegistryKey`, `RtlCreateRegistryKey`, `RtlDeleteRegistryValue`, `RtlFormatCurrentUserKeyPath`, `RtlFreeUnicodeString`, `RtlOpenCurrentUser`, `RtlQueryRegistryValues`, `RtlWriteRegistryValue`, `_wcsnicmp`, `memcmp`, `memcpy`, `memset`, `strlen`, `swprintf`, `wcslen`

## nt_sync

`NtAlertThread`, `NtCancelTimer`, `NtClearEvent`, `NtClose`, `NtCreateEvent`, `NtCreateKeyedEvent`, `NtCreateMutant`, `NtCreateSemaphore`, `NtCreateTimer`, `NtDelayExecution`, `NtDuplicateObject`, `NtOpenEvent`, `NtOpenMutant`, `NtOpenProcessToken`, `NtOpenSemaphore`, `NtOpenTimer`, `NtPulseEvent`, `NtQueryEvent`, `NtQueryInformationProcess`, `NtQueryMutant`, `NtQueryObject`, `NtQuerySemaphore`, `NtQueryTimer`, `NtQueueApcThread`, `NtReleaseKeyedEvent`, `NtReleaseMutant`, `NtReleaseSemaphore`, `NtResetEvent`, `NtSetEvent`, `NtSetInformationObject`, `NtSetTimer`, `NtSignalAndWaitForSingleObject`, `NtTestAlert`, `NtWaitForKeyedEvent`, `NtWaitForMultipleObjects`, `NtWaitForSingleObject`, `NtYieldExecution`, `_wcsnicmp`, `memcmp`, `memset`, `swprintf`, `wcslen`

## nt_thread

`NtClose`, `NtCreateThreadEx`, `NtGetContextThread`, `NtQueryInformationProcess`, `NtQueryInformationThread`, `NtResumeThread`, `NtSetContextThread`, `NtSetInformationThread`, `NtSuspendThread`, `NtTerminateThread`, `NtWaitForSingleObject`, `NtYieldExecution`, `RtlAcquirePebLock`, `RtlCreateUserThread`, `RtlExitUserThread`, `RtlGetCurrentProcessorNumber`, `RtlGetCurrentProcessorNumberEx`, `RtlGetNtGlobalFlags`, `RtlReleasePebLock`, `RtlSetThreadIsCritical`, `memcmp`, `memset`

## nt_token

`NtAccessCheck`, `NtAdjustPrivilegesToken`, `NtClose`, `NtDuplicateToken`, `NtFilterToken`, `NtOpenProcessToken`, `NtOpenThreadToken`, `NtQueryInformationToken`, `NtQuerySecurityObject`, `NtSetInformationToken`, `NtSetSecurityObject`, `RtlAddAccessAllowedAceEx`, `RtlAddAccessDeniedAceEx`, `RtlAdjustPrivilege`, `RtlCreateAcl`, `RtlCreateSecurityDescriptor`, `RtlGetDaclSecurityDescriptor`, `RtlGetOwnerSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlSetGroupSecurityDescriptor`, `RtlSetOwnerSecurityDescriptor`, `RtlValidSecurityDescriptor`, `memcmp`, `memcpy`, `memset`

## nt_vm

`NtAllocateVirtualMemory`, `NtClose`, `NtCreateSection`, `NtFlushVirtualMemory`, `NtFreeVirtualMemory`, `NtLockVirtualMemory`, `NtMapViewOfSection`, `NtProtectVirtualMemory`, `NtQuerySection`, `NtQueryVirtualMemory`, `NtReadVirtualMemory`, `NtUnlockVirtualMemory`, `NtUnmapViewOfSection`, `NtWriteVirtualMemory`, `memcmp`, `memcpy`, `memset`

## rtl_bitmap

`RtlAreBitsClear`, `RtlAreBitsSet`, `RtlClearAllBits`, `RtlClearBit`, `RtlClearBitEx`, `RtlClearBits`, `RtlFindClearBits`, `RtlFindClearBitsAndSet`, `RtlFindClearRuns`, `RtlFindLastBackwardRunClear`, `RtlFindLongestRunClear`, `RtlFindNextForwardRunClear`, `RtlFindSetBits`, `RtlFindSetBitsAndClear`, `RtlInitializeBitMap`, `RtlNumberOfClearBits`, `RtlNumberOfSetBits`, `RtlNumberOfSetBitsUlongPtr`, `RtlSetAllBits`, `RtlSetBit`, `RtlSetBitEx`, `RtlSetBits`, `RtlTestBit`, `RtlTestBitEx`, `memcmp`, `memcpy`, `memset`

## rtl_compression

`RtlCompressBuffer`, `RtlDecompressBuffer`, `RtlDecompressBufferEx`, `RtlDecompressFragment`, `RtlGetCompressionWorkSpaceSize`, `memcmp`, `memcpy`, `memset`

## rtl_context

`NtContinue`, `NtRaiseException`, `RtlAddFunctionTable`, `RtlAddVectoredContinueHandler`, `RtlAddVectoredExceptionHandler`, `RtlCaptureContext`, `RtlCaptureStackBackTrace`, `RtlDeleteFunctionTable`, `RtlGetEnabledExtendedFeatures`, `RtlGetExtendedContextLength`, `RtlGetExtendedFeaturesMask`, `RtlGetFunctionTableListHead`, `RtlInitializeExtendedContext`, `RtlInstallFunctionTableCallback`, `RtlLocateExtendedFeature`, `RtlLocateLegacyContext`, `RtlLookupFunctionEntry`, `RtlPcToFileHeader`, `RtlRaiseException`, `RtlRaiseStatus`, `RtlRemoveVectoredContinueHandler`, `RtlRemoveVectoredExceptionHandler`, `RtlRestoreContext`, `RtlSetExtendedFeaturesMask`, `RtlUnwindEx`, `RtlVirtualUnwind`, `atoi`, `memset`, `strcmp`

## rtl_conversion

`RtlAnsiStringToUnicodeString`, `RtlFreeAnsiString`, `RtlFreeOemString`, `RtlFreeUnicodeString`, `RtlMultiByteToUnicodeN`, `RtlMultiByteToUnicodeSize`, `RtlOemStringToUnicodeString`, `RtlOemToUnicodeN`, `RtlUTF8ToUnicodeN`, `RtlUnicodeStringToAnsiString`, `RtlUnicodeStringToOemString`, `RtlUnicodeToMultiByteN`, `RtlUnicodeToMultiByteSize`, `RtlUnicodeToOemN`, `RtlUnicodeToUTF8N`, `memcmp`, `memset`

## rtl_environment

`RtlCreateEnvironment`, `RtlDestroyEnvironment`, `RtlExpandEnvironmentStrings_U`, `RtlQueryEnvironmentVariable_U`, `RtlSetEnvironmentVariable`, `memcmp`, `memset`, `wcslen`

## rtl_hash

`RtlComputeCrc32`, `RtlCrc32`, `RtlCrc64`, `RtlRandom`, `RtlRandomEx`, `RtlUniform`, `memcmp`, `memcpy`

## rtl_heap

`RtlAllocateHeap`, `RtlCompactHeap`, `RtlCreateHeap`, `RtlDestroyHeap`, `RtlFreeHeap`, `RtlGetNtGlobalFlags`, `RtlGetProcessHeaps`, `RtlLockHeap`, `RtlQueryHeapInformation`, `RtlReAllocateHeap`, `RtlSetHeapInformation`, `RtlSizeHeap`, `RtlUnlockHeap`, `RtlValidateHeap`, `RtlValidateProcessHeaps`, `RtlWalkHeap`, `memcpy`, `memset`

## rtl_memory

`RtlCompareMemory`, `RtlCompareMemoryUlong`, `RtlCopyMemoryNonTemporal`, `RtlDecodePointer`, `RtlEncodePointer`, `RtlFillMemory`, `RtlMoveMemory`, `RtlRunDecodeUnicodeString`, `RtlRunEncodeUnicodeString`, `RtlZeroMemory`, `memcmp`, `memcpy`, `memmove`, `memset`

## rtl_netaddr

`RtlIpv4AddressToStringA`, `RtlIpv4AddressToStringExA`, `RtlIpv4AddressToStringExW`, `RtlIpv4AddressToStringW`, `RtlIpv4StringToAddressA`, `RtlIpv4StringToAddressExA`, `RtlIpv4StringToAddressExW`, `RtlIpv4StringToAddressW`, `RtlIpv6AddressToStringA`, `RtlIpv6AddressToStringExA`, `RtlIpv6AddressToStringExW`, `RtlIpv6AddressToStringW`, `RtlIpv6StringToAddressA`, `RtlIpv6StringToAddressExA`, `RtlIpv6StringToAddressExW`, `RtlIpv6StringToAddressW`, `memcmp`, `memset`, `strcmp`, `strlen`

## rtl_numeric

`RtlCharToInteger`, `RtlIntegerToChar`, `RtlIntegerToUnicodeString`, `RtlLargeIntegerToChar`, `RtlUnicodeStringToInteger`, `abs`, `labs`, `memcmp`, `memcpy`, `memset`, `strlen`

## rtl_path

`RtlDetermineDosPathNameType_U`, `RtlDosPathNameToNtPathName_U`, `RtlDosPathNameToNtPathName_U_WithStatus`, `RtlFreeUnicodeString`, `RtlGetCurrentDirectory_U`, `RtlGetFullPathName_U`, `RtlIsDosDeviceName_U`, `memcmp`, `memset`

## rtl_path_ext

`RtlDoesFileExists_U`, `RtlDosPathNameToNtPathName_U`, `RtlDosPathNameToRelativeNtPathName_U`, `RtlDosPathNameToRelativeNtPathName_U_WithStatus`, `RtlDosSearchPath_U`, `RtlFreeUnicodeString`, `RtlGenerate8dot3Name`, `RtlGetCurrentDirectory_U`, `RtlGetFullPathName_U`, `RtlGetFullPathName_UEx`, `RtlGetLongestNtPathLength`, `RtlIsNameLegalDOS8Dot3`, `RtlReleaseRelativeName`, `RtlSetCurrentDirectory_U`, `_wcsnicmp`, `abs`, `memcmp`, `memcpy`, `memset`, `wcschr`

## rtl_security

`RtlAbsoluteToSelfRelativeSD`, `RtlAddAccessAllowedAce`, `RtlAddAccessAllowedAceEx`, `RtlAddAccessDeniedAce`, `RtlAddAccessDeniedAceEx`, `RtlAddAce`, `RtlAddAuditAccessAce`, `RtlAllocateAndInitializeSid`, `RtlAreAllAccessesGranted`, `RtlAreAnyAccessesGranted`, `RtlConvertSidToUnicodeString`, `RtlCopyLuid`, `RtlCopySid`, `RtlCreateAcl`, `RtlCreateSecurityDescriptor`, `RtlCreateServiceSid`, `RtlDeleteAce`, `RtlEqualPrefixSid`, `RtlEqualSid`, `RtlFirstFreeAce`, `RtlFreeSid`, `RtlFreeUnicodeString`, `RtlGetAce`, `RtlGetControlSecurityDescriptor`, `RtlGetDaclSecurityDescriptor`, `RtlGetGroupSecurityDescriptor`, `RtlGetOwnerSecurityDescriptor`, `RtlGetSaclSecurityDescriptor`, `RtlIdentifierAuthoritySid`, `RtlInitializeSid`, `RtlLengthRequiredSid`, `RtlLengthSecurityDescriptor`, `RtlLengthSid`, `RtlMapGenericMask`, `RtlQueryInformationAcl`, `RtlSelfRelativeToAbsoluteSD`, `RtlSetControlSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlSetGroupSecurityDescriptor`, `RtlSetInformationAcl`, `RtlSetOwnerSecurityDescriptor`, `RtlSetSaclSecurityDescriptor`, `RtlSubAuthorityCountSid`, `RtlSubAuthoritySid`, `RtlValidAcl`, `RtlValidSecurityDescriptor`, `RtlValidSid`, `abs`, `memcmp`, `memcpy`, `memset`

## rtl_slist

`RtlFirstEntrySList`, `RtlInitializeSListHead`, `RtlInterlockedFlushSList`, `RtlInterlockedPopEntrySList`, `RtlInterlockedPushEntrySList`, `RtlInterlockedPushListSList`, `RtlInterlockedPushListSListEx`, `RtlQueryDepthSList`, `memset`

## rtl_status

`RtlGetLastNtStatus`, `RtlGetLastWin32Error`, `RtlNtStatusToDosError`, `RtlNtStatusToDosErrorNoTeb`, `RtlRestoreLastWin32Error`, `RtlSetLastWin32Error`, `RtlSetLastWin32ErrorAndNtStatusFromNtStatus`

## rtl_strings

`RtlAppendStringToString`, `RtlAppendUnicodeStringToString`, `RtlAppendUnicodeToString`, `RtlCompareString`, `RtlCompareUnicodeString`, `RtlCopyString`, `RtlCopyUnicodeString`, `RtlDowncaseUnicodeChar`, `RtlDuplicateUnicodeString`, `RtlEqualString`, `RtlEqualUnicodeString`, `RtlFindCharInUnicodeString`, `RtlFreeUnicodeString`, `RtlHashUnicodeString`, `RtlInitAnsiString`, `RtlInitUnicodeString`, `RtlInitUnicodeStringEx`, `RtlPrefixString`, `RtlPrefixUnicodeString`, `RtlUpcaseUnicodeChar`, `RtlUpcaseUnicodeString`, `memcmp`, `memset`, `wcslen`

## rtl_strings_ext

`RtlAppendAsciizToString`, `RtlCompareUnicodeStrings`, `RtlCreateUnicodeString`, `RtlCreateUnicodeStringFromAsciiz`, `RtlDowncaseUnicodeString`, `RtlFreeAnsiString`, `RtlFreeUnicodeString`, `RtlGUIDFromString`, `RtlInitAnsiStringEx`, `RtlInt64ToUnicodeString`, `RtlIsNormalizedString`, `RtlIsTextUnicode`, `RtlNormalizeString`, `RtlStringFromGUID`, `RtlUpcaseUnicodeStringToAnsiString`, `RtlUpcaseUnicodeToMultiByteN`, `RtlUpperString`, `RtlValidateUnicodeString`, `RtlxAnsiStringToUnicodeSize`, `RtlxUnicodeStringToAnsiSize`, `memcmp`, `memset`

## rtl_sync

`RtlAcquireSRWLockExclusive`, `RtlAcquireSRWLockShared`, `RtlCreateTimer`, `RtlCreateTimerQueue`, `RtlDeleteCriticalSection`, `RtlDeleteTimer`, `RtlDeleteTimerQueueEx`, `RtlDeregisterWait`, `RtlDeregisterWaitEx`, `RtlEnterCriticalSection`, `RtlInitializeConditionVariable`, `RtlInitializeCriticalSection`, `RtlInitializeCriticalSectionAndSpinCount`, `RtlInitializeCriticalSectionEx`, `RtlInitializeSRWLock`, `RtlIsCriticalSectionLocked`, `RtlIsCriticalSectionLockedByThread`, `RtlLeaveCriticalSection`, `RtlQueueWorkItem`, `RtlRegisterWait`, `RtlReleaseSRWLockExclusive`, `RtlReleaseSRWLockShared`, `RtlRunOnceBeginInitialize`, `RtlRunOnceComplete`, `RtlRunOnceExecuteOnce`, `RtlRunOnceInitialize`, `RtlSetCriticalSectionSpinCount`, `RtlSleepConditionVariableCS`, `RtlSleepConditionVariableSRW`, `RtlTryAcquireSRWLockExclusive`, `RtlTryAcquireSRWLockShared`, `RtlTryEnterCriticalSection`, `RtlUpdateTimer`, `RtlWaitOnAddress`, `RtlWakeAddressAll`, `RtlWakeAddressSingle`, `RtlWakeAllConditionVariable`, `RtlWakeConditionVariable`, `atoi`, `memcmp`, `memset`

## rtl_tables

`NtAddAtom`, `NtDeleteAtom`, `NtFindAtom`, `NtQueryInformationAtom`, `RtlAddAtomToAtomTable`, `RtlCreateAtomTable`, `RtlDelete`, `RtlDeleteAtomFromAtomTable`, `RtlDeleteElementGenericTable`, `RtlDeleteElementGenericTableAvl`, `RtlDeleteNoSplay`, `RtlDestroyAtomTable`, `RtlEmptyAtomTable`, `RtlEnumerateGenericTable`, `RtlEnumerateGenericTableAvl`, `RtlEnumerateGenericTableWithoutSplaying`, `RtlEnumerateGenericTableWithoutSplayingAvl`, `RtlGetElementGenericTable`, `RtlGetElementGenericTableAvl`, `RtlInitializeGenericTable`, `RtlInitializeGenericTableAvl`, `RtlInsertElementGenericTable`, `RtlInsertElementGenericTableFull`, `RtlInsertElementGenericTableFullAvl`, `RtlIsGenericTableEmpty`, `RtlIsGenericTableEmptyAvl`, `RtlLookupAtomInAtomTable`, `RtlLookupElementGenericTable`, `RtlLookupElementGenericTableFull`, `RtlLookupElementGenericTableFullAvl`, `RtlNumberGenericTableElements`, `RtlNumberGenericTableElementsAvl`, `RtlPinAtomInAtomTable`, `RtlQueryAtomInAtomTable`, `RtlRealPredecessor`, `RtlRealSuccessor`, `RtlSplay`, `RtlSubtreePredecessor`, `RtlSubtreeSuccessor`, `memcmp`, `memcpy`, `memset`

## rtl_threadpool

`TpAllocPool`, `TpAllocTimer`, `TpAllocWait`, `TpAllocWork`, `TpCallbackSetEventOnCompletion`, `TpIsTimerSet`, `TpPostWork`, `TpReleasePool`, `TpReleaseTimer`, `TpReleaseWait`, `TpReleaseWork`, `TpSetPoolMaxThreads`, `TpSetTimer`, `TpSetWait`, `TpSimpleTryPost`, `TpWaitForTimer`, `TpWaitForWait`, `TpWaitForWork`, `atoi`, `memset`

## rtl_time

`NtQueryPerformanceCounter`, `NtQuerySystemTime`, `NtQueryTimerResolution`, `NtSetTimerResolution`, `RtlGetCurrentProcessorNumber`, `RtlGetNtProductType`, `RtlGetSystemTimePrecise`, `RtlGetVersion`, `RtlLocalTimeToSystemTime`, `RtlQueryPerformanceCounter`, `RtlQueryPerformanceFrequency`, `RtlQueryTimeZoneInformation`, `RtlQueryUnbiasedInterruptTime`, `RtlSecondsSince1970ToTime`, `RtlSecondsSince1980ToTime`, `RtlSystemTimeToLocalTime`, `RtlTimeFieldsToTime`, `RtlTimeToElapsedTimeFields`, `RtlTimeToSecondsSince1970`, `RtlTimeToSecondsSince1980`, `RtlTimeToTimeFields`, `memcmp`, `memset`

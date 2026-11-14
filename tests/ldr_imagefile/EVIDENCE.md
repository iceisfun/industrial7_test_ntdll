# ldr_imagefile evidence

Oracle: Windows 10 22H2, ntdll 10.0.19041.2788 in the local guest; decompilation at
`http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp`. Fixture DLL: see ldr_resource/EVIDENCE.md.

## Image file execution options
| Export | Source | Expectation |
| --- | --- | --- |
| LdrQueryImageFileKeyOption | decomp 0x7a4a0 | on a throwaway HKCU key (any registry key handle works). DWORD: requested type 4 or 0, buffer exactly 4 bytes (0xC0000004 otherwise), length output optional; QWORD exact 8; REG_SZ copied with its terminator, too small buffer or size query returns 0x80000005 with the required length; REG_SZ read as DWORD is parsed (decimal "42", hex "0x10") and needs a 4-byte buffer; BINARY copied, requested type must match; type mismatch and unsupported stored types (EXPAND_SZ) 0xC0000024; missing value 0xC0000034. Value name lookup is case-insensitive. |
| LdrOpenImageFileOptionsKey | decomp 0xe1a40 | handle to the `Image File Execution Options\<leaf>` key of the image; missing key 0xC0000034; the BOOLEAN second argument has no effect on a 64-bit process |
| LdrQueryImageFileExecutionOptions / Ex | decomp 0x7a3c0 / 0x7a400 | unknown image 0xC0000034 and output untouched; NULL image name queries the options root; with an administrator token a throwaway key under HKLM is created and removed: full path and bare file name both locate it, DWORD/REG_SZ values and the length output are as above, missing value 0xC0000034. Standard users skip the round trip (HKLM write gives ERROR_ACCESS_DENIED). |

## Checksums
| Export | Source | Expectation |
| --- | --- | --- |
| LdrVerifyImageMatchesChecksum / Ex | decomp 0xce790 / 0x8ab90 | file handle needs read+execute access (image section): read-only access gives 0xC0000022. Correct checksum 0 (+Characteristics out, 0x2022 for the fixture); wrong checksum or modified data 0xC0000221 with the output untouched; checksum field 0 means "not computed" and passes (observed); NULL handle 0xC00000F2, pseudo handle 0xC0000024, closed/garbage handle 0xC0000008. Ex block: Size must be 0x40 and flags within 7 (0xC00000F0 otherwise, before any file access); with flag 1 the callback is called per import descriptor (kernel32.dll: ntdll.dll is among its imports). |

## Relocations
| Export | Source | Expectation |
| --- | --- | --- |
| LdrProcessRelocationBlock / Ex | decomp 0xe3b50 / 0xe3ba0 | page address, entry count, entry array, delta; returns the pointer after the processed entries. HIGHLOW (3) and DIR64 (10) add the full delta, HIGH (1) the high word, LOW (2) the low word, ABSOLUTE (0) is skipped; types 5-9/11-15 are not valid for x64 and return NULL; zero entries return the start; negative deltas wrap. Ex adds the machine: 0x8664 as above; ARM/Thumb machines do not change HIGHLOW (0x14c). |

## Delay load
| Export | Source | Expectation |
| --- | --- | --- |
| LdrQueryOptionalDelayLoadedAPI / LdrResolveDelayLoadsFromDll | decomp 0xce9d0 / 0xcea90 | flags must be 0 (0xC000000D); a module without a delay-load table (ntdll) gives 0xC0000135 |
| LdrResolveDelayLoadedAPI | decomp 0x10380 | unsupported flag bits return NULL without touching the IAT slot |

## MUI alternate resources and data export
| Export | Source | Expectation |
| --- | --- | --- |
| LdrUnloadAlternateResourceModuleEx / LdrUnloadAlternateResourceModule | decomp 0x6a7e0 / 0x6a7d0 | after a flush (empty cache) NULL module returns FALSE and a loaded module TRUE |
| LdrLoadAlternateResourceModule / Ex | decomp 0x7db10 / 0x34ea0 | NULL module, zero language (Ex) or NULL output give 0xC000000D; a module with no .mui file fails: LdrLoadAlternateResourceModule 0xC000003A, the Ex form 0xC00B0006 (observed on the guest); the Ex output stays NULL |
| LdrSystemDllInitBlock | exported data | address inside ntdll; first ULONG (PS_SYSTEM_DLL_INIT_BLOCK.Size) is plausible (0xF0 on this build, only the 0x20..0x400 range is asserted) |

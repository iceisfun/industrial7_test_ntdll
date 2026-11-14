# ldr_resource evidence

Oracle: Windows 10 22H2, ntdll 10.0.19041.2788, run in the local guest in both elevated and
standard-user mode. Decompilation (`http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/<Name>/decomp`) was used to find argument validation order
and status codes; every value below was then confirmed on the guest. Public docs do not describe
these native routines (`/docs` returned no contract), so nothing here is taken from documentation.

## Fixture

`pebuild.h` writes a code-free PE32+ DLL (no imports, entry point 0, one `.rsrc` section) into the
per-process scratch directory, with a hand-assembled resource tree, so every expected directory
count, language, size, data string and data-entry code page is known by construction:

| type / name / language | data |
| --- | --- |
| 10 / 1 / 0x409 | `data-1-409` (11 bytes) |
| 10 / 1 / 0x407 | `data-1-407` |
| 10 / 2 / 0 | `data-2-neutral` (15 bytes) |
| 23 / 7 / 0x409 | `<html/>` (8 bytes) |
| "CUSTOM" / "MYRES" / 0x409 | `named-res` (10 bytes) |
| "MUI" / 1 / 0 | 0xA4-byte resource-config block |

The "MUI" block is a valid resource configuration (signature 0xFECDFECD, size, version 0x10000, valid
attribute bits) whose main-file type lists contain every type present, so lookups stay in this file.
An earlier variant whose lists were empty made every type lookup fail with 0xC000008A, which is how
the externalised-resource contract was found.
The checksum field is the standard PE checksum so the file also loads without complaint.

The same file is mapped three ways: LoadLibrary (image), LOAD_LIBRARY_AS_DATAFILE (low bit tagged
handle, flat file mapping) and LOAD_LIBRARY_AS_IMAGE_RESOURCE. Results are identical for the
find/access/directory/enumeration APIs in all three.

## Contracts

| Export | Decompilation | Expectation (all observed on Windows 10) |
| --- | --- | --- |
| LdrFindResource_U | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrFindResource_U/decomp` (0x70690) forwards to `LdrpSearchResourceSection_U` with flags 0 | level must be 3: other levels give 0xC00000F1 (invalid parameter 3). Hit: 0 with the `IMAGE_RESOURCE_DATA_ENTRY` (Size, CodePage match the tree). Language not present (0x809, neutral-only 0x9): 0xC0000204. Name missing 0xC000008B, type missing 0xC000008A. Language 0 on a multi-language name selects one existing language. A name that only has the neutral language still resolves for 0x409. NULL base: 0xC0000089. Named types/names are matched against the stored (upper-case) string. |
| LdrFindResourceEx_U | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrFindResourceEx_U/decomp` (0x80fe0) same worker, flags first | flags 0 equals LdrFindResource_U (same entry pointer); same error codes |
| LdrFindResourceDirectory_U | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrFindResourceDirectory_U/decomp` (0xe0f90) worker with flag 2 | levels 0/1/2 return the root, type and name directories (entry counts from the fixture, addresses strictly increasing); missing type/name give the same 0xC000008A/B |
| LdrAccessResource | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrAccessResource/decomp` (0x207a0) | out pointer/size give the stored bytes; for a data-file mapping the RVA is converted through the section table |
| LdrEnumResources | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrEnumResources/decomp` (0xe0cc0) | capacity in / count out. Too small (incl. NULL buffer): 0xC0000004 with the total count. Entries are {type, name, language, data, size, reserved} (0x28 bytes) in directory order: named entries first, then ids ascending; named type/name fields point at the `IMAGE_RESOURCE_DIR_STRING_U`. Levels 1/2/3 filter by type/name/language (3/2/1 entries here); no match returns 0 with count 0. A module without a resource directory returns 0xC0000089. Data addresses are only dereferenced for the image mapping (the enumerator reports base+RVA). |
| LdrResFindResource | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrResFindResource/decomp` (0xe4060) | flags with bits 0x2/0x400/0x800: 0xC000000D; flag 0x1: 0xC00000F1; NULL base 0xC000000D; a config buffer without a size is 0xC000000D. Success returns data pointer and size consistent with LdrAccessResource |
| LdrResFindResourceDirectory | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrResFindResourceDirectory/decomp` (0x48af0) | type or type+name directories; neither given: 0xC000000D; flags 0x400/0x800: 0xC000000D |
| LdrResSearchResource | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrResSearchResource/decomp` (0x48b80) | NULL base/path/bad level, config without size: parameter errors; level 9 and 1 give 0xC00000F1, flag bits above 0x7FFFF give 0xC00000F2 |
| LdrResGetRCConfig | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrResGetRCConfig/decomp` (0x4b370) | NULL module 0xC000000D; flag 0x2000 returns the MUI block unvalidated; flags 0 validates it and returns the same block (signature 0xFECDFECD, size, version) |
| LdrRscIsTypeExist | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrRscIsTypeExist/decomp` (0x34c60) | operates on an in-memory config block: ORs 0x40000 when the type is missing from the main list and 0x20000 when missing from the MUI list (ids at +0x5c/+0x60 and +0x6c/+0x70, names at +0x54/+0x58 and +0x64/+0x68, case-insensitive); existing bits are preserved; NULL config or flags pointer 0xC000000D |
| LdrResRelease | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrResRelease/decomp` (0x89f00) | NULL base 0xC000000D; a data-file mapping with nothing cached returns 0 |
| LdrpResGetMappingSize | `http://docker1.dev.moonlightcompanies.com:8765/api/function/ntdll/LdrpResGetMappingSize/decomp` (0x4ac40) | for ntdll equals SizeOfImage; NULL base or size pointer 0xC000000D |
| LdrAddLoadAsDataTable / LdrRemoveLoadAsDataTable / LdrGetFileNameFromLoadAsDataTable | decomp 0x73110 / 0x738d0 / 0xe0fb0 | LoadLibraryEx(AS_DATAFILE) registers the mapping and its path. Lookup of an unknown handle or the untagged base gives 0xC0000001; NULL arguments 0xC000000D. Remove: 0, then lookup 0xC0000001, remove again 0xC0000139. Add stores its own copy of the path. |

## Notes
* The first LdrResFindResource lookup on a fresh mapping validates the MUI block (it succeeds because the
  fixture block satisfies the validator; with an invalid block the first call returned 0xC00B0003 and later
  calls succeeded from a cached result, which is why the block is built to be valid).
* Windows 10 tolerates the first/other calls in either elevated or standard mode; no privilege is needed.

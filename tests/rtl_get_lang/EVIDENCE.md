# RTL language/MUI getters: Windows 10 contracts

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788) with the en-US language; decompilation from the corpus
explorer for validation order, the guest run for the values. Locale-dependent data is compared with the
documented kernel32 wrappers instead of being hard-coded where possible.

| Export (RVA) | Contract asserted | Source |
| --- | --- | --- |
| RtlGetUserPreferredUILanguages (0x7c0b0), RtlGetSystemPreferredUILanguages (0x75fa0) | `(Flags, Locale, &Count, Buffer, &Size)`: size query with NULL buffer returns 0 and the size in WCHARs including both terminating NULs; exact buffer returns the same multi-string and count; one char short: 0xC0000023 and the needed size; MUI_LANGUAGE_ID gives 4-digit entries and the same count; NAME\|ID or reserved flag bits: 0xC000000D; identical to kernel32 Get*PreferredUILanguages | decomp, observed. A NULL count or size pointer dereferences NULL (access violation) and is not tested |
| RtlGetProcessPreferredUILanguages (0x8a540) | same shape without the locale parameter; flags 0 means NAME; NULL count, NULL size, NULL buffer with nonzero size: 0xC000000D; the count is not written when the process list is empty (two NULs, size 2) | decomp, observed |
| RtlGetThreadPreferredUILanguages (0x35ca0) | same; NULL count is accepted (0), NULL size is invalid; after SetThreadPreferredUILanguages the thread list is returned first (merged with fallbacks en-US, en, en-GB in NAME mode) | decomp, observed |
| RtlGetThreadLangIdByIndex (0xeef20) | `(0, Index, &LangId, &Total)`: ids and total from the thread list; out-of-range index 0xC0000225 with id 0; nonzero first arg or NULL id 0xC000000D | decomp, observed |
| RtlGetUILanguageInfo (0xeeff0) | en-US: status 0, attribute bits 0x61 (full, installed, licensed; kernel32 reports the same bits), empty fallback list; id form `0409` identical; empty/NULL list, NAME\|ID or a nonzero buffer size with NULL buffer: 0xC000000D; a 1-char fallback buffer: 0xC0000023 | decomp, observed |
| RtlGetParentLocaleName (0x3c490) | en-US -> en, de-DE -> de, fr-CA -> fr, pt-BR -> pt (equal to GetLocaleInfoEx LOCALE_SPARENT); unknown or NULL name 0xC00000EF; NULL/no-buffer output string 0xC00000F0; flag bits outside 0x6: 0xC00000F1; too small output 0xC0000023 | decomp, observed |
| RtlGetFileMUIPath | for kernel32.dll with the user language: language `en-US`, path `...\en-US\kernel32.dll.mui` that exists, equal to kernel32 GetFileMUIPath; lengths are only rewritten when a buffer is too small, and then the status is still 0 with the required size (observed); NULL file name or reserved flags 0xC000000D. The enumerator argument is stateful and is reset before every call | decomp, observed |

Skips: if the MUI file for kernel32 cannot be resolved (non en-US image) the content checks are skipped.

Review additions (observed): RtlGetParentLocaleName into a 1-char output and RtlGetUILanguageInfo with a 1-char fallback buffer both return STATUS_BUFFER_TOO_SMALL (0xC0000023); the latter reports the required length 2.

# rtl_rest_crt_other_3_a_crt: CRT-style exports

Oracle: Windows 10 22H2 (ntdll 10.0.19041.2788). Contract sources are the public C runtime
documentation for the matching functions, the decompilation of the Windows 10 ntdll bodies
(argument validation order, folding rules, exact-fit rules) and results observed on the Windows 10
guest, listed per row. Run in both administrator and standard-user mode (no privileged operation).

## Safety rule used throughout

The bounded `_s` functions and several others end in an internal invalid-parameter routine that
captures a context, prints a debug message and does not return. No test passes arguments that reach
it (NULL buffer with nonzero size, buffer too small, bad radix, NULL format). Only success paths,
exact-fit buffers and the documented non-reporting edge cases (truncation with a count limit or
`_TRUNCATE`, zero count with NULL buffer) are asserted.

## Exports and expected values

| Export(s) | Expectation | Source |
| --- | --- | --- |
| `_itoa`, `_ltoa`, `_itoa_s`, `_ltoa_s` | radix 2..36 lower-case digits; negative sign only for radix 10; other radices print the two's-complement 32-bit value; `_itoa`/`_ltoa` and `_itoa_s`/`_ltoa_s` are the same function (identical address) | decomp (shared body, `xtoa`/`xtoa_s`); observed |
| `_i64toa`, `_ui64toa`, `_i64toa_s`, `_ui64toa_s` | 64-bit variants, same rules; `_ui64toa(~0,10)` is `18446744073709551615` | decomp, observed |
| `_itow`, `_ltow`, `_i64tow`, `_ui64tow` and `_s` forms | wide results identical to the narrow ones; `_itow`/`_ltow` share an address | observed |
| `_s` conversions | succeed with a buffer of exactly strlen+1 characters and return 0; the unused tail is not written | decomp `xtoa_s` |
| `_atoi64` | leading whitespace, optional sign, stops at first non-digit, empty or non-numeric gives 0, NULL gives 0 | decomp (NULL check then `_strtoi64`), docs |
| `_errno` | returns the address of a per-thread int stored in the TEB (offset 0x1500); differs between threads | decomp |
| `__isascii`, `__toascii`, `__iscsym`, `__iscsymf` | exact C-locale results over 0..127; `__isascii` false and `__toascii` masks with 0x7f for 128..255 | docs; decomp (ctype table plus `_`) |
| `_lfind` | linear search returning first match, NULL if none; element count is not modified; empty table with NULL base returns NULL | decomp |
| `_memccpy` | stops after copying the first byte equal to the low 8 bits of the value; returns pointer past it, NULL if not found within count | decomp |
| `_memicmp`, `_strcmpi`, `_strnicmp` | ASCII letters folded to lower case before the compare (so `_` sorts below `A`), count limits, zero count returns 0 | decomp of `__ascii_memicmp`, `__ascii_strnicmp` |
| `_strlwr`, `_strupr`, `_strlwr_s`, `_strupr_s` | A-Z / a-z only in the `_s` forms (bytes at or above 0x80 untouched); exact-fit size accepted | decomp |
| `_strset_s`, `_strnset_s` | fill existing characters (low byte of the value) keeping the terminator; `_strnset_s` honours count; NULL buffer with size 0 and count 0 returns 0 | decomp |
| `_makepath_s` | `drive` gets a colon appended if missing, directory gets a backslash unless it ends with `/` or `\`, extension gets a dot unless it starts with one; exact-size buffer accepted | decomp |
| `_splitpath`, `_splitpath_s` | drive including colon, directory including trailing separator, name up to the last dot, extension from the last dot; NULL outputs skipped; exact-size buffers accepted | decomp |
| `_snprintf` | returns the length written; count equal to the output length returns that length without a terminator; truncation returns -1 and no terminator | CRT docs, observed |
| `_snprintf_s`, `_snwprintf_s` | with `_TRUNCATE` or a count below the output length, truncation returns -1 and the buffer is terminated; `(NULL, 0, 0)` returns 0 | decomp of `_vsnprintf_s`, observed |
| `_snwprintf`, `_swprintf` | wide equivalents (`%ls` strings) | observed |
| `_snscanf_s`, `_snwscanf_s` | field count, count limiting the input, 0 on matching failure; empty input is -1 (narrow) and 0 (wide, observed) | observed |
| `_setjmp`, `_setjmpex` | return 0; save frame (second argument), stack pointer near the caller, return address inside the caller image, MXCSR and x87 control word | decomp (jump buffer layout) |
| `__chkstk` | custom calling convention: probes the pages for the frame size in rax, leaves rsp and rax unchanged | disassembly and observed |

Floating-point conversions are deliberately not exercised: `%f` was observed not to format a double on Windows 10 ntdll.

## Not covered (see the report)

`_local_unwind`, `__C_specific_handler`, `__misaligned_access` (compiler/unwinder-internal, need
generated unwind data or are intrinsics), `_fltused` (data symbol constant).

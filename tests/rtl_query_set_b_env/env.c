/* Current directory, environment block, search-path mode and error-mode setters. */
#include "t.h"
#include <stdlib.h>
#include <wchar.h>

UDECL(NTSTATUS, RtlSetCurrentDirectory_U, (PUNICODE_STRING));
UDECL(ULONG, RtlGetCurrentDirectory_U, (ULONG, PWSTR));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));
UDECL(NTSTATUS, RtlSetEnvironmentVar, (PWSTR *, PWSTR, SIZE_T, PWSTR, SIZE_T));
UDECL(NTSTATUS, RtlQueryEnvironmentVariable_U, (PWSTR, PUNICODE_STRING, PUNICODE_STRING));
UDECL(NTSTATUS, RtlCreateEnvironment, (BOOLEAN, PWSTR *));
UDECL(NTSTATUS, RtlDestroyEnvironment, (PWSTR));
UDECL(NTSTATUS, RtlSetCurrentEnvironment, (PWSTR, PWSTR *));
UDECL(NTSTATUS, RtlSetEnvironmentStrings, (PWCHAR, SIZE_T));
UDECL(NTSTATUS, RtlSetSearchPathMode, (ULONG));
UDECL(NTSTATUS, RtlSetThreadErrorMode, (ULONG, PULONG));
UDECL(ULONG, RtlGetThreadErrorMode, (void));

#define S(x) ((NTSTATUS)(x))
#define ST_INVPARAM S(0xC000000D)
#define ST_NOTFOUND S(0xC0000034)

static void wstr(UNICODE_STRING *u, const WCHAR *s) { UN(RtlInitUnicodeString)(u, s); }

/* ---- current directory ---- */
static void cur_dir(WCHAR *out, size_t cap) { DWORD n = GetCurrentDirectoryW((DWORD)cap, out); if (!n) out[0] = 0; }

TEST(rtl_set_current_directory_u) {
    REQUIRE(UN(RtlSetCurrentDirectory_U)); REQUIRE(UN(RtlInitUnicodeString)); REQUIRE(UN(RtlGetCurrentDirectory_U));
    WCHAR orig[MAX_PATH], now[MAX_PATH], dir[MAX_PATH], sub[MAX_PATH], buf[MAX_PATH];
    cur_dir(orig, MAX_PATH);
    MultiByteToWideChar(CP_ACP, 0, t_tmpdir(), -1, dir, MAX_PATH);
    UNICODE_STRING u;
    wstr(&u, dir);                              /* ends with a backslash */
    EXPECT_EQ(UN(RtlSetCurrentDirectory_U)(&u), 0);
    cur_dir(now, MAX_PATH);
    /* Win32 and Rtl views agree; the Win32 form has a trailing backslash only for drive roots */
    size_t dl = wcslen(dir); while (dl > 3 && dir[dl - 1] == L'\\') dir[--dl] = 0;
    CHECKF(!_wcsicmp(now, dir), "now=%ls dir=%ls", now, dir);
    ULONG n = UN(RtlGetCurrentDirectory_U)(sizeof buf, buf);
    EXPECT_EQ(n, wcslen(dir) * 2); CHECK(!_wcsicmp(buf, dir));
    /* relative path resolves against the new current directory */
    swprintf(sub, MAX_PATH, L"%ls\\rcd_sub", dir);
    CreateDirectoryW(sub, NULL);
    wstr(&u, L"rcd_sub");
    EXPECT_EQ(UN(RtlSetCurrentDirectory_U)(&u), 0);
    cur_dir(now, MAX_PATH); CHECKF(!_wcsicmp(now, sub), "now=%ls", now);
    wstr(&u, L"..");
    EXPECT_EQ(UN(RtlSetCurrentDirectory_U)(&u), 0);
    cur_dir(now, MAX_PATH); CHECKF(!_wcsicmp(now, dir), "now=%ls", now);
    /* errors leave the directory unchanged */
    swprintf(buf, MAX_PATH, L"%ls\\no_such_dir_rcd", dir);
    wstr(&u, buf);
    EXPECT_EQ(UN(RtlSetCurrentDirectory_U)(&u), ST_NOTFOUND);
    cur_dir(now, MAX_PATH); CHECK(!_wcsicmp(now, dir));
    {   /* a file is not a directory */
        WCHAR f[MAX_PATH]; swprintf(f, MAX_PATH, L"%ls\\rcd_file.txt", dir);
        HANDLE h = CreateFileW(f, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h); wstr(&u, f);
            EXPECT_EQ(UN(RtlSetCurrentDirectory_U)(&u), S(0xC0000103));   /* STATUS_NOT_A_DIRECTORY */
            DeleteFileW(f);
        }
    }
    cur_dir(now, MAX_PATH); CHECK(!_wcsicmp(now, dir));
    /* DOS device names are refused */
    wstr(&u, L"NUL");
    NTSTATUS s = UN(RtlSetCurrentDirectory_U)(&u);
    EXPECT_EQ(s, S(0xC0000103));                      /* STATUS_NOT_A_DIRECTORY */
    cur_dir(now, MAX_PATH); CHECK(!_wcsicmp(now, dir));
    /* restore */
    wstr(&u, orig);
    EXPECT_EQ(UN(RtlSetCurrentDirectory_U)(&u), 0);
    RemoveDirectoryW(sub);
    cur_dir(now, MAX_PATH); CHECK(!_wcsicmp(now, orig));
}

/* ---- environment variables ---- */
static NTSTATUS qenv(PWSTR env, const WCHAR *name, WCHAR *out, size_t cap /*wchars*/, USHORT *len) {
    UNICODE_STRING n, v; wstr(&n, name); v.Buffer = out; v.Length = 0; v.MaximumLength = (USHORT)(cap * 2);
    NTSTATUS s = UN(RtlQueryEnvironmentVariable_U)(env, &n, &v);
    if (len) *len = v.Length;
    return s;
}

TEST(rtl_set_environment_var_private) {
    REQUIRE(UN(RtlSetEnvironmentVar)); REQUIRE(UN(RtlCreateEnvironment)); REQUIRE(UN(RtlDestroyEnvironment));
    REQUIRE(UN(RtlQueryEnvironmentVariable_U)); REQUIRE(UN(RtlInitUnicodeString));
    PWSTR env = NULL; WCHAR out[64]; USHORT len;
    EXPECT_EQ(UN(RtlCreateEnvironment)(FALSE, &env), 0);
    if (!env) { t_skip("no environment"); return; }
    /* add */
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"RQSB_A", 6, L"one", 3), 0);
    memset(out, 0, sizeof out);
    EXPECT_EQ(qenv(env, L"RQSB_A", out, 64, &len), 0); EXPECT_EQ(len, 6); CHECK(!wcsncmp(out, L"one", 3));
    /* second variable, replacement with longer and shorter values */
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"rqsb_b", 6, L"two", 3), 0);
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"RQSB_A", 6, L"a much longer value", 19), 0);
    EXPECT_EQ(qenv(env, L"RQSB_A", out, 64, &len), 0); EXPECT_EQ(len, 38); CHECK(!wcsncmp(out, L"a much longer value", 19));
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"RQSB_A", 6, L"x", 1), 0);
    EXPECT_EQ(qenv(env, L"RQSB_A", out, 64, &len), 0); EXPECT_EQ(len, 2); EXPECT_EQ(out[0], L'x');
    /* names are case-insensitive for lookup and replacement */
    EXPECT_EQ(qenv(env, L"RQSB_B", out, 64, &len), 0); EXPECT_EQ(len, 6);
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"RQSB_B", 6, L"zz", 2), 0);
    EXPECT_EQ(qenv(env, L"rqsb_b", out, 64, &len), 0); EXPECT_EQ(len, 4);
    /* the length arguments, not NULs, bound the strings: a prefix of the name is a different variable */
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"RQSB_AXYZ", 6, L"prefix", 6), 0);
    EXPECT_EQ(qenv(env, L"RQSB_A", out, 64, &len), 0); EXPECT_EQ(len, 12); CHECK(!wcsncmp(out, L"prefix", 6));
    /* empty value is allowed */
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"RQSB_E", 6, L"", 0), 0);
    EXPECT_EQ(qenv(env, L"RQSB_E", out, 64, &len), 0); EXPECT_EQ(len, 0);
    /* delete: NULL value */
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"RQSB_B", 6, NULL, 0), 0);
    EXPECT_EQ(qenv(env, L"RQSB_B", out, 64, &len), S(0xC0000100));   /* STATUS_VARIABLE_NOT_FOUND */
    EXPECT_EQ(qenv(env, L"RQSB_A", out, 64, &len), 0);                /* others untouched */
    /* deleting an absent variable */
    NTSTATUS s = UN(RtlSetEnvironmentVar)(&env, L"RQSB_NONE", 9, NULL, 0);
    EXPECT_EQ(s, 0);                                  /* deleting an absent variable succeeds */
    /* too-small output buffer reports the needed size */
    UNICODE_STRING n, v; wstr(&n, L"RQSB_A"); v.Buffer = out; v.Length = 0; v.MaximumLength = 2;
    s = UN(RtlQueryEnvironmentVariable_U)(env, &n, &v);
    EXPECT_EQ(s, S(0xC0000023)); EXPECT_EQ(v.Length, 12);
    /* invalid names */
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"", 0, L"v", 1), ST_INVPARAM);          /* empty name */
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"A=B", 3, L"v", 1), ST_INVPARAM);       /* '=' inside */
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"AB\0C", 4, L"v", 1), ST_INVPARAM);     /* NUL inside */
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"N", 1, L"v\0w", 3), ST_INVPARAM);      /* NUL inside value */
    EXPECT_EQ(qenv(env, L"A", out, 64, &len), S(0xC0000100));
    UN(RtlDestroyEnvironment)(env);
}

TEST(rtl_set_environment_var_process) {
    REQUIRE(UN(RtlSetEnvironmentVar)); REQUIRE(UN(RtlQueryEnvironmentVariable_U));
    WCHAR w[64]; DWORD n;
    /* NULL environment pointer addresses the process environment seen by GetEnvironmentVariableW */
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(NULL, L"RQSB_PROC", 9, L"hello", 5), 0);
    n = GetEnvironmentVariableW(L"RQSB_PROC", w, 64); EXPECT_EQ(n, 5); CHECK(!wcscmp(w, L"hello"));
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(NULL, L"RQSB_PROC", 9, L"bye", 3), 0);
    n = GetEnvironmentVariableW(L"RQSB_PROC", w, 64); EXPECT_EQ(n, 3); CHECK(!wcscmp(w, L"bye"));
    USHORT len; WCHAR out[16];
    EXPECT_EQ(qenv(NULL, L"RQSB_PROC", out, 16, &len), 0); EXPECT_EQ(len, 6);
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(NULL, L"RQSB_PROC", 9, NULL, 0), 0);
    SetLastError(0);
    n = GetEnvironmentVariableW(L"RQSB_PROC", w, 64); EXPECT_EQ(n, 0); EXPECT_EQ(GetLastError(), ERROR_ENVVAR_NOT_FOUND);
    /* SetEnvironmentVariableW and the Rtl setter share the block */
    SetEnvironmentVariableW(L"RQSB_PROC2", L"k32");
    EXPECT_EQ(qenv(NULL, L"RQSB_PROC2", out, 16, &len), 0); EXPECT_EQ(len, 6);
    SetEnvironmentVariableW(L"RQSB_PROC2", NULL);
}

TEST(rtl_set_current_environment) {
    REQUIRE(UN(RtlSetCurrentEnvironment)); REQUIRE(UN(RtlCreateEnvironment)); REQUIRE(UN(RtlDestroyEnvironment));
    REQUIRE(UN(RtlSetEnvironmentVar)); REQUIRE(UN(RtlQueryEnvironmentVariable_U));
    PWSTR env = NULL, old = NULL, back = NULL; WCHAR w[64]; DWORD n;
    SetEnvironmentVariableW(L"RQSB_OLDVAR", L"orig");
    EXPECT_EQ(UN(RtlCreateEnvironment)(FALSE, &env), 0);     /* empty private block */
    if (!env) { SetEnvironmentVariableW(L"RQSB_OLDVAR", NULL); t_skip("no environment"); return; }
    EXPECT_EQ(UN(RtlSetEnvironmentVar)(&env, L"RQSB_NEWVAR", 11, L"fresh", 5), 0);
    EXPECT_EQ(UN(RtlSetCurrentEnvironment)(env, &old), 0);
    CHECK(old != NULL); CHECK(old != env);
    n = GetEnvironmentVariableW(L"RQSB_NEWVAR", w, 64); EXPECT_EQ(n, 5); CHECK(!wcscmp(w, L"fresh"));
    SetLastError(0);
    n = GetEnvironmentVariableW(L"RQSB_OLDVAR", w, 64); EXPECT_EQ(n, 0); EXPECT_EQ(GetLastError(), ERROR_ENVVAR_NOT_FOUND);
    /* switch back: the previous block is returned to us untouched */
    EXPECT_EQ(UN(RtlSetCurrentEnvironment)(old, &back), 0);
    EXPECT_EQ(back, env);
    n = GetEnvironmentVariableW(L"RQSB_OLDVAR", w, 64); EXPECT_EQ(n, 4); CHECK(!wcscmp(w, L"orig"));
    SetLastError(0);
    n = GetEnvironmentVariableW(L"RQSB_NEWVAR", w, 64); EXPECT_EQ(n, 0);
    SetEnvironmentVariableW(L"RQSB_OLDVAR", NULL);
    UN(RtlDestroyEnvironment)(env);
}

TEST(rtl_set_environment_strings) {
    REQUIRE(UN(RtlSetEnvironmentStrings));
    /* snapshot the whole block, replace it, then put it back */
    LPWCH cur = GetEnvironmentStringsW(); if (!cur) { t_skip("no env strings"); return; }
    size_t chars = 0; while (cur[chars] || cur[chars + 1]) chars++;
    chars += 2;                                       /* final double NUL */
    WCHAR *save = malloc(chars * 2); memcpy(save, cur, chars * 2); FreeEnvironmentStringsW(cur);
    static const WCHAR blk[] = L"RQSB_X=1\0rqsb_y=two\0";   /* + implicit final NUL = double NUL */
    WCHAR w[64]; DWORD n;
    EXPECT_EQ(UN(RtlSetEnvironmentStrings)((PWCHAR)blk, sizeof blk), 0);
    n = GetEnvironmentVariableW(L"RQSB_X", w, 64); EXPECT_EQ(n, 1); CHECK(!wcscmp(w, L"1"));
    n = GetEnvironmentVariableW(L"RQSB_Y", w, 64); EXPECT_EQ(n, 3); CHECK(!wcscmp(w, L"two"));
    SetLastError(0);
    n = GetEnvironmentVariableW(L"PATH", w, 64); EXPECT_EQ(n, 0);       /* old contents are gone */
    LPWCH now = GetEnvironmentStringsW();
    if (now) { CHECK(!wcscmp(now, L"RQSB_X=1")); FreeEnvironmentStringsW(now); }
    /* a bigger block than the current one grows the allocation */
    WCHAR *big = calloc(8192, 2); size_t o = 0;
    for (int i = 0; i < 100; i++) o += swprintf(big + o, 64, L"RQSB_V%03d=value%d", i, i) + 1;
    EXPECT_EQ(UN(RtlSetEnvironmentStrings)(big, (o + 1) * 2), 0);
    n = GetEnvironmentVariableW(L"RQSB_V057", w, 64); EXPECT_EQ(n, 7); CHECK(!wcscmp(w, L"value57"));
    n = GetEnvironmentVariableW(L"RQSB_X", w, 64); EXPECT_EQ(n, 0);
    free(big);
    /* restore */
    EXPECT_EQ(UN(RtlSetEnvironmentStrings)(save, chars * 2), 0);
    n = GetEnvironmentVariableW(L"RQSB_V057", w, 64); EXPECT_EQ(n, 0);
    n = GetEnvironmentVariableW(L"PATH", w, 64); CHECK(n > 0);
    free(save);
}

/* ---- search path mode ---- */
TEST(rtl_set_search_path_mode) {
    REQUIRE(UN(RtlSetSearchPathMode));
    /* BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE=1, DISABLE_SAFE_SEARCHMODE=0x10000, PERMANENT=0x8000 */
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0x1), 0);
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0x10000), 0);
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0x1), 0);
    /* invalid combinations: none, both, permanent alone, unknown bits */
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0x10001), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0x8000), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0x18000), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0x2), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0x20001), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0x80000000u | 1), ST_INVPARAM);
    /* the failed calls left the mode alone: a valid call still succeeds */
    EXPECT_EQ(UN(RtlSetSearchPathMode)(0x1), 0);
}

/* ---- thread error mode ---- */
TEST(rtl_set_thread_error_mode) {
    REQUIRE(UN(RtlSetThreadErrorMode)); REQUIRE(UN(RtlGetThreadErrorMode));
    ULONG old = 0xdead;
    EXPECT_EQ(UN(RtlSetThreadErrorMode)(0, &old), 0);                  /* known starting point */
    EXPECT_EQ(UN(RtlSetThreadErrorMode)(0x10, &old), 0); EXPECT_EQ(old, 0);
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0x10);
    EXPECT_EQ(UN(RtlSetThreadErrorMode)(0x70, &old), 0); EXPECT_EQ(old, 0x10);
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0x70);
    EXPECT_EQ(UN(RtlSetThreadErrorMode)(0x20, NULL), 0);               /* old value pointer optional */
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0x20);
    /* invalid bits: STATUS_INVALID_PARAMETER_1, mode unchanged and old value not written */
    old = 0xdead;
    EXPECT_EQ(UN(RtlSetThreadErrorMode)(0x1, &old), S(0xC00000EF)); EXPECT_EQ(old, 0xdead);
    EXPECT_EQ(UN(RtlSetThreadErrorMode)(0x80, &old), S(0xC00000EF));
    EXPECT_EQ(UN(RtlSetThreadErrorMode)(0x8, &old), S(0xC00000EF));
    EXPECT_EQ(UN(RtlSetThreadErrorMode)(0x100, NULL), S(0xC00000EF));
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0x20);
    EXPECT_EQ(UN(RtlSetThreadErrorMode)(0, &old), 0); EXPECT_EQ(old, 0x20);
}

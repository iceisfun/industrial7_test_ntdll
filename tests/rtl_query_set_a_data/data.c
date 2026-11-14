/* RtlQuery* over caller-supplied data: environment, atoms, registry values, security descriptors,
 * UMS thread info, policies and heap queries. */
#include "t.h"
#include <sddl.h>
#include <stdlib.h>

typedef LONG NTS;
#define ST_SUCCESS            ((NTSTATUS)0)
#define ST_INVALID_PARAMETER  ((NTSTATUS)0xC000000D)
#define ST_INVALID_HANDLE     ((NTSTATUS)0xC0000008)
#define ST_NAME_NOT_FOUND     ((NTSTATUS)0xC0000034)
#define ST_BUFFER_TOO_SMALL   ((NTSTATUS)0xC0000023)
#define ST_BUFFER_OVERFLOW    ((NTSTATUS)0x80000005)
#define ST_LEN_MISMATCH       ((NTSTATUS)0xC0000004)
#define ST_NOT_SUPPORTED      ((NTSTATUS)0xC00000BB)
#define ST_VAR_NOT_FOUND      ((NTSTATUS)0xC0000100)
#define ST_NOT_FOUND         ((NTSTATUS)0xC0000225)
#define ST_UNSUCCESSFUL       ((NTSTATUS)0xC0000001)

/* ---- environment ---------------------------------------------------------------- */
UDECL(NTSTATUS, RtlQueryEnvironmentVariable, (PWSTR, PWSTR, SIZE_T, PWSTR, SIZE_T, PSIZE_T));

static WCHAR g_env[] = L"FOO=bar\0Baz=qux quux\0EMPTY=\0=C:=C:\\dir\0LongName_1=0123456789\0";

TEST(qs_env_custom_block) {
    REQUIRE(UN(RtlQueryEnvironmentVariable));
    WCHAR out[64]; SIZE_T len = 0x77;
    /* the env block above ends with an extra NUL after the last string (the literal's own terminator) */
    NTSTATUS s = UN(RtlQueryEnvironmentVariable)(g_env, L"FOO", 3, out, 64, &len);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, 3); EXPECT_WSTR(out, L"bar");
    len = 0; s = UN(RtlQueryEnvironmentVariable)(g_env, L"Baz", 3, out, 64, &len);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, 8); EXPECT_WSTR(out, L"qux quux");
    /* names compare case-insensitively */
    len = 0; s = UN(RtlQueryEnvironmentVariable)(g_env, L"fOo", 3, out, 64, &len);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, 3); EXPECT_WSTR(out, L"bar");
    len = 0; s = UN(RtlQueryEnvironmentVariable)(g_env, L"LONGNAME_1", 10, out, 64, &len);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, 10); EXPECT_WSTR(out, L"0123456789");
    /* empty value */
    out[0] = 0x1234; len = 9; s = UN(RtlQueryEnvironmentVariable)(g_env, L"EMPTY", 5, out, 64, &len);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, 0); EXPECT_EQ(out[0], 0);
    /* hidden drive-current-directory variables start with '=' */
    len = 0; s = UN(RtlQueryEnvironmentVariable)(g_env, L"=C:", 3, out, 64, &len);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, 6); EXPECT_WSTR(out, L"C:\\dir");
}

TEST(qs_env_errors) {
    REQUIRE(UN(RtlQueryEnvironmentVariable));
    WCHAR out[64]; SIZE_T len = 0x77; NTSTATUS s;
    s = UN(RtlQueryEnvironmentVariable)(g_env, L"NOPE", 4, out, 64, &len);
    EXPECT_EQ(s, ST_VAR_NOT_FOUND); EXPECT_EQ(len, 0);
    /* a name that is only a prefix / extension of a defined one does not match */
    s = UN(RtlQueryEnvironmentVariable)(g_env, L"FO", 2, out, 64, &len); EXPECT_EQ(s, ST_VAR_NOT_FOUND);
    s = UN(RtlQueryEnvironmentVariable)(g_env, L"FOOD", 4, out, 64, &len); EXPECT_EQ(s, ST_VAR_NOT_FOUND);
    s = UN(RtlQueryEnvironmentVariable)(g_env, L"FOO", 0, out, 64, &len); EXPECT_EQ(s, ST_VAR_NOT_FOUND);
    /* the value is searched by the supplied length, not by NUL */
    len = 0; s = UN(RtlQueryEnvironmentVariable)(g_env, L"FOOBAR", 3, out, 64, &len);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, 3);
    /* too small: STATUS_BUFFER_TOO_SMALL, ReturnLength = chars needed including the NUL, first char cleared */
    out[0] = 0x4242; len = 0;
    s = UN(RtlQueryEnvironmentVariable)(g_env, L"Baz", 3, out, 8, &len);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(len, 9); EXPECT_EQ(out[0], 0);
    /* exact fit needs room for the NUL */
    out[0] = 0x4242; len = 0;
    s = UN(RtlQueryEnvironmentVariable)(g_env, L"Baz", 3, out, 9, &len);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, 8); EXPECT_WSTR(out, L"qux quux");
    /* no output buffer: length query */
    len = 0; s = UN(RtlQueryEnvironmentVariable)(g_env, L"Baz", 3, NULL, 0, &len);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(len, 9);
    /* empty environment block */
    WCHAR empty[2] = {0, 0};
    s = UN(RtlQueryEnvironmentVariable)(empty, L"FOO", 3, out, 64, &len); EXPECT_EQ(s, ST_VAR_NOT_FOUND);
}

TEST(qs_env_process_block) {
    REQUIRE(UN(RtlQueryEnvironmentVariable));
    WCHAR out[64]; SIZE_T len = 0; NTSTATUS s;
    CHECK(SetEnvironmentVariableW(L"QS_ENV_PROBE", L"value1"));
    s = UN(RtlQueryEnvironmentVariable)(NULL, L"QS_ENV_PROBE", 12, out, 64, &len);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, 6); EXPECT_WSTR(out, L"value1");
    CHECK(SetEnvironmentVariableW(L"QS_ENV_PROBE", L"v2longer"));
    s = UN(RtlQueryEnvironmentVariable)(NULL, L"qs_env_probe", 12, out, 64, &len);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, 8); EXPECT_WSTR(out, L"v2longer");
    CHECK(SetEnvironmentVariableW(L"QS_ENV_PROBE", NULL));
    s = UN(RtlQueryEnvironmentVariable)(NULL, L"QS_ENV_PROBE", 12, out, 64, &len);
    EXPECT_EQ(s, ST_VAR_NOT_FOUND); EXPECT_EQ(len, 0);
    /* agrees with kernel32 for PATH-style variables */
    WCHAR k[2048]; DWORD kn = GetEnvironmentVariableW(L"SystemRoot", k, 2048);
    if (kn) { WCHAR big[2048]; s = UN(RtlQueryEnvironmentVariable)(NULL, L"SystemRoot", 10, big, 2048, &len);
        EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(len, kn); EXPECT_WSTR(big, k); }
}

/* ---- atoms ------------------------------------------------------------------------ */
UDECL(NTSTATUS, RtlCreateAtomTable, (ULONG, PVOID *));
UDECL(NTSTATUS, RtlDestroyAtomTable, (PVOID));
UDECL(NTSTATUS, RtlAddAtomToAtomTable, (PVOID, PWSTR, PUSHORT));
UDECL(NTSTATUS, RtlPinAtomInAtomTable, (PVOID, USHORT));
UDECL(NTSTATUS, RtlDeleteAtomFromAtomTable, (PVOID, USHORT));
UDECL(NTSTATUS, RtlQueryAtomInAtomTable, (PVOID, USHORT, PULONG, PULONG, PWSTR, PULONG));

TEST(qs_atom_string) {
    REQUIRE(UN(RtlQueryAtomInAtomTable)); REQUIRE(UN(RtlCreateAtomTable)); REQUIRE(UN(RtlAddAtomToAtomTable));
    REQUIRE(UN(RtlDestroyAtomTable)); REQUIRE(UN(RtlPinAtomInAtomTable)); REQUIRE(UN(RtlDeleteAtomFromAtomTable));
    PVOID tab = NULL; USHORT atom = 0, atom2 = 0;
    if (UN(RtlCreateAtomTable)(37, &tab) != 0) { t_skip("RtlCreateAtomTable failed"); return; }
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tab, L"QsAtomName", &atom), 0);
    CHECK(atom >= 0xc000);
    ULONG ref = 99, pin = 99, nlen = 64; WCHAR name[32]; memset(name, 0xcc, sizeof name);
    NTSTATUS s = UN(RtlQueryAtomInAtomTable)(tab, atom, &ref, &pin, name, &nlen);
    EXPECT_EQ(s, 0); EXPECT_EQ(ref, 1); EXPECT_EQ(pin, 0); EXPECT_EQ(nlen, 20); EXPECT_WSTR(name, L"QsAtomName");
    /* second add bumps the reference count */
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tab, L"QsAtomName", &atom2), 0); EXPECT_EQ(atom2, atom);
    nlen = 64; s = UN(RtlQueryAtomInAtomTable)(tab, atom, &ref, &pin, name, &nlen);
    EXPECT_EQ(s, 0); EXPECT_EQ(ref, 2);
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(tab, atom), 0);
    nlen = 64; s = UN(RtlQueryAtomInAtomTable)(tab, atom, &ref, &pin, name, &nlen);
    EXPECT_EQ(s, 0); EXPECT_EQ(pin, 1);
    /* counts only: no name buffer */
    ref = pin = 99; s = UN(RtlQueryAtomInAtomTable)(tab, atom, &ref, &pin, NULL, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(ref, 2); EXPECT_EQ(pin, 1);
    s = UN(RtlQueryAtomInAtomTable)(tab, atom, NULL, NULL, NULL, NULL); EXPECT_EQ(s, 0);
    /* a buffer shorter than the name plus NUL */
    nlen = 1; s = UN(RtlQueryAtomInAtomTable)(tab, atom, NULL, NULL, name, &nlen);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(nlen, 20);
    nlen = 0; s = UN(RtlQueryAtomInAtomTable)(tab, atom, NULL, NULL, name, &nlen);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(nlen, 20);
    nlen = 6; memset(name, 0xcc, sizeof name); s = UN(RtlQueryAtomInAtomTable)(tab, atom, NULL, NULL, name, &nlen);
    t_note("atom truncated query: status 0x%08lx len %lu name[0]=%04x", (unsigned long)s, nlen, name[0]);
    /* a buffer holding 3 chars: the name is truncated to fit with its NUL, and the call succeeds */
    EXPECT_EQ(s, 0); EXPECT_EQ(nlen, 4); EXPECT_WSTR(name, L"Qs");
    /* unknown / deleted atoms */
    nlen = 64; s = UN(RtlQueryAtomInAtomTable)(tab, 0xc7ff, &ref, &pin, name, &nlen); EXPECT_EQ(s, ST_INVALID_HANDLE);
    s = UN(RtlQueryAtomInAtomTable)(tab, 0xffff, &ref, &pin, name, &nlen); EXPECT_EQ(s, ST_INVALID_HANDLE);
    /* atom 0 is invalid */
    s = UN(RtlQueryAtomInAtomTable)(tab, 0, &ref, &pin, name, &nlen); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    /* invalid table pointer (zeroed memory fails the table-signature check) */
    char zeros[256] = {0};
    s = UN(RtlQueryAtomInAtomTable)(zeros, atom, &ref, &pin, name, &nlen); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    UN(RtlDestroyAtomTable)(tab);
}

TEST(qs_atom_integer) {
    REQUIRE(UN(RtlQueryAtomInAtomTable)); REQUIRE(UN(RtlCreateAtomTable)); REQUIRE(UN(RtlDestroyAtomTable));
    PVOID tab = NULL;
    if (UN(RtlCreateAtomTable)(37, &tab) != 0) { t_skip("RtlCreateAtomTable failed"); return; }
    ULONG ref = 99, pin = 99, nlen = 64; WCHAR name[32];
    /* integer atoms 1..0xbfff always exist, are pinned once, and render as "#N" */
    NTSTATUS s = UN(RtlQueryAtomInAtomTable)(tab, 1234, &ref, &pin, name, &nlen);
    EXPECT_EQ(s, 0); EXPECT_EQ(ref, 1); EXPECT_EQ(pin, 1); EXPECT_EQ(nlen, 10); EXPECT_WSTR(name, L"#1234");
    nlen = 64; s = UN(RtlQueryAtomInAtomTable)(tab, 0xbfff, NULL, NULL, name, &nlen);
    EXPECT_EQ(s, 0); EXPECT_EQ(nlen, 12); EXPECT_WSTR(name, L"#49151");
    nlen = 64; s = UN(RtlQueryAtomInAtomTable)(tab, 7, NULL, NULL, name, &nlen);
    EXPECT_EQ(s, 0); EXPECT_EQ(nlen, 4); EXPECT_WSTR(name, L"#7");
    nlen = 0; s = UN(RtlQueryAtomInAtomTable)(tab, 7, NULL, NULL, name, &nlen);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL);
    UN(RtlDestroyAtomTable)(tab);
}

/* ---- registry --------------------------------------------------------------------- */
typedef NTSTATUS (NTAPI *QRY_ROUTINE)(PWSTR, ULONG, PVOID, ULONG, PVOID, PVOID);
typedef struct { QRY_ROUTINE Routine; ULONG Flags; PWSTR Name; PVOID EntryContext; ULONG DefaultType; PVOID DefaultData; ULONG DefaultLength; } QTAB;
#define QF_SUBKEY 1
#define QF_TOPKEY 2
#define QF_REQUIRED 4
#define QF_NOVALUE 8
#define QF_NOEXPAND 0x10
#define QF_DIRECT 0x20
#define QF_DELETE 0x40
#define QF_NOSTRING 0x80
#define QF_TYPECHECK 0x100
#define RR_USER 5
#define RR_HANDLE 0x40000000

UDECL(NTSTATUS, RtlQueryRegistryValues, (ULONG, PCWSTR, QTAB *, PVOID, PVOID));
UDECL(NTSTATUS, RtlQueryRegistryValuesEx, (ULONG, PCWSTR, QTAB *, PVOID, PVOID));
UDECL(NTSTATUS, RtlQueryRegistryValueWithFallback, (HANDLE, HANDLE, PUNICODE_STRING, ULONG, PULONG, PVOID, PULONG));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));

#define ADV(n) UIN("advapi32.dll", n)
static WCHAR g_keyname[96];
static HKEY g_key, g_sub;

static int reg_setup(void) {
    if (!ADV(RegCreateKeyExW)) return 0;
    swprintf(g_keyname, 96, L"Software\\ntdllt_qs_%lu_%lu", GetCurrentProcessId(), GetTickCount());
    DWORD disp;
    if (ADV(RegCreateKeyExW)(HKEY_CURRENT_USER, g_keyname, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &g_key, &disp)) return 0;
    if (ADV(RegCreateKeyExW)(g_key, L"Sub", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &g_sub, &disp)) { ADV(RegCloseKey)(g_key); return 0; }
    DWORD dw = 0x12345678;
    ADV(RegSetValueExW)(g_key, L"Dword", 0, REG_DWORD, (BYTE *)&dw, 4);
    ADV(RegSetValueExW)(g_key, L"Str", 0, REG_SZ, (BYTE *)L"hello", 12);
    ADV(RegSetValueExW)(g_key, L"Expand", 0, REG_EXPAND_SZ, (BYTE *)L"%QS_REG_VAR%\\x", 28);
    ADV(RegSetValueExW)(g_key, L"Multi", 0, REG_MULTI_SZ, (BYTE *)L"one\0two\0three\0", 30);
    BYTE bin[5] = {1, 2, 3, 4, 5};
    ADV(RegSetValueExW)(g_key, L"Bin", 0, REG_BINARY, bin, 5);
    ADV(RegSetValueExW)(g_sub, L"SubVal", 0, REG_SZ, (BYTE *)L"inner", 12);
    return 1;
}
static void reg_teardown(void) {
    ADV(RegCloseKey)(g_sub); ADV(RegCloseKey)(g_key);
    if (ADV(RegDeleteTreeW)) ADV(RegDeleteTreeW)(HKEY_CURRENT_USER, g_keyname);
    else { WCHAR p[128]; swprintf(p, 128, L"%ls\\Sub", g_keyname); ADV(RegDeleteKeyW)(HKEY_CURRENT_USER, p); ADV(RegDeleteKeyW)(HKEY_CURRENT_USER, g_keyname); }
}

typedef struct { int n; WCHAR names[8][16]; ULONG types[8]; ULONG lens[8]; WCHAR data[8][40]; PVOID ctx[8]; PVOID ectx[8]; NTSTATUS ret; } COLLECT;
static NTSTATUS NTAPI collect_cb(PWSTR name, ULONG type, PVOID data, ULONG len, PVOID ctx, PVOID ectx) {
    COLLECT *c = (COLLECT *)ctx;
    if (c->n < 8) {
        int i = c->n++;
        if (name) lstrcpynW(c->names[i], name, 16); else c->names[i][0] = 0;
        c->types[i] = type; c->lens[i] = len; c->ctx[i] = ctx; c->ectx[i] = ectx;
        c->data[i][0] = 0;
        if (data && len && (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ)) lstrcpynW(c->data[i], (WCHAR *)data, 40);
        else if (data && len >= 4 && type == REG_DWORD) *(ULONG *)c->data[i] = *(ULONG *)data;
    }
    return c->ret;
}

static void reg_values_body(int ex) {
    NTSTATUS (WINAPI *Q)(ULONG, PCWSTR, QTAB *, PVOID, PVOID) = ex ? (void *)UN(RtlQueryRegistryValuesEx) : (void *)UN(RtlQueryRegistryValues);
    REQUIRE(Q); REQUIRE(UN(RtlInitUnicodeString));
    if (!reg_setup()) { t_skip("cannot create HKCU test key"); return; }
    COLLECT c; NTSTATUS s;
    SetEnvironmentVariableW(L"QS_REG_VAR", L"EXP");

    /* callback with named value: REG_SZ length includes the NUL */
    memset(&c, 0, sizeof c);
    QTAB t1[] = { { collect_cb, 0, L"Str", (PVOID)0x1111, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t1, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) { EXPECT_WSTR(c.names[0], L"Str"); EXPECT_EQ(c.types[0], REG_SZ); EXPECT_EQ(c.lens[0], 12); EXPECT_WSTR(c.data[0], L"hello"); EXPECT_EQ(c.ectx[0], 0x1111); }
    /* user-relative path form resolves the same key */
    memset(&c, 0, sizeof c);
    s = Q(RR_USER, g_keyname, t1, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) EXPECT_WSTR(c.data[0], L"hello");

    /* REG_DWORD arrives raw */
    memset(&c, 0, sizeof c);
    QTAB t2[] = { { collect_cb, 0, L"Dword", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t2, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) { EXPECT_EQ(c.types[0], REG_DWORD); EXPECT_EQ(c.lens[0], 4); EXPECT_EQ(*(ULONG *)c.data[0], 0x12345678); }

    /* REG_EXPAND_SZ is expanded and reported as REG_SZ unless NOEXPAND */
    memset(&c, 0, sizeof c);
    QTAB t3[] = { { collect_cb, 0, L"Expand", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t3, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) { EXPECT_EQ(c.types[0], REG_SZ); EXPECT_WSTR(c.data[0], L"EXP\\x"); EXPECT_EQ(c.lens[0], 12); }
    memset(&c, 0, sizeof c);
    QTAB t3b[] = { { collect_cb, QF_NOEXPAND, L"Expand", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t3b, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) { EXPECT_EQ(c.types[0], REG_EXPAND_SZ); EXPECT_WSTR(c.data[0], L"%QS_REG_VAR%\\x"); }

    /* REG_MULTI_SZ is delivered one string per call, as REG_SZ */
    memset(&c, 0, sizeof c);
    QTAB t4[] = { { collect_cb, 0, L"Multi", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t4, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 3);
    if (c.n == 3) { EXPECT_WSTR(c.data[0], L"one"); EXPECT_WSTR(c.data[1], L"two"); EXPECT_WSTR(c.data[2], L"three"); EXPECT_EQ(c.types[1], REG_SZ); }
    memset(&c, 0, sizeof c);
    QTAB t4b[] = { { collect_cb, QF_NOEXPAND, L"Multi", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t4b, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) { EXPECT_EQ(c.types[0], REG_MULTI_SZ); EXPECT_EQ(c.lens[0], 32); }   /* observed: stored 30 bytes + 2 for an extra terminator */

    /* binary */
    memset(&c, 0, sizeof c);
    QTAB t5[] = { { collect_cb, 0, L"Bin", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t5, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) { EXPECT_EQ(c.types[0], REG_BINARY); EXPECT_EQ(c.lens[0], 5); }

    /* DIRECT string into a caller-owned UNICODE_STRING. (The Ex entry point is not driven with DIRECT
     * entries here: on the reference system that combination terminates the process.) */
    if (!ex) {
        WCHAR sbuf[32] = {0}; UNICODE_STRING us = { 0, sizeof sbuf, sbuf };
        QTAB t7[] = { { NULL, QF_DIRECT, L"Str", &us, REG_NONE, NULL, 0 }, { 0 } };
        s = Q(RR_HANDLE, (PCWSTR)g_key, t7, NULL, NULL);
        EXPECT_EQ(s, 0); EXPECT_EQ(us.Length, 10); CHECK(us.Buffer == sbuf); EXPECT_WSTR(sbuf, L"hello");
        /* expanded direct string */
        WCHAR ebuf[32] = {0}; UNICODE_STRING ue = { 0, sizeof ebuf, ebuf };
        QTAB t7c[] = { { NULL, QF_DIRECT, L"Expand", &ue, REG_NONE, NULL, 0 }, { 0 } };
        s = Q(RR_HANDLE, (PCWSTR)g_key, t7c, NULL, NULL);
        EXPECT_EQ(s, 0); EXPECT_WSTR(ebuf, L"EXP\\x");

    }

    /* missing value: skipped unless REQUIRED, default applied if a DefaultType is given */
    memset(&c, 0, sizeof c);
    QTAB t8[] = { { collect_cb, 0, L"Missing", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t8, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 0);
    QTAB t8r[] = { { collect_cb, QF_REQUIRED, L"Missing", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t8r, &c, NULL);
    EXPECT_EQ(s, ST_NAME_NOT_FOUND); EXPECT_EQ(c.n, 0);
    memset(&c, 0, sizeof c);
    QTAB t8d[] = { { collect_cb, 0, L"Missing", NULL, REG_SZ, L"dflt", 10 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t8d, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) { EXPECT_EQ(c.types[0], REG_SZ); EXPECT_WSTR(c.data[0], L"dflt"); EXPECT_WSTR(c.names[0], L"Missing"); }

    /* NULL name: callback for every value in the key (5 values) */
    memset(&c, 0, sizeof c);
    QTAB t9[] = { { collect_cb, 0, NULL, NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t9, &c, NULL);
    EXPECT_EQ(s, 0);
    { int seen = 0; for (int i = 0; i < c.n; i++) { if (!lstrcmpiW(c.names[i], L"Dword") || !lstrcmpiW(c.names[i], L"Str") || !lstrcmpiW(c.names[i], L"Bin") || !lstrcmpiW(c.names[i], L"Expand") || !lstrcmpiW(c.names[i], L"Multi") ) seen++; }
      CHECKF(seen >= 5, "saw %d of 5 values among %d callbacks", seen, c.n); }

    /* SUBKEY moves to the child; later entries are relative to it */
    memset(&c, 0, sizeof c);
    QTAB t10[] = { { NULL, QF_SUBKEY | QF_NOVALUE, L"Sub", NULL, REG_NONE, NULL, 0 }, { collect_cb, 0, L"SubVal", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t10, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) EXPECT_WSTR(c.data[0], L"inner");
    /* TOPKEY returns to the base key */
    memset(&c, 0, sizeof c);
    QTAB t11[] = { { NULL, QF_SUBKEY | QF_NOVALUE, L"Sub", NULL, REG_NONE, NULL, 0 }, { collect_cb, QF_TOPKEY, L"Str", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t11, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) EXPECT_WSTR(c.data[0], L"hello");
    /* a missing subkey */
    QTAB t12[] = { { NULL, QF_SUBKEY | QF_NOVALUE, L"NoSuchSub", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t12, &c, NULL);
    EXPECT_EQ(s, ST_NAME_NOT_FOUND);

    /* callback failure status is propagated and stops the walk */
    memset(&c, 0, sizeof c); c.ret = ST_UNSUCCESSFUL;
    QTAB t13[] = { { collect_cb, 0, L"Str", NULL, REG_NONE, NULL, 0 }, { collect_cb, 0, L"Dword", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t13, &c, NULL);
    EXPECT_EQ(s, ST_UNSUCCESSFUL); EXPECT_EQ(c.n, 1);
    /* two entries in one call run in order */
    memset(&c, 0, sizeof c);
    s = Q(RR_HANDLE, (PCWSTR)g_key, t13, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 2);
    if (c.n == 2) { EXPECT_WSTR(c.names[0], L"Str"); EXPECT_WSTR(c.names[1], L"Dword"); }
    /* empty table */
    QTAB t14[] = { { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t14, &c, NULL); EXPECT_EQ(s, 0);

    /* DELETE removes the value after delivering it */
    DWORD two = 2; ADV(RegSetValueExW)(g_key, L"Temp", 0, REG_DWORD, (BYTE *)&two, 4);
    memset(&c, 0, sizeof c);
    QTAB t15[] = { { collect_cb, QF_DELETE, L"Temp", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t15, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.n, 1);
    if (c.n == 1) EXPECT_EQ(*(ULONG *)c.data[0], 2);
    EXPECT_EQ(ADV(RegQueryValueExW)(g_key, L"Temp", NULL, NULL, NULL, NULL), ERROR_FILE_NOT_FOUND);

    /* bad relative-to / bad path */
    s = Q(RR_USER, L"Software\\ntdllt_qs_no_such_key_xyz", t1, &c, NULL); EXPECT_EQ(s, ST_NAME_NOT_FOUND);
    s = Q(0x20, g_keyname, t1, &c, NULL); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    s = Q(RR_HANDLE, (PCWSTR)(ULONG_PTR)0x7ffffff0, t1, &c, NULL); EXPECT_EQ(s, ST_INVALID_HANDLE);
    /* a callback-less non-DIRECT entry has nothing to deliver to and is skipped */
    QTAB t16[] = { { NULL, 0, L"Str", NULL, REG_NONE, NULL, 0 }, { 0 } };
    s = Q(RR_HANDLE, (PCWSTR)g_key, t16, &c, NULL); EXPECT_EQ(s, 0);
    reg_teardown();
}
TEST(qs_registry_values) { reg_values_body(0); }
TEST(qs_registry_values_ex) { reg_values_body(1); }

TEST(qs_registry_fallback) {
    REQUIRE(UN(RtlQueryRegistryValueWithFallback)); REQUIRE(UN(RtlInitUnicodeString));
    if (!reg_setup()) { t_skip("cannot create HKCU test key"); return; }
    UNICODE_STRING nm; ULONG type = 0xff, res = 0xff; BYTE buf[64]; NTSTATUS s;
    DWORD alt = 0xa5a5a5a5;
    ADV(RegSetValueExW)(g_sub, L"Dword", 0, REG_DWORD, (BYTE *)&alt, 4);
    UN(RtlInitUnicodeString)(&nm, L"Dword");
    /* primary has the value */
    s = UN(RtlQueryRegistryValueWithFallback)(g_key, g_sub, &nm, sizeof buf, &type, buf, &res);
    EXPECT_EQ(s, 0); EXPECT_EQ(type, REG_DWORD); EXPECT_EQ(res, 4); EXPECT_EQ(*(ULONG *)buf, 0x12345678);
    /* primary lacks it: fallback is used */
    UN(RtlInitUnicodeString)(&nm, L"SubVal");
    type = res = 0xff; memset(buf, 0, sizeof buf);
    s = UN(RtlQueryRegistryValueWithFallback)(g_key, g_sub, &nm, sizeof buf, &type, buf, &res);
    EXPECT_EQ(s, 0); EXPECT_EQ(type, REG_SZ); EXPECT_EQ(res, 12); EXPECT_WSTR((WCHAR *)buf, L"inner");
    /* swapped roles: primary only, no fallback */
    s = UN(RtlQueryRegistryValueWithFallback)(g_sub, NULL, &nm, sizeof buf, &type, buf, &res);
    EXPECT_EQ(s, 0); EXPECT_EQ(res, 12);
    /* fallback only */
    type = res = 0xff;
    s = UN(RtlQueryRegistryValueWithFallback)(NULL, g_sub, &nm, sizeof buf, &type, buf, &res);
    EXPECT_EQ(s, 0); EXPECT_EQ(res, 12);
    /* missing in primary and no fallback */
    s = UN(RtlQueryRegistryValueWithFallback)(g_key, NULL, &nm, sizeof buf, &type, buf, &res); EXPECT_EQ(s, ST_NAME_NOT_FOUND);
    /* missing in both */
    UN(RtlInitUnicodeString)(&nm, L"NoSuchValue");
    s = UN(RtlQueryRegistryValueWithFallback)(g_key, g_sub, &nm, sizeof buf, &type, buf, &res); EXPECT_EQ(s, ST_NAME_NOT_FOUND);
    /* type output is optional */
    UN(RtlInitUnicodeString)(&nm, L"Dword");
    res = 0; s = UN(RtlQueryRegistryValueWithFallback)(g_key, NULL, &nm, sizeof buf, NULL, buf, &res);
    EXPECT_EQ(s, 0); EXPECT_EQ(res, 4);
    /* buffer too small: STATUS_BUFFER_OVERFLOW, ResultLength is the full size, type still returned */
    UN(RtlInitUnicodeString)(&nm, L"Str");
    type = 0xff; res = 0; memset(buf, 0x77, sizeof buf);
    s = UN(RtlQueryRegistryValueWithFallback)(g_key, NULL, &nm, 4, &type, buf, &res);
    EXPECT_EQ(s, ST_BUFFER_OVERFLOW); EXPECT_EQ(res, 12); EXPECT_EQ(type, REG_SZ);
    EXPECT_EQ(buf[0], 0x77);
    /* both handles NULL */
    s = UN(RtlQueryRegistryValueWithFallback)(NULL, NULL, &nm, sizeof buf, &type, buf, &res); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    /* a length that overflows the internal allocation size */
    s = UN(RtlQueryRegistryValueWithFallback)(g_key, NULL, &nm, 0xfffffff8, &type, buf, &res);
    EXPECT_EQ(s, (NTSTATUS)0xC0000095);
    /* invalid handle in primary slot */
    s = UN(RtlQueryRegistryValueWithFallback)((HANDLE)(ULONG_PTR)0x7ffffff0, NULL, &nm, sizeof buf, &type, buf, &res);
    EXPECT_EQ(s, ST_INVALID_HANDLE);
    reg_teardown();
}

/* ---- security descriptor ---------------------------------------------------------- */
UDECL(NTSTATUS, RtlQuerySecurityObject, (PSECURITY_DESCRIPTOR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG));

static PSECURITY_DESCRIPTOR make_sd(const WCHAR *sddl) {
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!UIN("advapi32.dll", ConvertStringSecurityDescriptorToSecurityDescriptorW)) return NULL;
    if (!ADV(ConvertStringSecurityDescriptorToSecurityDescriptorW)(sddl, SDDL_REVISION_1, &sd, NULL)) return NULL;
    return sd;
}

TEST(qs_security_object_self_relative) {
    REQUIRE(UN(RtlQuerySecurityObject));
    PSECURITY_DESCRIPTOR sd = make_sd(L"O:BAG:SYD:(A;;GA;;;WD)(D;;GR;;;BG)S:(AU;SA;GA;;;WD)");
    if (!sd) { t_skip("SDDL conversion unavailable"); return; }
    BYTE out[512]; ULONG need = 0; NTSTATUS s;
    BYTE *src = (BYTE *)sd;
    ULONG o_off = *(ULONG *)(src + 4), g_off = *(ULONG *)(src + 8), s_off = *(ULONG *)(src + 12), d_off = *(ULONG *)(src + 16);
    CHECK(o_off && g_off && s_off && d_off);
    ULONG o_len = 8 + 4 * src[o_off + 1], g_len = 8 + 4 * src[g_off + 1];
    ULONG d_len = *(USHORT *)(src + d_off + 2), s_len = *(USHORT *)(src + s_off + 2);

    /* owner only */
    memset(out, 0xcc, sizeof out);
    s = UN(RtlQuerySecurityObject)(sd, OWNER_SECURITY_INFORMATION, out, sizeof out, &need);
    EXPECT_EQ(s, 0); EXPECT_EQ(need, 0x14 + o_len);
    EXPECT_EQ(out[0], 1); EXPECT_EQ(*(USHORT *)(out + 2) & 0x8000, 0x8000);
    EXPECT_EQ(*(ULONG *)(out + 4), 0x14);
    EXPECT_EQ(*(ULONG *)(out + 8), 0); EXPECT_EQ(*(ULONG *)(out + 12), 0); EXPECT_EQ(*(ULONG *)(out + 16), 0);
    CHECK(!memcmp(out + 0x14, src + o_off, o_len));
    /* group only */
    s = UN(RtlQuerySecurityObject)(sd, GROUP_SECURITY_INFORMATION, out, sizeof out, &need);
    EXPECT_EQ(s, 0); EXPECT_EQ(need, 0x14 + g_len); EXPECT_EQ(*(ULONG *)(out + 4), 0); EXPECT_EQ(*(ULONG *)(out + 8), 0x14);
    CHECK(!memcmp(out + 0x14, src + g_off, g_len));
    /* DACL only: dacl-present flag */
    s = UN(RtlQuerySecurityObject)(sd, DACL_SECURITY_INFORMATION, out, sizeof out, &need);
    EXPECT_EQ(s, 0); EXPECT_EQ(need, 0x14 + ((d_len + 3) & ~3UL));
    EXPECT_EQ(*(ULONG *)(out + 16), 0x14); CHECK(*(USHORT *)(out + 2) & SE_DACL_PRESENT);
    CHECK(!memcmp(out + 0x14, src + d_off, d_len));
    /* all of owner, group, dacl */
    s = UN(RtlQuerySecurityObject)(sd, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, out, sizeof out, &need);
    EXPECT_EQ(s, 0); EXPECT_EQ(need, 0x14 + o_len + g_len + ((d_len + 3) & ~3UL));
    CHECK(*(ULONG *)(out + 4) && *(ULONG *)(out + 8) && *(ULONG *)(out + 16) && !*(ULONG *)(out + 12));
    /* nothing requested: bare header */
    s = UN(RtlQuerySecurityObject)(sd, 0, out, sizeof out, &need);
    EXPECT_EQ(s, 0); EXPECT_EQ(need, 0x14);
    EXPECT_EQ(*(ULONG *)(out + 4), 0); EXPECT_EQ(*(ULONG *)(out + 8), 0); EXPECT_EQ(*(ULONG *)(out + 12), 0); EXPECT_EQ(*(ULONG *)(out + 16), 0);
    /* SACL */
    s = UN(RtlQuerySecurityObject)(sd, SACL_SECURITY_INFORMATION, out, sizeof out, &need);
    t_note("SACL query: status 0x%08lx need %lu (acl %lu)", (unsigned long)s, need, s_len);
    EXPECT_EQ(s, 0); CHECK(*(ULONG *)(out + 12) != 0);

    /* too small: length is reported, status STATUS_BUFFER_TOO_SMALL */
    need = 0; s = UN(RtlQuerySecurityObject)(sd, OWNER_SECURITY_INFORMATION, out, 0x14, &need);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(need, 0x14 + o_len);
    need = 0; s = UN(RtlQuerySecurityObject)(sd, OWNER_SECURITY_INFORMATION, NULL, 0, &need);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(need, 0x14 + o_len);
    /* exact fit */
    s = UN(RtlQuerySecurityObject)(sd, OWNER_SECURITY_INFORMATION, out, 0x14 + o_len, &need); EXPECT_EQ(s, 0);
    LocalFree(sd);
}

TEST(qs_security_object_absolute) {
    REQUIRE(UN(RtlQuerySecurityObject));
    if (!ADV(InitializeSecurityDescriptor)) { t_skip("advapi32 missing"); return; }
    SECURITY_DESCRIPTOR a; CHECK(ADV(InitializeSecurityDescriptor)(&a, SECURITY_DESCRIPTOR_REVISION));
    SID_IDENTIFIER_AUTHORITY wa = SECURITY_WORLD_SID_AUTHORITY; PSID world = NULL;
    CHECK(ADV(AllocateAndInitializeSid)(&wa, 1, 0, 0, 0, 0, 0, 0, 0, 0, &world));
    CHECK(ADV(SetSecurityDescriptorOwner)(&a, world, FALSE));
    CHECK(ADV(SetSecurityDescriptorDacl)(&a, TRUE, NULL, FALSE));   /* NULL DACL present */
    BYTE out[128]; ULONG need = 0; memset(out, 0xcc, sizeof out);
    NTSTATUS s = UN(RtlQuerySecurityObject)(&a, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, out, sizeof out, &need);
    EXPECT_EQ(s, 0); EXPECT_EQ(need, 0x14 + 12);
    EXPECT_EQ(*(USHORT *)(out + 2) & (0x8000 | SE_DACL_PRESENT), 0x8000 | SE_DACL_PRESENT);
    EXPECT_EQ(*(ULONG *)(out + 16), 0);          /* NULL DACL => no offset */
    EXPECT_EQ(*(ULONG *)(out + 4), 0x14);
    CHECK(ADV(EqualSid)(out + 0x14, world));
    /* header bits not requested are not reported */
    s = UN(RtlQuerySecurityObject)(&a, OWNER_SECURITY_INFORMATION, out, sizeof out, &need);
    EXPECT_EQ(s, 0); CHECK(!(*(USHORT *)(out + 2) & SE_DACL_PRESENT));
    ADV(FreeSid)(world);
}

/* ---- UMS thread information (operates on a caller-supplied context block) ---------------- */
UDECL(NTSTATUS, RtlQueryUmsThreadInformation, (PVOID, ULONG, PVOID, ULONG, PULONG));

TEST(qs_ums_thread_information) {
    REQUIRE(UN(RtlQueryUmsThreadInformation));
    static BYTE ctx[0x600];
    memset(ctx, 0, sizeof ctx);
    *(ULONG64 *)(ctx + 0x4e8) = 0x1122334455667788ULL;   /* UmsThreadContext */
    *(ULONG64 *)(ctx + 0x4e0) = 0x8877665544332211ULL;   /* UmsThreadTeb */
    *(ULONG *)(ctx + 0x4f0) = 0x2;                       /* bit1: suspended */
    ULONG64 v = 0; ULONG rl = 0x55; NTSTATUS s;
    s = UN(RtlQueryUmsThreadInformation)(ctx, 1, &v, 8, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(v, 0x1122334455667788ULL); EXPECT_EQ(rl, 8);
    v = 0; rl = 0x55; s = UN(RtlQueryUmsThreadInformation)(ctx, 4, &v, 8, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(v, 0x8877665544332211ULL); EXPECT_EQ(rl, 8);
    BYTE b = 9; rl = 0x55; s = UN(RtlQueryUmsThreadInformation)(ctx, 5, &b, 1, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(b, 1); EXPECT_EQ(rl, 1);
    b = 9; rl = 0x55; s = UN(RtlQueryUmsThreadInformation)(ctx, 6, &b, 1, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(b, 0); EXPECT_EQ(rl, 1);
    *(ULONG *)(ctx + 0x4f0) = 0x8; b = 9;               /* bit3: terminated */
    s = UN(RtlQueryUmsThreadInformation)(ctx, 6, &b, 1, NULL); EXPECT_EQ(s, 0); EXPECT_EQ(b, 1);
    b = 9; s = UN(RtlQueryUmsThreadInformation)(ctx, 5, &b, 1, NULL); EXPECT_EQ(s, 0); EXPECT_EQ(b, 0);
    /* wrong size => STATUS_INFO_LENGTH_MISMATCH, return length cleared */
    rl = 0x55; s = UN(RtlQueryUmsThreadInformation)(ctx, 1, &v, 4, &rl); EXPECT_EQ(s, ST_LEN_MISMATCH); EXPECT_EQ(rl, 0);
    rl = 0x55; s = UN(RtlQueryUmsThreadInformation)(ctx, 1, &v, 16, &rl); EXPECT_EQ(s, ST_LEN_MISMATCH); EXPECT_EQ(rl, 0);
    rl = 0x55; s = UN(RtlQueryUmsThreadInformation)(ctx, 5, &b, 8, &rl); EXPECT_EQ(s, ST_LEN_MISMATCH);
    /* unsupported classes */
    for (ULONG cls = 0; cls <= 8; cls++) {
        if (cls == 1 || cls == 4 || cls == 5 || cls == 6) continue;
        rl = 0x55; s = UN(RtlQueryUmsThreadInformation)(ctx, cls, &v, 8, &rl);
        CHECKF(s == ST_NOT_SUPPORTED, "class %lu -> 0x%08lx", cls, (unsigned long)s);
        EXPECT_EQ(rl, 0);
    }
}

/* ---- policies --------------------------------------------------------------------- */
UDECL(NTSTATUS, RtlQueryProtectedPolicy, (const GUID *, PULONG_PTR));
UDECL(NTSTATUS, RtlQueryResourcePolicy, (ULONG, ULONG, PULONG, ULONG));
UDECL(NTSTATUS, RtlQueryImageMitigationPolicy, (PCWSTR, ULONG, ULONG, PVOID, ULONG));

TEST(qs_protected_policy) {
    REQUIRE(UN(RtlQueryProtectedPolicy));
    static const GUID g = {0x6ac9b3ab, 0x1f2e, 0x4a56, {0x9b, 0x0d, 0x31, 0x7f, 0x4c, 0x22, 0x91, 0x03}};
    ULONG_PTR v = 0x1234;
    NTSTATUS s = UN(RtlQueryProtectedPolicy)(&g, &v);
    EXPECT_EQ(s, ST_NOT_FOUND); EXPECT_EQ(v, 0x1234);
    GUID z; memset(&z, 0, sizeof z);
    s = UN(RtlQueryProtectedPolicy)(&z, &v); EXPECT_EQ(s, ST_NOT_FOUND);
}

TEST(qs_resource_policy) {
    REQUIRE(UN(RtlQueryResourcePolicy));
    ULONG v = 0xdead; NTSTATUS s;
    /* validation: NULL buffer, non-zero flags, wrong size => INVALID_PARAMETER; unknown type => INVALID_INFO_CLASS */
    s = UN(RtlQueryResourcePolicy)(0, 0, NULL, 4); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    s = UN(RtlQueryResourcePolicy)(0, 1, &v, 4); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    s = UN(RtlQueryResourcePolicy)(0, 0, &v, 8); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    s = UN(RtlQueryResourcePolicy)(0, 0, &v, 0); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    s = UN(RtlQueryResourcePolicy)(1, 0, &v, 3); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    s = UN(RtlQueryResourcePolicy)(4, 0, &v, 4); EXPECT_EQ(s, (NTSTATUS)0xC0000003);
    s = UN(RtlQueryResourcePolicy)(0x7fffffff, 0, &v, 4); EXPECT_EQ(s, (NTSTATUS)0xC0000003);
    s = UN(RtlQueryResourcePolicy)(4, 1, &v, 4); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    EXPECT_EQ(v, 0xdead);
    for (ULONG t = 0; t < 4; t++) {
        v = 0xdead; s = UN(RtlQueryResourcePolicy)(t, 0, &v, 4);
        t_note("RtlQueryResourcePolicy(%lu) = 0x%08lx value 0x%lx", t, (unsigned long)s, v);
    }
}

TEST(qs_image_mitigation_policy) {
    REQUIRE(UN(RtlQueryImageMitigationPolicy));
    BYTE buf[0x430]; NTSTATUS s;
    /* machine-wide (flag 4) with a name is invalid */
    s = UN(RtlQueryImageMitigationPolicy)(L"x.exe", 10, 4, buf, 0x18); EXPECT_EQ(s, ST_INVALID_PARAMETER);
    /* an image that has no Image File Execution Options key */
    memset(buf, 0xcc, sizeof buf);
    s = UN(RtlQueryImageMitigationPolicy)(L"ntdllt_no_such_image_for_policy_query.exe", 10, 0, buf, 0x18);
    t_note("unknown image policy status 0x%08lx", (unsigned long)s);
    CHECK(s < 0);
    /* machine-wide query of policy 10 needs a 0x18 byte buffer */
    s = UN(RtlQueryImageMitigationPolicy)(NULL, 10, 4, buf, 0x10);
    t_note("global policy 10 wrong size status 0x%08lx", (unsigned long)s);
    EXPECT_EQ(s, ST_INVALID_PARAMETER);
    memset(buf, 0xcc, sizeof buf);
    s = UN(RtlQueryImageMitigationPolicy)(NULL, 10, 4, buf, 0x18);
    t_note("global policy 10 status 0x%08lx", (unsigned long)s);
    if (s == 0) { ULONGLONG *q = (ULONGLONG *)buf; CHECK(q[0] <= 7 && q[1] <= 7 && q[2] <= 7); }
}

/* ---- heap ---------------------------------------------------------------------------- */
UDECL(NTSTATUS, RtlQueryHeapInformation, (PVOID, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(PWSTR, RtlQueryTagHeap, (PVOID, ULONG, USHORT, BOOLEAN, PVOID));
UDECL(PVOID, RtlCreateHeap, (ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID));
UDECL(PVOID, RtlDestroyHeap, (PVOID));

TEST(qs_heap_information) {
    REQUIRE(UN(RtlQueryHeapInformation)); REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap));
    PVOID h = UN(RtlCreateHeap)(2 /* HEAP_GROWABLE */, NULL, 0, 0, NULL, NULL);
    if (!h) { t_skip("RtlCreateHeap failed"); return; }
    ULONG v = 0xdead; SIZE_T rl = 0x55; NTSTATUS s;
    /* class 0: HeapCompatibilityInformation (0 = standard heap) */
    s = UN(RtlQueryHeapInformation)(h, 0, &v, 4, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(v, 0); EXPECT_EQ(rl, 4);
    v = 0xdead; s = UN(RtlQueryHeapInformation)(h, 0, &v, 4, NULL); EXPECT_EQ(s, 0); EXPECT_EQ(v, 0);
    rl = 0x55; v = 0xdead;
    s = UN(RtlQueryHeapInformation)(h, 0, &v, 3, &rl);
    t_note("heap class0 len 3: status 0x%08lx rl %llu", (unsigned long)s, (unsigned long long)rl);
    EXPECT_EQ(rl, 4); EXPECT_EQ(v, 0xdead);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL);
    rl = 0x55; s = UN(RtlQueryHeapInformation)(h, 0, NULL, 0, &rl); EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(rl, 4);
    /* process heap reports standard (0) or low-fragmentation (2) */
    HANDLE ph = GetProcessHeap(); v = 0xdead;
    s = UN(RtlQueryHeapInformation)(ph, 0, &v, 4, &rl);
    EXPECT_EQ(s, 0); CHECKF(v == 0 || v == 2, "process heap compat %lu", v);
    /* class 0x80000001: pointer to the global heap-failure information */
    ULONG_PTR p = 0; rl = 0x55;
    s = UN(RtlQueryHeapInformation)(h, 0x80000001, &p, 8, &rl);
    t_note("class 0x80000001 status 0x%08lx rl %llu p %p", (unsigned long)s, (unsigned long long)rl, (void *)p);
    EXPECT_EQ(rl, 8); if (s == 0) CHECK(p != 0);
    rl = 0x55; s = UN(RtlQueryHeapInformation)(h, 0x80000001, &p, 4, &rl); EXPECT_EQ(rl, 8); CHECK(s != 0);
    /* unsupported classes */
    for (ULONG cls = 1; cls <= 3; cls++) {
        if (cls == 2) continue;
        s = UN(RtlQueryHeapInformation)(h, cls, &v, 4, &rl);
        t_note("class %lu status 0x%08lx", cls, (unsigned long)s);
        CHECK(s < 0);
    }
    UN(RtlDestroyHeap)(h);
}

TEST(qs_tag_heap) {
    REQUIRE(UN(RtlQueryTagHeap)); REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap));
    BYTE *peb = *(BYTE **)((BYTE *)NtCurrentTeb() + 0x60);
    ULONG gflags = *(ULONG *)(peb + 0xbc);
    if (gflags & 0x800) { t_skip("heap tagging enabled in NtGlobalFlag"); return; }
    BYTE info[24]; memset(info, 0xcc, sizeof info);
    /* tag queries return NULL unless heap tagging (FLG_HEAP_ENABLE_TAGGING) is on */
    CHECK(UN(RtlQueryTagHeap)(GetProcessHeap(), 0, 1, FALSE, info) == NULL);
    EXPECT_EQ(info[0], 0xcc);
    PVOID h = UN(RtlCreateHeap)(2, NULL, 0, 0, NULL, NULL);
    if (h) { CHECK(UN(RtlQueryTagHeap)(h, 0, 0, TRUE, info) == NULL); UN(RtlDestroyHeap)(h); }
}


/* ---- module information (system module list) ---------------------------------------------- */
UDECL(NTSTATUS, RtlQueryModuleInformation, (PULONG, ULONG, PVOID));

TEST(qs_module_information) {
    REQUIRE(UN(RtlQueryModuleInformation));
    ULONG len = 0xdead; NTSTATUS s;
    /* size query (no buffer) for the 8-byte-per-module form */
    s = UN(RtlQueryModuleInformation)(&len, 8, NULL);
    t_note("size query (8): status 0x%08lx len %lu", (unsigned long)s, len);
    if (s != 0) { t_skip("system module list unavailable: 0x%08lx", (unsigned long)s); return; }
    CHECK(len >= 8 && len % 8 == 0);
    ULONG count = len / 8; CHECK(count >= 1);
    PVOID *bases = (PVOID *)calloc(count + 8, sizeof(PVOID));
    ULONG len2 = (count + 8) * 8;
    s = UN(RtlQueryModuleInformation)(&len2, 8, bases);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(len2, count * 8);
    CHECK(bases[0] != NULL);
    /* kernel-mode module bases live in the upper half of the address space */
    CHECK((ULONG_PTR)bases[0] >= 0xffff800000000000ULL);
    CHECK(bases[count] == NULL);
    /* the 0x110-byte form: ImageBase(8) ImageSize(4) OffsetToFileName(2) FullPathName[256]; first module is the kernel */
    len = 0; s = UN(RtlQueryModuleInformation)(&len, 0x110, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(len, count * 0x110);
    BYTE *big = (BYTE *)calloc(count + 2, 0x110);
    len2 = (count + 2) * 0x110;
    s = UN(RtlQueryModuleInformation)(&len2, 0x110, big);
    EXPECT_EQ(s, 0); EXPECT_EQ(len2, count * 0x110);
    CHECK(*(PVOID *)big == bases[0]);
    CHECK(*(ULONG *)(big + 8) > 0x10000);
    USHORT off = *(USHORT *)(big + 12);
    CHECK(off > 0 && off < 256);
    if (off > 0 && off < 256) CHECKF(!lstrcmpiA((char *)big + 0xe + off, "ntoskrnl.exe"), "first module file name %s", (char *)big + 0xe + off);
    /* output buffer must be 8-byte aligned */
    ULONG len3 = (count + 1) * 8;
    s = UN(RtlQueryModuleInformation)(&len3, 8, bases ? (PVOID)((BYTE *)bases + 4) : NULL);
    t_note("misaligned buffer: status 0x%08lx", (unsigned long)s);
    EXPECT_EQ(s, (NTSTATUS)0xC00000F1);
    /* an element size other than 8 or 0x110 is rejected */
    len3 = 0; s = UN(RtlQueryModuleInformation)(&len3, 16, bases);
    t_note("element size 16: status 0x%08lx", (unsigned long)s);
    EXPECT_EQ(s, (NTSTATUS)0xC00000F0);   /* STATUS_INVALID_PARAMETER_2 */
    free(big); free(bases);
}

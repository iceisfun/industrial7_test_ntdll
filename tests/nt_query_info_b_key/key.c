/* Registry query services on a private key under HKCU:
 * NtQueryKey, NtQueryValueKey, NtQueryMultipleValueKey, NtQueryOpenSubKeys, NtQueryOpenSubKeysEx.
 * The key holds two subkeys ("alpha", "beta_longer") and three values (REG_DWORD, REG_SZ, REG_BINARY).
 * Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, RtlOpenCurrentUser, (ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, RtlFormatCurrentUserKeyPath, (PUNICODE_STRING));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryKey, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryValueKey, (HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryMultipleValueKey, (HANDLE, PVOID, ULONG, PVOID, PULONG, PULONG));
UDECL(NTSTATUS, NtQueryOpenSubKeys, (POBJECT_ATTRIBUTES, PULONG));
UDECL(NTSTATUS, NtQueryOpenSubKeysEx, (POBJECT_ATTRIBUTES, ULONG, PVOID, PULONG));
UDECL(NTSTATUS, NtDuplicateObject, (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG));

#define S(x) ((NTSTATUS)(x))
#define ST_LEN_MISMATCH S(0xC0000004)
#define ST_INV_CLASS    S(0xC0000003)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_DENIED       S(0xC0000022)
#define ST_BUF_SMALL    S(0xC0000023)
#define ST_BUF_OVERFLOW S(0x80000005)
#define ST_INV_PARAM    S(0xC000000D)
#define ST_NAME_NOT_FOUND S(0xC0000034)
#define OBS(what, e) do { NTSTATUS os_ = (e); t_note("OBS %s: %08lx", what, (unsigned long)os_); } while (0)
#define CUR_PROC ((HANDLE)(LONG_PTR)-1)

static void alias(const char *n)
{
    char z[96];
    snprintf(z, sizeof z, "Zw%s", n + 2);
    CHECKF(t_proc(n) != NULL, "%s missing", n);
    CHECKF(t_proc(n) == t_proc(z), "%s and %s differ", n, z);
}
TEST(alias_pairs)
{
    static const char *n[] = { "NtQueryKey", "NtQueryValueKey", "NtQueryMultipleValueKey", "NtQueryOpenSubKeys", "NtQueryOpenSubKeysEx" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) alias(n[i]);
}

typedef struct { HANDLE root, key, sub1, sub2; WCHAR name[40]; USHORT nameLen; } FX;
static void us(UNICODE_STRING *u, WCHAR *w) { u->Buffer = w; u->Length = (USHORT)(lstrlenW(w) * 2); u->MaximumLength = u->Length + 2; }

static BOOL fx_make(FX *f)
{
    OBJECT_ATTRIBUTES oa; UNICODE_STRING n, cls; WCHAR a[] = L"alpha", b[] = L"beta_longer", c[] = L"MyClass";
    WCHAR v1[] = L"dw", v2[] = L"str", v3[] = L"bin"; WCHAR sz[] = L"hello"; DWORD dw = 0x12345678; BYTE bin[3] = { 1, 2, 3 };
    memset(f, 0, sizeof *f);
    if (!UN(RtlOpenCurrentUser) || !UN(NtCreateKey) || !UN(NtSetValueKey) || !UN(NtQueryKey)) return FALSE;
    if (UN(RtlOpenCurrentUser)(KEY_ALL_ACCESS, &f->root) != 0) return FALSE;
    wsprintfW(f->name, L"qib_key_%lu", GetCurrentProcessId()); f->nameLen = (USHORT)(lstrlenW(f->name) * 2);
    us(&n, f->name); us(&cls, c);
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, f->root, NULL);
    if (UN(NtCreateKey)(&f->key, KEY_ALL_ACCESS | DELETE, &oa, 0, &cls, 0, NULL) != 0) return FALSE;
    us(&n, a); InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, f->key, NULL);
    if (UN(NtCreateKey)(&f->sub1, KEY_ALL_ACCESS | DELETE, &oa, 0, NULL, 0, NULL) != 0) return FALSE;
    us(&n, b); InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, f->key, NULL);
    if (UN(NtCreateKey)(&f->sub2, KEY_ALL_ACCESS | DELETE, &oa, 0, NULL, 0, NULL) != 0) return FALSE;
    us(&n, v1); UN(NtSetValueKey)(f->key, &n, 0, REG_DWORD, &dw, 4);
    us(&n, v2); UN(NtSetValueKey)(f->key, &n, 0, REG_SZ, sz, sizeof sz);
    us(&n, v3); UN(NtSetValueKey)(f->key, &n, 0, REG_BINARY, bin, 3);
    return TRUE;
}
static void fx_free(FX *f)
{
    if (f->sub1) { UN(NtDeleteKey)(f->sub1); UN(NtClose)(f->sub1); }
    if (f->sub2) { UN(NtDeleteKey)(f->sub2); UN(NtClose)(f->sub2); }
    if (f->key) { UN(NtDeleteKey)(f->key); UN(NtClose)(f->key); }
    if (f->root) UN(NtClose)(f->root);
}
#define FX_START(f) FX f; do { if (!fx_make(&f)) { fx_free(&f); t_skip("cannot create a private key under HKCU"); return; } } while (0)

TEST(query_key_basic_name)
{
    BYTE buf[512]; ULONG ret; NTSTATUS st; FX_START(f);
    /* KeyBasicInformation (0): LastWriteTime, TitleIndex, NameLength, Name */
    memset(buf, 0xcc, sizeof buf); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryKey)(f.key, 0, buf, sizeof buf, &ret), 0);
    EXPECT_EQ(ret, 16 + f.nameLen);
    CHECK(*(LONGLONG *)buf > 0); EXPECT_EQ(*(ULONG *)(buf + 8), 0);
    EXPECT_EQ(*(ULONG *)(buf + 12), f.nameLen);
    CHECK(!memcmp(buf + 16, f.name, f.nameLen));
    /* too small for the fixed part */
    EXPECT_EQ(UN(NtQueryKey)(f.key, 0, buf, 15, &ret), ST_BUF_SMALL);
    EXPECT_EQ(ret, 16 + f.nameLen);
    /* fixed part fits, name truncated: BUFFER_OVERFLOW, partial name */
    memset(buf, 0xcc, sizeof buf);
    st = UN(NtQueryKey)(f.key, 0, buf, 16 + 4, &ret);
    EXPECT_EQ(st, ST_BUF_OVERFLOW); EXPECT_EQ(ret, 16 + f.nameLen);
    EXPECT_EQ(*(ULONG *)(buf + 12), f.nameLen);
    CHECK(!memcmp(buf + 16, f.name, 4));
    /* KeyNameInformation (3): full path */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryKey)(f.key, 3, buf, sizeof buf, &ret), 0);
    {
        ULONG nl = *(ULONG *)buf; WCHAR *p = (WCHAR *)(buf + 4);
        EXPECT_EQ(ret, 4 + nl);
        CHECK(nl > f.nameLen + 20);
        CHECK(!_wcsnicmp(p, L"\\REGISTRY\\USER\\", 15));
        CHECK(nl >= f.nameLen + 2 && !memcmp((BYTE *)p + nl - f.nameLen, f.name, f.nameLen) && p[(nl - f.nameLen) / 2 - 1] == L'\\');
        EXPECT_EQ(UN(NtQueryKey)(f.key, 3, buf, 3, &ret), ST_BUF_SMALL);
        EXPECT_EQ(ret, 4 + nl);
        st = UN(NtQueryKey)(f.key, 3, buf, 4 + 6, &ret);
        EXPECT_EQ(st, ST_BUF_OVERFLOW); EXPECT_EQ(ret, 4 + nl);
    }
    /* subkey name information is the same path plus the leaf */
    {
        ULONG k, s; BYTE b2[512];
        EXPECT_EQ(UN(NtQueryKey)(f.key, 3, buf, sizeof buf, &ret), 0); k = *(ULONG *)buf;
        EXPECT_EQ(UN(NtQueryKey)(f.sub1, 3, b2, sizeof b2, &ret), 0); s = *(ULONG *)b2;
        EXPECT_EQ(s, k + 2 + 10);
    }
    /* classes, handles, access */
    EXPECT_EQ(UN(NtQueryKey)(f.key, 0x100, buf, sizeof buf, &ret), ST_INV_PARAM);   /* observed: not INVALID_INFO_CLASS */
    EXPECT_EQ(UN(NtQueryKey)(f.key, 0xFFFF, buf, sizeof buf, &ret), ST_INV_PARAM);
    EXPECT_EQ(UN(NtQueryKey)(NULL, 0, buf, sizeof buf, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryKey)((HANDLE)(ULONG_PTR)0x7ffc, 0, buf, sizeof buf, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryKey)(CUR_PROC, 0, buf, sizeof buf, &ret), ST_TYPE_MISM);
    {
        HANDLE d = NULL;
        EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, f.key, CUR_PROC, &d, READ_CONTROL, 0, 0), 0);
        if (d) {
            EXPECT_EQ(UN(NtQueryKey)(d, 0, buf, sizeof buf, &ret), ST_DENIED);
            UN(NtClose)(d);
        }
    }
    fx_free(&f);
}

TEST(query_key_full_cached)
{
    BYTE buf[512]; ULONG ret; NTSTATUS st; FX_START(f);
    /* KeyFullInformation (2) */
    memset(buf, 0xcc, sizeof buf); ret = 0xdead;
    st = UN(NtQueryKey)(f.key, 2, buf, sizeof buf, &ret);
    EXPECT_EQ(st, 0);
    {
        ULONG *u = (ULONG *)(buf + 8);   /* TitleIndex, ClassOffset, ClassLength, SubKeys, MaxNameLen, MaxClassLen, Values, MaxValueNameLen, MaxValueDataLen */
        CHECK(*(LONGLONG *)buf > 0);
        EXPECT_EQ(u[2], 14);                     /* ClassLength: "MyClass" */
        EXPECT_EQ(u[3], 2);                      /* SubKeys */
        EXPECT_EQ(u[4], 22);                     /* MaxNameLen: "beta_longer" */
        EXPECT_EQ(u[5], 0);                      /* MaxClassLen: subkeys have no class */
        EXPECT_EQ(u[6], 3);                      /* Values */
        EXPECT_EQ(u[7], 6);                      /* MaxValueNameLen: "str"/"bin" */
        EXPECT_EQ(u[8], 12);                     /* MaxValueDataLen: "hello" + NUL */
        t_note("FullInformation ClassOffset=%lu ret=%lu", u[1], ret);
        CHECK(u[1] >= 44 && u[1] + u[2] <= ret);
        if (u[1] >= 44 && u[1] + u[2] <= sizeof buf) CHECK(!memcmp(buf + u[1], L"MyClass", 14));
        EXPECT_EQ(ret, u[1] + u[2]);
    }
    EXPECT_EQ(UN(NtQueryKey)(f.key, 2, buf, 43, &ret), ST_BUF_SMALL);
    st = UN(NtQueryKey)(f.key, 2, buf, 44 + 4, &ret);
    EXPECT_EQ(st, ST_BUF_OVERFLOW);
    /* leaf key without class: no class data, no subkeys, no values */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryKey)(f.sub1, 2, buf, sizeof buf, &ret), 0);
    { ULONG *u = (ULONG *)(buf + 8); EXPECT_EQ(u[2], 0); EXPECT_EQ(u[3], 0); EXPECT_EQ(u[4], 0); EXPECT_EQ(u[6], 0); EXPECT_EQ(u[7], 0); EXPECT_EQ(u[8], 0); }
    /* KeyCachedInformation (4): counts only */
    memset(buf, 0xcc, sizeof buf);
    st = UN(NtQueryKey)(f.key, 4, buf, sizeof buf, &ret);
    EXPECT_EQ(st, 0);
    t_note("CachedInformation ret=%lu", ret);
    if (st == 0) {
        ULONG *u = (ULONG *)(buf + 8);   /* TitleIndex, SubKeys, MaxNameLen, MaxClassLen... layout: TitleIndex, SubKeys, MaxNameLen, Values, MaxValueNameLen, MaxValueDataLen, NameLength */
        EXPECT_EQ(u[1], 2); EXPECT_EQ(u[2], 22); EXPECT_EQ(u[3], 3); EXPECT_EQ(u[4], 6); EXPECT_EQ(u[5], 12); EXPECT_EQ(u[6], f.nameLen);
        EXPECT_EQ(ret, 40);
        EXPECT_EQ(UN(NtQueryKey)(f.key, 4, buf, ret - 1, &ret), ST_BUF_SMALL);
    }
    /* KeyFlagsInformation (5) */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryKey)(f.key, 5, buf, sizeof buf, &ret), 0); EXPECT_EQ(ret, 12); EXPECT_EQ(*(ULONG *)buf, 0);          /* observed sizes */
    EXPECT_EQ(UN(NtQueryKey)(f.key, 6, buf, sizeof buf, &ret), 0); EXPECT_EQ(ret, 4); EXPECT_EQ(*(ULONG *)buf, 0);
    EXPECT_EQ(UN(NtQueryKey)(f.key, 7, buf, sizeof buf, &ret), 0); EXPECT_EQ(ret, 4); EXPECT_EQ(*(ULONG *)buf, 0);
    EXPECT_EQ(UN(NtQueryKey)(f.key, 8, buf, sizeof buf, &ret), 0); EXPECT_EQ(ret, 4); EXPECT_EQ(*(ULONG *)buf, 0);
    EXPECT_EQ(UN(NtQueryKey)(f.key, 9, buf, sizeof buf, &ret), ST_INV_PARAM);
    fx_free(&f);
}

/* ---- values ---- */
TEST(query_value_key)
{
    BYTE buf[512]; ULONG ret; UNICODE_STRING n; NTSTATUS st; WCHAR dw[] = L"dw", str[] = L"str", bin[] = L"bin", up[] = L"STR", none[] = L"missing";
    FX_START(f);
    /* KeyValuePartialInformation (2): TitleIndex, Type, DataLength, Data */
    us(&n, dw); memset(buf, 0xcc, sizeof buf); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, sizeof buf, &ret), 0);
    EXPECT_EQ(ret, 12 + 4); EXPECT_EQ(*(ULONG *)(buf + 4), REG_DWORD); EXPECT_EQ(*(ULONG *)(buf + 8), 4); EXPECT_EQ(*(ULONG *)(buf + 12), 0x12345678);
    us(&n, str);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, sizeof buf, &ret), 0);
    EXPECT_EQ(ret, 12 + 12); EXPECT_EQ(*(ULONG *)(buf + 4), REG_SZ); EXPECT_EQ(*(ULONG *)(buf + 8), 12);
    CHECK(!memcmp(buf + 12, L"hello", 12));
    us(&n, up);   /* names are case-insensitive */
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, sizeof buf, &ret), 0);
    EXPECT_EQ(*(ULONG *)(buf + 4), REG_SZ);
    us(&n, bin);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, sizeof buf, &ret), 0);
    EXPECT_EQ(*(ULONG *)(buf + 4), REG_BINARY); EXPECT_EQ(*(ULONG *)(buf + 8), 3); EXPECT_EQ(buf[12], 1); EXPECT_EQ(buf[14], 3);
    /* undersized: < 12 is TOO_SMALL, data truncated is OVERFLOW; both report the needed size */
    us(&n, str);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, 11, &ret), ST_BUF_SMALL); EXPECT_EQ(ret, 24);
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, 14, &ret), ST_BUF_OVERFLOW); EXPECT_EQ(ret, 24);
    EXPECT_EQ(*(ULONG *)(buf + 8), 12);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, 24, &ret), 0);
    /* KeyValueBasicInformation (0): TitleIndex, Type, NameLength, Name */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 0, buf, sizeof buf, &ret), 0);
    EXPECT_EQ(ret, 12 + 6); EXPECT_EQ(*(ULONG *)(buf + 4), REG_SZ); EXPECT_EQ(*(ULONG *)(buf + 8), 6); CHECK(!memcmp(buf + 12, L"str", 6));
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 0, buf, 11, &ret), ST_BUF_SMALL);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 0, buf, 14, &ret), ST_BUF_OVERFLOW);
    /* KeyValueFullInformation (1): TitleIndex, Type, DataOffset, DataLength, NameLength, Name, data */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 1, buf, sizeof buf, &ret), 0);
    {
        ULONG *u = (ULONG *)buf;
        EXPECT_EQ(u[1], REG_SZ); EXPECT_EQ(u[3], 12); EXPECT_EQ(u[4], 6);
        CHECK(u[2] >= 20 + 6 && u[2] + u[3] <= ret); EXPECT_EQ(ret, u[2] + u[3]);
        CHECK(!memcmp(buf + 20, L"str", 6));
        if (u[2] + u[3] <= sizeof buf) CHECK(!memcmp(buf + u[2], L"hello", 12));
        EXPECT_EQ(u[2] % 4, 0);
    }
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 1, buf, 19, &ret), ST_BUF_SMALL);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 1, buf, 22, &ret), ST_BUF_OVERFLOW);
    /* Align64 variants (3, 4) */
    memset(buf, 0xcc, sizeof buf);
    st = UN(NtQueryValueKey)(f.key, &n, 4, buf, sizeof buf, &ret);
    EXPECT_EQ(st, 0);
    if (st == 0) { EXPECT_EQ(*(ULONG *)buf, REG_SZ); EXPECT_EQ(*(ULONG *)(buf + 4), 12); EXPECT_EQ(ret, 8 + 12); CHECK(!memcmp(buf + 8, L"hello", 12)); }   /* no TitleIndex */
    st = UN(NtQueryValueKey)(f.key, &n, 3, buf, sizeof buf, &ret);
    EXPECT_EQ(st, 0);
    if (st == 0) { ULONG *u = (ULONG *)buf; EXPECT_EQ(u[1], REG_SZ); EXPECT_EQ(u[3], 12); CHECK(u[2] % 8 == 0); }
    /* missing, bad class, handles, access */
    us(&n, none);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, sizeof buf, &ret), ST_NAME_NOT_FOUND);
    us(&n, str);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 0x100, buf, sizeof buf, &ret), ST_INV_PARAM);
    EXPECT_EQ(UN(NtQueryValueKey)(NULL, &n, 2, buf, sizeof buf, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryValueKey)(CUR_PROC, &n, 2, buf, sizeof buf, &ret), ST_TYPE_MISM);
    {
        HANDLE d = NULL;
        EXPECT_EQ(UN(NtDuplicateObject)(CUR_PROC, f.key, CUR_PROC, &d, KEY_ENUMERATE_SUB_KEYS, 0, 0), 0);
        if (d) { EXPECT_EQ(UN(NtQueryValueKey)(d, &n, 2, buf, sizeof buf, &ret), ST_DENIED); UN(NtClose)(d); }
    }
    fx_free(&f);
}

typedef struct { PUNICODE_STRING name; ULONG dataLen, dataOff, type; } KVENT;

TEST(query_multiple_value_key)
{
    KVENT e[3]; UNICODE_STRING n[3]; WCHAR a[] = L"dw", b[] = L"str", c[] = L"bin", m[] = L"missing"; BYTE buf[256]; ULONG len, ret; NTSTATUS st;
    FX_START(f);
    REQUIRE(UN(NtQueryMultipleValueKey));
    us(&n[0], a); us(&n[1], b); us(&n[2], c);
    e[0].name = &n[0]; e[1].name = &n[1]; e[2].name = &n[2];
    memset(buf, 0xcc, sizeof buf); len = sizeof buf; ret = 0xdead;
    st = UN(NtQueryMultipleValueKey)(f.key, e, 3, buf, &len, &ret);
    EXPECT_EQ(st, 0);
    t_note("multi: len=%lu ret=%lu offs %lu %lu %lu", len, ret, e[0].dataOff, e[1].dataOff, e[2].dataOff);
    EXPECT_EQ(e[0].type, REG_DWORD); EXPECT_EQ(e[0].dataLen, 4);
    EXPECT_EQ(e[1].type, REG_SZ); EXPECT_EQ(e[1].dataLen, 12);
    EXPECT_EQ(e[2].type, REG_BINARY); EXPECT_EQ(e[2].dataLen, 3);
    if (st == 0) {
        EXPECT_EQ(*(ULONG *)(buf + e[0].dataOff), 0x12345678);
        CHECK(!memcmp(buf + e[1].dataOff, L"hello", 12));
        EXPECT_EQ(buf[e[2].dataOff + 1], 2);
        CHECK(len >= 4 + 12 + 3 && len <= sizeof buf);
        EXPECT_EQ(ret, len);
    }
    /* too small: STATUS_BUFFER_OVERFLOW and the needed size in *len and *ret */
    len = 8; ret = 0;
    st = UN(NtQueryMultipleValueKey)(f.key, e, 3, buf, &len, &ret);
    EXPECT_EQ(st, ST_BUF_OVERFLOW);
    t_note("multi small: len=%lu ret=%lu", len, ret);
    CHECK(ret >= 4 + 12 + 3);
    /* missing value */
    n[1].Buffer = m; n[1].Length = 14; n[1].MaximumLength = 16; e[1].name = &n[1];
    len = sizeof buf;
    EXPECT_EQ(UN(NtQueryMultipleValueKey)(f.key, e, 3, buf, &len, &ret), ST_NAME_NOT_FOUND);
    EXPECT_EQ(UN(NtQueryMultipleValueKey)(NULL, e, 3, buf, &len, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryMultipleValueKey)(CUR_PROC, e, 3, buf, &len, &ret), ST_TYPE_MISM);
    fx_free(&f);
}

TEST(query_open_subkeys)
{
    UNICODE_STRING path; OBJECT_ATTRIBUTES oa; ULONG cnt = 0xdead, cnt2 = 0xdead; NTSTATUS st; FX_START(f);
    REQUIRE(UN(RtlFormatCurrentUserKeyPath));
    if (UN(RtlFormatCurrentUserKeyPath)(&path) != 0) { fx_free(&f); t_skip("no current-user key path"); return; }
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = UN(NtQueryOpenSubKeys)(&oa, &cnt);
    t_note("NtQueryOpenSubKeys(HKCU hive root): %08lx count=%lu", (unsigned long)st, (unsigned long)cnt);
    if (st == S(0xC0000061)) { t_skip("NtQueryOpenSubKeys needs a privilege not held: STATUS_PRIVILEGE_NOT_HELD"); }
    else {
        EXPECT_EQ(st, 0);
        /* our fixture holds at least 3 open key handles below the hive root (key + 2 subkeys), plus root */
        CHECK(cnt >= 3);
        { HANDLE x = NULL; OBJECT_ATTRIBUTES o2; UNICODE_STRING n; WCHAR w[] = L"alpha";
          us(&n, w); InitializeObjectAttributes(&o2, &n, OBJ_CASE_INSENSITIVE, f.key, NULL);
          if (UN(NtOpenKey)(&x, KEY_READ, &o2) == 0) {
              st = UN(NtQueryOpenSubKeys)(&oa, &cnt2);
              EXPECT_EQ(st, 0); EXPECT_EQ(cnt2, cnt + 1);
              UN(NtClose)(x);
              st = UN(NtQueryOpenSubKeys)(&oa, &cnt2);
              EXPECT_EQ(cnt2, cnt);
          } }
    }
    /* a missing key */
    {
        UNICODE_STRING n; WCHAR w[] = L"\\Registry\\Machine\\Software\\qib_no_such_key_xyz";
        us(&n, w); InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, NULL, NULL);
        EXPECT_EQ(UN(NtQueryOpenSubKeys)(&oa, &cnt), ST_NAME_NOT_FOUND);
    }
    /* a non-hive-root key */
    {
        UNICODE_STRING n; WCHAR w[] = L"\\Registry\\Machine\\Software\\Microsoft";
        us(&n, w); InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, NULL, NULL);
        EXPECT_EQ(UN(NtQueryOpenSubKeys)(&oa, &cnt), ST_INV_PARAM);
    }
    UN(RtlFreeUnicodeString)(&path);
    fx_free(&f);
}

UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));

TEST(query_open_subkeys_ex)
{
    UNICODE_STRING path; OBJECT_ATTRIBUTES oa; BYTE hdr[64]; BYTE *buf = NULL; ULONG req = 0xdead, cap; NTSTATUS st; BOOLEAN old = 0; FX_START(f);
    REQUIRE(UN(NtQueryOpenSubKeysEx)); REQUIRE(UN(RtlFormatCurrentUserKeyPath)); REQUIRE(UN(RtlAdjustPrivilege));
    if (UN(RtlFormatCurrentUserKeyPath)(&path) != 0) { fx_free(&f); t_skip("no current-user key path"); return; }
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    memset(hdr, 0xcc, sizeof hdr);
    st = UN(NtQueryOpenSubKeysEx)(&oa, sizeof hdr, hdr, &req);
    EXPECT_EQ(st, S(0xC0000061) /* STATUS_PRIVILEGE_NOT_HELD: SeRestorePrivilege is required */);
    if (UN(RtlAdjustPrivilege)(18 /* SeRestorePrivilege */, TRUE, FALSE, &old) != 0) {
        UN(RtlFreeUnicodeString)(&path); fx_free(&f);
        t_skip("SeRestorePrivilege cannot be enabled for this token (STATUS_PRIVILEGE_NOT_HELD)");
        return;
    }
    /* header-only buffer: BUFFER_OVERFLOW with the required size */
    memset(hdr, 0xcc, sizeof hdr); req = 0xdead;
    st = UN(NtQueryOpenSubKeysEx)(&oa, 8, hdr, &req);
    EXPECT_EQ(st, ST_BUF_OVERFLOW);
    t_note("Ex: required %lu", (unsigned long)req);
    CHECK(req > 8 + 24 * 3);
    cap = (req + 0x10000) & ~1u;
    buf = (BYTE *)VirtualAlloc(NULL, cap, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(buf != NULL);
    if (buf) {
        memset(buf, 0xcc, 64); req = 0xdead;
        st = UN(NtQueryOpenSubKeysEx)(&oa, cap, buf, &req);
        EXPECT_EQ(st, 0);
        if (st == 0) {
            ULONG n = *(ULONG *)buf, i; int mine = 0, named = 0;
            t_note("Ex: count=%lu req=%lu", n, req);
            CHECK(n >= 3 && n < 5000);
            CHECK(req >= 8 + 24 * 3 && req <= cap);
            for (i = 0; i < n && i < 5000; i++) {
                BYTE *e = buf + 8 + 24 * i; UNICODE_STRING *u = (UNICODE_STRING *)(e + 8);
                if (*(ULONG *)e == GetCurrentProcessId()) mine++;
                if (u->Length >= 18 && (BYTE *)u->Buffer >= buf && (BYTE *)u->Buffer + u->Length <= buf + cap) {
                    size_t k, L = u->Length / 2; for (k = 0; k + 8 <= L; k++) if (!_wcsnicmp(u->Buffer + k, L"qib_key_", 8)) { named++; break; }
                }
            }
            CHECK(mine >= 3); CHECK(named >= 3);
        }
        /* odd, tiny and too-small lengths */
        EXPECT_EQ(UN(NtQueryOpenSubKeysEx)(&oa, 7, buf, &req), ST_BUF_SMALL);
        EXPECT_EQ(UN(NtQueryOpenSubKeysEx)(&oa, 13, buf, &req), ST_INV_PARAM);
        { UNICODE_STRING n; WCHAR w[] = L"\\Registry\\Machine\\Software\\Microsoft";
          us(&n, w); InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, NULL, NULL);
          EXPECT_EQ(UN(NtQueryOpenSubKeysEx)(&oa, cap, buf, &req), ST_INV_PARAM); }   /* not a hive root */
        VirtualFree(buf, 0, MEM_RELEASE);
    }
    UN(RtlAdjustPrivilege)(18, old, FALSE, &old);
    UN(RtlFreeUnicodeString)(&path);
    fx_free(&f);
}

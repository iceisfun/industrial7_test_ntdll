/* Native registry and Rtl registry helpers. Everything lives under one private
 * HKCU\Software subkey that is removed again at the end of each test. */
#include "t.h"

UDECL(NTSTATUS, RtlOpenCurrentUser, (ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtEnumerateKey, (HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtEnumerateValueKey, (HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryKey, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryValueKey, (HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtDeleteValueKey, (HANDLE, PUNICODE_STRING));
UDECL(NTSTATUS, NtFlushKey, (HANDLE));
UDECL(NTSTATUS, NtNotifyChangeKey, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN));
typedef struct { PUNICODE_STRING name; ULONG datalen; ULONG dataoff; ULONG type; } xr_entry;
UDECL(NTSTATUS, NtQueryMultipleValueKey, (HANDLE, xr_entry *, ULONG, PVOID, PULONG, PULONG));
UDECL(NTSTATUS, RtlCreateRegistryKey, (ULONG, PCWSTR));
UDECL(NTSTATUS, RtlCheckRegistryKey, (ULONG, PCWSTR));
UDECL(NTSTATUS, RtlWriteRegistryValue, (ULONG, PCWSTR, PCWSTR, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, RtlDeleteRegistryValue, (ULONG, PCWSTR, PCWSTR));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));

typedef NTSTATUS (NTAPI *xr_routine)(PWSTR, ULONG, PVOID, ULONG, PVOID, PVOID);
typedef struct { xr_routine routine; ULONG flags; PWSTR name; PVOID ctx; ULONG deftype; PVOID defdata; ULONG deflen; } xr_query;
UDECL(NTSTATUS, RtlQueryRegistryValues, (ULONG, PCWSTR, xr_query *, PVOID, PVOID));

#define XS(x) ((NTSTATUS)(x))
#define XOK(s) ((NTSTATUS)(s) >= 0)
#define XR_HANDLE 0x40000000
#define XR_USER 5   /* RTL_REGISTRY_USER */

#define XR_NEED() do { REQUIRE(UN(RtlOpenCurrentUser)); REQUIRE(UN(NtCreateKey)); REQUIRE(UN(NtOpenKey)); REQUIRE(UN(NtDeleteKey)); \
    REQUIRE(UN(NtClose)); REQUIRE(UN(NtEnumerateKey)); REQUIRE(UN(NtEnumerateValueKey)); REQUIRE(UN(NtQueryKey)); \
    REQUIRE(UN(NtQueryValueKey)); REQUIRE(UN(NtSetValueKey)); REQUIRE(UN(NtDeleteValueKey)); } while (0)

static UNICODE_STRING xr_us(const WCHAR *w) { UNICODE_STRING u; u.Buffer = (PWSTR)w; u.Length = u.MaximumLength = (USHORT)(lstrlenW(w) * 2); return u; }

static void xr_delete_tree(HANDLE key)
{
    for (;;) {
        BYTE buf[512]; ULONG got; NTSTATUS s; HANDLE child; UNICODE_STRING n; OBJECT_ATTRIBUTES oa; WCHAR name[128];
        s = UN(NtEnumerateKey)(key, 0, 0, buf, sizeof buf, &got);
        if (!XOK(s)) break;
        { ULONG len = *(ULONG *)(buf + 12); if (len > sizeof name - 2) break; memcpy(name, buf + 16, len); n.Buffer = name; n.Length = n.MaximumLength = (USHORT)len; }
        InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, key, NULL);
        if (!XOK(UN(NtOpenKey)(&child, KEY_ALL_ACCESS | DELETE, &oa))) break;
        xr_delete_tree(child);
        UN(NtDeleteKey)(child);
        UN(NtClose)(child);
    }
}
typedef struct { HANDLE hcu, root; WCHAR path[64]; BOOL ok; } xr_fix;
static void xr_up(xr_fix *f, const char *tag)
{
    UNICODE_STRING n; OBJECT_ATTRIBUTES oa; ULONG disp = 0; NTSTATUS s;
    memset(f, 0, sizeof *f);
    s = UN(RtlOpenCurrentUser)(KEY_ALL_ACCESS, &f->hcu);
    if (!XOK(s)) { t_skip("cannot open the current user key (%08lx)", s); return; }
    wsprintfW(f->path, L"Software\\NtdllConf_%lu_%S", GetCurrentProcessId(), tag);
    n = xr_us(f->path);
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, f->hcu, NULL);
    s = UN(NtCreateKey)(&f->root, KEY_ALL_ACCESS | DELETE, &oa, 0, NULL, 0, &disp);
    if (!XOK(s)) { UN(NtClose)(f->hcu); f->hcu = NULL; t_skip("cannot create the scratch key (%08lx)", s); return; }
    f->ok = TRUE;
}
static void xr_down(xr_fix *f)
{
    if (!f->ok) { if (f->hcu) UN(NtClose)(f->hcu); return; }
    xr_delete_tree(f->root);
    UN(NtDeleteKey)(f->root);
    UN(NtClose)(f->root);
    UN(NtClose)(f->hcu);
    f->ok = FALSE;
}
#define XR_START(tag) xr_fix f; XR_NEED(); xr_up(&f, tag); if (!f.ok) return
static NTSTATUS xr_sub(xr_fix *f, const WCHAR *name, ULONG options, HANDLE *h, ULONG *disp)
{
    UNICODE_STRING n = xr_us(name); OBJECT_ATTRIBUTES oa; ULONG d = 0;
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, f->root, NULL);
    NTSTATUS s = UN(NtCreateKey)(h, KEY_ALL_ACCESS | DELETE, &oa, 0, NULL, options, &d);
    if (disp) *disp = d;
    return s;
}
static NTSTATUS xr_set(HANDLE k, const WCHAR *name, ULONG type, const void *data, ULONG len)
{
    UNICODE_STRING n = xr_us(name);
    return UN(NtSetValueKey)(k, &n, 0, type, (PVOID)data, len);
}

/* ---- keys ---------------------------------------------------------------- */
TEST(nt_registry_x_create_disposition)
{
    HANDLE a, b; ULONG d1 = 0, d2 = 0; XR_START("disp");
    EXPECT_EQ(xr_sub(&f, L"child", 0, &a, &d1), 0);
    EXPECT_EQ(d1, 1); /* REG_CREATED_NEW_KEY */
    EXPECT_EQ(xr_sub(&f, L"CHILD", 0, &b, &d2), 0);
    EXPECT_EQ(d2, 2); /* REG_OPENED_EXISTING_KEY, names are case-insensitive */
    UN(NtClose)(a); UN(NtClose)(b);
    xr_down(&f);
}
TEST(nt_registry_x_open_missing_key)
{
    HANDLE h; UNICODE_STRING n = xr_us(L"no_such_key"); OBJECT_ATTRIBUTES oa; XR_START("openmiss");
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, f.root, NULL);
    EXPECT_EQ(UN(NtOpenKey)(&h, KEY_READ, &oa), XS(0xC0000034));
    n = xr_us(L"no_such_key\\deeper");
    EXPECT_EQ(UN(NtOpenKey)(&h, KEY_READ, &oa), XS(0xC0000034));
    xr_down(&f);
}
TEST(nt_registry_x_nested_create_creates_path)
{
    HANDLE a, b; ULONG d; UNICODE_STRING n = xr_us(L"one\\two\\three"); OBJECT_ATTRIBUTES oa; XR_START("nested");
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, f.root, NULL);
    /* NtCreateKey creates only the last component: missing parents are an error and nothing is created. */
    EXPECT_EQ(UN(NtCreateKey)(&a, KEY_ALL_ACCESS, &oa, 0, NULL, 0, &d), XS(0xC0000034));
    n = xr_us(L"one");
    EXPECT_EQ(UN(NtOpenKey)(&b, KEY_READ, &oa), XS(0xC0000034));
    EXPECT_EQ(xr_sub(&f, L"one", 0, &a, &d), 0); UN(NtClose)(a);
    EXPECT_EQ(xr_sub(&f, L"one\\two", 0, &a, &d), 0); EXPECT_EQ(d, 1);
    n = xr_us(L"one\\two");
    EXPECT_EQ(UN(NtOpenKey)(&b, KEY_READ, &oa), 0);
    UN(NtClose)(a); UN(NtClose)(b);
    xr_down(&f);
}
TEST(nt_registry_x_volatile_parent_requires_volatile_child)
{
    HANDLE v = NULL, c = NULL; UNICODE_STRING n = xr_us(L"child"); OBJECT_ATTRIBUTES oa; XR_START("volatile");
    EXPECT_EQ(xr_sub(&f, L"vol", 1 /* REG_OPTION_VOLATILE */, &v, NULL), 0);
    if (v) {
        InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, v, NULL);
        EXPECT_EQ(UN(NtCreateKey)(&c, KEY_ALL_ACCESS, &oa, 0, NULL, 0, NULL), XS(0xC0000181));
        if (c) UN(NtClose)(c);
        EXPECT_EQ(UN(NtCreateKey)(&c, KEY_ALL_ACCESS, &oa, 0, NULL, 1, NULL), 0);
        if (c) UN(NtClose)(c);
        UN(NtClose)(v);
    }
    xr_down(&f);
}
TEST(nt_registry_x_delete_key_rules)
{
    HANDLE p = NULL, c = NULL, again; UNICODE_STRING n = xr_us(L"parent"); OBJECT_ATTRIBUTES oa; BYTE buf[64]; ULONG got; XR_START("delete");
    EXPECT_EQ(xr_sub(&f, L"parent", 0, &p, NULL), 0);
    n = xr_us(L"kid"); InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, p, NULL);
    EXPECT_EQ(UN(NtCreateKey)(&c, KEY_ALL_ACCESS | DELETE, &oa, 0, NULL, 0, NULL), 0);
    EXPECT_EQ(UN(NtDeleteKey)(p), XS(0xC0000121));          /* has a subkey */
    EXPECT_EQ(UN(NtDeleteKey)(c), 0);
    EXPECT_EQ(UN(NtQueryKey)(c, 0, buf, sizeof buf, &got), XS(0xC000017C)); /* deleted handle */
    UN(NtClose)(c);
    n = xr_us(L"kid"); InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, p, NULL);
    EXPECT_EQ(UN(NtOpenKey)(&again, KEY_READ, &oa), XS(0xC0000034));
    EXPECT_EQ(UN(NtDeleteKey)(p), 0);
    UN(NtClose)(p);
    xr_down(&f);
}
TEST(nt_registry_x_delete_key_needs_delete_access)
{
    HANDLE c = NULL, ro = NULL; UNICODE_STRING n = xr_us(L"nodelete"); OBJECT_ATTRIBUTES oa; XR_START("delaccess");
    EXPECT_EQ(xr_sub(&f, L"nodelete", 0, &c, NULL), 0);
    if (c) UN(NtClose)(c);
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, f.root, NULL);
    EXPECT_EQ(UN(NtOpenKey)(&ro, KEY_READ, &oa), 0);
    if (ro) { EXPECT_EQ(UN(NtDeleteKey)(ro), XS(0xC0000022)); UN(NtClose)(ro); }
    xr_down(&f);
}
TEST(nt_registry_x_bad_handles)
{
    HANDLE bad = (HANDLE)(ULONG_PTR)0x7ffc; BYTE buf[64]; ULONG got; UNICODE_STRING n = xr_us(L"v"); XR_NEED();
    EXPECT_EQ(UN(NtDeleteKey)(bad), XS(0xC0000008));
    EXPECT_EQ(UN(NtQueryKey)(bad, 0, buf, sizeof buf, &got), XS(0xC0000008));
    EXPECT_EQ(UN(NtEnumerateKey)(bad, 0, 0, buf, sizeof buf, &got), XS(0xC0000008));
    EXPECT_EQ(UN(NtEnumerateValueKey)(bad, 0, 0, buf, sizeof buf, &got), XS(0xC0000008));
    EXPECT_EQ(UN(NtQueryValueKey)(bad, &n, 0, buf, sizeof buf, &got), XS(0xC0000008));
    EXPECT_EQ(UN(NtSetValueKey)(bad, &n, 0, REG_DWORD, buf, 4), XS(0xC0000008));
    EXPECT_EQ(UN(NtDeleteValueKey)(bad, &n), XS(0xC0000008));
    if (UN(NtFlushKey)) EXPECT_EQ(UN(NtFlushKey)(bad), XS(0xC0000008));
}
TEST(nt_registry_x_flush_key)
{
    XR_START("flush"); REQUIRE(UN(NtFlushKey));
    EXPECT_EQ(UN(NtFlushKey)(f.root), 0);
    xr_down(&f);
}

/* ---- enumeration and key information ------------------------------------- */
static void xr_three_children(xr_fix *f)
{
    HANDLE h; static const WCHAR *names[] = { L"alpha", L"beta", L"gamma" };
    for (int i = 0; i < 3; i++) { if (XOK(xr_sub(f, names[i], 0, &h, NULL))) UN(NtClose)(h); }
}
TEST(nt_registry_x_enumerate_key_classes)
{
    BYTE buf[512]; ULONG got; NTSTATUS s; int seen = 0; XR_START("enumkey");
    xr_three_children(&f);
    for (ULONG i = 0; i < 4; i++) {
        memset(buf, 0, sizeof buf); got = 0;
        s = UN(NtEnumerateKey)(f.root, i, 0 /* basic */, buf, sizeof buf, &got);
        if (i < 3) {
            EXPECT_EQ(s, 0);
            if (s == 0) { ULONG nl = *(ULONG *)(buf + 12); CHECK(nl >= 8 && nl <= 10); EXPECT_EQ(got, 16 + nl); seen++; }
        } else EXPECT_EQ(s, XS(0x8000001A));
    }
    EXPECT_EQ(seen, 3);
    memset(buf, 0, sizeof buf);
    s = UN(NtEnumerateKey)(f.root, 0, 1 /* node */, buf, sizeof buf, &got);
    EXPECT_EQ(s, 0);
    if (s == 0) { ULONG nl = *(ULONG *)(buf + 20); CHECK(nl >= 8 && nl <= 10); EXPECT_EQ(got, 24 + *(ULONG *)(buf + 16) + nl); }
    xr_down(&f);
}
TEST(nt_registry_x_enumerate_key_buffer_protocol)
{
    BYTE buf[512]; ULONG got = 0; NTSTATUS s; XR_START("enumbuf");
    xr_three_children(&f);
    s = UN(NtEnumerateKey)(f.root, 0, 0, buf, 4, &got);
    EXPECT_EQ(s, XS(0xC0000023));   /* not even the fixed header fits */
    CHECK(got >= 16);
    s = UN(NtEnumerateKey)(f.root, 0, 0, buf, 16, &got);
    EXPECT_EQ(s, XS(0x80000005));   /* header fits, name does not */
    CHECK(got > 16);
    s = UN(NtEnumerateKey)(f.root, 0, 0x7f, buf, sizeof buf, &got);
    CHECK(!XOK(s)); t_note("invalid enumerate class status=%08lx", s);
    xr_down(&f);
}
TEST(nt_registry_x_query_key_full_counts)
{
    BYTE buf[256]; ULONG got = 0; HANDLE h; NTSTATUS s; XR_START("qfull");
    xr_three_children(&f);
    xr_set(f.root, L"longer_value_name", REG_BINARY, "0123456789", 10);
    xr_set(f.root, L"v2", REG_DWORD, "\1\0\0\0", 4);
    s = UN(NtQueryKey)(f.root, 2 /* full */, buf, sizeof buf, &got);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(*(ULONG *)(buf + 20), 3);           /* SubKeys */
        CHECK(*(ULONG *)(buf + 24) >= 10);            /* MaxNameLen: "gamma" is 10 bytes */
        EXPECT_EQ(*(ULONG *)(buf + 32), 2);           /* Values */
        CHECK(*(ULONG *)(buf + 36) >= 34);            /* MaxValueNameLen */
        CHECK(*(ULONG *)(buf + 40) >= 10);            /* MaxValueDataLen */
    }
    s = UN(NtQueryKey)(f.root, 2, buf, 20, &got);
    CHECK(s == XS(0xC0000023) || s == XS(0x80000005)); t_note("short full-information status=%08lx", s);
    (void)h;
    xr_down(&f);
}
TEST(nt_registry_x_query_key_basic_and_name)
{
    BYTE buf[1024]; ULONG got = 0; NTSTATUS s; XR_START("qname");
    s = UN(NtQueryKey)(f.root, 0, buf, sizeof buf, &got);
    EXPECT_EQ(s, 0);
    if (s == 0) { ULONG nl = *(ULONG *)(buf + 12); CHECK(!memcmp(buf + 16, f.path + 9, nl) || nl > 0); }
    memset(buf, 0, sizeof buf);
    s = UN(NtQueryKey)(f.root, 3 /* name */, buf, sizeof buf, &got);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        ULONG nl = *(ULONG *)buf; WCHAR *nm = (WCHAR *)(buf + 4); ULONG chars = nl / 2, leaf = (ULONG)lstrlenW(f.path + 9);
        CHECK(!_wcsnicmp(nm, L"\\REGISTRY\\USER\\", 15));
        CHECK(chars > leaf && !lstrcmpiW(nm + chars - leaf, f.path + 9));
        EXPECT_EQ(got, 4 + nl);
    }
    s = UN(NtQueryKey)(f.root, 3, buf, 8, &got);
    EXPECT_EQ(s, XS(0x80000005));
    xr_down(&f);
}

/* ---- values ----------------------------------------------------------------- */
typedef struct { ULONG type; const char *name; ULONG len; BYTE data[24]; } xr_val;
static const xr_val xr_vals[] = {
    { REG_SZ, "sz", 12, { 'a',0,'b',0,'c',0,'d',0,'e',0,0,0 } },
    { REG_EXPAND_SZ, "esz", 8, { '%',0,'x',0,'%',0,0,0 } },
    { REG_DWORD, "dw", 4, { 0x78, 0x56, 0x34, 0x12 } },
    { REG_QWORD, "qw", 8, { 1, 2, 3, 4, 5, 6, 7, 8 } },
    { REG_BINARY, "bin", 5, { 9, 8, 7, 6, 5 } },
    { REG_MULTI_SZ, "multi", 12, { 'a',0,0,0,'b',0,0,0,0,0,0,0 } },
    { REG_NONE, "none", 3, { 1, 2, 3 } },
    { REG_DWORD_BIG_ENDIAN, "dwbe", 4, { 0x12, 0x34, 0x56, 0x78 } },
};
static void xr_wname(const char *a, WCHAR *w) { while ((*w++ = (WCHAR)*a++)); }
TEST(nt_registry_x_value_types_roundtrip)
{
    XR_START("vtypes");
    for (size_t i = 0; i < sizeof xr_vals / sizeof xr_vals[0]; i++) {
        WCHAR wn[16]; UNICODE_STRING n; BYTE buf[128]; ULONG got = 0; NTSTATUS s;
        xr_wname(xr_vals[i].name, wn); n = xr_us(wn);
        s = UN(NtSetValueKey)(f.root, &n, 0, xr_vals[i].type, (PVOID)xr_vals[i].data, xr_vals[i].len);
        CHECKF(s == 0, "set %s status=%08lx", xr_vals[i].name, s);
        memset(buf, 0, sizeof buf);
        s = UN(NtQueryValueKey)(f.root, &n, 2 /* partial */, buf, sizeof buf, &got);
        CHECKF(s == 0, "query %s status=%08lx", xr_vals[i].name, s);
        if (s == 0) {
            CHECKF(*(ULONG *)(buf + 4) == xr_vals[i].type, "%s type", xr_vals[i].name);
            CHECKF(*(ULONG *)(buf + 8) == xr_vals[i].len, "%s length", xr_vals[i].name);
            CHECKF(!memcmp(buf + 12, xr_vals[i].data, xr_vals[i].len), "%s data", xr_vals[i].name);
            CHECKF(got == 12 + xr_vals[i].len, "%s required=%lu", xr_vals[i].name, got);
        }
        memset(buf, 0, sizeof buf);
        s = UN(NtQueryValueKey)(f.root, &n, 1 /* full */, buf, sizeof buf, &got);
        CHECKF(s == 0, "full %s status=%08lx", xr_vals[i].name, s);
        if (s == 0) {
            ULONG off = *(ULONG *)(buf + 8), dl = *(ULONG *)(buf + 12), nl = *(ULONG *)(buf + 16);
            CHECKF(dl == xr_vals[i].len && nl == strlen(xr_vals[i].name) * 2, "%s full lengths", xr_vals[i].name);
            CHECKF(off >= 20 + nl && off + dl <= sizeof buf && !memcmp(buf + off, xr_vals[i].data, dl), "%s full data", xr_vals[i].name);
        }
        memset(buf, 0, sizeof buf);
        s = UN(NtQueryValueKey)(f.root, &n, 0 /* basic */, buf, sizeof buf, &got);
        CHECKF(s == 0 && *(ULONG *)(buf + 4) == xr_vals[i].type, "basic %s", xr_vals[i].name);
    }
    xr_down(&f);
}
TEST(nt_registry_x_value_overwrite_and_case)
{
    UNICODE_STRING n = xr_us(L"CaseValue"), n2 = xr_us(L"casevalue"); BYTE buf[64]; ULONG got; ULONG v1 = 1, v2 = 0xaabbccdd; XR_START("vcase");
    EXPECT_EQ(UN(NtSetValueKey)(f.root, &n, 0, REG_DWORD, &v1, 4), 0);
    EXPECT_EQ(UN(NtSetValueKey)(f.root, &n2, 0, REG_DWORD, &v2, 4), 0);
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &n, 2, buf, sizeof buf, &got), 0);
    EXPECT_EQ(*(ULONG *)(buf + 12), 0xaabbccdd);
    EXPECT_EQ(UN(NtEnumerateValueKey)(f.root, 1, 0, buf, sizeof buf, &got), XS(0x8000001A)); /* still one value */
    xr_down(&f);
}
TEST(nt_registry_x_default_value_empty_name)
{
    UNICODE_STRING n = {0, 0, NULL}; WCHAR text[] = L"default"; BYTE buf[128]; ULONG got = 0; NTSTATUS s; XR_START("vdefault");
    s = UN(NtSetValueKey)(f.root, &n, 0, REG_SZ, text, sizeof text);
    EXPECT_EQ(s, 0);
    s = UN(NtQueryValueKey)(f.root, &n, 2, buf, sizeof buf, &got);
    EXPECT_EQ(s, 0);
    if (s == 0) EXPECT_EQ(*(ULONG *)(buf + 8), sizeof text);
    s = UN(NtEnumerateValueKey)(f.root, 0, 0, buf, sizeof buf, &got);
    EXPECT_EQ(s, 0);
    if (s == 0) EXPECT_EQ(*(ULONG *)(buf + 8), 0); /* name length zero */
    EXPECT_EQ(UN(NtDeleteValueKey)(f.root, &n), 0);
    xr_down(&f);
}
TEST(nt_registry_x_value_missing_and_delete)
{
    UNICODE_STRING n = xr_us(L"present"), m = xr_us(L"absent"); ULONG v = 5; BYTE buf[64]; ULONG got; XR_START("vmissing");
    EXPECT_EQ(UN(NtSetValueKey)(f.root, &n, 0, REG_DWORD, &v, 4), 0);
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &m, 2, buf, sizeof buf, &got), XS(0xC0000034));
    EXPECT_EQ(UN(NtDeleteValueKey)(f.root, &m), XS(0xC0000034));
    EXPECT_EQ(UN(NtDeleteValueKey)(f.root, &n), 0);
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &n, 2, buf, sizeof buf, &got), XS(0xC0000034));
    EXPECT_EQ(UN(NtDeleteValueKey)(f.root, &n), XS(0xC0000034));
    xr_down(&f);
}
TEST(nt_registry_x_value_buffer_protocol)
{
    UNICODE_STRING n = xr_us(L"bigvalue"); BYTE data[100], buf[256]; ULONG got = 0; NTSTATUS s; XR_START("vbuf");
    memset(data, 0x41, sizeof data);
    EXPECT_EQ(UN(NtSetValueKey)(f.root, &n, 0, REG_BINARY, data, sizeof data), 0);
    s = UN(NtQueryValueKey)(f.root, &n, 2, buf, 8, &got);
    EXPECT_EQ(s, XS(0xC0000023)); EXPECT_EQ(got, 112);
    s = UN(NtQueryValueKey)(f.root, &n, 2, buf, 12, &got);
    EXPECT_EQ(s, XS(0x80000005)); EXPECT_EQ(got, 112);
    s = UN(NtQueryValueKey)(f.root, &n, 2, buf, 111, &got);
    EXPECT_EQ(s, XS(0x80000005));
    s = UN(NtQueryValueKey)(f.root, &n, 2, buf, 112, &got);
    EXPECT_EQ(s, 0);
    s = UN(NtQueryValueKey)(f.root, &n, 0x7f, buf, sizeof buf, &got);
    CHECK(!XOK(s)); t_note("invalid value class status=%08lx", s);
    xr_down(&f);
}
TEST(nt_registry_x_enumerate_value_key)
{
    BYTE buf[256]; ULONG got = 0; NTSTATUS s; ULONG v = 7; int count = 0; XR_START("venum");
    xr_set(f.root, L"one", REG_DWORD, &v, 4); xr_set(f.root, L"two", REG_DWORD, &v, 4); xr_set(f.root, L"three", REG_DWORD, &v, 4);
    for (ULONG i = 0; i < 4; i++) {
        s = UN(NtEnumerateValueKey)(f.root, i, 0, buf, sizeof buf, &got);
        if (i < 3) { EXPECT_EQ(s, 0); count += s == 0; if (s == 0) EXPECT_EQ(*(ULONG *)(buf + 4), REG_DWORD); }
        else EXPECT_EQ(s, XS(0x8000001A));
    }
    EXPECT_EQ(count, 3);
    s = UN(NtEnumerateValueKey)(f.root, 0, 2, buf, sizeof buf, &got);
    EXPECT_EQ(s, 0);
    if (s == 0) { EXPECT_EQ(*(ULONG *)(buf + 8), 4); EXPECT_EQ(got, 16); }
    s = UN(NtEnumerateValueKey)(f.root, 0, 0, buf, 4, &got);
    EXPECT_EQ(s, XS(0xC0000023));
    s = UN(NtEnumerateValueKey)(f.root, 0, 0, buf, 12, &got);
    EXPECT_EQ(s, XS(0x80000005));
    xr_down(&f);
}
TEST(nt_registry_x_set_value_on_read_only_handle)
{
    HANDLE ro = NULL; UNICODE_STRING n = xr_us(L"x"); ULONG v = 1; OBJECT_ATTRIBUTES oa; XR_START("vro");
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, NULL, NULL);
    { UNICODE_STRING self = xr_us(f.path); OBJECT_ATTRIBUTES o2; InitializeObjectAttributes(&o2, &self, OBJ_CASE_INSENSITIVE, f.hcu, NULL);
      EXPECT_EQ(UN(NtOpenKey)(&ro, KEY_READ, &o2), 0); }
    if (ro) {
        EXPECT_EQ(UN(NtSetValueKey)(ro, &n, 0, REG_DWORD, &v, 4), XS(0xC0000022));
        EXPECT_EQ(UN(NtDeleteValueKey)(ro, &n), XS(0xC0000022));
        UN(NtClose)(ro);
    }
    xr_down(&f);
}
TEST(nt_registry_x_set_value_odd_arguments)
{
    UNICODE_STRING n = xr_us(L"odd"); BYTE buf[64]; ULONG got; NTSTATUS s; XR_START("vodd");
    s = UN(NtSetValueKey)(f.root, &n, 0, REG_SZ, NULL, 0);          /* empty value */
    EXPECT_EQ(s, 0);
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &n, 2, buf, sizeof buf, &got), 0);
    EXPECT_EQ(*(ULONG *)(buf + 8), 0);
    s = UN(NtSetValueKey)(f.root, &n, 0, REG_SZ, "abc", 3);         /* odd byte count in a string value is stored as given */
    t_note("odd-length REG_SZ status=%08lx", s);
    s = UN(NtSetValueKey)(f.root, &n, 0, 0xFFFFFFF0, "ab", 2);      /* unusual type numbers are stored verbatim */
    t_note("unusual type status=%08lx", s);
    xr_down(&f);
}
TEST(nt_registry_x_query_multiple_values)
{
    UNICODE_STRING n1 = xr_us(L"first"), n2 = xr_us(L"second"), n3 = xr_us(L"third"); xr_entry e[2]; BYTE buf[256]; ULONG len, need = 0; NTSTATUS s;
    ULONG v = 0x11223344; WCHAR text[] = L"hello"; XR_START("vmulti"); REQUIRE(UN(NtQueryMultipleValueKey));
    xr_set(f.root, L"first", REG_DWORD, &v, 4); xr_set(f.root, L"second", REG_SZ, text, sizeof text);
    e[0].name = &n1; e[1].name = &n2;
    len = sizeof buf; memset(buf, 0, sizeof buf);
    s = UN(NtQueryMultipleValueKey)(f.root, e, 2, buf, &len, &need);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(e[0].type, REG_DWORD); EXPECT_EQ(e[0].datalen, 4);
        EXPECT_EQ(e[1].type, REG_SZ); EXPECT_EQ(e[1].datalen, sizeof text);
        CHECK(e[0].dataoff + 4 <= len && e[1].dataoff + sizeof text <= len);
        if (e[0].dataoff + 4 <= sizeof buf) CHECK(!memcmp(buf + e[0].dataoff, &v, 4));
        if (e[1].dataoff + sizeof text <= sizeof buf) CHECK(!memcmp(buf + e[1].dataoff, text, sizeof text));
    }
    len = 4;
    s = UN(NtQueryMultipleValueKey)(f.root, e, 2, buf, &len, &need);
    EXPECT_EQ(s, XS(0x80000005));
    CHECK(need >= 4 + sizeof text);
    e[1].name = &n3; len = sizeof buf;
    s = UN(NtQueryMultipleValueKey)(f.root, e, 2, buf, &len, &need);
    EXPECT_EQ(s, XS(0xC0000034));
    xr_down(&f);
}
TEST(nt_registry_x_notify_change_value)
{
    HANDLE ev, h = NULL; IO_STATUS_BLOCK io; NTSTATUS s; ULONG v = 1; UNICODE_STRING n = xr_us(L"changed"); BYTE nb[64];
    XR_START("notify"); REQUIRE(UN(NtNotifyChangeKey));
    REQUIRE(UIN("kernel32.dll", CreateEventW)); REQUIRE(UIN("kernel32.dll", WaitForSingleObject)); REQUIRE(UIN("kernel32.dll", CloseHandle));
    ev = UIN("kernel32.dll", CreateEventW)(NULL, TRUE, FALSE, NULL);
    CHECK(ev != NULL);
    if (ev) {
        memset(&io, 0, sizeof io);
        s = UN(NtNotifyChangeKey)(f.root, ev, NULL, NULL, &io, 4 /* LAST_SET */, FALSE, nb, sizeof nb, TRUE);
        EXPECT_EQ(s, XS(0x103));
        CHECK(UIN("kernel32.dll", WaitForSingleObject)(ev, 50) == WAIT_TIMEOUT);
        EXPECT_EQ(UN(NtSetValueKey)(f.root, &n, 0, REG_DWORD, &v, 4), 0);
        EXPECT_EQ(UIN("kernel32.dll", WaitForSingleObject)(ev, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, 0x10c);   /* STATUS_NOTIFY_ENUM_DIR: the change is reported without details, re-enumerate */
        UIN("kernel32.dll", CloseHandle)(ev);
    }
    (void)h;
    xr_down(&f);
}
TEST(nt_registry_x_notify_change_subtree_and_name)
{
    HANDLE ev, c = NULL; IO_STATUS_BLOCK io; NTSTATUS s; BYTE nb[64]; XR_START("notify2"); REQUIRE(UN(NtNotifyChangeKey));
    REQUIRE(UIN("kernel32.dll", CreateEventW)); REQUIRE(UIN("kernel32.dll", WaitForSingleObject)); REQUIRE(UIN("kernel32.dll", CloseHandle));
    ev = UIN("kernel32.dll", CreateEventW)(NULL, TRUE, FALSE, NULL);
    if (ev) {
        memset(&io, 0, sizeof io);
        s = UN(NtNotifyChangeKey)(f.root, ev, NULL, NULL, &io, 1 /* CHANGE_NAME */, TRUE, nb, sizeof nb, TRUE);
        EXPECT_EQ(s, XS(0x103));
        EXPECT_EQ(xr_sub(&f, L"newchild", 0, &c, NULL), 0);
        EXPECT_EQ(UIN("kernel32.dll", WaitForSingleObject)(ev, 10000), WAIT_OBJECT_0);
        if (c) UN(NtClose)(c);
        UIN("kernel32.dll", CloseHandle)(ev);
    }
    xr_down(&f);
}
TEST(nt_registry_x_notify_bad_handle)
{
    IO_STATUS_BLOCK io; BYTE nb[16]; REQUIRE(UN(NtNotifyChangeKey));
    EXPECT_EQ(UN(NtNotifyChangeKey)((HANDLE)(ULONG_PTR)0x7ffc, NULL, NULL, NULL, &io, 4, FALSE, nb, sizeof nb, TRUE), XS(0xC0000008));
}

/* ---- Rtl registry helpers ---------------------------------------------------- */
TEST(nt_registry_x_rtl_create_and_check_key)
{
    WCHAR path[128]; XR_START("rtlkey"); REQUIRE(UN(RtlCreateRegistryKey)); REQUIRE(UN(RtlCheckRegistryKey));
    wsprintfW(path, L"%s\\made", f.path);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(XR_USER, path), XS(0xC0000034));
    EXPECT_EQ(UN(RtlCreateRegistryKey)(XR_USER, path), 0);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(XR_USER, path), 0);
    EXPECT_EQ(UN(RtlCreateRegistryKey)(XR_USER, path), 0); /* creating again succeeds */
    EXPECT_EQ(UN(RtlCheckRegistryKey)(XR_HANDLE, (PCWSTR)f.root), 0);
    xr_down(&f);
}
TEST(nt_registry_x_rtl_write_and_delete_value)
{
    WCHAR text[] = L"written"; ULONG dw = 0x55; BYTE buf[128]; ULONG got; UNICODE_STRING n = xr_us(L"wv"); NTSTATUS s;
    XR_START("rtlwrite"); REQUIRE(UN(RtlWriteRegistryValue)); REQUIRE(UN(RtlDeleteRegistryValue));
    s = UN(RtlWriteRegistryValue)(XR_HANDLE, (PCWSTR)f.root, L"wv", REG_SZ, text, sizeof text);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &n, 2, buf, sizeof buf, &got), 0);
    EXPECT_EQ(*(ULONG *)(buf + 4), REG_SZ); EXPECT_EQ(*(ULONG *)(buf + 8), sizeof text);
    s = UN(RtlWriteRegistryValue)(XR_USER, f.path, L"dv", REG_DWORD, &dw, 4);
    EXPECT_EQ(s, 0);
    n = xr_us(L"dv");
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &n, 2, buf, sizeof buf, &got), 0);
    EXPECT_EQ(*(ULONG *)(buf + 12), 0x55);
    EXPECT_EQ(UN(RtlDeleteRegistryValue)(XR_USER, f.path, L"dv"), 0);
    EXPECT_EQ(UN(RtlDeleteRegistryValue)(XR_USER, f.path, L"dv"), XS(0xC0000034));
    EXPECT_EQ(UN(NtQueryValueKey)(f.root, &n, 2, buf, sizeof buf, &got), XS(0xC0000034));
    EXPECT_EQ(UN(RtlWriteRegistryValue)(XR_USER, L"Software\\NtdllConf_no_such_parent\\x", L"v", REG_DWORD, &dw, 4), XS(0xC0000034));
    xr_down(&f);
}

typedef struct { int calls; ULONG types[8]; ULONG lens[8]; WCHAR first[16]; } xr_cb;
static NTSTATUS NTAPI xr_collect(PWSTR name, ULONG type, PVOID data, ULONG len, PVOID ctx, PVOID ec)
{
    xr_cb *c = ctx;
    if (c->calls < 8) {
        c->types[c->calls] = type; c->lens[c->calls] = len;
        if (!c->calls && (type == REG_SZ || type == REG_EXPAND_SZ) && len <= sizeof c->first) memcpy(c->first, data, len);
    }
    c->calls++;
    return 0;
}
TEST(nt_registry_x_rtl_query_direct_dword_and_string)
{
    ULONG dw = 0, want = 0xcafe; UNICODE_STRING us; WCHAR text[] = L"direct text"; xr_query q[3]; NTSTATUS s;
    XR_START("rtlq1"); REQUIRE(UN(RtlQueryRegistryValues));
    xr_set(f.root, L"d", REG_DWORD, &want, 4); xr_set(f.root, L"s", REG_SZ, text, sizeof text);
    memset(q, 0, sizeof q); memset(&us, 0, sizeof us);
    q[0].flags = 0x20 /* DIRECT */; q[0].name = L"d"; q[0].ctx = &dw; q[0].deftype = REG_NONE;
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, NULL, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(dw, 0xcafe);
    q[0].name = L"s"; q[0].ctx = &us;
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, NULL, NULL);
    EXPECT_EQ(s, 0);
    if (s == 0 && us.Buffer) { EXPECT_EQ(us.Length, sizeof text - 2); CHECK(!lstrcmpW(us.Buffer, text)); UN(RtlFreeUnicodeString)(&us); }
    else CHECK(us.Buffer != NULL);
    xr_down(&f);
}
TEST(nt_registry_x_rtl_query_callback_routine)
{
    WCHAR text[] = L"cb text"; xr_query q[2]; xr_cb cb; NTSTATUS s; XR_START("rtlq2"); REQUIRE(UN(RtlQueryRegistryValues));
    xr_set(f.root, L"s", REG_SZ, text, sizeof text);
    memset(q, 0, sizeof q); memset(&cb, 0, sizeof cb);
    q[0].routine = xr_collect; q[0].name = L"s";
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, &cb, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(cb.calls, 1);
    EXPECT_EQ(cb.types[0], REG_SZ); EXPECT_EQ(cb.lens[0], sizeof text);
    CHECK(!lstrcmpW(cb.first, text));
    xr_down(&f);
}
TEST(nt_registry_x_rtl_query_multi_sz_one_call_per_string)
{
    static const WCHAR multi[] = L"one\0two\0three\0"; xr_query q[2]; xr_cb cb; NTSTATUS s; XR_START("rtlq3"); REQUIRE(UN(RtlQueryRegistryValues));
    xr_set(f.root, L"m", REG_MULTI_SZ, multi, sizeof multi);
    memset(q, 0, sizeof q); memset(&cb, 0, sizeof cb);
    q[0].routine = xr_collect; q[0].name = L"m";
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, &cb, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(cb.calls, 3);
    if (cb.calls == 3) { EXPECT_EQ(cb.types[0], REG_SZ); EXPECT_EQ(cb.lens[0], 8); EXPECT_EQ(cb.lens[2], 12); }
    memset(&cb, 0, sizeof cb);
    q[0].flags = 0x10; /* RTL_QUERY_REGISTRY_NOEXPAND: the whole value in one call */
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, &cb, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(cb.calls, 1);
    if (cb.calls == 1) EXPECT_EQ(cb.types[0], REG_MULTI_SZ);
    xr_down(&f);
}
TEST(nt_registry_x_rtl_query_missing_default_and_required)
{
    xr_query q[2]; xr_cb cb; WCHAR def[] = L"fallback"; NTSTATUS s; XR_START("rtlq4"); REQUIRE(UN(RtlQueryRegistryValues));
    memset(q, 0, sizeof q); memset(&cb, 0, sizeof cb);
    q[0].routine = xr_collect; q[0].name = L"absent";
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, &cb, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(cb.calls, 0);
    q[0].flags = 0x4; /* REQUIRED */
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, &cb, NULL);
    EXPECT_EQ(s, XS(0xC0000034));
    q[0].flags = 0; q[0].deftype = REG_SZ; q[0].defdata = def; q[0].deflen = sizeof def;
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, &cb, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(cb.calls, 1);
    if (cb.calls == 1) { EXPECT_EQ(cb.types[0], REG_SZ); EXPECT_EQ(cb.lens[0], sizeof def); CHECK(!lstrcmpW(cb.first, def)); }
    xr_down(&f);
}
TEST(nt_registry_x_rtl_query_subkey_flag)
{
    HANDLE c; ULONG v = 77, got = 0; xr_query q[3]; NTSTATUS s; XR_START("rtlq5"); REQUIRE(UN(RtlQueryRegistryValues));
    EXPECT_EQ(xr_sub(&f, L"sub", 0, &c, NULL), 0);
    xr_set(c, L"inner", REG_DWORD, &v, 4);
    UN(NtClose)(c);
    memset(q, 0, sizeof q);
    q[0].flags = 0x1 /* SUBKEY */; q[0].name = L"sub";
    q[1].flags = 0x20; q[1].name = L"inner"; q[1].ctx = &got;
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, NULL, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(got, 77);
    q[0].name = L"missing_sub";
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, NULL, NULL);
    EXPECT_EQ(s, XS(0xC0000034));
    xr_down(&f);
}
TEST(nt_registry_x_rtl_query_type_check)
{
    ULONG dw = 0, v = 9; xr_query q[2]; NTSTATUS s; XR_START("rtlq6"); REQUIRE(UN(RtlQueryRegistryValues));
    xr_set(f.root, L"d", REG_DWORD, &v, 4);
    memset(q, 0, sizeof q);
    q[0].flags = 0x20 | 0x100 /* DIRECT | TYPECHECK */; q[0].name = L"d"; q[0].ctx = &dw;
    q[0].deftype = (REG_DWORD << 24);
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, NULL, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(dw, 9);
    q[0].deftype = (REG_SZ << 24);
    s = UN(RtlQueryRegistryValues)(XR_HANDLE, (PCWSTR)f.root, q, NULL, NULL);
    EXPECT_EQ(s, XS(0xC0000024));
    xr_down(&f);
}

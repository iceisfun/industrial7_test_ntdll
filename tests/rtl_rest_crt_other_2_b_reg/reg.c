/* Registry helper wrappers (Rtlp key open/create/enumerate/query), RtlWriteRegistryValue, heap zeroing,
 * culture-name conversion helpers, device-family info, UI-language and dynamic time-zone checks.
 * See EVIDENCE.md for the source of every expectation. */
#include "t.h"
#include <stdlib.h>

#define S(x) ((NTSTATUS)(x))
#define ST_INVPARAM S(0xC000000D)
#define ST_NOTFOUND S(0xC0000034)
#define ST_BADHANDLE S(0xC0000008)
#define ST_OVERFLOW S(0x80000005)
#define ST_NOMORE S(0x8000001A)
#define RTL_REGISTRY_USER 5

UDECL(NTSTATUS, RtlOpenCurrentUser, (ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, RtlpNtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, RtlpNtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PVOID, PULONG));
UDECL(NTSTATUS, RtlpNtEnumerateSubKey, (HANDLE, PUNICODE_STRING, ULONG));
UDECL(NTSTATUS, RtlpNtQueryValueKey, (HANDLE, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, RtlpNtMakeTemporaryKey, (HANDLE));
UDECL(NTSTATUS, RtlWriteRegistryValue, (ULONG, PCWSTR, PCWSTR, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryValueKey, (HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtClose, (HANDLE));

typedef struct { HANDLE root, key; WCHAR path[64]; } FIX;

static void us_init(UNICODE_STRING *u, const WCHAR *s) { u->Buffer = (PWSTR)s; u->Length = (USHORT)(lstrlenW(s) * 2); u->MaximumLength = u->Length + 2; }
static void oa_init(OBJECT_ATTRIBUTES *oa, HANDLE root, UNICODE_STRING *n, ULONG attr) { memset(oa, 0, sizeof *oa); oa->Length = sizeof *oa; oa->RootDirectory = root; oa->ObjectName = n; oa->Attributes = attr; }

/* creates HKCU\Software\NtdllConf2b_<pid>_<tag> through the wrapper under test */
static int fix_up(FIX *f, const char *tag) {
    memset(f, 0, sizeof *f);
    if (UN(RtlOpenCurrentUser)(KEY_ALL_ACCESS, &f->root) < 0) { t_skip("cannot open the current user hive"); return 0; }
    wsprintfW(f->path, L"Software\\NtdllConf2b_%lu_%S", GetCurrentProcessId(), tag);
    UNICODE_STRING n; OBJECT_ATTRIBUTES oa; ULONG disp = 99;
    us_init(&n, f->path); oa_init(&oa, f->root, &n, OBJ_CASE_INSENSITIVE);
    NTSTATUS s = UN(RtlpNtCreateKey)(&f->key, KEY_ALL_ACCESS, &oa, 0, NULL, &disp);
    if (s < 0 || disp != 1) { UN(NtClose)(f->root); t_skip("cannot create scratch key (0x%lx)", (unsigned long)s); return 0; }
    return 1;
}
static void fix_down(FIX *f) {
    if (f->key) { UN(NtDeleteKey)(f->key); UN(NtClose)(f->key); }
    UN(NtClose)(f->root);
}
#define FIX_START(tag) FIX f; REQUIRE(UN(RtlOpenCurrentUser)); REQUIRE(UN(RtlpNtCreateKey)); REQUIRE(UN(NtDeleteKey)); REQUIRE(UN(NtClose)); if (!fix_up(&f, tag)) return;

TEST(rtlp_nt_create_key_disposition_and_attributes) {
    FIX f; REQUIRE(UN(RtlOpenCurrentUser)); REQUIRE(UN(RtlpNtCreateKey)); REQUIRE(UN(RtlpNtOpenKey)); REQUIRE(UN(NtDeleteKey)); REQUIRE(UN(NtClose));
    if (UN(RtlOpenCurrentUser)(KEY_ALL_ACCESS, &f.root) < 0) { t_skip("cannot open the current user hive"); return; }
    WCHAR path[64]; wsprintfW(path, L"Software\\NtdllConf2b_%lu_create", GetCurrentProcessId());
    UNICODE_STRING n; OBJECT_ATTRIBUTES oa; HANDLE h = NULL, h2 = NULL; ULONG disp = 99;
    us_init(&n, path);
    /* permanent/exclusive attribute bits are removed from the caller's object attributes before the call */
    oa_init(&oa, f.root, &n, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_EXCLUSIVE);
    EXPECT_EQ(UN(RtlpNtCreateKey)(&h, KEY_ALL_ACCESS, &oa, 0, NULL, &disp), 0);
    EXPECT_EQ(disp, 1);                                   /* REG_CREATED_NEW_KEY */
    EXPECT_EQ(oa.Attributes, OBJ_CASE_INSENSITIVE);
    CHECK(h != NULL);
    oa_init(&oa, f.root, &n, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT);
    EXPECT_EQ(UN(RtlpNtCreateKey)(&h2, KEY_READ, &oa, 0, NULL, &disp), 0);
    EXPECT_EQ(disp, 2);                                   /* REG_OPENED_EXISTING_KEY */
    EXPECT_EQ(oa.Attributes, OBJ_CASE_INSENSITIVE);
    if (h2) UN(NtClose)(h2);
    /* other attribute bits are preserved */
    oa_init(&oa, f.root, &n, OBJ_CASE_INSENSITIVE | OBJ_INHERIT | OBJ_EXCLUSIVE);
    h2 = NULL; EXPECT_EQ(UN(RtlpNtCreateKey)(&h2, KEY_READ, &oa, 0, NULL, NULL), 0);
    EXPECT_EQ(oa.Attributes, OBJ_CASE_INSENSITIVE | OBJ_INHERIT);
    if (h2) UN(NtClose)(h2);
    /* NULL object attributes reach the system call and fail its validation */
    h2 = (HANDLE)0x1234; NTSTATUS s = UN(RtlpNtCreateKey)(&h2, KEY_READ, NULL, 0, NULL, NULL);
    CHECKF(s < 0, "NULL object attributes accepted (0x%lx)", (unsigned long)s);
    t_note("create with NULL OA -> 0x%lx", (unsigned long)s);
    if (h) { UN(NtDeleteKey)(h); UN(NtClose)(h); }
    UN(NtClose)(f.root);
}

TEST(rtlp_nt_open_key) {
    FIX_START("open");
    REQUIRE(UN(RtlpNtOpenKey));
    UNICODE_STRING n; OBJECT_ATTRIBUTES oa; HANDLE h = NULL;
    us_init(&n, f.path);
    oa_init(&oa, f.root, &n, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_EXCLUSIVE);
    EXPECT_EQ(UN(RtlpNtOpenKey)(&h, KEY_READ, &oa, 0), 0);
    CHECK(h != NULL);
    EXPECT_EQ(oa.Attributes, OBJ_CASE_INSENSITIVE);
    if (h) UN(NtClose)(h);
    /* missing key */
    UNICODE_STRING nn; WCHAR miss[80]; wsprintfW(miss, L"%s\\no_such_child", f.path); us_init(&nn, miss);
    oa_init(&oa, f.root, &nn, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT);
    h = (HANDLE)0x1; EXPECT_EQ(UN(RtlpNtOpenKey)(&h, KEY_READ, &oa, 0), ST_NOTFOUND);
    EXPECT_EQ(oa.Attributes, OBJ_CASE_INSENSITIVE);
    /* invalid root handle */
    oa_init(&oa, (HANDLE)(ULONG_PTR)0x7ffffff0, &n, OBJ_CASE_INSENSITIVE);
    EXPECT_EQ(UN(RtlpNtOpenKey)(&h, KEY_READ, &oa, 0), ST_BADHANDLE);
    /* NULL object attributes is passed through to the system call */
    NTSTATUS s = UN(RtlpNtOpenKey)(&h, KEY_READ, NULL, 0);
    CHECKF(s < 0, "NULL object attributes accepted (0x%lx)", (unsigned long)s);
    fix_down(&f);
}

TEST(rtlp_nt_enumerate_subkey) {
    FIX_START("enum");
    REQUIRE(UN(RtlpNtEnumerateSubKey)); REQUIRE(UN(RtlpNtOpenKey));
    const WCHAR *subs[2] = { L"alpha", L"bravo_long" };
    for (int i = 0; i < 2; i++) {
        UNICODE_STRING n; OBJECT_ATTRIBUTES oa; HANDLE h = NULL; us_init(&n, subs[i]); oa_init(&oa, f.key, &n, OBJ_CASE_INSENSITIVE);
        EXPECT_EQ(UN(RtlpNtCreateKey)(&h, KEY_ALL_ACCESS, &oa, 0, NULL, NULL), 0);
        if (h) UN(NtClose)(h);
    }
    WCHAR buf[40]; UNICODE_STRING out;
    for (ULONG idx = 0; idx < 2; idx++) {
        memset(buf, 0x55, sizeof buf);
        out.Length = 0; out.MaximumLength = sizeof buf; out.Buffer = buf;
        EXPECT_EQ(UN(RtlpNtEnumerateSubKey)(f.key, &out, idx), 0);
        EXPECT_EQ(out.Length, lstrlenW(subs[idx]) * 2);
        CHECK(out.Length == lstrlenW(subs[idx]) * 2 && !memcmp(buf, subs[idx], out.Length));
    }
    out.Length = 0; out.MaximumLength = sizeof buf; out.Buffer = buf;
    EXPECT_EQ(UN(RtlpNtEnumerateSubKey)(f.key, &out, 2), ST_NOMORE);
    /* buffer too small: overflow status and the required length */
    out.Length = 0; out.MaximumLength = 4; out.Buffer = buf;
    NTSTATUS s = UN(RtlpNtEnumerateSubKey)(f.key, &out, 0);
    EXPECT_EQ(s, ST_OVERFLOW);
    EXPECT_EQ(out.Length, 10);                                       /* required length of "alpha" */
    out.Length = 0; out.MaximumLength = 10; out.Buffer = buf;       /* "alpha" fits exactly (no terminator stored) */
    EXPECT_EQ(UN(RtlpNtEnumerateSubKey)(f.key, &out, 0), 0); EXPECT_EQ(out.Length, 10);
    out.Length = 0; out.MaximumLength = 18; out.Buffer = buf;       /* "bravo_long" needs 20 */
    EXPECT_EQ(UN(RtlpNtEnumerateSubKey)(f.key, &out, 1), ST_OVERFLOW);
    out.Length = 0; out.MaximumLength = sizeof buf; out.Buffer = buf;
    EXPECT_EQ(UN(RtlpNtEnumerateSubKey)((HANDLE)(ULONG_PTR)0x7ffffff0, &out, 0), ST_BADHANDLE);
    /* remove the children so the parent can be deleted */
    for (int i = 0; i < 2; i++) {
        UNICODE_STRING n; OBJECT_ATTRIBUTES oa; HANDLE h = NULL; us_init(&n, subs[i]); oa_init(&oa, f.key, &n, OBJ_CASE_INSENSITIVE);
        if (UN(RtlpNtOpenKey)(&h, DELETE, &oa, 0) >= 0) { UN(NtDeleteKey)(h); UN(NtClose)(h); }
    }
    fix_down(&f);
}

TEST(rtlp_nt_query_value_key_default_value) {
    FIX_START("query");
    REQUIRE(UN(RtlpNtQueryValueKey)); REQUIRE(UN(NtSetValueKey));
    ULONG type = 0x77, len = 0; BYTE data[64];
    /* no default value: reported as success with type REG_NONE and zero length */
    len = sizeof data;
    EXPECT_EQ(UN(RtlpNtQueryValueKey)(f.key, &type, data, &len), 0);
    EXPECT_EQ(type, 0); EXPECT_EQ(len, 0);
    UNICODE_STRING empty = { 0, 2, (PWSTR)L"" }; WCHAR text[] = L"hello";
    EXPECT_EQ(UN(NtSetValueKey)(f.key, &empty, 0, REG_SZ, text, sizeof text), 0);
    memset(data, 0xCC, sizeof data); type = 0; len = sizeof data;
    EXPECT_EQ(UN(RtlpNtQueryValueKey)(f.key, &type, data, &len), 0);
    EXPECT_EQ(type, REG_SZ); EXPECT_EQ(len, sizeof text);
    CHECK(!memcmp(data, text, sizeof text)); EXPECT_EQ(data[sizeof text], 0xCC);
    /* too small: overflow with required size and type, nothing copied */
    memset(data, 0xCC, sizeof data); type = 0; len = 4;
    EXPECT_EQ(UN(RtlpNtQueryValueKey)(f.key, &type, data, &len), ST_OVERFLOW);
    EXPECT_EQ(type, REG_SZ); EXPECT_EQ(len, sizeof text); EXPECT_EQ(data[0], 0xCC);
    /* size query only: data pointer may be NULL */
    type = 0; len = sizeof data;
    EXPECT_EQ(UN(RtlpNtQueryValueKey)(f.key, &type, NULL, &len), 0);
    EXPECT_EQ(type, REG_SZ); EXPECT_EQ(len, sizeof text);
    /* type and length pointers are optional */
    memset(data, 0xCC, sizeof data);
    EXPECT_EQ(UN(RtlpNtQueryValueKey)(f.key, NULL, data, NULL), ST_OVERFLOW);   /* no length: zero-byte data buffer */
    EXPECT_EQ(data[0], 0xCC);
    DWORD dw = 0xA5A5; EXPECT_EQ(UN(NtSetValueKey)(f.key, &empty, 0, REG_DWORD, &dw, 4), 0);
    type = 0; len = sizeof data; memset(data, 0, sizeof data);
    EXPECT_EQ(UN(RtlpNtQueryValueKey)(f.key, &type, data, &len), 0);
    EXPECT_EQ(type, REG_DWORD); EXPECT_EQ(len, 4); EXPECT_EQ(*(DWORD *)data, 0xA5A5);
    type = 0; len = 4;
    EXPECT_EQ(UN(RtlpNtQueryValueKey)((HANDLE)(ULONG_PTR)0x7ffffff0, &type, data, &len), ST_BADHANDLE);
    fix_down(&f);
}

TEST(rtlp_nt_make_temporary_key) {
    FIX_START("temp");
    REQUIRE(UN(RtlpNtMakeTemporaryKey));
    EXPECT_EQ(UN(RtlpNtMakeTemporaryKey)((HANDLE)(ULONG_PTR)0x7ffffff0), ST_BADHANDLE);
    EXPECT_EQ(UN(RtlpNtMakeTemporaryKey)(f.key), 0);
    fix_down(&f);
}

TEST(rtl_write_registry_value) {
    FIX_START("write");
    REQUIRE(UN(RtlWriteRegistryValue)); REQUIRE(UN(NtQueryValueKey));
    WCHAR sub[80]; wsprintfW(sub, L"%s", f.path);
    DWORD dw = 0x1234; BYTE buf[128]; ULONG got; UNICODE_STRING n;
    EXPECT_EQ(UN(RtlWriteRegistryValue)(RTL_REGISTRY_USER, sub, L"dword", REG_DWORD, &dw, 4), 0);
    us_init(&n, L"dword"); memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, sizeof buf, &got), 0);
    EXPECT_EQ(*(ULONG *)(buf + 4), REG_DWORD); EXPECT_EQ(*(ULONG *)(buf + 8), 4); EXPECT_EQ(*(DWORD *)(buf + 12), 0x1234);
    /* replace in place, different type */
    WCHAR text[] = L"overwrite";
    EXPECT_EQ(UN(RtlWriteRegistryValue)(RTL_REGISTRY_USER, sub, L"dword", REG_SZ, text, sizeof text), 0);
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, sizeof buf, &got), 0);
    EXPECT_EQ(*(ULONG *)(buf + 4), REG_SZ); EXPECT_EQ(*(ULONG *)(buf + 8), sizeof text); CHECK(!memcmp(buf + 12, text, sizeof text));
    /* binary payload and zero-length data */
    BYTE bin[5] = { 1, 2, 3, 4, 5 };
    EXPECT_EQ(UN(RtlWriteRegistryValue)(RTL_REGISTRY_USER, sub, L"bin", REG_BINARY, bin, 5), 0);
    us_init(&n, L"bin");
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, sizeof buf, &got), 0);
    EXPECT_EQ(*(ULONG *)(buf + 8), 5); CHECK(!memcmp(buf + 12, bin, 5));
    EXPECT_EQ(UN(RtlWriteRegistryValue)(RTL_REGISTRY_USER, sub, L"empty", REG_BINARY, NULL, 0), 0);
    us_init(&n, L"empty");
    EXPECT_EQ(UN(NtQueryValueKey)(f.key, &n, 2, buf, sizeof buf, &got), 0);
    EXPECT_EQ(*(ULONG *)(buf + 8), 0);
    /* errors */
    EXPECT_EQ(UN(RtlWriteRegistryValue)(RTL_REGISTRY_USER, L"Software\\NtdllConf2b_no_such_parent\\x", L"v", REG_DWORD, &dw, 4), ST_NOTFOUND);
    EXPECT_EQ(UN(RtlWriteRegistryValue)(0x40, sub, L"v", REG_DWORD, &dw, 4), ST_INVPARAM);
    EXPECT_EQ(UN(RtlWriteRegistryValue)(RTL_REGISTRY_USER, sub, L"v", REG_DWORD, &dw, 4), 0);
    fix_down(&f);
}

/* ------------------------------------------------------------ RtlZeroHeap */
UDECL(NTSTATUS, RtlZeroHeap, (PVOID, ULONG));
TEST(zero_heap) {
    REQUIRE(UN(RtlZeroHeap));
    HANDLE hp = HeapCreate(0, 0x10000, 0);
    if (!hp) { t_skip("cannot create a private heap"); return; }
    PBYTE keep[8], freed[8]; int i;
    for (i = 0; i < 8; i++) { keep[i] = HeapAlloc(hp, 0, 100 + i * 20); memset(keep[i], 0xA0 + i, 100 + i * 20); }
    for (i = 0; i < 8; i++) { freed[i] = HeapAlloc(hp, 0, 200); memset(freed[i], 0xEE, 200); }
    for (i = 0; i < 8; i++) HeapFree(hp, 0, freed[i]);
    NTSTATUS s = UN(RtlZeroHeap)(hp, 0);
    EXPECT_EQ(s, 0);
    /* live blocks keep their contents and the heap stays consistent and usable */
    for (i = 0; i < 8; i++) {
        int ok = 1; for (int k = 0; k < 100 + i * 20; k++) if (keep[i][k] != (BYTE)(0xA0 + i)) ok = 0;
        CHECKF(ok, "live block %d was modified", i);
    }
    EXPECT_EQ(HeapValidate(hp, 0, NULL), TRUE);
    PBYTE n = HeapAlloc(hp, HEAP_ZERO_MEMORY, 64); CHECK(n != NULL);
    if (n) { HeapFree(hp, 0, n); }
    EXPECT_EQ(UN(RtlZeroHeap)(hp, 0), 0);                /* idempotent */
    for (i = 0; i < 8; i++) HeapFree(hp, 0, keep[i]);
    EXPECT_EQ(UN(RtlZeroHeap)(hp, 0), 0);                /* empty heap */
    HeapDestroy(hp);
}

/* ------------------------------------------------------------ culture name <-> LCID helpers */
UDECL(NTSTATUS, RtlpConvertCultureNamesToLCIDs, (PCWSTR, PWSTR *, PVOID, ULONG));
UDECL(NTSTATUS, RtlpConvertLCIDsToCultureNames, (PCWSTR, PWSTR *));
static int multisz_eq(const WCHAR *a, const WCHAR *b) {
    for (;;) { if (lstrcmpiW(a, b)) return 0; if (!*a) return 1; a += lstrlenW(a) + 1; b += lstrlenW(b) + 1; }
}
static const WCHAR *last_str(const WCHAR *p) { while (*p) p += lstrlenW(p) + 1; return p; }
TEST(culture_names_to_lcids) {
    REQUIRE(UN(RtlpConvertCultureNamesToLCIDs));
    PWSTR out = NULL; NTSTATUS s;
    s = UN(RtlpConvertCultureNamesToLCIDs)(L"en-US\0\0", &out, NULL, 0);
    t_note("en-US -> 0x%lx out=%p", (unsigned long)s, (void *)out);
    EXPECT_EQ(s, 0);
    CHECK(out != NULL);
    if (s == 0 && out) {
        EXPECT_EQ(multisz_eq(out, L"0409\0\0"), 1);
        HeapFree(GetProcessHeap(), 0, out);
    }
    out = NULL;
    s = UN(RtlpConvertCultureNamesToLCIDs)(L"de-DE\0fr-FR\0\0", &out, NULL, 0);
    EXPECT_EQ(s, 0);
    CHECK(out != NULL);
    if (s == 0 && out) { EXPECT_EQ(multisz_eq(out, L"0407\0" L"040c\0\0"), 1); HeapFree(GetProcessHeap(), 0, out); }
    out = NULL;
    EXPECT_EQ(UN(RtlpConvertCultureNamesToLCIDs)(L"zz-invalid-name\0\0", &out, NULL, 0), ST_INVPARAM);
    EXPECT_EQ(out, NULL);
    out = NULL;
    EXPECT_EQ(UN(RtlpConvertCultureNamesToLCIDs)(L"en-US\0en-US\0\0", &out, NULL, 0), ST_INVPARAM);      /* duplicates */
    EXPECT_EQ(UN(RtlpConvertCultureNamesToLCIDs)(NULL, &out, NULL, 0), ST_INVPARAM);
    EXPECT_EQ(UN(RtlpConvertCultureNamesToLCIDs)(L"en-US\0\0", NULL, NULL, 0), ST_INVPARAM);
    PWSTR pre = (PWSTR)(ULONG_PTR)8;          /* output must start NULL */
    EXPECT_EQ(UN(RtlpConvertCultureNamesToLCIDs)(L"en-US\0\0", &pre, NULL, 0), ST_INVPARAM);
}
TEST(lcids_to_culture_names) {
    REQUIRE(UN(RtlpConvertLCIDsToCultureNames));
    PWSTR out = NULL; NTSTATUS s;
    s = UN(RtlpConvertLCIDsToCultureNames)(L"0409\0\0", &out);
    t_note("0409 -> 0x%lx", (unsigned long)s);
    EXPECT_EQ(s, 0);
    if (s == 0 && out) { EXPECT_EQ(multisz_eq(out, L"en-US\0\0"), 1); HeapFree(GetProcessHeap(), 0, out); }
    out = NULL;
    s = UN(RtlpConvertLCIDsToCultureNames)(L"0407\0" L"040c\0\0", &out);
    EXPECT_EQ(s, 0);
    if (s == 0 && out) { EXPECT_EQ(multisz_eq(out, L"de-DE\0fr-FR\0\0"), 1); HeapFree(GetProcessHeap(), 0, out); }
    out = NULL;
    EXPECT_EQ(UN(RtlpConvertLCIDsToCultureNames)(NULL, &out), ST_INVPARAM);
    EXPECT_EQ(UN(RtlpConvertLCIDsToCultureNames)(L"0409\0\0", NULL), ST_INVPARAM);
    PWSTR pre = (PWSTR)(ULONG_PTR)8;
    EXPECT_EQ(UN(RtlpConvertLCIDsToCultureNames)(L"0409\0\0", &pre), ST_INVPARAM);
}

/* ------------------------------------------------------------ device family info */
UDECL(VOID, RtlpGetDeviceFamilyInfoEnum, (ULONGLONG *, ULONG *, ULONG *));
UDECL(NTSTATUS, RtlGetVersion, (PRTL_OSVERSIONINFOEXW));
TEST(device_family_info_enum) {
    REQUIRE(UN(RtlpGetDeviceFamilyInfoEnum)); REQUIRE(UN(RtlGetVersion));
    RTL_OSVERSIONINFOEXW v; memset(&v, 0, sizeof v); v.dwOSVersionInfoSize = sizeof v; UN(RtlGetVersion)(&v);
    ULONGLONG ver = 0xdead; ULONG fam = 0xdead, form = 0xdead;
    UN(RtlpGetDeviceFamilyInfoEnum)(&ver, &fam, &form);
    /* version quad: major.minor.build.revision, 16 bits each */
    EXPECT_EQ((ver >> 48) & 0xFFFF, v.dwMajorVersion);
    EXPECT_EQ((ver >> 32) & 0xFFFF, v.dwMinorVersion);
    EXPECT_EQ((ver >> 16) & 0xFFFF, v.dwBuildNumber);
    t_note("revision=%u family=%lu form=%lu", (unsigned)(ver & 0xFFFF), (unsigned long)fam, (unsigned long)form);
    CHECK((ver & 0xFFFF) != 0);
    CHECK(fam != 0xdead);
    EXPECT_NE(form, 0xdead);
    /* each pointer is optional and independent */
    ULONGLONG ver2 = 0; UN(RtlpGetDeviceFamilyInfoEnum)(&ver2, NULL, NULL); EXPECT_EQ(ver2, ver);
    ULONG fam2 = 0xdead; UN(RtlpGetDeviceFamilyInfoEnum)(NULL, &fam2, NULL); EXPECT_EQ(fam2, fam);
    ULONG form2 = 0xdead; UN(RtlpGetDeviceFamilyInfoEnum)(NULL, NULL, &form2); EXPECT_EQ(form2, form);
    UN(RtlpGetDeviceFamilyInfoEnum)(NULL, NULL, NULL);
}

/* ------------------------------------------------------------ system default UI language */
UDECL(NTSTATUS, RtlpGetSystemDefaultUILanguage, (USHORT *, PVOID, PVOID, PVOID));
TEST(system_default_ui_language) {
    REQUIRE(UN(RtlpGetSystemDefaultUILanguage));
    EXPECT_EQ(UN(RtlpGetSystemDefaultUILanguage)(NULL, NULL, NULL, NULL), ST_INVPARAM);
    USHORT lang = 0xBEEF;
    NTSTATUS s = UN(RtlpGetSystemDefaultUILanguage)(&lang, NULL, NULL, NULL);
    t_note("status 0x%lx lang 0x%x sysdefault 0x%x", (unsigned long)s, lang, (unsigned)GetSystemDefaultUILanguage());
    EXPECT_EQ(s, 0);
    EXPECT_EQ(lang, GetSystemDefaultUILanguage());
}

/* ------------------------------------------------------------ dynamic time zone check */
UDECL(BOOLEAN, RtlpCheckDynamicTimeZoneInformation, (DYNAMIC_TIME_ZONE_INFORMATION *, USHORT));
TEST(check_dynamic_time_zone_information) {
    REQUIRE(UN(RtlpCheckDynamicTimeZoneInformation));
    DYNAMIC_TIME_ZONE_INFORMATION d; memset(&d, 0, sizeof d);
    DWORD r = GetDynamicTimeZoneInformation(&d);
    if (r == TIME_ZONE_ID_INVALID || !d.TimeZoneKeyName[0]) { t_skip("no dynamic time zone key name available"); return; }
    SYSTEMTIME st; GetLocalTime(&st);
    DYNAMIC_TIME_ZONE_INFORMATION w = d;
    BOOLEAN a = UN(RtlpCheckDynamicTimeZoneInformation)(&w, st.wYear);
    (void)a;
    BOOLEAN b = UN(RtlpCheckDynamicTimeZoneInformation)(&w, st.wYear);
    EXPECT_EQ(b, 0);                               /* settled structure no longer changes */
    /* corrupt a field covered by the registry data and see whether it is restored */
    w.Bias = d.Bias + 77;
    BOOLEAN c = UN(RtlpCheckDynamicTimeZoneInformation)(&w, st.wYear);
    if (c) EXPECT_EQ(w.Bias, d.Bias);              /* registry value restored */
    else t_note("no registry time-zone data for the current year; Bias left alone");
    /* unknown key name: nothing to compare against */
    DYNAMIC_TIME_ZONE_INFORMATION x = d; lstrcpyW(x.TimeZoneKeyName, L"No Such Zone For Conformance");
    x.Bias = 5;
    EXPECT_EQ(UN(RtlpCheckDynamicTimeZoneInformation)(&x, st.wYear), 0);
    EXPECT_EQ(x.Bias, 5);
}

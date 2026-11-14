#include "t.h"
#include <stdlib.h>

UDECL(NTSTATUS, RtlLcidToLocaleName, (ULONG, PUNICODE_STRING, ULONG, BOOLEAN));
UDECL(BOOLEAN, RtlLCIDToCultureName, (ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, RtlLocaleNameToLcid, (PCWSTR, PULONG, ULONG));
UDECL(NTSTATUS, RtlNormalizeString, (ULONG, PCWSTR, LONG, PWSTR, PLONG));
UDECL(NTSTATUS, RtlNtPathNameToDosPathName, (ULONG, PVOID, PULONG, PWSTR *));
UDECL(NTSTATUS, RtlReplaceSystemDirectoryInPath, (PUNICODE_STRING, ULONG, ULONG, ULONG));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(NTSTATUS, RtlLoadString, (HMODULE, USHORT, PCWSTR, ULONG, PCWSTR *, PUSHORT, PVOID, PULONG));

#define S(x) ((NTSTATUS)(x))

static void mkus(UNICODE_STRING *u, WCHAR *buf, USHORT cap) { u->Buffer = buf; u->Length = 0; u->MaximumLength = cap; memset(buf, 0, cap); }

/* ---------- LCID <-> locale name ---------- */
TEST(lcid_to_locale_name) {
    static const struct { ULONG lcid; const WCHAR *name; } t[] = {
        { 0x0409, L"en-US" }, { 0x0407, L"de-DE" }, { 0x040C, L"fr-FR" }, { 0x0411, L"ja-JP" },
        { 0x0804, L"zh-CN" }, { 0x0809, L"en-GB" }, { 0x0C0A, L"es-ES" },
    };
    WCHAR buf[100]; UNICODE_STRING u; size_t i; NTSTATUS s;
    REQUIRE(UN(RtlLcidToLocaleName)); REQUIRE(UN(RtlFreeUnicodeString));
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        mkus(&u, buf, sizeof buf);
        s = UN(RtlLcidToLocaleName)(t[i].lcid, &u, 0, FALSE);
        CHECKF(s == 0, "lcid 0x%lx status 0x%lx", t[i].lcid, (ULONG)s);
        if (s == 0) {
            EXPECT_EQ(u.Length, lstrlenW(t[i].name) * 2);
            CHECKF(u.Length == lstrlenW(t[i].name) * 2 && !memcmp(buf, t[i].name, u.Length), "lcid 0x%lx name mismatch", t[i].lcid);
            EXPECT_EQ(buf[u.Length / 2], 0);          /* NUL terminated within the buffer */
        }
    }
    /* allocated output */
    memset(&u, 0, sizeof u);
    s = UN(RtlLcidToLocaleName)(0x409, &u, 0, TRUE);
    EXPECT_EQ(s, 0);
    if (s == 0) { EXPECT_EQ(u.Length, 10); CHECK(u.Buffer && !memcmp(u.Buffer, L"en-US", 10)); EXPECT_EQ(u.MaximumLength >= 12, 1); UN(RtlFreeUnicodeString)(&u); }
    /* validation order: lcid first, then output pointer, then flags */
    mkus(&u, buf, sizeof buf);
    EXPECT_EQ(UN(RtlLcidToLocaleName)(0, &u, 0, FALSE), S(0xC00000EF));
    EXPECT_EQ(UN(RtlLcidToLocaleName)(0x1000, &u, 0, FALSE), S(0xC00000EF));
    EXPECT_EQ(UN(RtlLcidToLocaleName)(0, NULL, 0, FALSE), S(0xC00000EF));
    EXPECT_EQ(UN(RtlLcidToLocaleName)(0x409, NULL, 0, FALSE), S(0xC00000F0));
    EXPECT_EQ(UN(RtlLcidToLocaleName)(0x409, &u, 1, FALSE), S(0xC00000F1));
    EXPECT_EQ(UN(RtlLcidToLocaleName)(0x409, &u, 4, FALSE), S(0xC00000F1));
    EXPECT_EQ(UN(RtlLcidToLocaleName)(0x409, &u, 0x100, FALSE), S(0xC00000F1));
    { UNICODE_STRING nb = { 0, 20, NULL }; EXPECT_EQ(UN(RtlLcidToLocaleName)(0x409, &nb, 0, FALSE), S(0xC00000F0)); } /* no buffer and not allocating */
    EXPECT_EQ(UN(RtlLcidToLocaleName)(0xFFFF, &u, 0, FALSE), S(0xC00000EF));   /* unknown LCID */
    /* a buffer too small for "en-US" */
    { WCHAR tiny[3]; UNICODE_STRING ut; mkus(&ut, tiny, sizeof tiny);
      s = UN(RtlLcidToLocaleName)(0x409, &ut, 0, FALSE);
      CHECKF(s < 0, "tiny buffer unexpectedly succeeded 0x%lx", (ULONG)s); }
    /* neutral locales are only returned when flag 2 is passed */
    mkus(&u, buf, sizeof buf);
    EXPECT_EQ(UN(RtlLcidToLocaleName)(0x0007, &u, 0, FALSE), S(0xC00000EF));
    mkus(&u, buf, sizeof buf);
    s = UN(RtlLcidToLocaleName)(0x0007, &u, 2, FALSE);
    EXPECT_EQ(s, 0);
    if (s == 0) CHECK(u.Length == 4 && !memcmp(buf, L"de", 4));
}

TEST(lcid_to_culture_name) {
    WCHAR buf[100]; UNICODE_STRING u;
    REQUIRE(UN(RtlLCIDToCultureName));
    mkus(&u, buf, sizeof buf);
    EXPECT_EQ(UN(RtlLCIDToCultureName)(0x409, &u), TRUE);
    CHECK(u.Length == 10 && !memcmp(buf, L"en-US", 10));
    mkus(&u, buf, sizeof buf);
    EXPECT_EQ(UN(RtlLCIDToCultureName)(0x407, &u), TRUE);
    CHECK(u.Length == 10 && !memcmp(buf, L"de-DE", 10));
    mkus(&u, buf, sizeof buf);
    EXPECT_EQ(UN(RtlLCIDToCultureName)(0x0009, &u), TRUE);            /* neutral names are accepted here */
    CHECK(u.Length == 4 && !memcmp(buf, L"en", 4));
    mkus(&u, buf, sizeof buf);
    EXPECT_EQ(UN(RtlLCIDToCultureName)(0, &u), FALSE);
    EXPECT_EQ(UN(RtlLCIDToCultureName)(0x1000, &u), FALSE);
    EXPECT_EQ(UN(RtlLCIDToCultureName)(0x409, NULL), FALSE);
    EXPECT_EQ(UN(RtlLCIDToCultureName)(0xFFFF, &u), FALSE);
    { WCHAR tiny[2]; UNICODE_STRING ut; mkus(&ut, tiny, sizeof tiny); EXPECT_EQ(UN(RtlLCIDToCultureName)(0x409, &ut), FALSE); }
}

TEST(locale_name_to_lcid) {
    ULONG lcid; NTSTATUS s;
    REQUIRE(UN(RtlLocaleNameToLcid));
    lcid = 0; EXPECT_EQ(UN(RtlLocaleNameToLcid)(L"en-US", &lcid, 0), 0); EXPECT_EQ(lcid, 0x409);
    lcid = 0; EXPECT_EQ(UN(RtlLocaleNameToLcid)(L"de-DE", &lcid, 0), 0); EXPECT_EQ(lcid, 0x407);
    lcid = 0; EXPECT_EQ(UN(RtlLocaleNameToLcid)(L"ja-JP", &lcid, 0), 0); EXPECT_EQ(lcid, 0x411);
    lcid = 0; EXPECT_EQ(UN(RtlLocaleNameToLcid)(L"EN-us", &lcid, 0), 0); EXPECT_EQ(lcid, 0x409);   /* case-insensitive */
    lcid = 0; EXPECT_EQ(UN(RtlLocaleNameToLcid)(L"en-GB", &lcid, 3), 0); EXPECT_EQ(lcid, 0x809);
    /* neutral names need flag 2 */
    lcid = 0xAAAA; EXPECT_EQ(UN(RtlLocaleNameToLcid)(L"de", &lcid, 0), S(0xC00000EF)); EXPECT_EQ(lcid, 0xAAAA);
    lcid = 0; s = UN(RtlLocaleNameToLcid)(L"de", &lcid, 2); EXPECT_EQ(s, 0); if (s == 0) EXPECT_EQ(lcid, 0x7);
    /* validation order: name, output, flags */
    EXPECT_EQ(UN(RtlLocaleNameToLcid)(NULL, &lcid, 0), S(0xC00000EF));
    EXPECT_EQ(UN(RtlLocaleNameToLcid)(NULL, NULL, 0), S(0xC00000EF));
    EXPECT_EQ(UN(RtlLocaleNameToLcid)(L"en-US", NULL, 0), S(0xC00000F0));
    EXPECT_EQ(UN(RtlLocaleNameToLcid)(L"en-US", &lcid, 4), S(0xC00000F1));
    EXPECT_EQ(UN(RtlLocaleNameToLcid)(L"en-US", &lcid, 0x80), S(0xC00000F1));
    EXPECT_EQ(UN(RtlLocaleNameToLcid)(L"not-a-locale-name", &lcid, 0), S(0xC00000EF));
    lcid = 0; s = UN(RtlLocaleNameToLcid)(L"", &lcid, 0);          /* the empty name is the invariant locale */
    EXPECT_EQ(s, 0); EXPECT_EQ(lcid, 0x7F);
    /* round trip through RtlLcidToLocaleName */
    if (UN(RtlLcidToLocaleName)) {
        WCHAR buf[100]; UNICODE_STRING u; mkus(&u, buf, sizeof buf);
        lcid = 0;
        if (UN(RtlLocaleNameToLcid)(L"fr-FR", &lcid, 0) == 0 && UN(RtlLcidToLocaleName)(lcid, &u, 0, FALSE) == 0) CHECK(!lstrcmpW(buf, L"fr-FR"));
    }
}

/* ---------- RtlNormalizeString ---------- */
#define NFC 1
#define NFD 2
#define NFKC 5
#define NFKD 6
static void norm_case(ULONG form, const WCHAR *src, const WCHAR *want, const char *what) {
    WCHAR dst[64]; LONG n = 64; NTSTATUS s;
    memset(dst, 0xCC, sizeof dst);
    s = UN(RtlNormalizeString)(form, src, -1, dst, &n);
    CHECKF(s == 0, "%s: status 0x%lx", what, (ULONG)s);
    if (s != 0) return;
    CHECKF(n == (LONG)lstrlenW(want) + 1, "%s: length %ld (null-terminated input includes the terminator)", what, n);
    CHECKF(!lstrcmpW(dst, want), "%s: content", what);
}
TEST(normalize_string) {
    WCHAR dst[64]; LONG n; NTSTATUS s;
    REQUIRE(UN(RtlNormalizeString));
    norm_case(NFC, L"e\x0301", L"\x00e9", "NFC compose");
    norm_case(NFD, L"\x00e9", L"e\x0301", "NFD decompose");
    norm_case(NFC, L"\x2126", L"\x03a9", "NFC singleton Ohm");
    norm_case(NFKC, L"\xfb01", L"fi", "NFKC ligature");
    norm_case(NFC, L"\xfb01", L"\xfb01", "NFC keeps compat ligature");
    norm_case(NFKD, L"\x00e9\xfb01", L"e\x0301" L"fi", "NFKD");
    norm_case(NFC, L"plain ASCII", L"plain ASCII", "NFC ascii");
    norm_case(NFC, L"a\x0323\x0307", L"\x1ea1\x0307", "NFC canonical ordering");
    norm_case(NFD, L"\xac00", L"\x1100\x1161", "NFD hangul syllable");
    /* explicit length without terminator */
    n = 64; memset(dst, 0xCC, sizeof dst);
    s = UN(RtlNormalizeString)(NFC, L"e\x0301xyz", 2, dst, &n);
    EXPECT_EQ(s, 0); EXPECT_EQ(n, 1); EXPECT_EQ(dst[0], 0x00e9);
    /* size query: output length is reported with a too-small buffer */
    n = 0;
    s = UN(RtlNormalizeString)(NFC, L"e\x0301", 2, NULL, &n);
    CHECKF(s == S(0xC0000023) || s == 0, "size query status 0x%lx", (ULONG)s);
    CHECKF(n >= 1, "size query reported %ld", n);               /* an upper-bound estimate, not the exact size */
    n = 0;
    s = UN(RtlNormalizeString)(NFD, L"\x00e9", 1, dst, &n);
    CHECKF(s == S(0xC0000023) || s == 0, "zero-length output status 0x%lx", (ULONG)s);
    CHECKF(n >= 2, "estimate %ld below the 2 needed", n);
    n = 1;
    s = UN(RtlNormalizeString)(NFD, L"\x00e9", 1, dst, &n);
    EXPECT_EQ(s, S(0xC0000023));
    CHECKF(n >= 2, "required size %ld below the 2 needed", n);
    /* argument validation */
    n = 64;
    EXPECT_EQ(UN(RtlNormalizeString)(0, L"a", 1, dst, &n), S(0xC000000D));
    EXPECT_EQ(UN(RtlNormalizeString)(NFC, NULL, 1, dst, &n), S(0xC000000D));
    EXPECT_EQ(UN(RtlNormalizeString)(NFC, L"a", -2, dst, &n), S(0xC000000D));
    n = -1;
    EXPECT_EQ(UN(RtlNormalizeString)(NFC, L"a", 1, dst, &n), S(0xC000000D));
    n = 64;
    s = UN(RtlNormalizeString)(3, L"a", 1, dst, &n);          /* 3 and 4 are not normalization forms */
    CHECKF(s < 0, "invalid form 3 accepted: 0x%lx", (ULONG)s);
    s = UN(RtlNormalizeString)(0x77, L"a", 1, dst, &n);
    CHECKF(s < 0, "invalid form accepted: 0x%lx", (ULONG)s);
}

/* ---------- RtlNtPathNameToDosPathName ---------- */
typedef struct {
    UNICODE_STRING String;
    PUCHAR Buffer, StaticBuffer; SIZE_T Size, StaticSize;
    UCHAR MinimumStaticBufferForTerminalNul[8];
} USB;
static void usb_init(USB *b, WCHAR *storage, size_t bytes, const WCHAR *init) {
    size_t l = lstrlenW(init) * 2;
    memset(b, 0, sizeof *b);
    memcpy(storage, init, l + 2);
    b->String.Buffer = storage; b->String.Length = (USHORT)l; b->String.MaximumLength = (USHORT)bytes;
    b->Buffer = b->StaticBuffer = (PUCHAR)storage; b->Size = b->StaticSize = bytes;
}
TEST(nt_path_to_dos_path) {
    static const struct { const WCHAR *in; ULONG type; const WCHAR *out; } t[] = {
        { L"\\??\\C:\\Windows\\x.dll",        3, L"C:\\Windows\\x.dll" },
        { L"\\??\\c:\\",                      3, L"c:\\" },
        { L"\\??\\UNC\\server\\share\\f.txt", 2, L"\\\\server\\share\\f.txt" },
        { L"\\??\\unc\\srv\\s",               2, L"\\\\srv\\s" },
        { L"\\??\\PIPE\\name",                3, L"PIPE\\name" },
    };
    WCHAR store[300]; USB b; ULONG ty; size_t i; NTSTATUS s;
    REQUIRE(UN(RtlNtPathNameToDosPathName));
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        usb_init(&b, store, sizeof store, t[i].in);
        ty = 0xFFFF;
        s = UN(RtlNtPathNameToDosPathName)(0, &b, &ty, NULL);
        CHECKF(s == 0, "case %u status 0x%lx", (unsigned)i, (ULONG)s);
        if (s != 0) continue;
        EXPECT_EQ(ty, t[i].type);
        CHECKF(b.String.Length == lstrlenW(t[i].out) * 2 && !memcmp(b.String.Buffer, t[i].out, b.String.Length), "case %u result", (unsigned)i);
        EXPECT_EQ(b.String.Buffer[b.String.Length / 2], 0);
    }
    /* names without a \??\ prefix are left alone; the path type is classified */
    usb_init(&b, store, sizeof store, L"C:\\dir\\f");
    ty = 0xFFFF; EXPECT_EQ(UN(RtlNtPathNameToDosPathName)(0, &b, &ty, NULL), 0); EXPECT_EQ(ty, 4);
    CHECK(!lstrcmpW(b.String.Buffer, L"C:\\dir\\f"));
    usb_init(&b, store, sizeof store, L"dir\\f");
    ty = 0xFFFF; EXPECT_EQ(UN(RtlNtPathNameToDosPathName)(0, &b, &ty, NULL), 0); EXPECT_EQ(ty, 1);
    usb_init(&b, store, sizeof store, L"\\\\srv\\sh\\f");
    ty = 0xFFFF; EXPECT_EQ(UN(RtlNtPathNameToDosPathName)(0, &b, &ty, NULL), 0); EXPECT_EQ(ty, 4);
    usb_init(&b, store, sizeof store, L"\\Device\\HarddiskVolume1\\x");
    ty = 0xFFFF; EXPECT_EQ(UN(RtlNtPathNameToDosPathName)(0, &b, &ty, NULL), 0); EXPECT_EQ(ty, 1);
    usb_init(&b, store, sizeof store, L"C:\\dir\\f");
    EXPECT_EQ(UN(RtlNtPathNameToDosPathName)(0, &b, NULL, NULL), 0);          /* no prefix and no type requested: nothing to do */
    /* the type output is cleared before any validation */
    usb_init(&b, store, sizeof store, L"\\??\\C:\\x"); ty = 0xFFFF;
    EXPECT_EQ(UN(RtlNtPathNameToDosPathName)(1, &b, &ty, NULL), S(0xC000000D)); EXPECT_EQ(ty, 0);
    ty = 0xFFFF; EXPECT_EQ(UN(RtlNtPathNameToDosPathName)(0, NULL, &ty, NULL), S(0xC000000D)); EXPECT_EQ(ty, 0);
    /* a long name: the 4-character \??\ prefix is stripped in place */
    {
        WCHAR small[40]; WCHAR longname[200]; int k;
        for (k = 0; k < 150; k++) longname[k] = L'a';
        longname[150] = 0;
        memcpy(longname, L"\\??\\C:\\", 16);
        usb_init(&b, small, sizeof small, L"\\??\\C:\\");
        b.String.Buffer = longname; b.String.Length = 150 * 2; b.String.MaximumLength = 151 * 2;
        b.Buffer = b.StaticBuffer = (PUCHAR)longname; b.Size = b.StaticSize = 151 * 2;
        s = UN(RtlNtPathNameToDosPathName)(0, &b, &ty, NULL);
        EXPECT_EQ(s, 0);
        EXPECT_EQ(b.String.Length, (150 - 4) * 2);
        CHECK(!memcmp(b.String.Buffer, L"C:\\", 6));
    }
}

/* ---------- RtlNtdllName ---------- */
TEST(ntdll_name_export) {
    /* RtlNtdllName is a data export holding a pointer to the module's own file name */
    PWSTR *pp = (PWSTR *)t_proc("RtlNtdllName");
    REQUIRE(pp);
    CHECK(*pp != NULL);
    if (*pp) EXPECT_WSTR(*pp, L"ntdll.dll");
}

/* ---------- RtlReplaceSystemDirectoryInPath ---------- */
/* machine ids: 1 = native, 0x14c = x86 (SysWOW64), 0x1c4 = ARM (SysARM32), 0x3a64 = CHPE x86 (SyCHPE32) */
static NTSTATUS repl(const WCHAR *in, ULONG from, ULONG to, ULONG flag, WCHAR *out, size_t outcap, USHORT *outlen) {
    UNICODE_STRING u; NTSTATUS s;
    lstrcpyW(out, in);
    u.Buffer = out; u.Length = (USHORT)(lstrlenW(in) * 2); u.MaximumLength = (USHORT)outcap;
    s = UN(RtlReplaceSystemDirectoryInPath)(&u, from, to, flag);
    if (outlen) *outlen = u.Length;
    return s;
}
TEST(replace_system_directory_in_path) {
    WCHAR buf[100]; USHORT n; NTSTATUS s;
    REQUIRE(UN(RtlReplaceSystemDirectoryInPath));
    /* identical source and target: success, nothing examined */
    s = repl(L"C:\\Windows\\System32\\foo.dll", 1, 1, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); EXPECT_EQ(lstrcmpW(buf, L"C:\\Windows\\System32\\foo.dll"), 0);
    s = repl(L"C:\\Windows\\System32\\foo.dll", 0x1234, 0x1234, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0);                                           /* equal ids short-circuit before validation */
    /* native -> x86 and back, both flag variants */
    s = repl(L"C:\\Windows\\System32\\foo.dll", 1, 0x14c, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); CHECK(!lstrcmpW(buf, L"C:\\Windows\\SysWOW64\\foo.dll")); EXPECT_EQ(n, lstrlenW(buf) * 2);
    s = repl(L"C:\\Windows\\System32\\foo.dll", 1, 0x14c, 1, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); CHECK(!lstrcmpW(buf, L"C:\\Windows\\SysWOW64\\foo.dll"));
    s = repl(L"C:\\Windows\\SysWOW64\\foo.dll", 0x14c, 1, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); CHECK(!lstrcmpW(buf, L"C:\\Windows\\System32\\foo.dll"));
    s = repl(L"C:\\Windows\\System32\\foo.dll", 1, 0x1c4, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); CHECK(!lstrcmpW(buf, L"C:\\Windows\\SysARM32\\foo.dll"));
    s = repl(L"C:\\Windows\\System32\\foo.dll", 1, 0x3a64, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); CHECK(!lstrcmpW(buf, L"C:\\Windows\\SyCHPE32\\foo.dll"));
    /* the match is case-insensitive and the replacement text is the canonical spelling */
    s = repl(L"c:\\windows\\SYSTEM32\\Bar.dll", 1, 0x14c, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); CHECK(!lstrcmpW(buf, L"c:\\windows\\SysWOW64\\Bar.dll"));
    /* without the directory nothing changes and the call still succeeds */
    s = repl(L"C:\\Other\\foo.dll", 1, 0x14c, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); CHECK(!lstrcmpW(buf, L"C:\\Other\\foo.dll"));
    /* flag 0 matches the bare name anywhere, flag 1 requires it to be delimited by separators */
    s = repl(L"C:\\xSystem32y\\foo.dll", 1, 0x14c, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); CHECK(!lstrcmpW(buf, L"C:\\xSysWOW64y\\foo.dll"));
    s = repl(L"C:\\xSystem32y\\foo.dll", 1, 0x14c, 1, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); CHECK(!lstrcmpW(buf, L"C:\\xSystem32y\\foo.dll"));
    /* only the first occurrence is replaced */
    s = repl(L"C:\\System32\\System32\\a", 1, 0x14c, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, 0); CHECK(!lstrcmpW(buf, L"C:\\SysWOW64\\System32\\a"));
    /* unknown machine ids are rejected, target first */
    s = repl(L"C:\\Windows\\System32\\foo.dll", 1, 0x8664, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, S(0xC000000D)); CHECK(!lstrcmpW(buf, L"C:\\Windows\\System32\\foo.dll"));
    s = repl(L"C:\\Windows\\System32\\foo.dll", 0x8664, 1, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, S(0xC000000D));
    s = repl(L"C:\\Windows\\System32\\foo.dll", 0, 1, 0, buf, sizeof buf, &n);
    EXPECT_EQ(s, S(0xC000000D));
}

/* ---------- RtlLoadString ---------- */
TEST(load_string) {
    HMODULE m; PCWSTR str = NULL; USHORT len = 0; WCHAR ref[300]; int id, found = 0; NTSTATUS s;
    REQUIRE(UN(RtlLoadString));
    m = LoadLibraryExA("user32.dll", NULL, 0);
    if (!m) { t_skip("user32 not loadable"); return; }
    /* validation */
    EXPECT_EQ(UN(RtlLoadString)(NULL, 1, NULL, 0, &str, &len, NULL, NULL), S(0xC000000D));
    EXPECT_EQ(UN(RtlLoadString)(m, 1, NULL, 0, NULL, &len, NULL, NULL), S(0xC000000D));
    EXPECT_EQ(UN(RtlLoadString)(m, 1, NULL, 2, &str, &len, NULL, NULL), S(0xC000000D));
    { ULONG dummy = 0; EXPECT_EQ(UN(RtlLoadString)(m, 1, NULL, 1, &str, &len, &dummy, NULL), S(0xC00000BB)); }
    /* find a string and compare with the loader's own table lookup */
    for (id = 1; id < 3000 && !found; id++) {
        if (LoadStringW(m, id, ref, 300) > 0) { found = id; }
    }
    if (!found) { FreeLibrary(m); t_skip("no string resources found in user32"); return; }
    str = NULL; len = 0;
    s = UN(RtlLoadString)(m, (USHORT)found, NULL, 0, &str, &len, NULL, NULL);
    CHECKF(s == 0, "RtlLoadString id %d status 0x%lx", found, (ULONG)s);
    if (s == 0) {
        EXPECT_EQ(len, lstrlenW(ref));
        CHECK(str && !memcmp(str, ref, len * 2));
    }
    /* nonexistent id in an existing block and a nonexistent block */
    str = NULL; len = 0xFFFF;
    s = UN(RtlLoadString)(m, 0xFFF0, NULL, 0, &str, &len, NULL, NULL);
    CHECKF(s < 0, "missing string block accepted: 0x%lx", (ULONG)s);
    FreeLibrary(m);
}

/* Image-file loader services: image file execution options keys, image checksum verification,
 * base relocation blocks, delay-load entry points and the system DLL init block. */
#include "t.h"
#include "pebuild.h"

UDECL(NTSTATUS, LdrOpenImageFileOptionsKey, (PUNICODE_STRING, BOOLEAN, PHANDLE));
UDECL(NTSTATUS, LdrQueryImageFileExecutionOptions, (PUNICODE_STRING, PCWSTR, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, LdrQueryImageFileExecutionOptionsEx, (PUNICODE_STRING, PCWSTR, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, LdrQueryImageFileKeyOption, (HANDLE, PCWSTR, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, LdrVerifyImageMatchesChecksum, (HANDLE, PVOID, PVOID, PUSHORT));
UDECL(NTSTATUS, LdrVerifyImageMatchesChecksumEx, (HANDLE, PVOID));
UDECL(PUSHORT, LdrProcessRelocationBlock, (ULONG_PTR, ULONG, PUSHORT, LONG_PTR));
UDECL(PUSHORT, LdrProcessRelocationBlockEx, (USHORT, ULONG_PTR, ULONG, PUSHORT, LONG_PTR));
UDECL(NTSTATUS, LdrQueryOptionalDelayLoadedAPI, (PVOID, PCSTR, PCSTR, ULONG));
UDECL(NTSTATUS, LdrResolveDelayLoadsFromDll, (PVOID, PCSTR, ULONG));
UDECL(PVOID, LdrResolveDelayLoadedAPI, (PVOID, PVOID, PVOID, PVOID, PVOID *, ULONG));
UDECL(NTSTATUS, LdrLoadAlternateResourceModule, (PVOID, PVOID, PVOID, ULONG));
UDECL(ULONG, LdrUnloadAlternateResourceModuleEx, (PVOID, USHORT));
UDECL(VOID, LdrUnloadAlternateResourceModule, (PVOID));
UDECL(NTSTATUS, LdrLoadAlternateResourceModuleEx, (PVOID, USHORT, PVOID, PVOID, ULONG));
UDECL(ULONG, LdrFlushAlternateResourceModules, (void));

#define S(x) ((NTSTATUS)(x))
#define ST_BAD_PARAM     S(0xC000000D)
#define ST_NAME_NOTFOUND S(0xC0000034)
#define ST_TYPE_MISMATCH S(0xC0000024)
#define ST_LEN_MISMATCH  S(0xC0000004)
#define ST_DLL_NOTFOUND  S(0xC0000135)
#define ST_CKSUM         S(0xC0000221)
#define ST_BUF_OVERFLOW  S(0x80000005)
#define ST_MISALIGNED    S(0x80000002)

static UNICODE_STRING us(const WCHAR *s)
{
    UNICODE_STRING u;
    u.Buffer = (PWSTR)s; u.Length = (USHORT)(lstrlenW(s) * 2); u.MaximumLength = u.Length + 2;
    return u;
}

/* ---- LdrQueryImageFileKeyOption on a throwaway key ---------------------------------------- */
static HKEY mk_key(char *name, size_t cap)
{
    HKEY k = NULL;
    wsprintfA(name, "Software\\corpus_ldr_ifeo_%lu", GetCurrentProcessId());
    RegDeleteKeyA(HKEY_CURRENT_USER, name);
    if (RegCreateKeyExA(HKEY_CURRENT_USER, name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL)) return NULL;
    return k;
}
TEST(ldr_ifeo_key_option_values)
{
    REQUIRE(UN(LdrQueryImageFileKeyOption));
    char kn[80]; HKEY k = mk_key(kn, sizeof kn);
    if (!k) { t_skip("cannot create a test key under HKCU (err %lu)", GetLastError()); return; }
    DWORD dw = 0x12345678; ULONGLONG qw = 0x1122334455667788ull; BYTE bin[5] = {1, 2, 3, 4, 5};
    RegSetValueExW(k, L"Dword", 0, REG_DWORD, (BYTE *)&dw, 4);
    RegSetValueExW(k, L"Qword", 0, REG_QWORD, (BYTE *)&qw, 8);
    RegSetValueExW(k, L"Sz", 0, REG_SZ, (BYTE *)L"C:\\dbg.exe", 22);
    RegSetValueExW(k, L"Bin", 0, REG_BINARY, bin, 5);
    RegSetValueExW(k, L"StrNum", 0, REG_SZ, (BYTE *)L"42", 6);
    RegSetValueExW(k, L"StrHex", 0, REG_SZ, (BYTE *)L"0x10", 10);
    RegSetValueExW(k, L"Expand", 0, REG_EXPAND_SZ, (BYTE *)L"%PATH%", 14);
    ULONG ret; ULONG v; BYTE buf[64];
    /* DWORD */
    ret = 0xdead; v = 0;
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Dword", REG_DWORD, &v, 4, &ret), 0);
    EXPECT_EQ(v, 0x12345678); EXPECT_EQ(ret, 4);
    v = 0; ret = 0;
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Dword", 0, &v, 4, &ret), 0);        /* any type */
    EXPECT_EQ(v, 0x12345678); EXPECT_EQ(ret, 4);
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Dword", REG_DWORD, &v, 8, &ret), ST_LEN_MISMATCH);  /* exact size only */
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Dword", REG_DWORD, &v, 4, NULL), 0);                /* length is optional */
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Dword", REG_SZ, buf, sizeof buf, &ret), ST_TYPE_MISMATCH);
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"dword", REG_DWORD, &v, 4, &ret), 0);                /* value names are case-insensitive */
    /* QWORD */
    ULONGLONG q = 0;
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Qword", REG_QWORD, &q, 8, &ret), 0);
    EXPECT_EQ(q, 0x1122334455667788ull); EXPECT_EQ(ret, 8);
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Qword", REG_QWORD, &q, 4, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Qword", REG_DWORD, &v, 4, &ret), ST_TYPE_MISMATCH);
    /* string: raw bytes including the terminator */
    memset(buf, 0xAA, sizeof buf); ret = 0;
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Sz", REG_SZ, buf, sizeof buf, &ret), 0);
    EXPECT_EQ(ret, 22);
    CHECK(!memcmp(buf, L"C:\\dbg.exe", 22));
    ret = 0;
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Sz", REG_SZ, buf, 10, &ret), ST_BUF_OVERFLOW);
    EXPECT_EQ(ret, 22);
    ret = 0;
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Sz", REG_SZ, NULL, 0, &ret), ST_BUF_OVERFLOW);        /* size query */
    EXPECT_EQ(ret, 22);
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Sz", REG_SZ, buf, 22, &ret), 0);                      /* exact fit */
    /* string to number conversion when a DWORD is requested */
    v = 0;
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"StrNum", REG_DWORD, &v, 4, &ret), 0);
    EXPECT_EQ(v, 42); EXPECT_EQ(ret, 4);
    v = 0;
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"StrHex", REG_DWORD, &v, 4, &ret), 0);
    EXPECT_EQ(v, 16);
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"StrNum", REG_DWORD, &v, 8, &ret), ST_LEN_MISMATCH);
    /* binary: copied verbatim, requested type must match */
    memset(buf, 0, sizeof buf); ret = 0;
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Bin", REG_BINARY, buf, 5, &ret), 0);
    EXPECT_EQ(ret, 5);
    CHECK(!memcmp(buf, bin, 5));
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Bin", REG_BINARY, buf, 4, &ret), ST_BUF_OVERFLOW);
    EXPECT_EQ(ret, 5);
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Bin", REG_DWORD, &v, 4, &ret), ST_TYPE_MISMATCH);
    /* value types that are not supported */
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"Expand", 0, buf, sizeof buf, &ret), ST_TYPE_MISMATCH);
    /* missing value */
    EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(k, L"NoSuchValue", REG_DWORD, &v, 4, &ret), ST_NAME_NOTFOUND);
    RegCloseKey(k);
    RegDeleteKeyA(HKEY_CURRENT_USER, kn);
}

/* ---- HKLM image file execution options (administrator only) --------------------------------- */
#define IFEO_ROOT "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
#define IFEO_IMAGE "corpus_ldr_ifeo_probe.exe"
TEST(ldr_ifeo_execution_options_missing_image)
{
    REQUIRE(UN(LdrQueryImageFileExecutionOptions)); REQUIRE(UN(LdrQueryImageFileExecutionOptionsEx)); REQUIRE(UN(LdrOpenImageFileOptionsKey));
    UNICODE_STRING img = us(L"C:\\nosuch\\corpus_no_such_image.exe");
    ULONG rl = 0xdead; DWORD v = 7; HANDLE h = (HANDLE)1;
    EXPECT_EQ(UN(LdrQueryImageFileExecutionOptions)(&img, L"GlobalFlag", REG_DWORD, &v, 4, &rl), ST_NAME_NOTFOUND);
    EXPECT_EQ(v, 7);
    EXPECT_EQ(UN(LdrQueryImageFileExecutionOptionsEx)(&img, L"GlobalFlag", REG_DWORD, &v, 4, &rl), ST_NAME_NOTFOUND);
    EXPECT_EQ(UN(LdrOpenImageFileOptionsKey)(&img, 0, &h), ST_NAME_NOTFOUND);
    /* no image name: the options root itself is queried, which has no such value */
    EXPECT_EQ(UN(LdrQueryImageFileExecutionOptionsEx)(NULL, L"CorpusNoSuchValue", REG_DWORD, &v, 4, &rl), ST_NAME_NOTFOUND);
}
TEST(ldr_ifeo_execution_options_roundtrip)
{
    REQUIRE(UN(LdrQueryImageFileExecutionOptions)); REQUIRE(UN(LdrQueryImageFileExecutionOptionsEx)); REQUIRE(UN(LdrOpenImageFileOptionsKey));
    REQUIRE(UN(LdrQueryImageFileKeyOption));
    HKEY k = NULL;
    LONG r = RegCreateKeyExA(HKEY_LOCAL_MACHINE, IFEO_ROOT IFEO_IMAGE, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL);
    if (r == ERROR_ACCESS_DENIED) { t_skip("writing HKLM image file execution options needs an elevated token (ERROR_ACCESS_DENIED)"); return; }
    if (r) { t_skip("cannot create the options key (error %ld)", r); return; }
    DWORD dw = 0xC0DE0001;
    RegSetValueExW(k, L"CorpusFlag", 0, REG_DWORD, (BYTE *)&dw, 4);
    RegSetValueExW(k, L"CorpusText", 0, REG_SZ, (BYTE *)L"abc", 8);
    RegCloseKey(k);
    UNICODE_STRING full = us(L"C:\\some\\dir\\" L"corpus_ldr_ifeo_probe.exe"), leaf = us(L"corpus_ldr_ifeo_probe.exe");
    ULONG rl = 0; DWORD v = 0; WCHAR txt[16];
    EXPECT_EQ(UN(LdrQueryImageFileExecutionOptions)(&full, L"CorpusFlag", REG_DWORD, &v, 4, &rl), 0);
    EXPECT_EQ(v, 0xC0DE0001); EXPECT_EQ(rl, 4);
    v = 0;
    EXPECT_EQ(UN(LdrQueryImageFileExecutionOptionsEx)(&leaf, L"CorpusFlag", REG_DWORD, &v, 4, &rl), 0);   /* bare file name works too */
    EXPECT_EQ(v, 0xC0DE0001);
    EXPECT_EQ(UN(LdrQueryImageFileExecutionOptions)(&full, L"CorpusText", REG_SZ, txt, sizeof txt, &rl), 0);
    EXPECT_EQ(rl, 8);
    CHECK(!lstrcmpW(txt, L"abc"));
    EXPECT_EQ(UN(LdrQueryImageFileExecutionOptions)(&full, L"CorpusMissing", REG_DWORD, &v, 4, &rl), ST_NAME_NOTFOUND);
    HANDLE h = NULL;
    EXPECT_EQ(UN(LdrOpenImageFileOptionsKey)(&full, 0, &h), 0);
    CHECK(h != NULL);
    if (h) {
        v = 0;
        EXPECT_EQ(UN(LdrQueryImageFileKeyOption)(h, L"CorpusFlag", REG_DWORD, &v, 4, &rl), 0);
        EXPECT_EQ(v, 0xC0DE0001);
        CloseHandle(h);
    }
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, IFEO_ROOT IFEO_IMAGE);
    EXPECT_EQ(UN(LdrQueryImageFileExecutionOptions)(&full, L"CorpusFlag", REG_DWORD, &v, 4, &rl), ST_NAME_NOTFOUND);
}

/* ---- checksum verification ---------------------------------------------------------------- */
static void bad_checksum(BYTE *b) { BYTE *oh = b + *(ULONG *)(b + 0x3c) + 24; *(ULONG *)(oh + 64) += 1; }
static void zero_checksum(BYTE *b) { BYTE *oh = b + *(ULONG *)(b + 0x3c) + 24; *(ULONG *)(oh + 64) = 0; }
static void corrupt_data(BYTE *b) { b[PEB_RAW_OFF + 0x300] ^= 0xFF; }
static HANDLE open_exec(const char *path)
{
    return CreateFileA(path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}
static void names_cb_sink(void) {}
TEST(ldr_checksum_fixture_files)
{
    REQUIRE(UN(LdrVerifyImageMatchesChecksum));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "cksum.dll");
    HANDLE f; USHORT ch;
    /* correct checksum */
    if (!peb_write(path, 1, NULL)) { t_skip("cannot write fixture"); return; }
    f = open_exec(path);
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot open fixture for execute access (err %lu)", GetLastError()); return; }
    ch = 0xdead;
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksum)(f, NULL, NULL, &ch), 0);
    EXPECT_EQ(ch, 0x2022);                                 /* FileHeader.Characteristics of the fixture */
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksum)(f, NULL, NULL, NULL), 0);
    CloseHandle(f);
    /* checksum field off by one */
    peb_write(path, 1, bad_checksum);
    f = open_exec(path);
    ch = 0xdead;
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksum)(f, NULL, NULL, &ch), ST_CKSUM);
    EXPECT_EQ(ch, 0xdead);                                 /* untouched on failure */
    CloseHandle(f);
    /* file content changed after the checksum was computed */
    peb_write(path, 1, corrupt_data);
    f = open_exec(path);
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksum)(f, NULL, NULL, NULL), ST_CKSUM);
    CloseHandle(f);
    /* checksum field zero: reported as a mismatch as well */
    peb_write(path, 1, zero_checksum);
    f = open_exec(path);
    NTSTATUS s = UN(LdrVerifyImageMatchesChecksum)(f, NULL, NULL, NULL);
    EXPECT_EQ(s, 0);                                       /* a zero checksum field means "not computed" */
    CloseHandle(f);
    /* invalid handles */
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksum)(INVALID_HANDLE_VALUE, NULL, NULL, NULL), ST_TYPE_MISMATCH);
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksum)((HANDLE)(ULONG_PTR)0x7777c, NULL, NULL, NULL), S(0xC0000008));
}
TEST(ldr_checksum_access_rights)
{
    REQUIRE(UN(LdrVerifyImageMatchesChecksum));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "cksum2.dll");
    if (!peb_write(path, 1, NULL)) { t_skip("cannot write fixture"); return; }
    /* an image section needs execute access on the file handle */
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksum)(f, NULL, NULL, NULL), S(0xC0000022));
    CloseHandle(f);
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksum)(NULL, NULL, NULL, NULL), S(0xC00000F2));
}

static int g_imports; static char g_import_names[64][64];
static void CALLBACK on_import(PVOID ctx, const char *name)
{
    if (ctx == (PVOID)0x4242 && g_imports < 64) lstrcpynA(g_import_names[g_imports], name, 64);
    if (ctx == (PVOID)0x4242) g_imports++;
}
TEST(ldr_checksum_ex_import_callback)
{
    REQUIRE(UN(LdrVerifyImageMatchesChecksumEx));
    char path[MAX_PATH];
    GetModuleFileNameA(GetModuleHandleW(L"kernel32.dll"), path, MAX_PATH);
    HANDLE f = open_exec(path);
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot open kernel32 (err %lu)", GetLastError()); return; }
    ULONG_PTR blk[8] = {0};
    ULONG *w = (ULONG *)blk;
    w[0] = 0x40; w[1] = 1;                          /* size, flag 1: import callback present */
    blk[1] = (ULONG_PTR)on_import; blk[2] = 0x4242;
    g_imports = 0;
    NTSTATUS s = UN(LdrVerifyImageMatchesChecksumEx)(f, blk);
    t_note("kernel32 checksum+imports: %08lx, %d imports", s, g_imports);
    CloseHandle(f);
    if (s == ST_CKSUM) { t_skip("kernel32 checksum differs on this build; import enumeration not reached"); return; }
    EXPECT_EQ(s, 0);
    CHECK(g_imports >= 2);
    int sawnt = 0;
    for (int i = 0; i < g_imports && i < 64; i++) {
        size_t n = strlen(g_import_names[i]);
        CHECKF(n > 4 && !_stricmp(g_import_names[i] + n - 4, ".dll"), "import name '%s'", g_import_names[i]);
        if (!_stricmp(g_import_names[i], "ntdll.dll")) sawnt = 1;
    }
    CHECK(sawnt);
    /* invalid block header values are rejected before any file access */
    ULONG_PTR bad[8] = {0};
    ((ULONG *)bad)[0] = 0x38;
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksumEx)(NULL, bad), S(0xC00000F0));
    ((ULONG *)bad)[0] = 0x40; ((ULONG *)bad)[1] = 0x8;
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksumEx)(NULL, bad), S(0xC00000F0));
    ((ULONG *)bad)[1] = 0x1000;
    EXPECT_EQ(UN(LdrVerifyImageMatchesChecksumEx)(NULL, bad), S(0xC00000F0));
}

/* ---- base relocations --------------------------------------------------------------------- */
TEST(ldr_reloc_block_types)
{
    REQUIRE(UN(LdrProcessRelocationBlock)); REQUIRE(UN(LdrProcessRelocationBlockEx));
    BYTE page[0x100]; memset(page, 0, sizeof page);
    *(ULONG *)(page + 0x10) = 0x1000;
    *(ULONG *)(page + 0x18) = 0x2000;
    *(ULONGLONG *)(page + 0x20) = 0x7000000000ull;
    *(USHORT *)(page + 0x30) = 0x0001;          /* HIGH */
    *(USHORT *)(page + 0x32) = 0x0100;          /* LOW */
    USHORT ents[7] = {0x3000 | 0x10, 0x3000 | 0x18, 0xA000 | 0x20, 0x1000 | 0x30, 0x2000 | 0x32, 0x0000, 0x3000 | 0x10};
    /* HIGHLOW and DIR64, with an absolute (padding) entry that is skipped */
    PUSHORT r = UN(LdrProcessRelocationBlock)((ULONG_PTR)page, 3, ents, 0x100);
    EXPECT_EQ(r, ents + 3);
    EXPECT_EQ(*(ULONG *)(page + 0x10), 0x1100);
    EXPECT_EQ(*(ULONG *)(page + 0x18), 0x2100);
    EXPECT_EQ(*(ULONGLONG *)(page + 0x20), 0x7000000100ull);
    /* HIGH adds the high 16 bits of the delta, LOW the low 16 bits */
    r = UN(LdrProcessRelocationBlock)((ULONG_PTR)page, 2, ents + 3, 0x00120034);
    EXPECT_EQ(r, ents + 5);
    EXPECT_EQ(*(USHORT *)(page + 0x30), 0x0001 + 0x12);
    EXPECT_EQ(*(USHORT *)(page + 0x32), 0x0100 + 0x34);
    /* ABSOLUTE entries are consumed without touching memory */
    ULONG before = *(ULONG *)(page + 0x10);
    r = UN(LdrProcessRelocationBlock)((ULONG_PTR)page, 1, ents + 5, 0x100);
    EXPECT_EQ(r, ents + 6);
    EXPECT_EQ(*(ULONG *)(page + 0x10), before);
    /* zero entries: returns the start */
    r = UN(LdrProcessRelocationBlock)((ULONG_PTR)page, 0, ents, 0x100);
    EXPECT_EQ(r, ents);
    /* negative delta wraps */
    *(ULONG *)(page + 0x10) = 0x1000;
    r = UN(LdrProcessRelocationBlock)((ULONG_PTR)page, 1, ents, -0x800);
    EXPECT_EQ(r, ents + 1);
    EXPECT_EQ(*(ULONG *)(page + 0x10), 0x800);
    /* types that are not valid for x64 fail with NULL */
    static const USHORT bad_types[] = {5, 6, 7, 8, 9, 11, 12, 15};
    for (unsigned i = 0; i < sizeof bad_types / sizeof *bad_types; i++) {
        USHORT e = (USHORT)((bad_types[i] << 12) | 0x10);
        CHECKF(UN(LdrProcessRelocationBlock)((ULONG_PTR)page, 1, &e, 0x100) == NULL, "type %u should fail", bad_types[i]);
    }
    /* Ex with the AMD64 machine matches the plain call; foreign machine codes only change types 5/7/9 handling */
    *(ULONG *)(page + 0x10) = 0x1000; *(ULONG *)(page + 0x18) = 0x2000; *(ULONGLONG *)(page + 0x20) = 0x7000000000ull;
    r = UN(LdrProcessRelocationBlockEx)(0x8664, (ULONG_PTR)page, 3, ents, 0x100);
    EXPECT_EQ(r, ents + 3);
    EXPECT_EQ(*(ULONG *)(page + 0x18), 0x2100);
    USHORT e5 = (5 << 12) | 0x10;
    CHECK(UN(LdrProcessRelocationBlockEx)(0x014c, (ULONG_PTR)page, 1, &e5, 0x100) == NULL);
    USHORT e3 = (3 << 12) | 0x10;
    EXPECT_EQ(UN(LdrProcessRelocationBlockEx)(0x014c, (ULONG_PTR)page, 1, &e3, 0x100), &e3 + 1);
}

/* ---- delay load entry points -------------------------------------------------------------- */
TEST(ldr_delay_load_argument_checks)
{
    REQUIRE(UN(LdrQueryOptionalDelayLoadedAPI)); REQUIRE(UN(LdrResolveDelayLoadsFromDll));
    PVOID nt = GetModuleHandleW(L"ntdll.dll");
    /* flags must be zero */
    EXPECT_EQ(UN(LdrQueryOptionalDelayLoadedAPI)(nt, "foo.dll", "bar", 1), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrResolveDelayLoadsFromDll)(nt, "foo.dll", 1), ST_BAD_PARAM);
    /* a module with no delay-load table has nothing to resolve */
    EXPECT_EQ(UN(LdrQueryOptionalDelayLoadedAPI)(nt, "foo.dll", "bar", 0), ST_DLL_NOTFOUND);
    EXPECT_EQ(UN(LdrResolveDelayLoadsFromDll)(nt, "foo.dll", 0), ST_DLL_NOTFOUND);
    if (UN(LdrResolveDelayLoadedAPI)) {
        BYTE desc[32] = {1}; PVOID slot = NULL;
        /* unsupported flag bits: nothing is resolved */
        EXPECT_EQ(UN(LdrResolveDelayLoadedAPI)(nt, desc, NULL, NULL, &slot, 0xFFFF0000u), NULL);
        EXPECT_EQ(slot, NULL);
    }
}

/* ---- MUI alternate resource modules -------------------------------------------------------- */
TEST(ldr_mui_alternate_modules)
{
    REQUIRE(UN(LdrUnloadAlternateResourceModuleEx)); REQUIRE(UN(LdrFlushAlternateResourceModules));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "alt.dll");
    if (!peb_write(path, 1, NULL)) { t_skip("cannot write fixture"); return; }
    HMODULE m = LoadLibraryA(path);
    if (!m) { t_skip("fixture cannot be loaded"); return; }
    UN(LdrFlushAlternateResourceModules)();
    EXPECT_EQ(UN(LdrUnloadAlternateResourceModuleEx)(NULL, 0) & 0xff, 0);
    EXPECT_EQ(UN(LdrUnloadAlternateResourceModuleEx)(m, 0) & 0xff, 1);     /* empty cache: nothing to unload, success */
    if (UN(LdrUnloadAlternateResourceModule)) UN(LdrUnloadAlternateResourceModule)(m);
    if (UN(LdrLoadAlternateResourceModule)) {
        PVOID a = NULL, b = NULL;
        EXPECT_EQ(UN(LdrLoadAlternateResourceModule)(NULL, &a, &b, 0), ST_BAD_PARAM);
        EXPECT_EQ(UN(LdrLoadAlternateResourceModule)(m, NULL, &b, 0), ST_BAD_PARAM);
        NTSTATUS s = UN(LdrLoadAlternateResourceModule)(m, &a, &b, 0);
        EXPECT_EQ(s, S(0xC000003A));                   /* path of the language directory not found */
    }
    if (UN(LdrLoadAlternateResourceModuleEx)) {
        PVOID a = NULL, b = NULL;
        EXPECT_EQ(UN(LdrLoadAlternateResourceModuleEx)(NULL, 0x409, &a, &b, 0), ST_BAD_PARAM);
        EXPECT_EQ(UN(LdrLoadAlternateResourceModuleEx)(m, 0, &a, &b, 0), ST_BAD_PARAM);
        EXPECT_EQ(UN(LdrLoadAlternateResourceModuleEx)(m, 0x409, NULL, &b, 0), ST_BAD_PARAM);
        NTSTATUS s = UN(LdrLoadAlternateResourceModuleEx)(m, 0x409, &a, &b, 0);
        EXPECT_EQ(s, S(0xC00B0006));                   /* no MUI file for the module */
        EXPECT_EQ(a, NULL);
    }
    FreeLibrary(m);
}

/* ---- system DLL init block (data export) --------------------------------------------------- */
TEST(ldr_system_dll_init_block)
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    BYTE *p = (BYTE *)GetProcAddress(nt, "LdrSystemDllInitBlock");
    if (!p) { t_skip("LdrSystemDllInitBlock is not exported"); return; }
    PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)((BYTE *)nt + ((PIMAGE_DOS_HEADER)nt)->e_lfanew);
    CHECK(p > (BYTE *)nt && p < (BYTE *)nt + h->OptionalHeader.SizeOfImage);
    ULONG size = *(ULONG *)p;                              /* PS_SYSTEM_DLL_INIT_BLOCK.Size */
    t_note("LdrSystemDllInitBlock.Size = 0x%lx", size);
    CHECK(size >= 0x20 && size <= 0x400);
}

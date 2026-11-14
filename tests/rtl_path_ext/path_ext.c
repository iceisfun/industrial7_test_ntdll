#include "t.h"

/* DOS path services beyond the basic classification: 8.3 names, search path, current
 * directory, extended normalization, relative NT names. */
typedef struct { USHORT Checksum; BOOLEAN ChecksumInserted; BYTE NameLength; WCHAR NameBuffer[8];
                 ULONG ExtensionLength; WCHAR ExtensionBuffer[4]; ULONG LastIndexValue; } GEN8_CTX;
typedef struct { UNICODE_STRING RelativeName; HANDLE ContainingDirectory; PVOID CurDirRef; } REL_NAME;

UDECL(BOOLEAN, RtlIsNameLegalDOS8Dot3, (PCUNICODE_STRING, PSTRING, PBOOLEAN));
UDECL(void, RtlGenerate8dot3Name, (PCUNICODE_STRING, BOOLEAN, GEN8_CTX *, PUNICODE_STRING));
UDECL(ULONG, RtlDosSearchPath_U, (PCWSTR, PCWSTR, PCWSTR, ULONG, PWSTR, PWSTR *));
UDECL(NTSTATUS, RtlSetCurrentDirectory_U, (PUNICODE_STRING));
UDECL(ULONG, RtlGetCurrentDirectory_U, (ULONG, PWSTR));
UDECL(ULONG, RtlGetFullPathName_U, (PCWSTR, ULONG, PWSTR, PWSTR *));
UDECL(NTSTATUS, RtlGetFullPathName_UEx, (PCWSTR, ULONG, PWSTR, PWSTR *, ULONG *));
UDECL(BOOLEAN, RtlDosPathNameToNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, PVOID));
UDECL(NTSTATUS, RtlDosPathNameToRelativeNtPathName_U_WithStatus, (PCWSTR, PUNICODE_STRING, PWSTR *, REL_NAME *));
UDECL(BOOLEAN, RtlDosPathNameToRelativeNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, REL_NAME *));
UDECL(void, RtlReleaseRelativeName, (REL_NAME *));
UDECL(BOOLEAN, RtlDoesFileExists_U, (PCWSTR));
UDECL(ULONG, RtlGetLongestNtPathLength, (void));
UDECL(void, RtlFreeUnicodeString, (PUNICODE_STRING));

#define NOTFOUND ((NTSTATUS)0xC0000034)
#define SMALL    ((NTSTATUS)0xC0000023)
#define OVERFLOW ((NTSTATUS)0x80000005)

static void wtmp(WCHAR *out, size_t cap, const char *leaf)
{
    char n[MAX_PATH];
    t_tmpfile(n, sizeof n, leaf);
    MultiByteToWideChar(CP_ACP, 0, n, -1, out, (int)cap);
}

static void touch_file(const WCHAR *path)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

/* ---- RtlIsNameLegalDOS8Dot3 -------------------------------------------- */

static BOOLEAN legal(const WCHAR *name, BOOLEAN *spaces, char *oem_out, size_t oem_cap)
{
    UNICODE_STRING u; STRING o; BOOLEAN sp = 0xFF, r;
    char buf[32];
    u.Buffer = (PWSTR)name; u.Length = (USHORT)(lstrlenW(name) * 2); u.MaximumLength = u.Length + 2;
    memset(buf, 0x55, sizeof buf);
    o.Buffer = buf; o.Length = 0; o.MaximumLength = sizeof buf;
    r = UN(RtlIsNameLegalDOS8Dot3)(&u, &o, &sp);
    if (spaces) *spaces = sp;
    if (oem_out && r) { size_t n = o.Length < oem_cap - 1 ? o.Length : oem_cap - 1; memcpy(oem_out, buf, n); oem_out[n] = 0; }
    return r;
}

TEST(pathx_8dot3_legal)
{
    static const WCHAR *const ok[] = {
        L"A", L"FILE", L"FILE.TXT", L"ABCDEFGH", L"ABCDEFGH.IJK", L"A.B", L"ABC.D", L"NAME.E",
        L"1234.567", L"A-B_C.D~E", L"A$B", L"A#B", L"A@B", L"A!B", L"A%B", L"A&B", L"A(B).C", L"A'B", L"A^B", L"A{B}", L"A`B",
    };
    REQUIRE(UN(RtlIsNameLegalDOS8Dot3));
    for (unsigned i = 0; i < sizeof ok / sizeof ok[0]; ++i) {
        BOOLEAN sp;
        CHECKF(legal(ok[i], &sp, NULL, 0), "case %u should be legal", i);
        if (legal(ok[i], &sp, NULL, 0)) CHECKF(!sp, "case %u should not report spaces", i);
    }
}

TEST(pathx_8dot3_illegal_length_and_structure)
{
    static const WCHAR *const bad[] = {
        L"ABCDEFGHI", L"ABCDEFGHI.TXT", L"ABC.DEFG", L"A.B.C", L"..A", L".A.B",
        L"ABCDEFGH.IJKL", L"VERYLONGNAME", L"A..B",
    };
    REQUIRE(UN(RtlIsNameLegalDOS8Dot3));
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; ++i)
        CHECKF(!legal(bad[i], NULL, NULL, 0), "case %u (\"%ls\") should be illegal", i, bad[i]);
}

TEST(pathx_8dot3_illegal_characters)
{
    static const WCHAR *const bad[] = {
        L"A*B", L"A?B", L"A<B", L"A>B", L"A|B", L"A\"B", L"A/B", L"A\\B", L"A:B", L"*.TXT", L"A.T?T",
    };
    REQUIRE(UN(RtlIsNameLegalDOS8Dot3));
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; ++i)
        CHECKF(!legal(bad[i], NULL, NULL, 0), "case %u (\"%ls\") should be illegal", i, bad[i]);
}

TEST(pathx_8dot3_oem_form_is_uppercase)
{
    char oem[32]; BOOLEAN sp;
    REQUIRE(UN(RtlIsNameLegalDOS8Dot3));
    CHECK(legal(L"file.txt", &sp, oem, sizeof oem));
    EXPECT_STR(oem, "FILE.TXT");
    CHECK(legal(L"MiXeD.Ab", &sp, oem, sizeof oem));
    EXPECT_STR(oem, "MIXED.AB");
}

TEST(pathx_8dot3_spaces_flag)
{
    BOOLEAN sp = 0xFF, r;
    REQUIRE(UN(RtlIsNameLegalDOS8Dot3));
    r = legal(L"A B.TXT", &sp, NULL, 0);
    t_note("name with an interior blank: legal=%d spaces=%d", r, sp);
    if (r) EXPECT_EQ(sp, TRUE);
    sp = 0xFF; r = legal(L"AB.TXT", &sp, NULL, 0);
    EXPECT_EQ(r, TRUE); EXPECT_EQ(sp, FALSE);
}

TEST(pathx_8dot3_dot_names_note)
{
    static const WCHAR *const n[] = { L".", L"..", L"...", L".A", L"A.", L"", L"A+B", L"A,B", L"A;B", L"A=B", L"A[B]", L"A B", L" A", L"A ", L"\x00E9.TXT" };
    REQUIRE(UN(RtlIsNameLegalDOS8Dot3));
    for (unsigned i = 0; i < sizeof n / sizeof n[0]; ++i) {
        BOOLEAN sp;
        BOOLEAN r = legal(n[i], &sp, NULL, 0);
        t_note("\"%ls\": legal=%d spaces=%d", n[i], r, sp);
    }
}

/* ---- RtlGenerate8dot3Name ---------------------------------------------- */

static void gen(GEN8_CTX *ctx, const WCHAR *in, BOOLEAN ext, WCHAR *out, size_t cap)
{
    UNICODE_STRING u, o; WCHAR buf[16]; size_t n;
    u.Buffer = (PWSTR)in; u.Length = (USHORT)(lstrlenW(in) * 2); u.MaximumLength = u.Length + 2;
    for (unsigned i = 0; i < 16; ++i) buf[i] = 0x5555;
    o.Buffer = buf; o.Length = 0; o.MaximumLength = sizeof buf;
    UN(RtlGenerate8dot3Name)(&u, ext, ctx, &o);
    n = o.Length / 2; if (n >= cap) n = cap - 1;
    memcpy(out, buf, n * 2); out[n] = 0;
}

TEST(pathx_gen8dot3_basic)
{
    GEN8_CTX c; WCHAR r[16];
    REQUIRE(UN(RtlGenerate8dot3Name));
    memset(&c, 0, sizeof c);
    gen(&c, L"LongFileName.txt", FALSE, r, 16);
    EXPECT_WSTR(r, L"LONGFI~1.TXT");
    memset(&c, 0, sizeof c);
    /* A base name shorter than three characters gets a four-hex-digit checksum before the tilde; an extension
       longer than three characters is cut and marked with a trailing tilde. */
    gen(&c, L"ab.cdefgh", FALSE, r, 16);
    EXPECT_WSTR(r, L"ABA3E4~1.CD~");
    memset(&c, 0, sizeof c);
    gen(&c, L"abc.txt", FALSE, r, 16);
    EXPECT_WSTR(r, L"ABC~1.TXT");
    memset(&c, 0, sizeof c);
    gen(&c, L"ab.txt", FALSE, r, 16);
    EXPECT_WSTR(r, L"AB8D7B~1.TXT");
    memset(&c, 0, sizeof c);
    gen(&c, L"noextension_long", FALSE, r, 16);
    EXPECT_WSTR(r, L"NOEXTE~1");
}

TEST(pathx_gen8dot3_collision_sequence)
{
    GEN8_CTX c; WCHAR r[16];
    REQUIRE(UN(RtlGenerate8dot3Name));
    memset(&c, 0, sizeof c);
    gen(&c, L"LongFileName.txt", FALSE, r, 16); EXPECT_WSTR(r, L"LONGFI~1.TXT");
    gen(&c, L"LongFileName.txt", FALSE, r, 16); EXPECT_WSTR(r, L"LONGFI~2.TXT");
    for (unsigned i = 3; i <= 6; ++i) {
        gen(&c, L"LongFileName.txt", FALSE, r, 16);
        t_note("candidate %u: %ls (checksum inserted: %d)", i, r, c.ChecksumInserted);
        CHECK(wcschr(r, '~') != NULL);
    }
}

TEST(pathx_gen8dot3_filters_characters)
{
    GEN8_CTX c; WCHAR r[16];
    REQUIRE(UN(RtlGenerate8dot3Name));
    memset(&c, 0, sizeof c);
    gen(&c, L"My Long File.doc", FALSE, r, 16);   /* blanks are dropped */
    EXPECT_WSTR(r, L"MYLONG~1.DOC");
    memset(&c, 0, sizeof c);
    gen(&c, L"..leading.dots.txt", FALSE, r, 16);
    t_note("leading dots: %ls", r);
    memset(&c, 0, sizeof c);
    gen(&c, L"a+b,c;d=e[f]g.txt", FALSE, r, 16);
    t_note("characters illegal in 8.3: %ls", r);
    memset(&c, 0, sizeof c);
    gen(&c, L"caf\x00E9_longer.txt", FALSE, r, 16);
    t_note("non-ASCII, extended characters off: %ls", r);
    memset(&c, 0, sizeof c);
    gen(&c, L"caf\x00E9_longer.txt", TRUE, r, 16);
    t_note("non-ASCII, extended characters on: %ls", r);
}

TEST(pathx_gen8dot3_buffer_too_small)
{
    GEN8_CTX c; UNICODE_STRING u, o; WCHAR small[8]; WCHAR in[] = L"LongFileName.txt";
    REQUIRE(UN(RtlGenerate8dot3Name));
    memset(&c, 0, sizeof c);
    u.Buffer = in; u.Length = sizeof in - 2; u.MaximumLength = sizeof in;
    o.Buffer = small; o.Length = 0; o.MaximumLength = sizeof small;   /* 12 characters are needed */
    UN(RtlGenerate8dot3Name)(&u, FALSE, &c, &o);
    t_note("small output: Length %u Maximum %u", o.Length, o.MaximumLength);
}

/* ---- RtlDosSearchPath_U ------------------------------------------------- */

TEST(pathx_search_found_in_second_directory)
{
    WCHAR dir_a[MAX_PATH], dir_b[MAX_PATH], file[MAX_PATH], path[MAX_PATH * 2], out[MAX_PATH], want[MAX_PATH];
    PWSTR part = NULL; ULONG n;
    REQUIRE(UN(RtlDosSearchPath_U));
    wtmp(dir_a, MAX_PATH, "pxs_a"); wtmp(dir_b, MAX_PATH, "pxs_b");
    CreateDirectoryW(dir_a, NULL); CreateDirectoryW(dir_b, NULL);
    lstrcpyW(file, dir_b); lstrcatW(file, L"\\target.dat"); touch_file(file);
    lstrcpyW(path, dir_a); lstrcatW(path, L";"); lstrcatW(path, dir_b);
    memset(out, 0x55, sizeof out);
    n = UN(RtlDosSearchPath_U)(path, L"target.dat", NULL, sizeof out, out, &part);
    lstrcpyW(want, file);
    EXPECT_EQ(n, lstrlenW(want) * 2);
    if (n == (ULONG)lstrlenW(want) * 2) {
        CHECK(!lstrcmpiW(out, want));
        EXPECT_EQ(out[n / 2], 0);
        EXPECT_EQ(part, out + lstrlenW(dir_b) + 1);
    }
    /* not present anywhere */
    memset(out, 0x55, sizeof out);
    n = UN(RtlDosSearchPath_U)(path, L"absent.dat", NULL, sizeof out, out, &part);
    EXPECT_EQ(n, 0);
    DeleteFileW(file); RemoveDirectoryW(dir_a); RemoveDirectoryW(dir_b);
}

TEST(pathx_search_default_extension)
{
    WCHAR dir[MAX_PATH], file[MAX_PATH], out[MAX_PATH]; PWSTR part = NULL; ULONG n;
    REQUIRE(UN(RtlDosSearchPath_U));
    wtmp(dir, MAX_PATH, "pxe"); CreateDirectoryW(dir, NULL);
    lstrcpyW(file, dir); lstrcatW(file, L"\\prog.dat"); touch_file(file);
    n = UN(RtlDosSearchPath_U)(dir, L"prog", L".dat", sizeof out, out, &part);
    EXPECT_EQ(n, lstrlenW(file) * 2);                                  /* extension supplied when the name has none */
    n = UN(RtlDosSearchPath_U)(dir, L"prog", L".bin", sizeof out, out, &part);
    EXPECT_EQ(n, 0);
    n = UN(RtlDosSearchPath_U)(dir, L"prog.dat", L".bin", sizeof out, out, &part);
    EXPECT_EQ(n, lstrlenW(file) * 2);                                  /* name already has an extension */
    n = UN(RtlDosSearchPath_U)(dir, L"prog.", L".dat", sizeof out, out, &part);
    t_note("name with a trailing dot and default extension: %lu", (unsigned long)n);
    DeleteFileW(file); RemoveDirectoryW(dir);
}

TEST(pathx_search_buffer_size)
{
    WCHAR dir[MAX_PATH], file[MAX_PATH], out[MAX_PATH]; PWSTR part = NULL; ULONG n, need;
    REQUIRE(UN(RtlDosSearchPath_U));
    wtmp(dir, MAX_PATH, "pxb"); CreateDirectoryW(dir, NULL);
    lstrcpyW(file, dir); lstrcatW(file, L"\\buf.dat"); touch_file(file);
    need = lstrlenW(file) * 2;
    memset(out, 0x55, sizeof out);
    n = UN(RtlDosSearchPath_U)(dir, L"buf.dat", NULL, need + 2, out, &part);
    EXPECT_EQ(n, need); EXPECT_EQ(out[need / 2], 0);
    memset(out, 0x55, sizeof out);
    n = UN(RtlDosSearchPath_U)(dir, L"buf.dat", NULL, 4, out, &part);
    t_note("4-byte buffer: returned %lu (name needs %lu bytes)", (unsigned long)n, (unsigned long)need);
    CHECK(n == 0 || n >= need);
    DeleteFileW(file); RemoveDirectoryW(dir);
}

TEST(pathx_search_rooted_name_bypasses_path)
{
    WCHAR dir[MAX_PATH], file[MAX_PATH], out[MAX_PATH]; PWSTR part = NULL; ULONG n;
    REQUIRE(UN(RtlDosSearchPath_U));
    wtmp(dir, MAX_PATH, "pxr"); CreateDirectoryW(dir, NULL);
    lstrcpyW(file, dir); lstrcatW(file, L"\\abs.dat"); touch_file(file);
    n = UN(RtlDosSearchPath_U)(L"Z:\\does\\not\\exist", file, NULL, sizeof out, out, &part);
    EXPECT_EQ(n, lstrlenW(file) * 2);
    n = UN(RtlDosSearchPath_U)(dir, L"..\\nope.dat", NULL, sizeof out, out, &part);
    EXPECT_EQ(n, 0);
    DeleteFileW(file); RemoveDirectoryW(dir);
}

/* ---- current directory --------------------------------------------------- */

struct cwd_guard { WCHAR saved[MAX_PATH]; };
static void cwd_save(struct cwd_guard *g) { UN(RtlGetCurrentDirectory_U)(sizeof g->saved, g->saved); }
static void cwd_restore(struct cwd_guard *g)
{
    UNICODE_STRING u; u.Buffer = g->saved; u.Length = (USHORT)(lstrlenW(g->saved) * 2); u.MaximumLength = u.Length + 2;
    UN(RtlSetCurrentDirectory_U)(&u);
}

TEST(pathx_cwd_set_and_get)
{
    struct cwd_guard g; WCHAR dir[MAX_PATH], sub[MAX_PATH], got[MAX_PATH]; UNICODE_STRING u; NTSTATUS st; ULONG n;
    REQUIRE(UN(RtlSetCurrentDirectory_U)); REQUIRE(UN(RtlGetCurrentDirectory_U));
    cwd_save(&g);
    wtmp(dir, MAX_PATH, "pxc"); CreateDirectoryW(dir, NULL);
    lstrcpyW(sub, dir); lstrcatW(sub, L"\\inner"); CreateDirectoryW(sub, NULL);
    u.Buffer = sub; u.Length = (USHORT)(lstrlenW(sub) * 2); u.MaximumLength = u.Length + 2;
    st = UN(RtlSetCurrentDirectory_U)(&u);
    EXPECT_EQ(st, 0);
    memset(got, 0x55, sizeof got);
    n = UN(RtlGetCurrentDirectory_U)(sizeof got, got);
    EXPECT_EQ(n, lstrlenW(sub) * 2);
    CHECK(!lstrcmpiW(got, sub));
    /* a relative path is resolved against the directory now current */
    {
        UNICODE_STRING up; WCHAR rel[] = L"..";
        up.Buffer = rel; up.Length = 4; up.MaximumLength = 6;
        st = UN(RtlSetCurrentDirectory_U)(&up);
        EXPECT_EQ(st, 0);
        n = UN(RtlGetCurrentDirectory_U)(sizeof got, got);
        EXPECT_EQ(n, lstrlenW(dir) * 2);
        CHECK(!lstrcmpiW(got, dir));
    }
    cwd_restore(&g);
    RemoveDirectoryW(sub); RemoveDirectoryW(dir);
}

TEST(pathx_cwd_trailing_separator)
{
    struct cwd_guard g; WCHAR dir[MAX_PATH], withsep[MAX_PATH], got[MAX_PATH]; UNICODE_STRING u; ULONG n;
    REQUIRE(UN(RtlSetCurrentDirectory_U)); REQUIRE(UN(RtlGetCurrentDirectory_U));
    cwd_save(&g);
    wtmp(dir, MAX_PATH, "pxt"); CreateDirectoryW(dir, NULL);
    lstrcpyW(withsep, dir); lstrcatW(withsep, L"\\");
    u.Buffer = withsep; u.Length = (USHORT)(lstrlenW(withsep) * 2); u.MaximumLength = u.Length + 2;
    EXPECT_EQ(UN(RtlSetCurrentDirectory_U)(&u), 0);
    n = UN(RtlGetCurrentDirectory_U)(sizeof got, got);
    t_note("directory set with trailing separator reads back %lu bytes", (unsigned long)n);
    CHECK(n == (ULONG)lstrlenW(dir) * 2 || n == (ULONG)lstrlenW(withsep) * 2);
    cwd_restore(&g);
    RemoveDirectoryW(dir);
}

TEST(pathx_cwd_set_failures)
{
    struct cwd_guard g, after; WCHAR dir[MAX_PATH], file[MAX_PATH], missing[MAX_PATH]; UNICODE_STRING u; NTSTATUS st;
    REQUIRE(UN(RtlSetCurrentDirectory_U)); REQUIRE(UN(RtlGetCurrentDirectory_U));
    cwd_save(&g);
    wtmp(dir, MAX_PATH, "pxf"); CreateDirectoryW(dir, NULL);
    lstrcpyW(missing, dir); lstrcatW(missing, L"\\nothing_here");
    u.Buffer = missing; u.Length = (USHORT)(lstrlenW(missing) * 2); u.MaximumLength = u.Length + 2;
    st = UN(RtlSetCurrentDirectory_U)(&u);
    CHECKF(st == NOTFOUND || st == (NTSTATUS)0xC000003A, "missing directory status 0x%lx", (unsigned long)st);
    cwd_save(&after);
    CHECK(!lstrcmpiW(g.saved, after.saved));                              /* failure leaves the directory unchanged */
    lstrcpyW(file, dir); lstrcatW(file, L"\\plain.txt"); touch_file(file);
    u.Buffer = file; u.Length = (USHORT)(lstrlenW(file) * 2); u.MaximumLength = u.Length + 2;
    st = UN(RtlSetCurrentDirectory_U)(&u);
    CHECK(st != 0);
    t_note("plain file as directory: status 0x%lx", (unsigned long)st);
    cwd_save(&after);
    CHECK(!lstrcmpiW(g.saved, after.saved));
    cwd_restore(&g);
    DeleteFileW(file); RemoveDirectoryW(dir);
}

TEST(pathx_cwd_drives_relative_paths)
{
    struct cwd_guard g; WCHAR dir[MAX_PATH], want[MAX_PATH], out[MAX_PATH]; UNICODE_STRING u; PWSTR part = NULL; ULONG n;
    REQUIRE(UN(RtlSetCurrentDirectory_U)); REQUIRE(UN(RtlGetFullPathName_U));
    cwd_save(&g);
    wtmp(dir, MAX_PATH, "pxd"); CreateDirectoryW(dir, NULL);
    u.Buffer = dir; u.Length = (USHORT)(lstrlenW(dir) * 2); u.MaximumLength = u.Length + 2;
    EXPECT_EQ(UN(RtlSetCurrentDirectory_U)(&u), 0);
    lstrcpyW(want, dir); lstrcatW(want, L"\\rel\\file.txt");
    memset(out, 0x55, sizeof out);
    n = UN(RtlGetFullPathName_U)(L"rel\\file.txt", sizeof out, out, &part);
    EXPECT_EQ(n, lstrlenW(want) * 2);
    CHECK(!lstrcmpiW(out, want));
    if (part) CHECK(!lstrcmpW(part, L"file.txt"));
    lstrcpyW(want, dir); lstrcatW(want, L"\\file.txt");
    n = UN(RtlGetFullPathName_U)(L".\\file.txt", sizeof out, out, &part);
    CHECK(n == (ULONG)lstrlenW(want) * 2 && !lstrcmpiW(out, want));
    cwd_restore(&g);
    RemoveDirectoryW(dir);
}

/* ---- full path (extended) ------------------------------------------------ */

TEST(pathx_fullpath_ex_types)
{
    /* Returns an NTSTATUS and, in the last argument, the byte length of the result (without the terminator). */
    static const struct { const WCHAR *in; const WCHAR *out; } c[] = {
        { L"C:\\a\\b.txt",       L"C:\\a\\b.txt" },
        { L"C:/a/./b/../c",      L"C:\\a\\c" },
        { L"C:\\a\\\\b",         L"C:\\a\\b" },
        { L"C:\\..\\x",          L"C:\\x" },
        { L"\\\\server\\share\\d\\..\\f", L"\\\\server\\share\\f" },
        { L"\\\\?\\C:\\a\\.\\b", L"\\\\?\\C:\\a\\b" },   /* the ntdll call collapses "." after the prefix; the Win32 layer skips normalization for this prefix */
        { L"\\\\.\\PIPE\\name",  L"\\\\.\\PIPE\\name" },
    };
    REQUIRE(UN(RtlGetFullPathName_UEx));
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; ++i) {
        WCHAR out[MAX_PATH]; PWSTR part = NULL; ULONG len = 0xFFFF; NTSTATUS st;
        memset(out, 0x55, sizeof out);
        st = UN(RtlGetFullPathName_UEx)(c[i].in, sizeof out, out, &part, &len);
        CHECKF(st == 0, "case %u status 0x%lx", i, (unsigned long)st);
        CHECKF(len == (ULONG)lstrlenW(c[i].out) * 2, "case %u length %lu", i, (unsigned long)len);
        if (len == (ULONG)lstrlenW(c[i].out) * 2) CHECKF(!lstrcmpW(out, c[i].out), "case %u text \"%ls\"", i, out);
    }
}

TEST(pathx_fullpath_ex_relative_and_rooted)
{
    WCHAR cwd[MAX_PATH], out[MAX_PATH], want[MAX_PATH]; PWSTR part = NULL; ULONG n; NTSTATUS st;
    REQUIRE(UN(RtlGetFullPathName_UEx)); REQUIRE(UN(RtlGetCurrentDirectory_U));
    UN(RtlGetCurrentDirectory_U)(sizeof cwd, cwd);
    n = 0xFFFF;
    st = UN(RtlGetFullPathName_UEx)(L"leaf.txt", sizeof out, out, &part, &n);
    EXPECT_EQ(st, 0);
    {
        size_t cl = lstrlenW(cwd);
        lstrcpyW(want, cwd);
        if (cl && cwd[cl - 1] != '\\') lstrcatW(want, L"\\");
        lstrcatW(want, L"leaf.txt");
    }
    EXPECT_EQ(n, lstrlenW(want) * 2);
    CHECK(!lstrcmpiW(out, want));
    n = 0xFFFF;
    st = UN(RtlGetFullPathName_UEx)(L"\\rooted\\x", sizeof out, out, &part, &n);
    EXPECT_EQ(st, 0);
    if (cwd[1] == ':') {
        want[0] = cwd[0]; want[1] = ':'; want[2] = 0; lstrcatW(want, L"\\rooted\\x");
        CHECK(!lstrcmpiW(out, want));
    }
}

TEST(pathx_fullpath_trailing_dots_and_blanks_note)
{
    static const WCHAR *const in[] = { L"C:\\a\\b. ", L"C:\\a\\b...", L"C:\\a\\b ", L"C:\\a\\.", L"C:\\a\\..", L"C:\\a\\...", L"C:\\a\\ ", L"C:\\a\\", L"NUL", L"C:\\a\\NUL", L"C:\\a\\COM1.txt", L"\\\\.\\C:", L"C:" };
    REQUIRE(UN(RtlGetFullPathName_U));
    for (unsigned i = 0; i < sizeof in / sizeof in[0]; ++i) {
        WCHAR out[MAX_PATH]; PWSTR part = NULL;
        ULONG n = UN(RtlGetFullPathName_U)(in[i], sizeof out, out, &part);
        t_note("\"%ls\" -> %lu bytes \"%ls\" leaf %ls", in[i], (unsigned long)n, n ? out : L"", part ? part : L"(none)");
    }
}

TEST(pathx_fullpath_long_buffer_requirements)
{
    WCHAR in[600], out[MAX_PATH]; PWSTR part = NULL; ULONG n, i;
    REQUIRE(UN(RtlGetFullPathName_U));
    lstrcpyW(in, L"C:\\");
    for (i = 0; i < 20; ++i) lstrcatW(in, L"0123456789abcdef0123456789\\");     /* 3 + 20*27 characters */
    lstrcatW(in, L"leaf");
    n = UN(RtlGetFullPathName_U)(in, sizeof out, out, &part);
    CHECKF(n > sizeof out, "result larger than the buffer reports the required size (%lu)", (unsigned long)n);
    n = UN(RtlGetFullPathName_U)(in, 0, NULL, NULL);
    CHECK(n >= (ULONG)lstrlenW(in) * 2);
}

/* ---- NT path conversion -------------------------------------------------- */

static void nt_case(const WCHAR *in, const WCHAR *want)
{
    UNICODE_STRING nt = {0}; PWSTR part = NULL; BOOLEAN ok;
    REQUIRE(UN(RtlDosPathNameToNtPathName_U)); REQUIRE(UN(RtlFreeUnicodeString));
    ok = UN(RtlDosPathNameToNtPathName_U)(in, &nt, &part, NULL);
    CHECKF(ok, "\"%ls\" did not convert", in);
    if (!ok) return;
    CHECKF(nt.Length == lstrlenW(want) * 2 && !memcmp(nt.Buffer, want, nt.Length), "\"%ls\" -> \"%.*ls\" want \"%ls\"", in, nt.Length / 2, nt.Buffer, want);
    UN(RtlFreeUnicodeString)(&nt);
}
#define NT_CASE(n, in, want) TEST(pathx_nt_##n) { nt_case(in, want); }
NT_CASE(forward_slashes, L"C:/a/b", L"\\??\\C:\\a\\b")
NT_CASE(duplicate_separators, L"C:\\a\\\\b", L"\\??\\C:\\a\\b")
NT_CASE(above_root, L"C:\\..\\x", L"\\??\\C:\\x")
NT_CASE(trailing_dot_component, L"C:\\dir\\.", L"\\??\\C:\\dir")
NT_CASE(trailing_separator, L"C:\\dir\\", L"\\??\\C:\\dir\\")
NT_CASE(device_name, L"NUL", L"\\??\\NUL")
NT_CASE(local_device_pipe, L"\\\\.\\PIPE\\x", L"\\??\\PIPE\\x")
NT_CASE(local_device_drive, L"\\\\.\\C:", L"\\??\\C:")
NT_CASE(extended_unc, L"\\\\?\\UNC\\srv\\sh\\f", L"\\??\\UNC\\srv\\sh\\f")
NT_CASE(unc_collapses_parent, L"\\\\srv\\sh\\d\\..\\f", L"\\??\\UNC\\srv\\sh\\f")

TEST(pathx_nt_relative_name_absolute_input)
{
    UNICODE_STRING nt = {0}; PWSTR part = NULL; REL_NAME rel; NTSTATUS st;
    REQUIRE(UN(RtlDosPathNameToRelativeNtPathName_U_WithStatus)); REQUIRE(UN(RtlReleaseRelativeName)); REQUIRE(UN(RtlFreeUnicodeString));
    memset(&rel, 0xCC, sizeof rel);
    st = UN(RtlDosPathNameToRelativeNtPathName_U_WithStatus)(L"C:\\a\\b\\c.txt", &nt, &part, &rel);
    EXPECT_EQ(st, 0);
    if (st) return;
    CHECK(nt.Length == 2 * lstrlenW(L"\\??\\C:\\a\\b\\c.txt") && !memcmp(nt.Buffer, L"\\??\\C:\\a\\b\\c.txt", nt.Length));
    if (part) CHECK(!lstrcmpW(part, L"c.txt"));
    t_note("relative part: Length %u, containing handle %p", rel.RelativeName.Length, (void *)rel.ContainingDirectory);
    UN(RtlReleaseRelativeName)(&rel);
    UN(RtlFreeUnicodeString)(&nt);
}

TEST(pathx_nt_relative_name_under_cwd)
{
    struct cwd_guard g; WCHAR dir[MAX_PATH]; UNICODE_STRING u, nt = {0}; PWSTR part = NULL; REL_NAME rel; NTSTATUS st;
    WCHAR want[MAX_PATH + 16];
    REQUIRE(UN(RtlDosPathNameToRelativeNtPathName_U_WithStatus)); REQUIRE(UN(RtlReleaseRelativeName));
    REQUIRE(UN(RtlFreeUnicodeString)); REQUIRE(UN(RtlSetCurrentDirectory_U)); REQUIRE(UN(RtlGetCurrentDirectory_U));
    cwd_save(&g);
    wtmp(dir, MAX_PATH, "pxn"); CreateDirectoryW(dir, NULL);
    u.Buffer = dir; u.Length = (USHORT)(lstrlenW(dir) * 2); u.MaximumLength = u.Length + 2;
    EXPECT_EQ(UN(RtlSetCurrentDirectory_U)(&u), 0);
    memset(&rel, 0xCC, sizeof rel);
    st = UN(RtlDosPathNameToRelativeNtPathName_U_WithStatus)(L"sub\\f.txt", &nt, &part, &rel);
    EXPECT_EQ(st, 0);
    if (st == 0) {
        lstrcpyW(want, L"\\??\\"); lstrcatW(want, dir); lstrcatW(want, L"\\sub\\f.txt");
        CHECK(nt.Length == 2 * lstrlenW(want) && !_wcsnicmp(nt.Buffer, want, nt.Length / 2));
        if (rel.RelativeName.Length) {
            CHECK(rel.RelativeName.Length == 2 * lstrlenW(L"sub\\f.txt") && !_wcsnicmp(rel.RelativeName.Buffer, L"sub\\f.txt", rel.RelativeName.Length / 2));
            CHECK(rel.ContainingDirectory != NULL);
        }
        UN(RtlReleaseRelativeName)(&rel);
        UN(RtlFreeUnicodeString)(&nt);
    }
    cwd_restore(&g);
    RemoveDirectoryW(dir);
}

TEST(pathx_nt_relative_name_boolean_form)
{
    UNICODE_STRING nt = {0}; PWSTR part = NULL; REL_NAME rel; BOOLEAN ok;
    REQUIRE(UN(RtlDosPathNameToRelativeNtPathName_U)); REQUIRE(UN(RtlReleaseRelativeName)); REQUIRE(UN(RtlFreeUnicodeString));
    memset(&rel, 0xCC, sizeof rel);
    ok = UN(RtlDosPathNameToRelativeNtPathName_U)(L"C:\\x\\y", &nt, &part, &rel);
    CHECK(ok);
    if (ok) {
        CHECK(nt.Length == 2 * lstrlenW(L"\\??\\C:\\x\\y") && !memcmp(nt.Buffer, L"\\??\\C:\\x\\y", nt.Length));
        UN(RtlReleaseRelativeName)(&rel); UN(RtlFreeUnicodeString)(&nt);
    }
}

/* ---- existence and limits ----------------------------------------------- */

TEST(pathx_file_exists)
{
    WCHAR dir[MAX_PATH], file[MAX_PATH], missing[MAX_PATH];
    REQUIRE(UN(RtlDoesFileExists_U));
    wtmp(dir, MAX_PATH, "pxx"); CreateDirectoryW(dir, NULL);
    lstrcpyW(file, dir); lstrcatW(file, L"\\here.txt"); touch_file(file);
    lstrcpyW(missing, dir); lstrcatW(missing, L"\\gone.txt");
    EXPECT_EQ(UN(RtlDoesFileExists_U)(file), TRUE);
    EXPECT_EQ(UN(RtlDoesFileExists_U)(dir), TRUE);
    EXPECT_EQ(UN(RtlDoesFileExists_U)(missing), FALSE);
    {
        WCHAR inside[MAX_PATH]; lstrcpyW(inside, file); lstrcatW(inside, L"\\child");
        EXPECT_EQ(UN(RtlDoesFileExists_U)(inside), FALSE);               /* a file has no children */
    }
    EXPECT_EQ(UN(RtlDoesFileExists_U)(L"C:\\"), TRUE);
    DeleteFileW(file); RemoveDirectoryW(dir);
}

TEST(pathx_longest_nt_path_length)
{
    ULONG n;
    REQUIRE(UN(RtlGetLongestNtPathLength));
    n = UN(RtlGetLongestNtPathLength)();
    t_note("longest NT path length: %lu", (unsigned long)n);
    CHECK(n >= 260);
    EXPECT_EQ(UN(RtlGetLongestNtPathLength)(), n);
}

/* Path-based and enumeration file queries: NtQueryAttributesFile, NtQueryFullAttributesFile,
 * NtQueryInformationByName, NtQueryDirectoryFile (Zw alias), NtQueryDirectoryFileEx, NtQueryEaFile,
 * NtQueryQuotaInformationFile. All objects live in the per-process scratch directory. */
#include "t.h"

UDECL(NTSTATUS, NtQueryAttributesFile, (POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, NtQueryFullAttributesFile, (POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, NtQueryInformationByName, (POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryDirectoryFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN, PUNICODE_STRING, BOOLEAN));
UDECL(NTSTATUS, NtQueryDirectoryFileEx, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, NtQueryEaFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN));
UDECL(NTSTATUS, NtSetEaFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryQuotaInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PVOID, BOOLEAN));
UDECL(NTSTATUS, NtCreateFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtWriteFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(BOOLEAN, RtlDosPathNameToNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, void *));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));

#define S(x) ((NTSTATUS)(x))
#define ST_NO_MORE     S(0x80000006)
#define ST_OVERFLOW    S(0x80000005)
#define ST_NOT_FOUND   S(0xC0000034)
#define ST_PATH_NF     S(0xC000003A)
#define ST_NO_SUCH     S(0xC000000F)
#define ST_INV_CLASS   S(0xC0000003)
#define ST_LEN_MISM    S(0xC0000004)
#define ST_INV_PARM    S(0xC000000D)
#define ST_AV          S(0xC0000005)
#define ST_NO_EAS      S(0xC0000052)
#define ST_INV_HANDLE  S(0xC0000008)
#define ST_TOO_SMALL   S(0xC0000023)
#define ST_NAME_INV    S(0xC0000033)

#define SYNCF (FILE_SYNCHRONOUS_IO_NONALERT)
#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

typedef struct { LARGE_INTEGER ct, at, wt, cht; ULONG attr; } BASICI;                 /* FILE_BASIC_INFORMATION (pad) */
typedef struct { LARGE_INTEGER ct, at, wt, cht, alloc, eof; ULONG attr; ULONG pad; } NETOPEN;   /* FILE_NETWORK_OPEN_INFORMATION */
_Static_assert(sizeof(NETOPEN) == 56, "netopen");

#define NEED() do { REQUIRE(UN(NtCreateFile)); REQUIRE(UN(NtClose)); REQUIRE(UN(RtlDosPathNameToNtPathName_U)); \
    REQUIRE(UN(RtlFreeUnicodeString)); REQUIRE(UN(RtlInitUnicodeString)); } while (0)

/* NT path of scratch leaf; caller frees with RtlFreeUnicodeString */
static BOOL nt_scratch(const char *leaf, UNICODE_STRING *us, WCHAR *dos_out)
{
    char p[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(p, sizeof p, leaf);
    if (!MultiByteToWideChar(CP_ACP, 0, p, -1, w, MAX_PATH)) return FALSE;
    if (dos_out) lstrcpyW(dos_out, w);
    return UN(RtlDosPathNameToNtPathName_U)(w, us, NULL, NULL);
}

static NTSTATUS mkfile(const char *leaf, ULONG bytes, ULONG attrs)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h = NULL; NTSTATUS s; BYTE b[8192];
    if (!nt_scratch(leaf, &us, NULL)) return S(0xC0000001);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = UN(NtCreateFile)(&h, GENERIC_WRITE | SYNCHRONIZE | DELETE, &oa, &io, NULL, attrs, SHARE_ALL, FILE_CREATE, SYNCF | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (s >= 0) {
        memset(b, 'x', sizeof b);
        if (bytes) { LARGE_INTEGER z = {0}; (void)z; UN(NtWriteFile)(h, NULL, NULL, NULL, &io, b, bytes, NULL, NULL); }
        UN(NtClose)(h);
    }
    UN(RtlFreeUnicodeString)(&us);
    return s;
}

static void rmfile(const char *leaf)
{
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, leaf);
    if (!DeleteFileA(p)) RemoveDirectoryA(p);
}

TEST(qfile_alias_pairs)
{
    static const char *n[] = { "QueryAttributesFile", "QueryDirectoryFile", "QueryDirectoryFileEx", "QueryEaFile",
        "QueryFullAttributesFile", "QueryInformationByName", "QueryQuotaInformationFile" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64]; sprintf(a, "Nt%s", n[i]); sprintf(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a);
        if (!pa) { t_note("%s not exported", a); continue; }
        CHECKF(pa == t_proc(b), "%s/%s address", a, b);
    }
}

TEST(qfile_attributes_file)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; BASICI bi; NTSTATUS s; WIN32_FILE_ATTRIBUTE_DATA d; WCHAR dos[MAX_PATH];
    NEED(); REQUIRE(UN(NtQueryAttributesFile));
    CHECK(mkfile("qa_file.dat", 1234, FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY) == 0);
    CHECK(nt_scratch("qa_file.dat", &us, dos));
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    memset(&bi, 0xcc, sizeof bi);
    s = UN(NtQueryAttributesFile)(&oa, &bi);
    EXPECT_EQ(s, 0);
    CHECK(GetFileAttributesExW(dos, GetFileExInfoStandard, &d));
    EXPECT_EQ(bi.attr, d.dwFileAttributes);
    CHECK(bi.attr & FILE_ATTRIBUTE_READONLY);
    EXPECT_EQ(bi.wt.LowPart, d.ftLastWriteTime.dwLowDateTime);
    EXPECT_EQ(bi.wt.HighPart, d.ftLastWriteTime.dwHighDateTime);
    EXPECT_EQ(bi.ct.LowPart, d.ftCreationTime.dwLowDateTime);
    CHECK(bi.ct.QuadPart > 0);
    /* a directory */
    { WCHAR dir[MAX_PATH]; UNICODE_STRING du; char tp[MAX_PATH]; int n;
      lstrcpynA(tp, t_tmpdir(), MAX_PATH); n = (int)strlen(tp); if (n > 3 && tp[n - 1] == '\\') tp[n - 1] = 0;
      MultiByteToWideChar(CP_ACP, 0, tp, -1, dir, MAX_PATH);
      CHECK(UN(RtlDosPathNameToNtPathName_U)(dir, &du, NULL, NULL));
      InitializeObjectAttributes(&oa, &du, OBJ_CASE_INSENSITIVE, NULL, NULL);
      s = UN(NtQueryAttributesFile)(&oa, &bi);
      EXPECT_EQ(s, 0);
      CHECK(bi.attr & FILE_ATTRIBUTE_DIRECTORY);
      UN(RtlFreeUnicodeString)(&du); }
    /* missing leaf in an existing directory / missing directory / bad name */
    { UNICODE_STRING m; WCHAR w[MAX_PATH];
      CHECK(nt_scratch("qa_missing.dat", &m, w));
      InitializeObjectAttributes(&oa, &m, OBJ_CASE_INSENSITIVE, NULL, NULL);
      s = UN(NtQueryAttributesFile)(&oa, &bi); EXPECT_EQ(s, ST_NOT_FOUND);
      UN(RtlFreeUnicodeString)(&m);
      UN(RtlInitUnicodeString)(&m, L"\\??\\C:\\ntdllt_no_such_dir_zz\\x.dat");
      InitializeObjectAttributes(&oa, &m, OBJ_CASE_INSENSITIVE, NULL, NULL);
      s = UN(NtQueryAttributesFile)(&oa, &bi); EXPECT_EQ(s, ST_PATH_NF);
      UN(RtlInitUnicodeString)(&m, L"\\??\\C:\\a<b");
      InitializeObjectAttributes(&oa, &m, OBJ_CASE_INSENSITIVE, NULL, NULL);
      s = UN(NtQueryAttributesFile)(&oa, &bi); t_note("wildcard name = %08lx", (unsigned long)s);
      CHECK(s == ST_NAME_INV || s == ST_NOT_FOUND || s == ST_PATH_NF); }
    s = UN(NtQueryAttributesFile)(&oa, NULL);
    t_note("NULL out = %08lx", (unsigned long)s);
    UN(RtlFreeUnicodeString)(&us);
    rmfile("qa_file.dat");
}

TEST(qfile_full_attributes_file)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; NETOPEN ni; NTSTATUS s; WIN32_FILE_ATTRIBUTE_DATA d; WCHAR dos[MAX_PATH];
    NEED(); REQUIRE(UN(NtQueryFullAttributesFile));
    CHECK(mkfile("qfa_file.dat", 5000, FILE_ATTRIBUTE_NORMAL) == 0);
    CHECK(nt_scratch("qfa_file.dat", &us, dos));
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    memset(&ni, 0xcc, sizeof ni);
    s = UN(NtQueryFullAttributesFile)(&oa, &ni);
    EXPECT_EQ(s, 0);
    CHECK(GetFileAttributesExW(dos, GetFileExInfoStandard, &d));
    EXPECT_EQ(ni.eof.QuadPart, 5000);
    EXPECT_EQ(ni.eof.QuadPart, ((LONGLONG)d.nFileSizeHigh << 32) | d.nFileSizeLow);
    CHECK(ni.alloc.QuadPart >= 5000 && (ni.alloc.QuadPart % 512) == 0);
    EXPECT_EQ(ni.attr, d.dwFileAttributes);
    EXPECT_EQ(ni.wt.LowPart, d.ftLastWriteTime.dwLowDateTime);
    /* missing */
    { UNICODE_STRING m;
      CHECK(nt_scratch("qfa_missing.dat", &m, NULL));
      InitializeObjectAttributes(&oa, &m, OBJ_CASE_INSENSITIVE, NULL, NULL);
      s = UN(NtQueryFullAttributesFile)(&oa, &ni); EXPECT_EQ(s, ST_NOT_FOUND);
      UN(RtlFreeUnicodeString)(&m); }
    UN(RtlFreeUnicodeString)(&us);
    rmfile("qfa_file.dat");
}

TEST(qfile_by_name)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; NTSTATUS s; WIN32_FILE_ATTRIBUTE_DATA d; WCHAR dos[MAX_PATH];
    union { ULONGLONG a; BYTE b[256]; } buf;
    NEED(); REQUIRE(UN(NtQueryInformationByName));
    CHECK(mkfile("qbn_file.dat", 777, FILE_ATTRIBUTE_NORMAL) == 0);
    CHECK(nt_scratch("qbn_file.dat", &us, dos));
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    CHECK(GetFileAttributesExW(dos, GetFileExInfoStandard, &d));
    /* FileStatInformation = 68 */
    memset(&buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
    s = UN(NtQueryInformationByName)(&oa, &io, &buf, 72, 68);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE *p = buf.b;
        EXPECT_EQ(io.Status, 0);
        EXPECT_EQ(io.Information, 72);
        EXPECT_EQ(*(LONGLONG *)(p + 48), 777);                   /* EndOfFile */
        CHECK(*(LONGLONG *)(p + 40) >= 777);                     /* AllocationSize */
        EXPECT_EQ(*(ULONG *)(p + 56), d.dwFileAttributes);       /* FileAttributes */
        EXPECT_EQ(*(ULONG *)(p + 64), 1);                        /* NumberOfLinks */
        EXPECT_EQ(*(ULONG *)(p + 32), d.ftLastWriteTime.dwLowDateTime);
        EXPECT_EQ(*(ULONG *)(p + 36), d.ftLastWriteTime.dwHighDateTime);
    }
    /* FileStatLxInformation = 70 */
    memset(&buf, 0xcc, sizeof buf);
    s = UN(NtQueryInformationByName)(&oa, &io, &buf, 96, 70);
    EXPECT_EQ(s, 0);
    if (s == 0) { EXPECT_EQ(io.Information, 96); EXPECT_EQ(*(LONGLONG *)(buf.b + 48), 777); }
    /* too short */
    s = UN(NtQueryInformationByName)(&oa, &io, &buf, 8, 68);
    t_note("ByName short = %08lx", (unsigned long)s);
    CHECK(s == ST_LEN_MISM || s == ST_TOO_SMALL);
    /* classes without a by-name implementation */
    s = UN(NtQueryInformationByName)(&oa, &io, &buf, 256, 4);  EXPECT_EQ(s, ST_INV_PARM);
    s = UN(NtQueryInformationByName)(&oa, &io, &buf, 256, 5);  EXPECT_EQ(s, ST_INV_PARM);
    s = UN(NtQueryInformationByName)(&oa, &io, &buf, 256, 0x7777); EXPECT_EQ(s, ST_INV_CLASS);
    s = UN(NtQueryInformationByName)(&oa, &io, &buf, 256, 0);  EXPECT_EQ(s, ST_INV_CLASS);
    /* missing file */
    { UNICODE_STRING m; CHECK(nt_scratch("qbn_missing.dat", &m, NULL));
      InitializeObjectAttributes(&oa, &m, OBJ_CASE_INSENSITIVE, NULL, NULL);
      s = UN(NtQueryInformationByName)(&oa, &io, &buf, 72, 68); t_note("ByName missing = %08lx", (unsigned long)s);
      CHECK(s == ST_NOT_FOUND);
      UN(RtlFreeUnicodeString)(&m); }
    UN(RtlFreeUnicodeString)(&us);
    rmfile("qbn_file.dat");
}

/* ---- directory enumeration ---------------------------------------------- */

static HANDLE open_scratch_dir(void)
{
    UNICODE_STRING du; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h = NULL; WCHAR dir[MAX_PATH]; char tp[MAX_PATH]; int n; NTSTATUS s;
    lstrcpynA(tp, t_tmpdir(), MAX_PATH); n = (int)strlen(tp); if (n > 3 && tp[n - 1] == '\\') tp[n - 1] = 0;
    MultiByteToWideChar(CP_ACP, 0, tp, -1, dir, MAX_PATH);
    if (!UN(RtlDosPathNameToNtPathName_U)(dir, &du, NULL, NULL)) return NULL;
    InitializeObjectAttributes(&oa, &du, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = UN(NtCreateFile)(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &io, NULL, 0, SHARE_ALL, FILE_OPEN, SYNCF | FILE_DIRECTORY_FILE, NULL, 0);
    UN(RtlFreeUnicodeString)(&du);
    return s >= 0 ? h : NULL;
}

typedef struct { ULONG next, index, len; WCHAR name[1]; } NAMEINFO;   /* FILE_NAMES_INFORMATION: NextEntryOffset, FileIndex, FileNameLength, FileName */

/* count entries named dq_* in a FileNamesInformation buffer; returns total entries, sets bit mask of which dq_<c> seen */
static int scan_names(BYTE *b, ULONG_PTR used, unsigned *mask)
{
    int n = 0; BYTE *p = b;
    if (!used) return 0;
    for (;;) {
        NAMEINFO *e = (NAMEINFO *)p; n++;
        if (e->len == 12 && !memcmp(e->name, L"dq_", 6) && e->name[3] >= 'a' && e->name[3] <= 'z' && e->name[4] == '.' ) *mask |= 1u << (e->name[3] - 'a');
        if (!e->next) break;
        p += e->next;
    }
    return n;
}

#define FN_CLASS 12   /* FileNamesInformation */
#define FD_CLASS 1    /* FileDirectoryInformation */

static void mk3(void)
{
    CHECK(mkfile("dq_a.x", 1, FILE_ATTRIBUTE_NORMAL) == 0);
    CHECK(mkfile("dq_b.x", 2, FILE_ATTRIBUTE_NORMAL) == 0);
    CHECK(mkfile("dq_c.x", 3, FILE_ATTRIBUTE_NORMAL) == 0);
}
static void rm3(void) { rmfile("dq_a.x"); rmfile("dq_b.x"); rmfile("dq_c.x"); }

TEST(qfile_directory_classic)
{
    HANDLE h; IO_STATUS_BLOCK io; BYTE buf[8192]; NTSTATUS s; unsigned mask = 0; UNICODE_STRING pat;
    NEED(); REQUIRE(UN(NtQueryDirectoryFile));
    mk3();
    h = open_scratch_dir(); CHECK(h != NULL);
    if (!h) { rm3(); return; }
    UN(RtlInitUnicodeString)(&pat, L"dq_?.x");
    memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
    s = UN(NtQueryDirectoryFile)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, FALSE, &pat, TRUE);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(io.Status, 0);
    CHECK(io.Information >= 3 * 24);
    EXPECT_EQ(scan_names(buf, io.Information, &mask), 3);
    EXPECT_EQ(mask, 7);
    /* pattern is sticky; continuing yields no more files */
    s = UN(NtQueryDirectoryFile)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, FALSE, NULL, FALSE);
    EXPECT_EQ(s, ST_NO_MORE);
    /* restart + single entry */
    s = UN(NtQueryDirectoryFile)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, TRUE, NULL, TRUE);
    EXPECT_EQ(s, 0);
    { NAMEINFO *e = (void *)buf; EXPECT_EQ(e->next, 0); EXPECT_EQ(e->len, 12); EXPECT_EQ(io.Information, 12 + e->len); }
    /* FileDirectoryInformation carries the size */
    { UNICODE_STRING one; BYTE db[1024];
      UN(RtlInitUnicodeString)(&one, L"dq_b.x");
      s = UN(NtQueryDirectoryFile)(h, NULL, NULL, NULL, &io, db, sizeof db, FD_CLASS, TRUE, &one, TRUE);
      EXPECT_EQ(s, 0);
      EXPECT_EQ(*(LONGLONG *)(db + 40), 2);   /* EndOfFile at offset 40 */
    }
    /* no match on first call */
    UN(RtlInitUnicodeString)(&pat, L"dq_zz*");
    s = UN(NtQueryDirectoryFile)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, TRUE, &pat, TRUE);
    EXPECT_EQ(s, ST_NO_MORE);
    /* a first enumeration on a fresh handle that matches nothing reports STATUS_NO_SUCH_FILE */
    { HANDLE h2 = open_scratch_dir();
      UN(RtlInitUnicodeString)(&pat, L"dq_zz.x");
      if (h2) { s = UN(NtQueryDirectoryFile)(h2, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, FALSE, &pat, FALSE);
                EXPECT_EQ(s, ST_NO_SUCH); UN(NtClose)(h2); } }
    /* invalid class / tiny buffer */
    UN(RtlInitUnicodeString)(&pat, L"dq_a.x");
    s = UN(NtQueryDirectoryFile)(h, NULL, NULL, NULL, &io, buf, sizeof buf, 0x7777, TRUE, &pat, TRUE);
    EXPECT_EQ(s, ST_INV_CLASS);
    s = UN(NtQueryDirectoryFile)(h, NULL, NULL, NULL, &io, buf, 8, FN_CLASS, TRUE, &pat, TRUE);
    EXPECT_EQ(s, ST_LEN_MISM);
    /* invalid handle */
    s = UN(NtQueryDirectoryFile)((HANDLE)(ULONG_PTR)0x7777, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, TRUE, NULL, TRUE);
    EXPECT_EQ(s, ST_INV_HANDLE);
    UN(NtClose)(h);
    rm3();
}

TEST(qfile_directory_ex)
{
    HANDLE h; IO_STATUS_BLOCK io; BYTE buf[8192]; NTSTATUS s; unsigned mask = 0; UNICODE_STRING pat;
    NEED(); REQUIRE(UN(NtQueryDirectoryFileEx));
    mk3();
    h = open_scratch_dir(); CHECK(h != NULL);
    if (!h) { rm3(); return; }
    UN(RtlInitUnicodeString)(&pat, L"dq_?.x");
    /* SL_RESTART_SCAN = 1 */
    s = UN(NtQueryDirectoryFileEx)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 1, &pat);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(scan_names(buf, io.Information, &mask), 3);
    EXPECT_EQ(mask, 7);
    s = UN(NtQueryDirectoryFileEx)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 0, NULL);
    EXPECT_EQ(s, ST_NO_MORE);
    /* SL_RESTART_SCAN | SL_RETURN_SINGLE_ENTRY = 3: one entry at a time through the three names */
    mask = 0;
    s = UN(NtQueryDirectoryFileEx)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 3, &pat);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(scan_names(buf, io.Information, &mask), 1);
    for (int i = 0; i < 2; i++) {
        s = UN(NtQueryDirectoryFileEx)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 2, NULL);
        EXPECT_EQ(s, 0);
        EXPECT_EQ(scan_names(buf, io.Information, &mask), 1);
    }
    s = UN(NtQueryDirectoryFileEx)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 2, NULL);
    EXPECT_EQ(s, ST_NO_MORE);
    /* SL_INDEX_SPECIFIED = 4 needs a FileIndex; index 0 on NTFS: just observe */
    UN(RtlInitUnicodeString)(&pat, L"dq_a.x");
    s = UN(NtQueryDirectoryFileEx)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 1, &pat);
    EXPECT_EQ(s, 0);
    UN(RtlInitUnicodeString)(&pat, L"dq_zz*");
    s = UN(NtQueryDirectoryFileEx)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 1, &pat);
    EXPECT_EQ(s, ST_NO_MORE);
    { HANDLE h2 = open_scratch_dir();
      UN(RtlInitUnicodeString)(&pat, L"dq_zz.x");
      if (h2) { s = UN(NtQueryDirectoryFileEx)(h2, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 0, &pat);
                EXPECT_EQ(s, ST_NO_SUCH); UN(NtClose)(h2); } }
    s = UN(NtQueryDirectoryFileEx)(h, NULL, NULL, NULL, &io, buf, sizeof buf, 0x7777, 1, NULL);
    EXPECT_EQ(s, ST_INV_CLASS);
    s = UN(NtQueryDirectoryFileEx)(h, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 0x80000000, NULL);
    t_note("Ex bad flags = %08lx", (unsigned long)s);
    s = UN(NtQueryDirectoryFileEx)((HANDLE)(ULONG_PTR)0x7777, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 1, NULL);
    EXPECT_EQ(s, ST_INV_HANDLE);
    /* a non-directory handle is rejected */
    { UNICODE_STRING us; OBJECT_ATTRIBUTES oa; HANDLE fh = NULL;
      CHECK(nt_scratch("dq_a.x", &us, NULL));
      InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
      s = UN(NtCreateFile)(&fh, FILE_READ_DATA | SYNCHRONIZE, &oa, &io, NULL, 0, SHARE_ALL, FILE_OPEN, SYNCF | FILE_NON_DIRECTORY_FILE, NULL, 0);
      EXPECT_EQ(s, 0);
      if (s == 0) {
          s = UN(NtQueryDirectoryFileEx)(fh, NULL, NULL, NULL, &io, buf, sizeof buf, FN_CLASS, 1, NULL);
          EXPECT_EQ(s, ST_INV_PARM);
          UN(NtClose)(fh);
      }
      UN(RtlFreeUnicodeString)(&us); }
    UN(NtClose)(h);
    rm3();
}

/* ---- extended attributes ---------------------------------------------- */

typedef struct { ULONG next; BYTE flags; BYTE nlen; USHORT vlen; char name[1]; } FEA;
typedef struct { ULONG next; BYTE nlen; char name[1]; } GEA;   /* FILE_GET_EA_INFORMATION */

TEST(qfile_ea)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h = NULL; NTSTATUS s; BYTE set[64], out[512];
    FEA *e;
    NEED(); REQUIRE(UN(NtQueryEaFile)); REQUIRE(UN(NtSetEaFile));
    CHECK(nt_scratch("ea_file.dat", &us, NULL));
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = UN(NtCreateFile)(&h, FILE_READ_EA | FILE_WRITE_EA | GENERIC_WRITE | DELETE | SYNCHRONIZE, &oa, &io, NULL, 0, SHARE_ALL, FILE_CREATE, SYNCF | FILE_NON_DIRECTORY_FILE, NULL, 0);
    EXPECT_EQ(s, 0);
    if (s != 0) { UN(RtlFreeUnicodeString)(&us); return; }
    /* none yet */
    s = UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE);
    EXPECT_EQ(s, ST_NO_EAS);
    /* set one */
    memset(set, 0, sizeof set);
    e = (FEA *)set; e->next = 0; e->flags = 0; e->nlen = 6; e->vlen = 5;
    memcpy(e->name, "MYATTR", 7); memcpy(e->name + 7, "hello", 5);
    s = UN(NtSetEaFile)(h, &io, set, 8 + 7 + 5);
    if (s == S(0xC00000BB) || s == S(0xC0000010) || s == S(0xC000010A)) { t_skip("file system on scratch volume lacks EA support (%08lx)", (unsigned long)s); goto done; }
    EXPECT_EQ(s, 0);
    memset(out, 0xcc, sizeof out);
    s = UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE);
    EXPECT_EQ(s, 0);
    e = (FEA *)out;
    EXPECT_EQ(e->next, 0);
    EXPECT_EQ(e->nlen, 6);
    EXPECT_EQ(e->vlen, 5);
    CHECK(!memcmp(e->name, "MYATTR", 7));    /* names are stored upper-cased with trailing NUL */
    CHECK(!memcmp(e->name + 7, "hello", 5));
    EXPECT_EQ(io.Information, 8 + 7 + 5);
    /* single-entry + index */
    { ULONG idx = 1; memset(out, 0xcc, sizeof out);
      s = UN(NtQueryEaFile)(h, &io, out, sizeof out, TRUE, NULL, 0, &idx, FALSE);
      EXPECT_EQ(s, 0);
      EXPECT_EQ(((FEA *)out)->nlen, 6);
      idx = 2;
      s = UN(NtQueryEaFile)(h, &io, out, sizeof out, TRUE, NULL, 0, &idx, FALSE);
      t_note("EA index 2 = %08lx", (unsigned long)s);
      EXPECT_EQ(s, S(0x80000012));       /* STATUS_NO_MORE_EAS */
    }
    /* buffer too small for the single entry */
    s = UN(NtQueryEaFile)(h, &io, out, 8, FALSE, NULL, 0, NULL, TRUE);
    t_note("EA small buffer = %08lx", (unsigned long)s);
    CHECK(s == ST_OVERFLOW || s == ST_TOO_SMALL || s == ST_LEN_MISM);
    /* EA list with a name that is absent: entry returned with zero value length */
    { BYTE list[32]; GEA *g = (GEA *)list; memset(list, 0, sizeof list);
      g->nlen = 6; memcpy(g->name, "NOSUCH", 7);
      memset(out, 0xcc, sizeof out);
      s = UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, list, 5 + 7, NULL, TRUE);
      t_note("EA list absent = %08lx info %llu", (unsigned long)s, (unsigned long long)io.Information);
      if (s >= 0) { EXPECT_EQ(((FEA *)out)->vlen, 0); EXPECT_EQ(((FEA *)out)->nlen, 6); }
      memset(list, 0, sizeof list); g->nlen = 6; memcpy(g->name, "MYATTR", 7);
      s = UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, list, 5 + 7, NULL, TRUE);
      EXPECT_EQ(s, 0);
      EXPECT_EQ(((FEA *)out)->vlen, 5);
      CHECK(!memcmp(((FEA *)out)->name + 7, "hello", 5));
      /* malformed list (name length past the end) */
      memset(list, 0, sizeof list); g->nlen = 30; memcpy(g->name, "MYATTR", 7);
      s = UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, list, 5 + 7, NULL, TRUE);
      t_note("EA malformed list = %08lx", (unsigned long)s);
      EXPECT_EQ(s, S(0x80000014));      /* STATUS_EA_LIST_INCONSISTENT */
    }
    /* invalid handle */
    s = UN(NtQueryEaFile)((HANDLE)(ULONG_PTR)0x7777, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE);
    EXPECT_EQ(s, ST_INV_HANDLE);
    s = UN(NtQueryEaFile)(h, &io, out, 0, FALSE, NULL, 0, NULL, TRUE);
    t_note("EA zero length = %08lx", (unsigned long)s);
    CHECK(s < 0 || s == 0);
done:
    UN(NtClose)(h);
    UN(RtlFreeUnicodeString)(&us);
    rmfile("ea_file.dat");
}

TEST(qfile_quota)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h = NULL; NTSTATUS s; BYTE out[512];
    NEED(); REQUIRE(UN(NtQueryQuotaInformationFile));
    CHECK(mkfile("quota_file.dat", 1, 0) == 0);
    CHECK(nt_scratch("quota_file.dat", &us, NULL));
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = UN(NtCreateFile)(&h, FILE_READ_DATA | SYNCHRONIZE, &oa, &io, NULL, 0, SHARE_ALL, FILE_OPEN, SYNCF | FILE_NON_DIRECTORY_FILE, NULL, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        s = UN(NtQueryQuotaInformationFile)(h, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE);
        t_note("Quota on a file handle = %08lx info %llu", (unsigned long)s, (unsigned long long)io.Information);
        UN(NtClose)(h);
    }
    s = UN(NtQueryQuotaInformationFile)((HANDLE)(ULONG_PTR)0x7777, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE);
    EXPECT_EQ(s, ST_INV_HANDLE);
    /* volume handle: quota tracking state of the scratch volume decides the answer */
    { UNICODE_STRING vol; UN(RtlInitUnicodeString)(&vol, L"\\??\\C:");
      InitializeObjectAttributes(&oa, &vol, OBJ_CASE_INSENSITIVE, NULL, NULL);
      h = NULL;
      s = UN(NtCreateFile)(&h, FILE_READ_DATA | SYNCHRONIZE, &oa, &io, NULL, 0, SHARE_ALL, FILE_OPEN, SYNCF | FILE_NON_DIRECTORY_FILE, NULL, 0);
      t_note("open C: volume = %08lx", (unsigned long)s);
      if (s == 0) {
          s = UN(NtQueryQuotaInformationFile)(h, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE);
          t_note("Quota on a volume handle = %08lx info %llu", (unsigned long)s, (unsigned long long)io.Information);
          UN(NtClose)(h);
      } }
    UN(RtlFreeUnicodeString)(&us);
    rmfile("quota_file.dat");
}

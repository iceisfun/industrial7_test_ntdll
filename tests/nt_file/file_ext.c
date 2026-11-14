/* Native file API: error statuses, attribute queries, locks, deletion, information classes,
 * directory enumeration patterns and volume information. Scratch files only. */
#include "t.h"

UDECL(BOOLEAN, RtlDosPathNameToNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, void *));
UDECL(NTSTATUS, NtCreateFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtOpenFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtReadFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtWriteFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtQueryInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtSetInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryDirectoryFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN, PUNICODE_STRING, BOOLEAN));
UDECL(NTSTATUS, NtQueryVolumeInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtSetVolumeInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryAttributesFile, (POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, NtQueryFullAttributesFile, (POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, NtDeleteFile, (POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtLockFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG, BOOLEAN, BOOLEAN));
UDECL(NTSTATUS, NtUnlockFile, (HANDLE, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG));
UDECL(NTSTATUS, NtFsControlFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtDeviceIoControlFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtCancelIoFile, (HANDLE, PIO_STATUS_BLOCK));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));

#define XS(x) ((NTSTATUS)(x))
#define XOK(s) ((NTSTATUS)(s) >= 0)
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x1
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x40
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x20
#endif
#ifndef FILE_NO_INTERMEDIATE_BUFFERING
#define FILE_NO_INTERMEDIATE_BUFFERING 0x8
#endif
#ifndef FILE_DELETE_ON_CLOSE
#define FILE_DELETE_ON_CLOSE 0x1000
#endif
#define XF_SYNC (FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE)
#define XF_ALL_SHARE (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define XF_RW (FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)

#define XF_NEED() do { \
    REQUIRE(UN(NtCreateFile)); REQUIRE(UN(NtOpenFile)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtReadFile)); \
    REQUIRE(UN(NtWriteFile)); REQUIRE(UN(NtQueryInformationFile)); REQUIRE(UN(NtSetInformationFile)); \
    REQUIRE(UN(RtlDosPathNameToNtPathName_U)); REQUIRE(UN(RtlFreeUnicodeString)); \
    REQUIRE(UIN("kernel32.dll", DeleteFileW)); REQUIRE(UIN("kernel32.dll", MultiByteToWideChar)); \
    REQUIRE(UIN("kernel32.dll", SetFileAttributesW)); } while (0)

/* <tmpdir>\<rel> for a fixed relative path; unlike t_tmpfile it allows one directory level (rel is always a literal). */
static void xf_path(const char *rel, char *out, size_t cap)
{
    if (strchr(rel, '\\')) snprintf(out, cap, "%s%s", t_tmpdir(), rel); else t_tmpfile(out, cap, rel);
}
/* NT path (caller frees) for <tmpdir>\<leaf>; leaf may be NULL for the directory itself. */
static BOOL xf_nt(const char *leaf, UNICODE_STRING *nt, WCHAR *dos)
{
    char path[MAX_PATH];
    WCHAR local[MAX_PATH];
    if (!dos) dos = local;
    if (leaf) xf_path(leaf, path, sizeof path); else { strcpy(path, t_tmpdir()); path[strlen(path) - 1] = 0; }
    if (!UIN("kernel32.dll", MultiByteToWideChar)(CP_ACP, 0, path, -1, dos, MAX_PATH)) return FALSE;
    memset(nt, 0, sizeof *nt);
    return UN(RtlDosPathNameToNtPathName_U)(dos, nt, NULL, NULL) ? TRUE : FALSE;
}
static NTSTATUS xf_open(HANDLE *h, const UNICODE_STRING *nt, ACCESS_MASK access, ULONG share, ULONG disp, ULONG opts, ULONG attrs, ULONG_PTR *info)
{
    OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io = {0}; NTSTATUS s;
    InitializeObjectAttributes(&oa, (PUNICODE_STRING)nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    *h = NULL;
    s = UN(NtCreateFile)(h, access, &oa, &io, NULL, attrs, share, disp, opts, NULL, 0);
    if (info) *info = io.Information;
    if (!XOK(s)) *h = NULL;
    return s;
}
/* Create <leaf> holding n bytes of a known pattern; closes it again. */
static BOOL xf_make(const char *leaf, ULONG n)
{
    UNICODE_STRING nt; HANDLE h; BYTE buf[8192]; IO_STATUS_BLOCK io; NTSTATUS s;
    if (!xf_nt(leaf, &nt, NULL)) return FALSE;
    s = xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OVERWRITE_IF, XF_SYNC, FILE_ATTRIBUTE_NORMAL, NULL);
    UN(RtlFreeUnicodeString)(&nt);
    if (!XOK(s)) return FALSE;
    for (ULONG i = 0; i < n && i < sizeof buf; i++) buf[i] = (BYTE)(i * 7 + 3);
    if (n) s = UN(NtWriteFile)(h, NULL, NULL, NULL, &io, buf, n < sizeof buf ? n : sizeof buf, NULL, NULL);
    UN(NtClose)(h);
    return XOK(s);
}
static void xf_rm(const char *leaf)
{
    char path[MAX_PATH]; WCHAR dos[MAX_PATH];
    xf_path(leaf, path, sizeof path);
    UIN("kernel32.dll", MultiByteToWideChar)(CP_ACP, 0, path, -1, dos, MAX_PATH);
    UIN("kernel32.dll", SetFileAttributesW)(dos, FILE_ATTRIBUTE_NORMAL);
    UIN("kernel32.dll", DeleteFileW)(dos);
}

typedef struct { LARGE_INTEGER ct, at, wt, cht; ULONG attrs; } xf_basic;
typedef struct { LARGE_INTEGER ct, at, wt, cht, alloc, eof; ULONG attrs; } xf_netopen;
typedef struct { LARGE_INTEGER alloc, eof; ULONG links; BOOLEAN del, dir; } xf_standard;

/* ---- error statuses of create/open ------------------------------------ */
TEST(nt_file_x_open_missing_file)
{
    UNICODE_STRING nt; HANDLE h; XF_NEED();
    CHECK(xf_nt("x_missing_file.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, FILE_READ_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), XS(0xC0000034));
    UN(RtlFreeUnicodeString)(&nt);
}
TEST(nt_file_x_open_missing_parent)
{
    UNICODE_STRING nt; HANDLE h; XF_NEED();
    CHECK(xf_nt("x_no_such_dir\\child.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, FILE_READ_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), XS(0xC000003A));
    EXPECT_EQ(xf_open(&h, &nt, FILE_WRITE_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_CREATE, XF_SYNC, FILE_ATTRIBUTE_NORMAL, NULL), XS(0xC000003A));
    UN(RtlFreeUnicodeString)(&nt);
}
TEST(nt_file_x_create_info_values)
{
    UNICODE_STRING nt; HANDLE h; ULONG_PTR info; XF_NEED();
    CHECK(xf_nt("x_create_info.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN_IF, XF_SYNC, FILE_ATTRIBUTE_NORMAL, &info), 0);
    EXPECT_EQ(info, FILE_CREATED);
    if (h) UN(NtClose)(h);
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN_IF, XF_SYNC, FILE_ATTRIBUTE_NORMAL, &info), 0);
    EXPECT_EQ(info, FILE_OPENED);
    if (h) UN(NtClose)(h);
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OVERWRITE, XF_SYNC, FILE_ATTRIBUTE_NORMAL, &info), 0);
    EXPECT_EQ(info, FILE_OVERWRITTEN);
    if (h) UN(NtClose)(h);
    UN(RtlFreeUnicodeString)(&nt);
    xf_rm("x_create_info.tmp");
}
TEST(nt_file_x_overwrite_missing)
{
    UNICODE_STRING nt; HANDLE h; XF_NEED();
    CHECK(xf_nt("x_overwrite_missing.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OVERWRITE, XF_SYNC, FILE_ATTRIBUTE_NORMAL, NULL), XS(0xC0000034));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, 6, XF_SYNC, FILE_ATTRIBUTE_NORMAL, NULL), XS(0xC000000D));
    UN(RtlFreeUnicodeString)(&nt);
}
TEST(nt_file_x_directory_flag_mismatch)
{
    UNICODE_STRING nt, dir; HANDLE h; XF_NEED();
    CHECK(xf_make("x_dirflag.tmp", 4));
    CHECK(xf_nt("x_dirflag.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, FILE_READ_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, NULL), XS(0xC0000103));
    UN(RtlFreeUnicodeString)(&nt);
    CHECK(xf_nt(NULL, &dir, NULL));
    EXPECT_EQ(xf_open(&h, &dir, FILE_READ_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), XS(0xC00000BA));
    UN(RtlFreeUnicodeString)(&dir);
    xf_rm("x_dirflag.tmp");
}
TEST(nt_file_x_sharing_violation)
{
    UNICODE_STRING nt; HANDLE a = NULL, b = NULL; XF_NEED();
    CHECK(xf_nt("x_share.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&a, &nt, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, 0, FILE_CREATE, XF_SYNC, FILE_ATTRIBUTE_NORMAL, NULL), 0);
    EXPECT_EQ(xf_open(&b, &nt, FILE_READ_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), XS(0xC0000043));
    if (a) UN(NtClose)(a);
    /* share read only: a writer is refused, a reader succeeds */
    EXPECT_EQ(xf_open(&a, &nt, FILE_READ_DATA | SYNCHRONIZE, FILE_SHARE_READ, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    EXPECT_EQ(xf_open(&b, &nt, FILE_WRITE_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), XS(0xC0000043));
    EXPECT_EQ(xf_open(&b, &nt, FILE_READ_DATA | SYNCHRONIZE, FILE_SHARE_READ, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    if (b) UN(NtClose)(b);
    if (a) UN(NtClose)(a);
    UN(RtlFreeUnicodeString)(&nt);
    xf_rm("x_share.tmp");
}
TEST(nt_file_x_invalid_name_characters)
{
    UNICODE_STRING nt; HANDLE h; XF_NEED();
    CHECK(xf_nt("x_wild.tmp", &nt, NULL));
    /* replace the last characters of the leaf with a wildcard */
    nt.Buffer[nt.Length / 2 - 5] = L'*';
    EXPECT_EQ(xf_open(&h, &nt, FILE_WRITE_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_CREATE, XF_SYNC, FILE_ATTRIBUTE_NORMAL, NULL), XS(0xC0000033));
    if (h) UN(NtClose)(h);
    UN(RtlFreeUnicodeString)(&nt);
}
TEST(nt_file_x_delete_on_close_needs_delete_access)
{
    UNICODE_STRING nt; HANDLE h; XF_NEED();
    CHECK(xf_make("x_doc_access.tmp", 1));
    CHECK(xf_nt("x_doc_access.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, FILE_READ_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC | FILE_DELETE_ON_CLOSE, 0, NULL), XS(0xC000000D));   /* DELETE must be among the requested rights: invalid parameter */
    if (h) UN(NtClose)(h);
    UN(RtlFreeUnicodeString)(&nt);
    xf_rm("x_doc_access.tmp");
}
TEST(nt_file_x_delete_on_close_removes_file)
{
    UNICODE_STRING nt; HANDLE h; OBJECT_ATTRIBUTES oa; xf_basic b; XF_NEED(); REQUIRE(UN(NtQueryAttributesFile));
    CHECK(xf_make("x_doc.tmp", 1));
    CHECK(xf_nt("x_doc.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC | FILE_DELETE_ON_CLOSE, 0, NULL), 0);
    if (h) UN(NtClose)(h);
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtQueryAttributesFile)(&oa, &b), XS(0xC0000034));
    UN(RtlFreeUnicodeString)(&nt);
    xf_rm("x_doc.tmp");
}
TEST(nt_file_x_readonly_refuses_write_open)
{
    UNICODE_STRING nt; HANDLE h; XF_NEED();
    CHECK(xf_make("x_ro.tmp", 1));
    CHECK(xf_nt("x_ro.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, FILE_WRITE_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    if (h) UN(NtClose)(h);
    {
        xf_basic b = {0}; IO_STATUS_BLOCK io; HANDLE a;
        EXPECT_EQ(xf_open(&a, &nt, FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
        b.attrs = FILE_ATTRIBUTE_READONLY;
        if (a) { EXPECT_EQ(UN(NtSetInformationFile)(a, &io, &b, sizeof b, 4), 0); UN(NtClose)(a); }
    }
    EXPECT_EQ(xf_open(&h, &nt, FILE_WRITE_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), XS(0xC0000022));
    if (h) UN(NtClose)(h);
    EXPECT_EQ(xf_open(&h, &nt, FILE_READ_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    if (h) UN(NtClose)(h);
    UN(RtlFreeUnicodeString)(&nt);
    xf_rm("x_ro.tmp");
}

/* ---- attribute queries -------------------------------------------------- */
TEST(nt_file_x_query_attributes_file)
{
    UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; xf_basic b; XF_NEED(); REQUIRE(UN(NtQueryAttributesFile));
    CHECK(xf_make("x_qa.tmp", 100));
    CHECK(xf_nt("x_qa.tmp", &nt, NULL));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    memset(&b, 0xcc, sizeof b);
    EXPECT_EQ(UN(NtQueryAttributesFile)(&oa, &b), 0);
    CHECK(!(b.attrs & FILE_ATTRIBUTE_DIRECTORY));
    CHECK(b.ct.QuadPart != 0 && b.wt.QuadPart != 0 && b.cht.QuadPart != 0);
    CHECK(b.ct.QuadPart > 116444736000000000LL);
    UN(RtlFreeUnicodeString)(&nt);
    xf_rm("x_qa.tmp");
}
TEST(nt_file_x_query_attributes_directory)
{
    UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; xf_basic b; XF_NEED(); REQUIRE(UN(NtQueryAttributesFile));
    CHECK(xf_nt(NULL, &nt, NULL));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtQueryAttributesFile)(&oa, &b), 0);
    CHECK(b.attrs & FILE_ATTRIBUTE_DIRECTORY);
    UN(RtlFreeUnicodeString)(&nt);
}
TEST(nt_file_x_query_attributes_errors)
{
    UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; xf_basic b; XF_NEED(); REQUIRE(UN(NtQueryAttributesFile));
    CHECK(xf_nt("x_qa_missing.tmp", &nt, NULL));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtQueryAttributesFile)(&oa, &b), XS(0xC0000034));
    UN(RtlFreeUnicodeString)(&nt);
    CHECK(xf_nt("x_qa_nodir\\leaf.tmp", &nt, NULL));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtQueryAttributesFile)(&oa, &b), XS(0xC000003A));
    UN(RtlFreeUnicodeString)(&nt);
}
TEST(nt_file_x_query_attributes_works_while_locked_exclusive)
{
    UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; xf_basic b; HANDLE h; XF_NEED(); REQUIRE(UN(NtQueryAttributesFile));
    CHECK(xf_nt("x_qa_excl.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, 0, FILE_CREATE, XF_SYNC, FILE_ATTRIBUTE_NORMAL, NULL), 0);
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtQueryAttributesFile)(&oa, &b), 0);
    if (h) UN(NtClose)(h);
    UN(RtlFreeUnicodeString)(&nt);
    xf_rm("x_qa_excl.tmp");
}
TEST(nt_file_x_query_full_attributes_sizes)
{
    UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; xf_netopen n; XF_NEED(); REQUIRE(UN(NtQueryFullAttributesFile));
    CHECK(xf_make("x_qfa.tmp", 1234));
    CHECK(xf_nt("x_qfa.tmp", &nt, NULL));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    memset(&n, 0, sizeof n);
    EXPECT_EQ(UN(NtQueryFullAttributesFile)(&oa, &n), 0);
    EXPECT_EQ(n.eof.QuadPart, 1234);
    CHECK(n.alloc.QuadPart >= 1234);
    CHECK(!(n.attrs & FILE_ATTRIBUTE_DIRECTORY));
    UN(RtlFreeUnicodeString)(&nt);
    xf_rm("x_qfa.tmp");
}
TEST(nt_file_x_query_full_attributes_directory)
{
    UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; xf_netopen n; XF_NEED(); REQUIRE(UN(NtQueryFullAttributesFile));
    CHECK(xf_nt(NULL, &nt, NULL));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtQueryFullAttributesFile)(&oa, &n), 0);
    CHECK(n.attrs & FILE_ATTRIBUTE_DIRECTORY);
    UN(RtlFreeUnicodeString)(&nt);
}
TEST(nt_file_x_query_full_attributes_missing)
{
    UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; xf_netopen n; XF_NEED(); REQUIRE(UN(NtQueryFullAttributesFile));
    CHECK(xf_nt("x_qfa_missing.tmp", &nt, NULL));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtQueryFullAttributesFile)(&oa, &n), XS(0xC0000034));
    UN(RtlFreeUnicodeString)(&nt);
}

/* ---- NtDeleteFile --------------------------------------------------------- */
TEST(nt_file_x_delete_file_basic)
{
    UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; xf_basic b; XF_NEED(); REQUIRE(UN(NtDeleteFile)); REQUIRE(UN(NtQueryAttributesFile));
    CHECK(xf_make("x_del.tmp", 10));
    CHECK(xf_nt("x_del.tmp", &nt, NULL));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtDeleteFile)(&oa), 0);
    EXPECT_EQ(UN(NtQueryAttributesFile)(&oa, &b), XS(0xC0000034));
    EXPECT_EQ(UN(NtDeleteFile)(&oa), XS(0xC0000034));
    UN(RtlFreeUnicodeString)(&nt);
}
TEST(nt_file_x_delete_file_sharing_violation)
{
    UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; HANDLE h; XF_NEED(); REQUIRE(UN(NtDeleteFile));
    CHECK(xf_nt("x_del_busy.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, FILE_READ_DATA | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, XF_SYNC, FILE_ATTRIBUTE_NORMAL, NULL), 0);
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtDeleteFile)(&oa), XS(0xC0000043));
    if (h) UN(NtClose)(h);
    EXPECT_EQ(UN(NtDeleteFile)(&oa), 0);
    UN(RtlFreeUnicodeString)(&nt);
    xf_rm("x_del_busy.tmp");
}
TEST(nt_file_x_delete_file_directory_nonempty)
{
    UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; HANDLE d; IO_STATUS_BLOCK io; XF_NEED(); REQUIRE(UN(NtDeleteFile));
    CHECK(xf_nt("x_deldir", &nt, NULL));
    EXPECT_EQ(xf_open(&d, &nt, FILE_LIST_DIRECTORY | SYNCHRONIZE, XF_ALL_SHARE, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, FILE_ATTRIBUTE_DIRECTORY, NULL), 0);
    if (d) UN(NtClose)(d);
    CHECK(xf_make("x_deldir\\child.tmp", 1));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    /* NtDeleteFile opens with delete-on-close, so a non-empty directory is not reported as an error but is not removed. */
    EXPECT_EQ(UN(NtDeleteFile)(&oa), 0);
    EXPECT_EQ(xf_open(&d, &nt, FILE_LIST_DIRECTORY | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, NULL), 0);
    if (d) UN(NtClose)(d);
    xf_rm("x_deldir\\child.tmp");
    EXPECT_EQ(UN(NtDeleteFile)(&oa), 0);
    EXPECT_EQ(xf_open(&d, &nt, FILE_LIST_DIRECTORY | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, NULL), XS(0xC0000034));
    if (d) UN(NtClose)(d);
    UN(RtlFreeUnicodeString)(&nt);
    (void)io;
}

/* ---- byte-range locks --------------------------------------------------- */
static void xf_close2(HANDLE a, HANDLE b)
{
    if (a) UN(NtClose)(a);
    if (b) UN(NtClose)(b);
}
static BOOL xf_two(const char *leaf, HANDLE *a, HANDLE *b)
{
    UNICODE_STRING nt; NTSTATUS s;
    if (!xf_make(leaf, 300) || !xf_nt(leaf, &nt, NULL)) return FALSE;
    s = xf_open(a, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL);
    if (XOK(s)) s = xf_open(b, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL);
    UN(RtlFreeUnicodeString)(&nt);
    return XOK(s);
}
static NTSTATUS xf_lock(HANDLE h, LONGLONG off, LONGLONG len, ULONG key, BOOLEAN excl)
{
    IO_STATUS_BLOCK io = {0}; LARGE_INTEGER o, l; o.QuadPart = off; l.QuadPart = len;
    return UN(NtLockFile)(h, NULL, NULL, NULL, &io, &o, &l, key, TRUE, excl);
}
static NTSTATUS xf_unlock(HANDLE h, LONGLONG off, LONGLONG len, ULONG key)
{
    IO_STATUS_BLOCK io = {0}; LARGE_INTEGER o, l; o.QuadPart = off; l.QuadPart = len;
    return UN(NtUnlockFile)(h, &io, &o, &l, key);
}
TEST(nt_file_x_lock_unlock_roundtrip)
{
    HANDLE a = NULL, b = NULL; XF_NEED(); REQUIRE(UN(NtLockFile)); REQUIRE(UN(NtUnlockFile));
    CHECK(xf_two("x_lock1.tmp", &a, &b));
    EXPECT_EQ(xf_lock(a, 0, 100, 1, TRUE), 0);
    EXPECT_EQ(xf_unlock(a, 0, 100, 1), 0);
    EXPECT_EQ(xf_lock(a, 0, 100, 1, TRUE), 0);
    EXPECT_EQ(xf_unlock(a, 0, 100, 1), 0);
    xf_close2(a, b);
    xf_rm("x_lock1.tmp");
}
TEST(nt_file_x_lock_conflicts)
{
    HANDLE a = NULL, b = NULL; XF_NEED(); REQUIRE(UN(NtLockFile)); REQUIRE(UN(NtUnlockFile));
    CHECK(xf_two("x_lock2.tmp", &a, &b));
    EXPECT_EQ(xf_lock(a, 10, 50, 1, TRUE), 0);
    EXPECT_EQ(xf_lock(b, 10, 50, 2, TRUE), XS(0xC0000055));
    EXPECT_EQ(xf_lock(b, 59, 10, 2, TRUE), XS(0xC0000055));
    EXPECT_EQ(xf_lock(a, 20, 5, 1, TRUE), XS(0xC0000055));
    EXPECT_EQ(xf_lock(b, 60, 10, 2, TRUE), 0);
    EXPECT_EQ(xf_lock(b, 0, 10, 2, TRUE), 0);
    EXPECT_EQ(xf_unlock(b, 60, 10, 2), 0);
    EXPECT_EQ(xf_unlock(b, 0, 10, 2), 0);
    EXPECT_EQ(xf_unlock(a, 10, 50, 1), 0);
    EXPECT_EQ(xf_lock(b, 10, 50, 2, TRUE), 0);
    EXPECT_EQ(xf_unlock(b, 10, 50, 2), 0);
    xf_close2(a, b);
    xf_rm("x_lock2.tmp");
}
TEST(nt_file_x_lock_shared_locks_coexist)
{
    HANDLE a = NULL, b = NULL; XF_NEED(); REQUIRE(UN(NtLockFile)); REQUIRE(UN(NtUnlockFile));
    CHECK(xf_two("x_lock3.tmp", &a, &b));
    EXPECT_EQ(xf_lock(a, 0, 64, 1, FALSE), 0);
    EXPECT_EQ(xf_lock(b, 0, 64, 2, FALSE), 0);
    EXPECT_EQ(xf_lock(b, 0, 64, 3, TRUE), XS(0xC0000055));
    EXPECT_EQ(xf_unlock(a, 0, 64, 1), 0);
    EXPECT_EQ(xf_unlock(b, 0, 64, 2), 0);
    xf_close2(a, b);
    xf_rm("x_lock3.tmp");
}
TEST(nt_file_x_unlock_errors)
{
    HANDLE a = NULL, b = NULL; XF_NEED(); REQUIRE(UN(NtLockFile)); REQUIRE(UN(NtUnlockFile));
    CHECK(xf_two("x_lock4.tmp", &a, &b));
    EXPECT_EQ(xf_unlock(a, 0, 10, 1), XS(0xC000007E));
    EXPECT_EQ(xf_lock(a, 0, 100, 1, TRUE), 0);
    EXPECT_EQ(xf_unlock(a, 0, 50, 1), XS(0xC000007E));  /* range must match exactly */
    EXPECT_EQ(xf_unlock(a, 0, 100, 9), XS(0xC000007E)); /* and so must the key */
    EXPECT_EQ(xf_unlock(b, 0, 100, 1), XS(0xC000007E)); /* and the handle */
    EXPECT_EQ(xf_unlock(a, 0, 100, 1), 0);
    xf_close2(a, b);
    xf_rm("x_lock4.tmp");
}
TEST(nt_file_x_locked_range_blocks_other_handle_io)
{
    HANDLE a = NULL, b = NULL; IO_STATUS_BLOCK io; LARGE_INTEGER pos; BYTE buf[16] = {1}; NTSTATUS s; ULONG key1 = 1; XF_NEED(); REQUIRE(UN(NtLockFile)); REQUIRE(UN(NtUnlockFile));
    CHECK(xf_two("x_lock5.tmp", &a, &b));
    EXPECT_EQ(xf_lock(a, 0, 100, 1, TRUE), 0);
    pos.QuadPart = 10;
    s = UN(NtWriteFile)(b, NULL, NULL, NULL, &io, buf, 4, &pos, NULL);
    EXPECT_EQ(s, XS(0xC0000054));
    s = UN(NtReadFile)(b, NULL, NULL, NULL, &io, buf, 4, &pos, NULL);
    EXPECT_EQ(s, XS(0xC0000054));
    s = UN(NtReadFile)(a, NULL, NULL, NULL, &io, buf, 4, &pos, &key1);   /* the lock owner presents its lock key */
    EXPECT_EQ(s, 0);
    pos.QuadPart = 200; /* outside the locked range */
    s = UN(NtWriteFile)(b, NULL, NULL, NULL, &io, buf, 4, &pos, NULL);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(xf_unlock(a, 0, 100, 1), 0);
    pos.QuadPart = 10;
    s = UN(NtWriteFile)(b, NULL, NULL, NULL, &io, buf, 4, &pos, NULL);
    EXPECT_EQ(s, 0);
    xf_close2(a, b);
    xf_rm("x_lock5.tmp");
}
TEST(nt_file_x_lock_beyond_eof)
{
    HANDLE a = NULL, b = NULL; XF_NEED(); REQUIRE(UN(NtLockFile)); REQUIRE(UN(NtUnlockFile));
    CHECK(xf_two("x_lock6.tmp", &a, &b));
    EXPECT_EQ(xf_lock(a, 100000, 10, 1, TRUE), 0);
    EXPECT_EQ(xf_lock(b, 100005, 10, 2, TRUE), XS(0xC0000055));
    EXPECT_EQ(xf_unlock(a, 100000, 10, 1), 0);
    xf_close2(a, b);
    xf_rm("x_lock6.tmp");
}

/* ---- control codes and cancel -------------------------------------------- */
TEST(nt_file_x_fsctl_invalid_code)
{
    HANDLE h; UNICODE_STRING nt; IO_STATUS_BLOCK io; BYTE out[16]; NTSTATUS s; XF_NEED(); REQUIRE(UN(NtFsControlFile));
    CHECK(xf_make("x_fsctl.tmp", 4)); CHECK(xf_nt("x_fsctl.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        s = UN(NtFsControlFile)(h, NULL, NULL, NULL, &io, 0xFFFFFFFF, NULL, 0, out, sizeof out);
        CHECK(!XOK(s)); t_note("fsctl 0xFFFFFFFF status=%08lx", s);
        s = UN(NtFsControlFile)(h, NULL, NULL, NULL, &io, 0, NULL, 0, NULL, 0);
        CHECK(!XOK(s)); t_note("fsctl 0 status=%08lx", s);
        UN(NtClose)(h);
    }
    xf_rm("x_fsctl.tmp");
}
TEST(nt_file_x_ioctl_invalid_code)
{
    HANDLE h; UNICODE_STRING nt; IO_STATUS_BLOCK io; BYTE out[16]; NTSTATUS s; XF_NEED(); REQUIRE(UN(NtDeviceIoControlFile));
    CHECK(xf_make("x_ioctl.tmp", 4)); CHECK(xf_nt("x_ioctl.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        s = UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, &io, 0xFFFFFFFF, NULL, 0, out, sizeof out);
        CHECK(!XOK(s)); t_note("ioctl 0xFFFFFFFF status=%08lx", s);
        s = UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, &io, 0x12345678, out, sizeof out, out, sizeof out);
        CHECK(!XOK(s)); t_note("ioctl 0x12345678 status=%08lx", s);
        UN(NtClose)(h);
    }
    xf_rm("x_ioctl.tmp");
}
TEST(nt_file_x_fsctl_bad_handle)
{
    IO_STATUS_BLOCK io; XF_NEED(); REQUIRE(UN(NtFsControlFile)); REQUIRE(UN(NtDeviceIoControlFile));
    EXPECT_EQ(UN(NtFsControlFile)((HANDLE)(ULONG_PTR)0x7ffc, NULL, NULL, NULL, &io, 0x9003C, NULL, 0, NULL, 0), XS(0xC0000008));
    EXPECT_EQ(UN(NtDeviceIoControlFile)((HANDLE)(ULONG_PTR)0x7ffc, NULL, NULL, NULL, &io, 0x9003C, NULL, 0, NULL, 0), XS(0xC0000008));
    EXPECT_EQ(UN(NtFsControlFile)(NULL, NULL, NULL, NULL, &io, 0x9003C, NULL, 0, NULL, 0), XS(0xC0000008));
}
TEST(nt_file_x_fsctl_get_compression)
{
    HANDLE h; UNICODE_STRING nt; IO_STATUS_BLOCK io = {0}; USHORT fmt = 0xffff; NTSTATUS s; XF_NEED(); REQUIRE(UN(NtFsControlFile));
    CHECK(xf_make("x_fsctl_c.tmp", 4)); CHECK(xf_nt("x_fsctl_c.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        s = UN(NtFsControlFile)(h, NULL, NULL, NULL, &io, 0x9003C, NULL, 0, &fmt, sizeof fmt);
        if (XOK(s)) { EXPECT_EQ(fmt, 0); EXPECT_EQ(io.Information, 2); }
        else t_note("FSCTL_GET_COMPRESSION status=%08lx", s);
        s = UN(NtFsControlFile)(h, NULL, NULL, NULL, &io, 0x9003C, NULL, 0, &fmt, 0);
        CHECK(!XOK(s)); t_note("FSCTL_GET_COMPRESSION empty output status=%08lx", s);
        UN(NtClose)(h);
    }
    xf_rm("x_fsctl_c.tmp");
}
TEST(nt_file_x_cancel_io_idle)
{
    HANDLE h; UNICODE_STRING nt; IO_STATUS_BLOCK io; XF_NEED(); REQUIRE(UN(NtCancelIoFile));
    CHECK(xf_make("x_cancel.tmp", 4)); CHECK(xf_nt("x_cancel.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) { memset(&io, 0xcc, sizeof io); EXPECT_EQ(UN(NtCancelIoFile)(h, &io), 0); EXPECT_EQ(io.Status, 0); UN(NtClose)(h); }
    xf_rm("x_cancel.tmp");
}
TEST(nt_file_x_cancel_io_bad_handle)
{
    IO_STATUS_BLOCK io; XF_NEED(); REQUIRE(UN(NtCancelIoFile));
    EXPECT_EQ(UN(NtCancelIoFile)((HANDLE)(ULONG_PTR)0x7ffc, &io), XS(0xC0000008));
}

/* ---- NtQueryInformationFile / NtSetInformationFile classes --------------- */
typedef struct { ULONG cls; ULONG size; const char *name; BOOL soft; } xf_class;
static const xf_class xf_classes[] = {
    { 4, 40, "Basic", 0 }, { 5, 24, "Standard", 0 }, { 6, 8, "Internal", 0 }, { 7, 4, "Ea", 0 },
    { 8, 4, "Access", 0 }, { 14, 8, "Position", 0 }, { 16, 4, "Mode", 0 }, { 17, 4, "Alignment", 0 },
    { 34, 56, "NetworkOpen", 0 }, { 35, 8, "AttributeTag", 0 }, { 59, 24, "Id", 1 }, { 68, 72, "Stat", 1 },
};
TEST(nt_file_x_info_classes_fixed_size)
{
    HANDLE h; UNICODE_STRING nt; XF_NEED();
    CHECK(xf_make("x_info.tmp", 777)); CHECK(xf_nt("x_info.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        for (size_t i = 0; i < sizeof xf_classes / sizeof xf_classes[0]; i++) {
            union { ULONGLONG a; BYTE b[256]; } buf; IO_STATUS_BLOCK io = {0}; NTSTATUS s;
            memset(&buf, 0xcc, sizeof buf);
            s = UN(NtQueryInformationFile)(h, &io, &buf, xf_classes[i].size, xf_classes[i].cls);
            if (xf_classes[i].soft && !XOK(s)) { t_note("%s information status=%08lx", xf_classes[i].name, s); continue; }
            CHECKF(s == 0, "%s status=%08lx", xf_classes[i].name, s);
            if (s == 0) { CHECKF(io.Information == xf_classes[i].size, "%s Information=%llu", xf_classes[i].name, (unsigned long long)io.Information); }
            if (xf_classes[i].size > 0) {
                memset(&buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
                s = UN(NtQueryInformationFile)(h, &io, &buf, xf_classes[i].size - 1, xf_classes[i].cls);
                CHECKF(s == XS(0xC0000004), "%s short buffer status=%08lx", xf_classes[i].name, s);
            }
        }
        UN(NtClose)(h);
    }
    xf_rm("x_info.tmp");
}
TEST(nt_file_x_info_standard_values)
{
    HANDLE h; UNICODE_STRING nt; xf_standard st; IO_STATUS_BLOCK io; XF_NEED();
    CHECK(xf_make("x_info2.tmp", 777)); CHECK(xf_nt("x_info2.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &st, sizeof st, 5), 0);
        EXPECT_EQ(st.eof.QuadPart, 777); CHECK(st.alloc.QuadPart >= 777);
        EXPECT_EQ(st.links, 1); EXPECT_EQ(st.del, 0); EXPECT_EQ(st.dir, 0);
        UN(NtClose)(h);
    }
    xf_rm("x_info2.tmp");
}
TEST(nt_file_x_info_access_and_mode)
{
    HANDLE h; UNICODE_STRING nt; ULONG v; IO_STATUS_BLOCK io; XF_NEED();
    CHECK(xf_make("x_info3.tmp", 8)); CHECK(xf_nt("x_info3.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, FILE_READ_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &v, 4, 8), 0);
        CHECK(v & FILE_READ_DATA); CHECK(!(v & FILE_WRITE_DATA));
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &v, 4, 16), 0);
        CHECK(v & FILE_SYNCHRONOUS_IO_NONALERT); CHECK(!(v & FILE_DELETE_ON_CLOSE));
        UN(NtClose)(h);
    }
    xf_rm("x_info3.tmp");
}
TEST(nt_file_x_info_name)
{
    HANDLE h; UNICODE_STRING nt; struct { ULONG len; WCHAR name[260]; } n; IO_STATUS_BLOCK io; NTSTATUS s; XF_NEED();
    CHECK(xf_make("x_info4.tmp", 1)); CHECK(xf_nt("x_info4.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, FILE_READ_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        memset(&n, 0, sizeof n);
        s = UN(NtQueryInformationFile)(h, &io, &n, sizeof n, 9);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            ULONG chars = n.len / 2;
            CHECK(chars > 11 && n.name[0] == L'\\');
            CHECK(!lstrcmpiW(n.name + chars - 11, L"x_info4.tmp"));
            EXPECT_EQ(io.Information, 4 + n.len);
            /* a buffer holding only part of the name reports the whole length */
            { ULONG full = n.len; memset(&n, 0, sizeof n);
              s = UN(NtQueryInformationFile)(h, &io, &n, 4 + 6, 9);
              EXPECT_EQ(s, XS(0x80000005)); EXPECT_EQ(n.len, full); EXPECT_EQ(io.Information, 10); }
        }
        UN(NtClose)(h);
    }
    xf_rm("x_info4.tmp");
}
TEST(nt_file_x_info_invalid_class)
{
    HANDLE h; UNICODE_STRING nt; BYTE buf[256]; IO_STATUS_BLOCK io; XF_NEED();
    CHECK(xf_make("x_info5.tmp", 1)); CHECK(xf_nt("x_info5.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, sizeof buf, 0), XS(0xC0000003));
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, sizeof buf, 0x100), XS(0xC0000003));
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, buf, sizeof buf, 0), XS(0xC0000003));
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, buf, sizeof buf, 0x100), XS(0xC0000003));
        UN(NtClose)(h);
    }
    xf_rm("x_info5.tmp");
}
TEST(nt_file_x_info_bad_handle)
{
    BYTE buf[64]; IO_STATUS_BLOCK io; XF_NEED();
    EXPECT_EQ(UN(NtQueryInformationFile)((HANDLE)(ULONG_PTR)0x7ffc, &io, buf, sizeof buf, 5), XS(0xC0000008));
    EXPECT_EQ(UN(NtSetInformationFile)((HANDLE)(ULONG_PTR)0x7ffc, &io, buf, 8, 14), XS(0xC0000008));
}
TEST(nt_file_x_set_basic_times_roundtrip)
{
    HANDLE h; UNICODE_STRING nt; xf_basic set = {0}, got; IO_STATUS_BLOCK io; XF_NEED();
    CHECK(xf_make("x_set1.tmp", 1)); CHECK(xf_nt("x_set1.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE | FILE_WRITE_ATTRIBUTES, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        set.wt.QuadPart = 132000000000000000LL; /* 0 and -1 mean "leave unchanged" */
        set.at.QuadPart = 132000001000000000LL;
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &set, sizeof set, 4), 0);
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &got, sizeof got, 4), 0);
        EXPECT_EQ(got.wt.QuadPart, set.wt.QuadPart);
        CHECK(got.ct.QuadPart != 0);
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &set, sizeof set - 1, 4), XS(0xC0000004));
        UN(NtClose)(h);
    }
    xf_rm("x_set1.tmp");
}
TEST(nt_file_x_set_position_and_io_pointer)
{
    HANDLE h; UNICODE_STRING nt; LARGE_INTEGER p; BYTE buf[8]; IO_STATUS_BLOCK io; NTSTATUS s; XF_NEED();
    CHECK(xf_make("x_set2.tmp", 100)); CHECK(xf_nt("x_set2.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        p.QuadPart = 40;
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &p, 8, 14), 0);
        s = UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 8, NULL, NULL);
        EXPECT_EQ(s, 0); EXPECT_EQ(io.Information, 8);
        CHECK(buf[0] == (BYTE)(40 * 7 + 3));
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &p, 8, 14), 0);
        EXPECT_EQ(p.QuadPart, 48);
        p.QuadPart = -1;
        s = UN(NtSetInformationFile)(h, &io, &p, 8, 14);
        CHECK(!XOK(s)); t_note("negative position status=%08lx", s);
        UN(NtClose)(h);
    }
    xf_rm("x_set2.tmp");
}
TEST(nt_file_x_read_write_offsets_and_eof)
{
    HANDLE h; UNICODE_STRING nt; LARGE_INTEGER p; BYTE buf[64]; IO_STATUS_BLOCK io; NTSTATUS s; xf_standard st; XF_NEED();
    CHECK(xf_make("x_io1.tmp", 100)); CHECK(xf_nt("x_io1.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        p.QuadPart = 90;                                   /* partial read at the end */
        s = UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, sizeof buf, &p, NULL);
        EXPECT_EQ(s, 0); EXPECT_EQ(io.Information, 10);
        p.QuadPart = 100;                                  /* exactly at EOF */
        s = UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 1, &p, NULL);
        EXPECT_EQ(s, XS(0xC0000011)); EXPECT_EQ(io.Information, 0);
        p.QuadPart = 5000;                                 /* far beyond EOF */
        s = UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 1, &p, NULL);
        EXPECT_EQ(s, XS(0xC0000011));
        p.QuadPart = -1;                                   /* FILE_WRITE_TO_END_OF_FILE */
        memset(buf, 0x5a, 4);
        s = UN(NtWriteFile)(h, NULL, NULL, NULL, &io, buf, 4, &p, NULL);
        EXPECT_EQ(s, 0); EXPECT_EQ(io.Information, 4);
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &st, sizeof st, 5), 0);
        EXPECT_EQ(st.eof.QuadPart, 104);
        p.QuadPart = 200;                                  /* write beyond EOF extends the file */
        s = UN(NtWriteFile)(h, NULL, NULL, NULL, &io, buf, 4, &p, NULL);
        EXPECT_EQ(s, 0);
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &st, sizeof st, 5), 0);
        EXPECT_EQ(st.eof.QuadPart, 204);
        p.QuadPart = 150;                                  /* the gap reads back as zeros */
        s = UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 8, &p, NULL);
        EXPECT_EQ(s, 0); CHECK(buf[0] == 0 && buf[7] == 0);
        UN(NtClose)(h);
    }
    xf_rm("x_io1.tmp");
}
TEST(nt_file_x_sync_handle_tracks_current_position)
{
    HANDLE h; UNICODE_STRING nt; LARGE_INTEGER p; BYTE buf[16]; IO_STATUS_BLOCK io; XF_NEED();
    CHECK(xf_make("x_io2.tmp", 64)); CHECK(xf_nt("x_io2.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        EXPECT_EQ(UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 16, NULL, NULL), 0);
        EXPECT_EQ(UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 16, NULL, NULL), 0);
        CHECK(buf[0] == (BYTE)(16 * 7 + 3));
        p.QuadPart = 4;  /* explicit offsets also move the pointer on synchronous handles */
        EXPECT_EQ(UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 8, &p, NULL), 0);
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &p, 8, 14), 0);
        EXPECT_EQ(p.QuadPart, 12);
        p.HighPart = -1; p.LowPart = 0xFFFFFFFE; /* FILE_USE_FILE_POINTER_POSITION */
        EXPECT_EQ(UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 4, &p, NULL), 0);
        CHECK(buf[0] == (BYTE)(12 * 7 + 3));
        UN(NtClose)(h);
    }
    xf_rm("x_io2.tmp");
}
TEST(nt_file_x_unbuffered_requires_sector_alignment)
{
    HANDLE h; UNICODE_STRING nt; LARGE_INTEGER p; BYTE *raw, *buf; IO_STATUS_BLOCK io; NTSTATUS s; XF_NEED();
    CHECK(xf_make("x_io3.tmp", 4096)); CHECK(xf_nt("x_io3.tmp", &nt, NULL));
    /* FILE_NO_INTERMEDIATE_BUFFERING cannot be combined with FILE_APPEND_DATA access, so request write-data only */
    s = xf_open(&h, &nt, FILE_GENERIC_READ | FILE_WRITE_DATA | DELETE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC | FILE_NO_INTERMEDIATE_BUFFERING, 0, NULL);
    UN(RtlFreeUnicodeString)(&nt);
    EXPECT_EQ(s, 0);
    raw = (BYTE *)UIN("kernel32.dll", VirtualAlloc)(NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (h && raw) {
        buf = raw; p.QuadPart = 0;
        s = UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 4096, &p, NULL);
        EXPECT_EQ(s, 0);
        s = UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 100, &p, NULL);
        EXPECT_EQ(s, XS(0xC000000D));
        s = UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf + 1, 512, &p, NULL);
        CHECK(!XOK(s)); t_note("unaligned buffer status=%08lx", s);
        p.QuadPart = 3;
        s = UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 512, &p, NULL);
        EXPECT_EQ(s, XS(0xC000000D));
    }
    if (raw) UIN("kernel32.dll", VirtualFree)(raw, 0, MEM_RELEASE);
    if (h) UN(NtClose)(h);
    xf_rm("x_io3.tmp");
}
TEST(nt_file_x_set_eof_and_allocation)
{
    HANDLE h; UNICODE_STRING nt; LARGE_INTEGER v; xf_standard st; IO_STATUS_BLOCK io; XF_NEED();
    CHECK(xf_make("x_set3.tmp", 10)); CHECK(xf_nt("x_set3.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        v.QuadPart = 20000;
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &v, 8, 19), 0);
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &st, sizeof st, 5), 0);
        CHECK(st.alloc.QuadPart >= 20000); EXPECT_EQ(st.eof.QuadPart, 10);
        v.QuadPart = 5000;
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &v, 8, 20), 0);
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &st, sizeof st, 5), 0);
        EXPECT_EQ(st.eof.QuadPart, 5000);
        v.QuadPart = 3;
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &v, 4, 20), XS(0xC0000004));
        v.QuadPart = -5;
        { NTSTATUS s = UN(NtSetInformationFile)(h, &io, &v, 8, 20); CHECK(!XOK(s)); t_note("negative end of file status=%08lx", s); }
        UN(NtClose)(h);
    }
    xf_rm("x_set3.tmp");
}
TEST(nt_file_x_set_disposition)
{
    HANDLE h, o; UNICODE_STRING nt; BOOLEAN del = TRUE; xf_standard st; IO_STATUS_BLOCK io; XF_NEED();
    CHECK(xf_make("x_set4.tmp", 10)); CHECK(xf_nt("x_set4.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    if (h) {
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &del, 1, 13), 0);
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &st, sizeof st, 5), 0);
        EXPECT_EQ(st.del, 1);
        EXPECT_EQ(xf_open(&o, &nt, FILE_READ_ATTRIBUTES | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), XS(0xC0000056));
        if (o) UN(NtClose)(o);
        del = FALSE;
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &del, 1, 13), 0);
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &st, sizeof st, 5), 0);
        EXPECT_EQ(st.del, 0);
        UN(NtClose)(h);
    }
    /* a handle opened without DELETE access cannot request deletion */
    EXPECT_EQ(xf_open(&h, &nt, FILE_READ_DATA | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    del = TRUE;
    if (h) { EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &del, 1, 13), XS(0xC0000022)); UN(NtClose)(h); }
    UN(RtlFreeUnicodeString)(&nt);
    xf_rm("x_set4.tmp");
}
TEST(nt_file_x_set_rename)
{
    HANDLE h, o; UNICODE_STRING nt, to; struct { BOOLEAN rep; HANDLE root; ULONG len; WCHAR name[300]; } *ri;
    OBJECT_ATTRIBUTES oa; xf_basic b; IO_STATUS_BLOCK io; NTSTATUS s; XF_NEED(); REQUIRE(UN(NtQueryAttributesFile));
    CHECK(xf_make("x_ren_a.tmp", 10)); CHECK(xf_nt("x_ren_a.tmp", &nt, NULL)); CHECK(xf_nt("x_ren_b.tmp", &to, NULL));
    ri = (void *)UIN("kernel32.dll", HeapAlloc)(UIN("kernel32.dll", GetProcessHeap)(), HEAP_ZERO_MEMORY, sizeof *ri);
    if (!ri) { t_skip("alloc"); return; }
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    if (h && to.Length < sizeof ri->name) {
        ri->rep = FALSE; ri->root = NULL; ri->len = to.Length; memcpy(ri->name, to.Buffer, to.Length);
        s = UN(NtSetInformationFile)(h, &io, ri, offsetof(__typeof__(*ri), name) + to.Length, 10);
        EXPECT_EQ(s, 0);
        InitializeObjectAttributes(&oa, &to, OBJ_CASE_INSENSITIVE, NULL, NULL);
        EXPECT_EQ(UN(NtQueryAttributesFile)(&oa, &b), 0);
        InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
        EXPECT_EQ(UN(NtQueryAttributesFile)(&oa, &b), XS(0xC0000034));
        UN(NtClose)(h);
        /* renaming onto an existing name collides unless replacement is requested */
        CHECK(xf_make("x_ren_a.tmp", 5));
        EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
        if (h) {
            s = UN(NtSetInformationFile)(h, &io, ri, offsetof(__typeof__(*ri), name) + to.Length, 10);
            EXPECT_EQ(s, XS(0xC0000035));
            ri->rep = TRUE;
            s = UN(NtSetInformationFile)(h, &io, ri, offsetof(__typeof__(*ri), name) + to.Length, 10);
            EXPECT_EQ(s, 0);
            UN(NtClose)(h);
        }
    } else if (h) UN(NtClose)(h);
    (void)o;
    UIN("kernel32.dll", HeapFree)(UIN("kernel32.dll", GetProcessHeap)(), 0, ri);
    UN(RtlFreeUnicodeString)(&nt); UN(RtlFreeUnicodeString)(&to);
    xf_rm("x_ren_a.tmp"); xf_rm("x_ren_b.tmp");
}

/* ---- directory enumeration ------------------------------------------------ */
typedef struct { ULONG cls; ULONG name_len_off; ULONG name_off; const char *name; } xf_dirclass;
static const xf_dirclass xf_dirclasses[] = {
    { 1, 60, 64, "Directory" }, { 2, 60, 68, "FullDirectory" }, { 3, 60, 94, "BothDirectory" },
    { 12, 8, 12, "Names" }, { 37, 60, 104, "IdBothDirectory" }, { 38, 60, 80, "IdFullDirectory" },
};
static HANDLE xf_dir_fixture(void)
{
    UNICODE_STRING nt; HANDLE d = NULL; NTSTATUS s;
    if (!xf_make("x_dq_one.xfd", 3) || !xf_make("x_dq_two.xfd", 5) || !xf_make("x_dq_three.txt", 7)) return NULL;
    if (!xf_nt(NULL, &nt, NULL)) return NULL;
    s = xf_open(&d, &nt, FILE_LIST_DIRECTORY | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, NULL);
    UN(RtlFreeUnicodeString)(&nt);
    return XOK(s) ? d : NULL;
}
static void xf_dir_cleanup(void) { xf_rm("x_dq_one.xfd"); xf_rm("x_dq_two.xfd"); xf_rm("x_dq_three.txt"); }
static UNICODE_STRING xf_pat(const WCHAR *w) { UNICODE_STRING u; u.Buffer = (PWSTR)w; u.Length = u.MaximumLength = (USHORT)(lstrlenW(w) * 2); return u; }
/* Walk a returned buffer; count entries whose name equals one of the two *.xfd leaves. */
static int xf_walk(const BYTE *buf, const xf_dirclass *c, int *total, ULONGLONG *eof_one)
{
    int hits = 0; const BYTE *p = buf; *total = 0;
    for (;;) {
        ULONG next = *(const ULONG *)p, nl = *(const ULONG *)(p + c->name_len_off); const WCHAR *nm = (const WCHAR *)(p + c->name_off);
        (*total)++;
        if (nl == 24 && !memcmp(nm, L"x_dq_one.xfd", 24)) { hits++; if (eof_one && c->cls != 12) *eof_one = *(const ULONGLONG *)(p + 40); }
        if (nl == 24 && !memcmp(nm, L"x_dq_two.xfd", 24)) hits++;
        if (!next) break;
        p += next;
    }
    return hits;
}
TEST(nt_file_x_dir_pattern_all_classes)
{
    HANDLE d; XF_NEED(); REQUIRE(UN(NtQueryDirectoryFile));
    d = xf_dir_fixture(); CHECK(d != NULL);
    if (d) {
        UNICODE_STRING pat = xf_pat(L"*.xfd");
        for (size_t i = 0; i < sizeof xf_dirclasses / sizeof xf_dirclasses[0]; i++) {
            union { ULONGLONG a; BYTE b[4096]; } buf; IO_STATUS_BLOCK io = {0}; NTSTATUS s; int total = 0; ULONGLONG eof = 0;
            memset(&buf, 0, sizeof buf);
            s = UN(NtQueryDirectoryFile)(d, NULL, NULL, NULL, &io, &buf, sizeof buf, xf_dirclasses[i].cls, FALSE, &pat, TRUE);
            CHECKF(s == 0, "%s status=%08lx", xf_dirclasses[i].name, s);
            if (s != 0) continue;
            CHECKF(xf_walk(buf.b, &xf_dirclasses[i], &total, &eof) == 2 && total == 2, "%s entries=%d", xf_dirclasses[i].name, total);
            if (xf_dirclasses[i].cls != 12) EXPECT_EQ(eof, 3);
            memset(&buf, 0, sizeof buf);
            s = UN(NtQueryDirectoryFile)(d, NULL, NULL, NULL, &io, &buf, sizeof buf, xf_dirclasses[i].cls, FALSE, &pat, FALSE);
            CHECKF(s == XS(0x80000006), "%s second call status=%08lx", xf_dirclasses[i].name, s);
        }
        UN(NtClose)(d);
    }
    xf_dir_cleanup();
}
TEST(nt_file_x_dir_no_match_status)
{
    HANDLE d; XF_NEED(); REQUIRE(UN(NtQueryDirectoryFile));
    d = xf_dir_fixture(); CHECK(d != NULL);
    if (d) {
        UNICODE_STRING pat = xf_pat(L"*.nomatch"); BYTE buf[1024]; IO_STATUS_BLOCK io;
        EXPECT_EQ(UN(NtQueryDirectoryFile)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 12, FALSE, &pat, TRUE), XS(0xC000000F));
        UN(NtClose)(d);
    }
    xf_dir_cleanup();
}
TEST(nt_file_x_dir_wildcard_question_mark)
{
    HANDLE d; XF_NEED(); REQUIRE(UN(NtQueryDirectoryFile));
    d = xf_dir_fixture(); CHECK(d != NULL);
    if (d) {
        UNICODE_STRING pat = xf_pat(L"x_dq_t??.xfd"); union { ULONGLONG a; BYTE b[1024]; } buf; IO_STATUS_BLOCK io; int total = 0;
        EXPECT_EQ(UN(NtQueryDirectoryFile)(d, NULL, NULL, NULL, &io, &buf, sizeof buf, 12, FALSE, &pat, TRUE), 0);
        CHECK(xf_walk(buf.b, &xf_dirclasses[3], &total, NULL) == 0 || total == 1);
        pat = xf_pat(L"X_DQ_ONE.XFD"); /* patterns match case-insensitively */
        EXPECT_EQ(UN(NtQueryDirectoryFile)(d, NULL, NULL, NULL, &io, &buf, sizeof buf, 12, FALSE, &pat, TRUE), 0);
        CHECK(xf_walk(buf.b, &xf_dirclasses[3], &total, NULL) == 1 && total == 1);
        UN(NtClose)(d);
    }
    xf_dir_cleanup();
}
TEST(nt_file_x_dir_single_entry_and_restart)
{
    HANDLE d; XF_NEED(); REQUIRE(UN(NtQueryDirectoryFile));
    d = xf_dir_fixture(); CHECK(d != NULL);
    if (d) {
        UNICODE_STRING pat = xf_pat(L"*.xfd"); union { ULONGLONG a; BYTE b[1024]; } buf; IO_STATUS_BLOCK io; NTSTATUS s; int seen = 0;
        for (int i = 0; i < 4; i++) {
            memset(&buf, 0, sizeof buf);
            s = UN(NtQueryDirectoryFile)(d, NULL, NULL, NULL, &io, &buf, sizeof buf, 12, TRUE, i ? NULL : &pat, i == 0);
            if (i < 2) { EXPECT_EQ(s, 0); EXPECT_EQ(*(ULONG *)buf.b, 0); seen++; }
            else EXPECT_EQ(s, XS(0x80000006));
        }
        EXPECT_EQ(seen, 2);
        /* restart: enumeration begins again; the pattern from the first call is sticky when not respecified */
        s = UN(NtQueryDirectoryFile)(d, NULL, NULL, NULL, &io, &buf, sizeof buf, 12, TRUE, NULL, TRUE);
        EXPECT_EQ(s, 0);
        UN(NtClose)(d);
    }
    xf_dir_cleanup();
}
TEST(nt_file_x_dir_small_buffer)
{
    HANDLE d; XF_NEED(); REQUIRE(UN(NtQueryDirectoryFile));
    d = xf_dir_fixture(); CHECK(d != NULL);
    if (d) {
        UNICODE_STRING pat = xf_pat(L"*.xfd"); BYTE buf[256]; IO_STATUS_BLOCK io; NTSTATUS s;
        s = UN(NtQueryDirectoryFile)(d, NULL, NULL, NULL, &io, buf, 4, 12, FALSE, &pat, TRUE);
        CHECK(!XOK(s) || s == XS(0x80000005)); t_note("4-byte buffer status=%08lx", s);
        s = UN(NtQueryDirectoryFile)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 0x7f, FALSE, &pat, TRUE);
        EXPECT_EQ(s, XS(0xC0000003));
        UN(NtClose)(d);
    }
    xf_dir_cleanup();
}
TEST(nt_file_x_dir_query_on_file_handle)
{
    HANDLE h; UNICODE_STRING nt; BYTE buf[512]; IO_STATUS_BLOCK io; NTSTATUS s; XF_NEED(); REQUIRE(UN(NtQueryDirectoryFile));
    CHECK(xf_make("x_dq_file.tmp", 1)); CHECK(xf_nt("x_dq_file.tmp", &nt, NULL));
    EXPECT_EQ(xf_open(&h, &nt, XF_RW | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL), 0);
    UN(RtlFreeUnicodeString)(&nt);
    if (h) {
        s = UN(NtQueryDirectoryFile)(h, NULL, NULL, NULL, &io, buf, sizeof buf, 12, FALSE, NULL, TRUE);
        CHECK(!XOK(s)); t_note("directory query on a file handle status=%08lx", s);
        UN(NtClose)(h);
    }
    xf_rm("x_dq_file.tmp");
}

/* ---- volume information ---------------------------------------------------- */
typedef struct { LARGE_INTEGER total, avail; ULONG spau, bps; } xf_fs_size;
static HANDLE xf_open_scratch(void)
{
    UNICODE_STRING nt; HANDLE h; NTSTATUS s;
    if (!xf_make("x_vol.tmp", 1) || !xf_nt("x_vol.tmp", &nt, NULL)) return NULL;
    s = xf_open(&h, &nt, FILE_READ_ATTRIBUTES | SYNCHRONIZE, XF_ALL_SHARE, FILE_OPEN, XF_SYNC, 0, NULL);
    UN(RtlFreeUnicodeString)(&nt);
    return XOK(s) ? h : NULL;
}
TEST(nt_file_x_volume_size_information)
{
    HANDLE h; xf_fs_size sz; IO_STATUS_BLOCK io; XF_NEED(); REQUIRE(UN(NtQueryVolumeInformationFile));
    h = xf_open_scratch(); CHECK(h != NULL);
    if (h) {
        EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &sz, sizeof sz, 3), 0);
        EXPECT_EQ(io.Information, 24);
        CHECK(sz.bps >= 512 && (sz.bps & (sz.bps - 1)) == 0);
        CHECK(sz.spau >= 1); CHECK(sz.total.QuadPart > 0 && sz.avail.QuadPart <= sz.total.QuadPart);
        EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &sz, sizeof sz - 1, 3), XS(0xC0000004));
        EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &sz, sizeof sz, 0x7f), XS(0xC0000003));
        EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &sz, sizeof sz, 0), XS(0xC0000003));
        UN(NtClose)(h);
    }
    xf_rm("x_vol.tmp");
}
TEST(nt_file_x_volume_full_size_information)
{
    HANDLE h; struct { LARGE_INTEGER total, caller, actual; ULONG spau, bps; } fs; xf_fs_size sz; IO_STATUS_BLOCK io; NTSTATUS s; XF_NEED(); REQUIRE(UN(NtQueryVolumeInformationFile));
    h = xf_open_scratch(); CHECK(h != NULL);
    if (h) {
        s = UN(NtQueryVolumeInformationFile)(h, &io, &fs, sizeof fs, 7);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            EXPECT_EQ(io.Information, 32);
            CHECK(fs.actual.QuadPart >= fs.caller.QuadPart); CHECK(fs.total.QuadPart >= fs.actual.QuadPart);
            EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &sz, sizeof sz, 3), 0);
            EXPECT_EQ(fs.total.QuadPart, sz.total.QuadPart); EXPECT_EQ(fs.spau, sz.spau); EXPECT_EQ(fs.bps, sz.bps);
        }
        EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &fs, sizeof fs - 1, 7), XS(0xC0000004));
        UN(NtClose)(h);
    }
    xf_rm("x_vol.tmp");
}
TEST(nt_file_x_volume_device_and_sector_size)
{
    HANDLE h; struct { ULONG type, chars; } dev; struct { ULONG logical, atomic, perf, effective, flags, align, partition; } ss; IO_STATUS_BLOCK io; NTSTATUS s; XF_NEED(); REQUIRE(UN(NtQueryVolumeInformationFile));
    h = xf_open_scratch(); CHECK(h != NULL);
    if (h) {
        EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &dev, sizeof dev, 4), 0);
        EXPECT_EQ(io.Information, 8);
        CHECK(dev.type == 7 || dev.type == 8); /* FILE_DEVICE_DISK or FILE_DEVICE_DISK_FILE_SYSTEM */
        t_note("device type=%lu", dev.type);
        EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &dev, 7, 4), XS(0xC0000004));
        s = UN(NtQueryVolumeInformationFile)(h, &io, &ss, sizeof ss, 11);
        if (XOK(s)) {
            CHECK(ss.logical >= 512 && (ss.logical & (ss.logical - 1)) == 0);
            CHECK(ss.effective >= 512); CHECK(ss.perf >= ss.logical);
        } else t_note("FileFsSectorSizeInformation status=%08lx", s);
        UN(NtClose)(h);
    }
    xf_rm("x_vol.tmp");
}
TEST(nt_file_x_volume_attribute_information)
{
    HANDLE h; struct { ULONG attrs; LONG maxcomp; ULONG namelen; WCHAR name[32]; } at; IO_STATUS_BLOCK io; NTSTATUS s; XF_NEED(); REQUIRE(UN(NtQueryVolumeInformationFile));
    h = xf_open_scratch(); CHECK(h != NULL);
    if (h) {
        memset(&at, 0, sizeof at);
        s = UN(NtQueryVolumeInformationFile)(h, &io, &at, sizeof at, 5);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            CHECK(at.maxcomp >= 12); CHECK(at.namelen >= 6 && at.namelen <= 64);
            CHECK(at.attrs & FILE_CASE_PRESERVED_NAMES);
            EXPECT_EQ(io.Information, 12 + at.namelen);
            t_note("file system name length=%lu max component=%ld", at.namelen, at.maxcomp);
        }
        /* the fixed part is the 16-byte structure including padding and one name character: smaller is a
           length mismatch, exactly that size reports the name as truncated */
        EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &at, 15, 5), XS(0xC0000004));
        s = UN(NtQueryVolumeInformationFile)(h, &io, &at, 16, 5);
        CHECK(s == 0 || s == XS(0x80000005));
        UN(NtClose)(h);
    }
    xf_rm("x_vol.tmp");
}
TEST(nt_file_x_volume_label_information)
{
    HANDLE h; struct { LARGE_INTEGER created; ULONG serial; ULONG labellen; BOOLEAN objects; WCHAR label[64]; } v; IO_STATUS_BLOCK io; NTSTATUS s; XF_NEED(); REQUIRE(UN(NtQueryVolumeInformationFile));
    h = xf_open_scratch(); CHECK(h != NULL);
    if (h) {
        memset(&v, 0, sizeof v);
        s = UN(NtQueryVolumeInformationFile)(h, &io, &v, sizeof v, 1);
        EXPECT_EQ(s, 0);
        if (s == 0) { CHECK(io.Information >= 18); CHECK(v.labellen <= 64 * 2); }
        /* the fixed part is the 24-byte structure including padding and one label character */
        EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &v, 17, 1), XS(0xC0000004));
        EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, &v, 23, 1), XS(0xC0000004));
        s = UN(NtQueryVolumeInformationFile)(h, &io, &v, 24, 1);
        CHECK(s == 0 || s == XS(0x80000005));
        UN(NtClose)(h);
    }
    xf_rm("x_vol.tmp");
}
TEST(nt_file_x_set_volume_information_rejects_invalid)
{
    HANDLE h; BYTE buf[64] = {0}; IO_STATUS_BLOCK io; NTSTATUS s; XF_NEED(); REQUIRE(UN(NtSetVolumeInformationFile));
    h = xf_open_scratch(); CHECK(h != NULL);
    if (h) {
        s = UN(NtSetVolumeInformationFile)(h, &io, buf, sizeof buf, 0x7f);
        CHECK(!XOK(s)); t_note("invalid class status=%08lx", s);
        s = UN(NtSetVolumeInformationFile)(h, &io, buf, sizeof buf, 3);   /* size info is query-only */
        CHECK(!XOK(s)); t_note("size class status=%08lx", s);
        /* the scratch handle lacks write access, so a label change must be refused */
        s = UN(NtSetVolumeInformationFile)(h, &io, buf, 8, 2);
        CHECK(!XOK(s)); t_note("label status=%08lx", s);
        UN(NtClose)(h);
    }
    xf_rm("x_vol.tmp");
}
TEST(nt_file_x_set_volume_information_bad_handle)
{
    BYTE buf[16] = {0}; IO_STATUS_BLOCK io; XF_NEED(); REQUIRE(UN(NtSetVolumeInformationFile)); REQUIRE(UN(NtQueryVolumeInformationFile));
    EXPECT_EQ(UN(NtSetVolumeInformationFile)((HANDLE)(ULONG_PTR)0x7ffc, &io, buf, 16, 2), XS(0xC0000008));
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)((HANDLE)(ULONG_PTR)0x7ffc, &io, buf, 16, 3), XS(0xC0000004)); /* length is validated before the handle */
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)((HANDLE)(ULONG_PTR)0x7ffc, &io, buf, 24, 3), XS(0xC0000008));
}

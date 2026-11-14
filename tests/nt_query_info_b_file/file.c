/* File query services on private scratch files and directories:
 * NtQueryInformationFile, NtQueryVolumeInformationFile, NtQueryDirectoryFileEx,
 * NtQueryFullAttributesFile, NtQueryInformationByName, NtQueryEaFile, NtQueryQuotaInformationFile.
 * Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(BOOLEAN, RtlDosPathNameToNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, void *));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtWriteFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtQueryInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryVolumeInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryDirectoryFileEx, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, NtQueryFullAttributesFile, (POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, NtQueryInformationByName, (POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryEaFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN));
UDECL(NTSTATUS, NtQueryQuotaInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PVOID, BOOLEAN));
UDECL(NTSTATUS, NtDuplicateObject, (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG));

#define S(x) ((NTSTATUS)(x))
#define ST_LEN_MISMATCH S(0xC0000004)
#define ST_INV_CLASS    S(0xC0000003)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_DENIED       S(0xC0000022)
#define ST_BUF_SMALL    S(0xC0000023)
#define ST_BUF_OVERFLOW S(0x80000005)
#define ST_NO_MORE_FILES S(0x80000006)
#define ST_NO_SUCH_FILE S(0xC000000F)
#define ST_INV_PARAM    S(0xC000000D)
#define ST_NAME_NOT_FOUND S(0xC0000034)
#define ST_PATH_NOT_FOUND S(0xC000003A)
#define ST_NO_EAS       S(0xC0000052)
#define OBS(what, e) do { NTSTATUS os_ = (e); t_note("OBS %s: %08lx", what, (unsigned long)os_); } while (0)
#define PSEUDO_PROCESS ((HANDLE)(LONG_PTR)-1)
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x20
#endif
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 1
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x40
#endif
#define ALLSHARE (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define FILE_READ_ATTRIBUTES_ 0x80

#define NEED() do { REQUIRE(UN(NtCreateFile)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtWriteFile)); \
    REQUIRE(UN(RtlDosPathNameToNtPathName_U)); REQUIRE(UN(RtlFreeUnicodeString)); } while (0)

static void alias(const char *n)
{
    char z[96];
    snprintf(z, sizeof z, "Zw%s", n + 2);
    CHECKF(t_proc(n) != NULL, "%s missing", n);
    CHECKF(t_proc(n) == t_proc(z), "%s and %s differ", n, z);
}
TEST(alias_pairs)
{
    static const char *n[] = { "NtQueryInformationFile", "NtQueryVolumeInformationFile", "NtQueryDirectoryFileEx",
        "NtQueryFullAttributesFile", "NtQueryInformationByName", "NtQueryEaFile", "NtQueryQuotaInformationFile" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) alias(n[i]);
}

/* NT path of <tmpdir><leaf> (leaf may contain one backslash); caller frees. */
static BOOL nt_path(const char *leaf, UNICODE_STRING *nt)
{
    char p[MAX_PATH]; WCHAR w[MAX_PATH];
    snprintf(p, sizeof p, "%s%s", t_tmpdir(), leaf);
    if (!MultiByteToWideChar(CP_ACP, 0, p, -1, w, MAX_PATH)) return FALSE;
    memset(nt, 0, sizeof *nt);
    return UN(RtlDosPathNameToNtPathName_U)(w, nt, NULL, NULL) ? TRUE : FALSE;
}
static NTSTATUS open_nt(HANDLE *h, UNICODE_STRING *nt, ACCESS_MASK acc, ULONG disp, ULONG opts, PVOID ea, ULONG ealen)
{
    OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io;
    InitializeObjectAttributes(&oa, nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    *h = NULL;
    return UN(NtCreateFile)(h, acc, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, ALLSHARE, disp, opts, ea, ealen);
}
/* Create <tmpdir><leaf> with `len` bytes of 'x'. */
static HANDLE mkfile(const char *leaf, ULONG len, ULONG acc_extra)
{
    UNICODE_STRING nt; HANDLE h = NULL; IO_STATUS_BLOCK io; char data[256];
    if (!nt_path(leaf, &nt)) return NULL;
    if (open_nt(&h, &nt, FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | acc_extra, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0) != 0) h = NULL;
    UN(RtlFreeUnicodeString)(&nt);
    if (h && len) { memset(data, 'x', sizeof data); UN(NtWriteFile)(h, NULL, NULL, NULL, &io, data, len, NULL, NULL); }
    return h;
}
static HANDLE mkdir_(const char *leaf)
{
    UNICODE_STRING nt; HANDLE h = NULL;
    if (!nt_path(leaf, &nt)) return NULL;
    if (open_nt(&h, &nt, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE | DELETE, FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0) != 0) h = NULL;
    UN(RtlFreeUnicodeString)(&nt);
    return h;
}
static void rmfile(const char *leaf)
{
    char p[MAX_PATH]; snprintf(p, sizeof p, "%s%s", t_tmpdir(), leaf);
    if (!DeleteFileA(p)) RemoveDirectoryA(p);
}

/* ---- NtQueryInformationFile ---- */
typedef struct { LARGE_INTEGER create, access, write, change; ULONG attrs; } FBASIC;
typedef struct { LARGE_INTEGER alloc, eof; ULONG links; BOOLEAN del, dir; } FSTD;
typedef struct { LARGE_INTEGER create, access, write, change, alloc, eof; ULONG attrs; } FNETOPEN;

TEST(file_info_basic_classes)
{
    HANDLE h; IO_STATUS_BLOCK io; BYTE buf[512]; NTSTATUS st;
    NEED(); REQUIRE(UN(NtQueryInformationFile));
    h = mkfile("qibf_basic.bin", 100, 0); CHECK(h != NULL); if (!h) return;
    /* FileBasicInformation (4) */
    memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, sizeof(FBASIC), 4), 0);
    EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 40);
    CHECK(((FBASIC *)buf)->create.QuadPart > 0); CHECK(((FBASIC *)buf)->write.QuadPart > 0);
    EXPECT_EQ(((FBASIC *)buf)->attrs & ~FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_ARCHIVE);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 39, 4), ST_LEN_MISMATCH);
    /* FileStandardInformation (5) */
    memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, sizeof(FSTD), 5), 0);
    EXPECT_EQ(io.Information, 24);
    { FSTD *s = (FSTD *)buf; EXPECT_EQ(s->eof.QuadPart, 100); CHECK(s->alloc.QuadPart >= 100); EXPECT_EQ(s->links, 1); EXPECT_EQ(s->del, 0); EXPECT_EQ(s->dir, 0); }
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 23, 5), ST_LEN_MISMATCH);
    /* FileInternalInformation (6): the file ID */
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 8, 6), 0);
    EXPECT_EQ(io.Information, 8); CHECK(*(ULONGLONG *)buf != 0);
    /* FileEaInformation (7) */
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 4, 7), 0);
    EXPECT_EQ(io.Information, 4); EXPECT_EQ(*(ULONG *)buf, 0);
    /* FileAccessInformation (8) */
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 4, 8), 0);
    EXPECT_EQ(io.Information, 4);
    EXPECT_EQ(*(ULONG *)buf & (FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE), FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE);
    /* FilePositionInformation (14): after writing 100 bytes the position is 100 */
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 8, 14), 0);
    EXPECT_EQ(io.Information, 8); EXPECT_EQ(*(LONGLONG *)buf, 100);
    /* FileModeInformation (16): synchronous non-alert */
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 4, 16), 0);
    EXPECT_EQ(*(ULONG *)buf & 0x30, 0x20);
    /* FileAlignmentInformation (17) */
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 4, 17), 0);
    EXPECT_EQ(io.Information, 4);
    /* FileNetworkOpenInformation (34) */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, sizeof(FNETOPEN), 34), 0);
    EXPECT_EQ(io.Information, 56);
    EXPECT_EQ(((FNETOPEN *)buf)->eof.QuadPart, 100);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 55, 34), ST_LEN_MISMATCH);
    /* FileAttributeTagInformation (35) */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 8, 35), 0);
    EXPECT_EQ(io.Information, 8);
    EXPECT_EQ(((ULONG *)buf)[0] & FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE);
    EXPECT_EQ(((ULONG *)buf)[1], 0);
    /* FileCompressionInformation (28) */
    memset(buf, 0xcc, sizeof buf);
    st = UN(NtQueryInformationFile)(h, &io, buf, 16, 28);
    EXPECT_EQ(st, 0); EXPECT_EQ(io.Information, 16);
    EXPECT_EQ(*(ULONGLONG *)buf, 100); /* CompressedFileSize of an uncompressed file is its size */
    /* invalid classes and handles */
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, sizeof buf, 0), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, sizeof buf, 0xFF), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, sizeof buf, 0x10000), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationFile)(NULL, &io, buf, 40, 4), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationFile)((HANDLE)(ULONG_PTR)0x7ffc, &io, buf, 40, 4), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryInformationFile)(PSEUDO_PROCESS, &io, buf, 40, 4), ST_TYPE_MISM);
    UN(NtClose)(h);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 40, 4), ST_INV_HANDLE);
    rmfile("qibf_basic.bin");
}

TEST(file_info_name_and_all)
{
    HANDLE h; IO_STATUS_BLOCK io; BYTE buf[1024]; NTSTATUS st; ULONG full;
    NEED(); REQUIRE(UN(NtQueryInformationFile));
    h = mkfile("qibf_name.bin", 10, 0); CHECK(h != NULL); if (!h) return;
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, sizeof buf, 9), 0);
    full = *(ULONG *)buf;
    EXPECT_EQ(io.Information, 4 + full);
    { /* name is the volume-relative path: it ends with the file leaf */
        WCHAR *nm = (WCHAR *)(buf + 4); size_t n = full / 2; static const WCHAR leaf[] = L"qibf_name.bin";
        CHECK(n > 13 && nm[0] == L'\\');
        CHECK(n >= 13 && !_wcsnicmp(nm + n - 13, leaf, 13));
    }
    /* partial name: STATUS_BUFFER_OVERFLOW with the buffer filled and the full length reported */
    memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
    st = UN(NtQueryInformationFile)(h, &io, buf, 4 + 6, 9);
    EXPECT_EQ(st, ST_BUF_OVERFLOW);
    EXPECT_EQ(*(ULONG *)buf, full);
    EXPECT_EQ(io.Information, 10);
    CHECK(((WCHAR *)(buf + 4))[0] == L'\\');
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, 3, 9), ST_LEN_MISMATCH);
    /* FileAllInformation (18) */
    memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
    st = UN(NtQueryInformationFile)(h, &io, buf, sizeof buf, 18);
    EXPECT_EQ(st, 0);
    t_note("FileAllInformation Information=%lu", (unsigned long)io.Information);
    EXPECT_EQ(io.Information, 96 + 4 + full);
    EXPECT_EQ(((FSTD *)(buf + 40))->eof.QuadPart, 10);
    EXPECT_EQ(*(ULONG *)(buf + 96), full);       /* NameInformation.FileNameLength follows the 96 fixed bytes */
    /* an undersized buffer still fills the fixed part and reports overflow */
    memset(buf, 0xcc, sizeof buf);
    st = UN(NtQueryInformationFile)(h, &io, buf, 100, 18);
    t_note("FileAllInformation len 100: %08lx info=%lu", (unsigned long)st, (unsigned long)io.Information);
    EXPECT_EQ(st, ST_LEN_MISMATCH);   /* the structure is 104 bytes: name length plus one WCHAR */
    memset(buf, 0xcc, sizeof buf);
    st = UN(NtQueryInformationFile)(h, &io, buf, 104, 18);
    t_note("FileAllInformation len 104: %08lx info=%lu", (unsigned long)st, (unsigned long)io.Information);
    EXPECT_EQ(st, ST_BUF_OVERFLOW); EXPECT_EQ(io.Information, 104);
    EXPECT_EQ(*(ULONG *)(buf + 96), full);
    UN(NtClose)(h);
    rmfile("qibf_name.bin");
}

TEST(file_info_directory_and_stream)
{
    HANDLE d, h; IO_STATUS_BLOCK io; BYTE buf[512];
    NEED(); REQUIRE(UN(NtQueryInformationFile));
    d = mkdir_("qibf_dir1"); CHECK(d != NULL); if (!d) return;
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationFile)(d, &io, buf, 24, 5), 0);
    EXPECT_EQ(((FSTD *)buf)->dir, 1); EXPECT_EQ(((FSTD *)buf)->del, 0);
    EXPECT_EQ(UN(NtQueryInformationFile)(d, &io, buf, 40, 4), 0);
    EXPECT_EQ(((FBASIC *)buf)->attrs & FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_DIRECTORY);
    UN(NtClose)(d);
    rmfile("qibf_dir1");
    /* FileStreamInformation (22) of a plain file: one unnamed data stream */
    h = mkfile("qibf_stream.bin", 100, 0); CHECK(h != NULL); if (!h) return;
    memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, buf, sizeof buf, 22), 0);
    {
        struct { ULONG next, namelen; LONGLONG size, alloc; WCHAR name[1]; } *e = (void *)buf;
        EXPECT_EQ(e->next, 0); EXPECT_EQ(e->namelen, 14); EXPECT_EQ(e->size, 100);
        CHECK(e->alloc >= 100); CHECK(!memcmp(e->name, L"::$DATA", 14));
        EXPECT_EQ(io.Information, 24 + 14);
    }
    /* a handle opened without FILE_READ_ATTRIBUTES is refused for attribute classes */
    UN(NtClose)(h);
    {
        UNICODE_STRING nt; HANDLE r = NULL;
        if (nt_path("qibf_stream.bin", &nt)) {
            NTSTATUS st = open_nt(&r, &nt, FILE_READ_DATA | SYNCHRONIZE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            UN(RtlFreeUnicodeString)(&nt);
            EXPECT_EQ(st, 0);
            if (r) {
                EXPECT_EQ(UN(NtQueryInformationFile)(r, &io, buf, 40, 4), ST_DENIED);
                EXPECT_EQ(UN(NtQueryInformationFile)(r, &io, buf, 24, 5), 0);
                UN(NtClose)(r);
            }
        }
    }
    rmfile("qibf_stream.bin");
}

/* ---- NtQueryVolumeInformationFile ---- */
TEST(volume_info)
{
    HANDLE h; IO_STATUS_BLOCK io; BYTE buf[512]; char root[MAX_PATH]; DWORD spc, bps, fc, tc;
    NEED(); REQUIRE(UN(NtQueryVolumeInformationFile));
    h = mkfile("qibf_vol.bin", 1, 0); CHECK(h != NULL); if (!h) return;
    /* FileFsSizeInformation (3) */
    memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, 24, 3), 0);
    EXPECT_EQ(io.Information, 24);
    { LONGLONG *q = (LONGLONG *)buf; ULONG *u = (ULONG *)(buf + 16);
      CHECK(q[0] > 0); CHECK(q[1] <= q[0]); CHECK(u[0] >= 1 && u[1] >= 512);
      snprintf(root, sizeof root, "%s", t_tmpdir()); root[3] = 0;
      if (GetDiskFreeSpaceA(root, &spc, &bps, &fc, &tc)) { EXPECT_EQ(u[0], spc); EXPECT_EQ(u[1], bps); } }
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, 23, 3), ST_LEN_MISMATCH);
    /* FileFsFullSizeInformation (7) */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, 32, 7), 0);
    EXPECT_EQ(io.Information, 32);
    { LONGLONG *q = (LONGLONG *)buf; CHECK(q[0] > 0); CHECK(q[2] <= q[0]); CHECK(q[1] >= q[2]); }
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, 31, 7), ST_LEN_MISMATCH);
    /* FileFsDeviceInformation (4): disk device */
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, 8, 4), 0);
    EXPECT_EQ(io.Information, 8); EXPECT_EQ(((ULONG *)buf)[0], 7 /* FILE_DEVICE_DISK */);
    /* FileFsVolumeInformation (1): needs 18 fixed bytes; label follows */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, sizeof buf, 1), 0);
    { ULONG labelLen = *(ULONG *)(buf + 12); CHECK(labelLen <= 64); EXPECT_EQ(io.Information, 18 + labelLen); }
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, 17, 1), ST_LEN_MISMATCH);
    /* FileFsAttributeInformation (5): fixed 12 bytes + name */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, sizeof buf, 5), 0);
    { ULONG nlen = *(ULONG *)(buf + 8); CHECK(nlen >= 6 && nlen <= 20); EXPECT_EQ(io.Information, 12 + nlen); CHECK(*(ULONG *)buf & 0x2 /* FILE_CASE_PRESERVED_NAMES */); CHECK(*(LONG *)(buf + 4) >= 255); }
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, 11, 5), ST_LEN_MISMATCH);
    /* short buffer for the variable part: overflow with fixed part filled */
    memset(buf, 0xcc, sizeof buf);
    OBS("fs attribute len 14", UN(NtQueryVolumeInformationFile)(h, &io, buf, 14, 5));
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, sizeof buf, 0), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(h, &io, buf, sizeof buf, 0x100), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(NULL, &io, buf, 24, 3), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryVolumeInformationFile)(PSEUDO_PROCESS, &io, buf, 24, 3), ST_TYPE_MISM);
    UN(NtClose)(h);
    rmfile("qibf_vol.bin");
}

/* ---- NtQueryFullAttributesFile / NtQueryInformationByName ---- */
TEST(full_attributes_file)
{
    HANDLE h, d; UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; FNETOPEN n; NTSTATUS st;
    NEED(); REQUIRE(UN(NtQueryFullAttributesFile));
    h = mkfile("qibf_attr.bin", 100, 0); CHECK(h != NULL); if (!h) return;
    UN(NtClose)(h);
    CHECK(nt_path("qibf_attr.bin", &nt));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    memset(&n, 0xcc, sizeof n);
    EXPECT_EQ(UN(NtQueryFullAttributesFile)(&oa, &n), 0);
    EXPECT_EQ(n.eof.QuadPart, 100); CHECK(n.alloc.QuadPart >= 100);
    EXPECT_EQ(n.attrs & FILE_ATTRIBUTE_DIRECTORY, 0); EXPECT_EQ(n.attrs & FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE);
    CHECK(n.create.QuadPart > 0 && n.write.QuadPart > 0);
    UN(RtlFreeUnicodeString)(&nt);
    /* directory */
    d = mkdir_("qibf_attrdir"); CHECK(d != NULL);
    if (d) {
        CHECK(nt_path("qibf_attrdir", &nt));
        InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
        memset(&n, 0xcc, sizeof n);
        EXPECT_EQ(UN(NtQueryFullAttributesFile)(&oa, &n), 0);
        EXPECT_EQ(n.attrs & FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_DIRECTORY);
        UN(RtlFreeUnicodeString)(&nt);
        UN(NtClose)(d); rmfile("qibf_attrdir");
    }
    /* missing leaf, missing parent */
    CHECK(nt_path("qibf_nonexistent.bin", &nt));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtQueryFullAttributesFile)(&oa, &n), ST_NAME_NOT_FOUND);
    UN(RtlFreeUnicodeString)(&nt);
    CHECK(nt_path("qibf_nodir\\x.bin", &nt));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtQueryFullAttributesFile)(&oa, &n), ST_PATH_NOT_FOUND);
    UN(RtlFreeUnicodeString)(&nt);
    rmfile("qibf_attr.bin");
}

TEST(information_by_name)
{
    HANDLE h; UNICODE_STRING nt; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; BYTE buf[512]; NTSTATUS st;
    NEED(); REQUIRE(UN(NtQueryInformationByName));
    h = mkfile("qibf_byname.bin", 100, 0); CHECK(h != NULL); if (!h) return;
    UN(NtClose)(h);
    CHECK(nt_path("qibf_byname.bin", &nt));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    /* FileStatInformation (68): file id, times, sizes, attributes, reparse tag, link count, effective access */
    memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
    st = UN(NtQueryInformationByName)(&oa, &io, buf, 0x48, 68);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 0x48);
    EXPECT_EQ(*(LONGLONG *)(buf + 48), 100);
    CHECK(*(LONGLONG *)(buf + 40) >= 100);
    EXPECT_EQ(*(ULONG *)(buf + 56) & FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_ARCHIVE);
    EXPECT_EQ(*(ULONG *)(buf + 60), 0);          /* ReparseTag */
    EXPECT_EQ(*(ULONG *)(buf + 64), 1);          /* NumberOfLinks */
    CHECK(*(LONGLONG *)buf != 0 && *(LONGLONG *)(buf + 8) > 0);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 0x47, 68), ST_LEN_MISMATCH);
    /* FileStatLxInformation (70) extends it to 96 bytes */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 96, 70), 0);
    EXPECT_EQ(io.Information, 96); EXPECT_EQ(*(LONGLONG *)(buf + 48), 100);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 95, 70), ST_LEN_MISMATCH);
    /* FileCaseSensitiveInformation (71): per-directory flag, off by default */
    memset(buf, 0xcc, sizeof buf);
    OBS("case sensitive info on a file", UN(NtQueryInformationByName)(&oa, &io, buf, 4, 71));
    /* only the stat classes are accepted; everything else is an invalid parameter */
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 24, 5), ST_INV_PARAM);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 40, 4), ST_INV_PARAM);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 256, 9), ST_INV_PARAM);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 512, 18), ST_INV_PARAM);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 64, 0), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 64, 69), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 64, 0xFF), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 0x68, 75), ST_INV_PARAM);
    UN(RtlFreeUnicodeString)(&nt);
    CHECK(nt_path("qibf_nonexistent2.bin", &nt));
    InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtQueryInformationByName)(&oa, &io, buf, 0x48, 68), ST_NAME_NOT_FOUND);
    UN(RtlFreeUnicodeString)(&nt);
    rmfile("qibf_byname.bin");
}

/* ---- NtQueryDirectoryFileEx ---- */
typedef struct { ULONG next, index, nameLen; WCHAR name[1]; } FNAMES;
#define SL_RESTART_SCAN 1
#define SL_RETURN_SINGLE_ENTRY 2
#define SL_NO_CURSOR_UPDATE 0x10

/* Collect names from one call's buffer; returns entry count. */
static int collect(BYTE *buf, char names[][16], int max, int cls)
{
    int n = 0; BYTE *p = buf;
    for (;;) {
        ULONG next = *(ULONG *)p, nl; WCHAR *nm; int i;
        if (cls == 12) { nl = ((FNAMES *)p)->nameLen; nm = ((FNAMES *)p)->name; }
        else if (cls == 1) { nl = *(ULONG *)(p + 60); nm = (WCHAR *)(p + 64); }
        else { nl = *(ULONG *)(p + 60); nm = (WCHAR *)(p + 94); }   /* class 3: BothDirectory 94 byte header with ShortName */
        if (n < max) { for (i = 0; i < (int)(nl / 2) && i < 15; i++) names[n][i] = (char)nm[i]; names[n][i] = 0; }
        n++;
        if (!next) break;
        p += next;
    }
    return n;
}
static int has(char names[][16], int n, const char *s) { for (int i = 0; i < n && i < 16; i++) if (!_stricmp(names[i], s)) return 1; return 0; }

TEST(directory_ex)
{
    HANDLE d, f[3]; IO_STATUS_BLOCK io; BYTE buf[4096]; char names[16][16]; int n, i; NTSTATUS st;
    UNICODE_STRING pat; static WCHAR pb[] = L"b*", pn[] = L"zzz*";
    NEED(); REQUIRE(UN(NtQueryDirectoryFileEx));
    d = mkdir_("qibf_enum"); CHECK(d != NULL); if (!d) return;
    f[0] = mkfile("qibf_enum\\a.txt", 1, 0); f[1] = mkfile("qibf_enum\\b.txt", 2, 0); f[2] = mkfile("qibf_enum\\c.txt", 3, 0);
    for (i = 0; i < 3; i++) CHECK(f[i] != NULL);
    for (i = 0; i < 3; i++) { if (f[i]) UN(NtClose)(f[i]); f[i] = NULL; }   /* directory sizes are updated when the handles close */
    /* FileNamesInformation (12), all entries */
    memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
    st = UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 12, SL_RESTART_SCAN, NULL);
    EXPECT_EQ(st, 0);
    n = collect(buf, names, 16, 12);
    EXPECT_EQ(n, 5);
    CHECK(has(names, n, ".") && has(names, n, "..") && has(names, n, "a.txt") && has(names, n, "b.txt") && has(names, n, "c.txt"));
    CHECK(io.Information > 0 && io.Information <= sizeof buf);
    /* continued scan: nothing left */
    st = UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 12, 0, NULL);
    EXPECT_EQ(st, ST_NO_MORE_FILES);
    /* restart: single entry per call, five calls */
    n = 0;
    for (;;) {
        st = UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 12, (n == 0 ? SL_RESTART_SCAN : 0) | SL_RETURN_SINGLE_ENTRY, NULL);
        if (st != 0) break;
        EXPECT_EQ(*(ULONG *)buf, 0);
        if (++n > 8) break;
    }
    EXPECT_EQ(n, 5); EXPECT_EQ(st, ST_NO_MORE_FILES);
    /* no-cursor-update: repeated calls return the same first entry */
    {
        char first[2][16];
        for (i = 0; i < 2; i++) {
            st = UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 12, SL_RESTART_SCAN | SL_RETURN_SINGLE_ENTRY | SL_NO_CURSOR_UPDATE, NULL);
            EXPECT_EQ(st, 0);
            collect(buf, first + i, 1, 12);
        }
        EXPECT_STR(first[0], first[1]);
    }
    /* FileDirectoryInformation (1): sizes are reported */
    st = UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 1, SL_RESTART_SCAN, NULL);
    EXPECT_EQ(st, 0);
    {
        BYTE *p = buf; int seen = 0;
        for (;;) {
            ULONG nl = *(ULONG *)(p + 60); WCHAR *nm = (WCHAR *)(p + 64);
            if (nl == 10 && !_wcsnicmp(nm, L"c.txt", 5)) { EXPECT_EQ(*(LONGLONG *)(p + 40), 3); seen++; }
            if (nl == 10 && !_wcsnicmp(nm, L"a.txt", 5)) { EXPECT_EQ(*(LONGLONG *)(p + 40), 1); seen++; }
            if (!*(ULONG *)p) break;
            p += *(ULONG *)p;
        }
        EXPECT_EQ(seen, 2);
    }
    /* FileBothDirectoryInformation (3), FileIdBothDirectoryInformation (37), FileIdExtdDirectoryInformation (60) */
    st = UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 3, SL_RESTART_SCAN, NULL);
    EXPECT_EQ(st, 0);
    st = UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 37, SL_RESTART_SCAN, NULL);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 60, SL_RESTART_SCAN, NULL), 0);
    /* buffer too small for the first entry */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, 16, 12, SL_RESTART_SCAN, NULL), 0);   /* room for exactly the "." entry */
    EXPECT_EQ(io.Information, 14); EXPECT_EQ(*(ULONG *)buf, 0); EXPECT_EQ(((FNAMES *)buf)->nameLen, 2);
    EXPECT_EQ(UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, 8, 12, SL_RESTART_SCAN, NULL), ST_LEN_MISMATCH);
    /* errors */
    EXPECT_EQ(UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 0, SL_RESTART_SCAN, NULL), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 4, SL_RESTART_SCAN, NULL), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryDirectoryFileEx)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 12, 0x80 | SL_RESTART_SCAN, NULL), 0);   /* unknown flag bits are ignored */
    /* the search pattern is captured per handle: use fresh handles */
    {
        HANDLE d2 = mkdir_("qibf_enum");
        if (d2) {
            pat.Buffer = pn; pat.Length = 8; pat.MaximumLength = 10;
            st = UN(NtQueryDirectoryFileEx)(d2, NULL, NULL, NULL, &io, buf, sizeof buf, 12, SL_RESTART_SCAN, &pat);
            EXPECT_EQ(st, ST_NO_SUCH_FILE);
            UN(NtClose)(d2);
        }
        d2 = mkdir_("qibf_enum");
        if (d2) {
            pat.Buffer = pb; pat.Length = 4; pat.MaximumLength = 6;
            st = UN(NtQueryDirectoryFileEx)(d2, NULL, NULL, NULL, &io, buf, sizeof buf, 12, SL_RESTART_SCAN, &pat);
            EXPECT_EQ(st, 0);
            n = collect(buf, names, 16, 12);
            EXPECT_EQ(n, 1); CHECK(has(names, n, "b.txt"));
            st = UN(NtQueryDirectoryFileEx)(d2, NULL, NULL, NULL, &io, buf, sizeof buf, 12, 0, NULL);
            EXPECT_EQ(st, ST_NO_MORE_FILES);
            UN(NtClose)(d2);
        }
    }
    EXPECT_EQ(UN(NtQueryDirectoryFileEx)(NULL, NULL, NULL, NULL, &io, buf, sizeof buf, 12, 1, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryDirectoryFileEx)(PSEUDO_PROCESS, NULL, NULL, NULL, &io, buf, sizeof buf, 12, 1, NULL), ST_TYPE_MISM);
    /* a plain file handle is not a directory */
    { HANDLE fh = mkfile("qibf_enumfile.bin", 1, 0); if (fh) { EXPECT_EQ(UN(NtQueryDirectoryFileEx)(fh, NULL, NULL, NULL, &io, buf, sizeof buf, 12, 1, NULL), ST_INV_PARAM); UN(NtClose)(fh); rmfile("qibf_enumfile.bin"); } }
    UN(NtClose)(d);
    rmfile("qibf_enum\\a.txt"); rmfile("qibf_enum\\b.txt"); rmfile("qibf_enum\\c.txt"); rmfile("qibf_enum");
}

/* ---- NtQueryEaFile ---- */
typedef struct { ULONG next; BYTE flags, nameLen; USHORT valLen; char name[1]; } FEA;

TEST(ea_file)
{
    BYTE ea[128], out[512]; UNICODE_STRING nt; HANDLE h = NULL; IO_STATUS_BLOCK io; NTSTATUS st; FEA *e;
    NEED(); REQUIRE(UN(NtQueryEaFile));
    memset(ea, 0, sizeof ea);
    e = (FEA *)ea; e->next = 20; e->nameLen = 4; e->valLen = 5; memcpy(e->name, "QIBA\0hello", 10);       /* 8 header + 4 + 1 + 5 = 18 -> 24 */
    e = (FEA *)(ea + 20); e->next = 0; e->nameLen = 4; e->valLen = 3; memcpy(e->name, "QIBB\0abc", 8);    /* 8 + 4 + 1 + 3 = 16 */
    CHECK(nt_path("qibf_ea.bin", &nt));
    st = open_nt(&h, &nt, FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | 0x8 /* FILE_READ_EA */, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, ea, 36);
    UN(RtlFreeUnicodeString)(&nt);
    if (st != 0) { t_skip("extended attributes not creatable here: %08lx", (unsigned long)st); return; }
    memset(out, 0xcc, sizeof out); memset(&io, 0xcc, sizeof io);
    st = UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE);
    EXPECT_EQ(st, 0);
    t_note("EA all: info=%lu", (unsigned long)io.Information);
    e = (FEA *)out;
    EXPECT_EQ(e->nameLen, 4); EXPECT_EQ(e->valLen, 5);
    CHECK(!memcmp(e->name, "QIBA", 4)); CHECK(!memcmp(e->name + 5, "hello", 5));
    if (e->next) {
        e = (FEA *)((BYTE *)e + e->next);
        EXPECT_EQ(e->next, 0); EXPECT_EQ(e->nameLen, 4); EXPECT_EQ(e->valLen, 3);
        CHECK(!memcmp(e->name, "QIBB", 4)); CHECK(!memcmp(e->name + 5, "abc", 3));
    } else CHECK(!"second EA present");
    /* single entry per call, continuing */
    memset(out, 0xcc, sizeof out);
    EXPECT_EQ(UN(NtQueryEaFile)(h, &io, out, sizeof out, TRUE, NULL, 0, NULL, TRUE), 0);
    EXPECT_EQ(((FEA *)out)->next, 0); CHECK(!memcmp(((FEA *)out)->name, "QIBA", 4));
    EXPECT_EQ(UN(NtQueryEaFile)(h, &io, out, sizeof out, TRUE, NULL, 0, NULL, FALSE), 0);
    CHECK(!memcmp(((FEA *)out)->name, "QIBB", 4));
    EXPECT_EQ(UN(NtQueryEaFile)(h, &io, out, sizeof out, TRUE, NULL, 0, NULL, FALSE), S(0x80000012));   /* STATUS_NO_MORE_EAS */
    /* by index (1-based) */
    {
        ULONG idx = 2;
        memset(out, 0xcc, sizeof out);
        st = UN(NtQueryEaFile)(h, &io, out, sizeof out, TRUE, NULL, 0, &idx, FALSE);
        EXPECT_EQ(st, 0); CHECK(!memcmp(((FEA *)out)->name, "QIBB", 4));
        idx = 9;
        EXPECT_EQ(UN(NtQueryEaFile)(h, &io, out, sizeof out, TRUE, NULL, 0, &idx, FALSE), S(0xC0000051));   /* STATUS_NONEXISTENT_EA_ENTRY */
    }
    /* by name list */
    {
        BYTE list[16]; memset(list, 0, sizeof list);
        *(ULONG *)list = 0; list[4] = 4; memcpy(list + 5, "QIBB", 5);      /* FILE_GET_EA_INFORMATION: next, nameLen, name */
        memset(out, 0xcc, sizeof out);
        st = UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, list, 12, NULL, TRUE);
        EXPECT_EQ(st, 0);
        EXPECT_EQ(((FEA *)out)->next, 0); CHECK(!memcmp(((FEA *)out)->name, "QIBB", 4));
        EXPECT_EQ(((FEA *)out)->valLen, 3);
        memcpy(list + 5, "NOPE", 5);
        memset(out, 0xcc, sizeof out);
        st = UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, list, 12, NULL, TRUE);
        t_note("EA missing name: %08lx info=%lu valLen=%u", (unsigned long)st, (unsigned long)io.Information, ((FEA *)out)->valLen);
        EXPECT_EQ(st, 0); EXPECT_EQ(io.Information, 13);
        EXPECT_EQ(((FEA *)out)->valLen, 0); EXPECT_EQ(((FEA *)out)->nameLen, 4);
    }
    /* buffer too small for the first entry */
    EXPECT_EQ(UN(NtQueryEaFile)(h, &io, out, 8, FALSE, NULL, 0, NULL, TRUE), ST_BUF_SMALL);
    EXPECT_EQ(UN(NtQueryEaFile)(h, &io, out, 0, FALSE, NULL, 0, NULL, TRUE), ST_BUF_SMALL);
    EXPECT_EQ(UN(NtQueryEaFile)(NULL, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryEaFile)(PSEUDO_PROCESS, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE), ST_TYPE_MISM);
    UN(NtClose)(h);
    /* a file without EAs */
    h = mkfile("qibf_noea.bin", 1, 0x8);
    if (h) {
        EXPECT_EQ(UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE), ST_NO_EAS);
        UN(NtClose)(h);
    }
    rmfile("qibf_ea.bin"); rmfile("qibf_noea.bin");
}

/* ---- NtQueryQuotaInformationFile ---- */
/* FILE_QUOTA_INFORMATION: NextEntryOffset, SidLength, ChangeTime, QuotaUsed, QuotaThreshold, QuotaLimit, Sid (40 bytes + SID). */
static void check_quota(NTSTATUS st, IO_STATUS_BLOCK *io, BYTE *buf, const char *what)
{
    t_note("%s: %08lx Information=%lu", what, (unsigned long)st, (unsigned long)io->Information);
    if (st == 0) {
        ULONG sidlen = *(ULONG *)(buf + 4);
        CHECK(io->Information >= 40 + 8);
        CHECK(sidlen >= 8 && sidlen <= 68);
        if (*(ULONG *)buf == 0) EXPECT_EQ(io->Information, 40 + sidlen);
        EXPECT_EQ(buf[40], 1);                                  /* SID revision */
        EXPECT_EQ(8 + 4 * buf[41], sidlen);                      /* SID length follows from its subauthority count */
    } else {
        CHECK(st == S(0x8000001A) /* STATUS_NO_MORE_ENTRIES */ || st == S(0xC0000002) /* NOT_IMPLEMENTED */ || st == ST_DENIED);
    }
}

TEST(quota_information)
{
    HANDLE h; IO_STATUS_BLOCK io; BYTE buf[512]; NTSTATUS st;
    NEED(); REQUIRE(UN(NtQueryQuotaInformationFile));
    EXPECT_EQ(UN(NtQueryQuotaInformationFile)(NULL, &io, buf, sizeof buf, FALSE, NULL, 0, NULL, TRUE), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryQuotaInformationFile)(PSEUDO_PROCESS, &io, buf, sizeof buf, FALSE, NULL, 0, NULL, TRUE), ST_TYPE_MISM);
    /* a regular file handle is accepted and answers for its volume (observed) */
    h = mkfile("qibf_quota.bin", 1, 0); CHECK(h != NULL);
    if (h) {
        memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
        st = UN(NtQueryQuotaInformationFile)(h, &io, buf, sizeof buf, FALSE, NULL, 0, NULL, TRUE);
        check_quota(st, &io, buf, "quota via file handle");
        /* a buffer that cannot hold the first entry */
        OBS("quota len 8", UN(NtQueryQuotaInformationFile)(h, &io, buf, 8, FALSE, NULL, 0, NULL, TRUE));
        UN(NtClose)(h);
    }
    rmfile("qibf_quota.bin");
    /* the volume itself */
    {
        UNICODE_STRING nt; static WCHAR v[] = L"\\??\\C:"; HANDLE vh = NULL; OBJECT_ATTRIBUTES oa;
        nt.Buffer = v; nt.Length = sizeof v - 2; nt.MaximumLength = sizeof v;
        InitializeObjectAttributes(&oa, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
        st = UN(NtCreateFile)(&vh, FILE_READ_DATA | SYNCHRONIZE, &oa, &io, NULL, 0, ALLSHARE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (st == 0) {
            memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
            st = UN(NtQueryQuotaInformationFile)(vh, &io, buf, sizeof buf, FALSE, NULL, 0, NULL, TRUE);
            check_quota(st, &io, buf, "quota via volume handle");
            UN(NtClose)(vh);
        } else t_note("volume open: %08lx (volume quota query via volume handle skipped)", (unsigned long)st);
    }
}

/* NtSetInformationFile, NtSetEaFile, NtSetQuotaInformationFile, NtSetVolumeInformationFile,
 * NtSetSecurityObject. Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtSetInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtSetEaFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryEaFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN));
UDECL(NTSTATUS, NtSetQuotaInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG));
UDECL(NTSTATUS, NtSetVolumeInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtSetSecurityObject, (HANDLE, ULONG, PVOID));
UDECL(NTSTATUS, NtQuerySecurityObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PVOID, ULONG));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PVOID, BOOLEAN, PVOID, BOOLEAN));
UDECL(NTSTATUS, RtlAbsoluteToSelfRelativeSD, (PVOID, PVOID, PULONG));
UDECL(NTSTATUS, RtlCreateAcl, (PVOID, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAce, (PVOID, ULONG, ACCESS_MASK, PSID));

#define S(x) ((NTSTATUS)(x))
#define ST_INV_HANDLE S(0xC0000008)
#define ST_TYPE_MISM  S(0xC0000024)
#define ST_DENIED     S(0xC0000022)
#define ST_INV_PARAM  S(0xC000000D)
#define ST_LEN_MISM   S(0xC0000004)
#define ST_INV_CLASS  S(0xC0000003)

enum { FBasic = 4, FStandard = 5, FRename = 10, FLink = 11, FDisposition = 13, FPosition = 14,
       FMode = 16, FAllocation = 19, FEndOfFile = 20 };

typedef struct { LARGE_INTEGER Create, Access, Write, Change; ULONG Attr; } FBASIC;
typedef struct { LARGE_INTEGER Alloc, EOFile; ULONG Links; BOOLEAN DelPending, Dir; } FSTANDARD;
typedef struct { BOOLEAN Replace; HANDLE Root; ULONG Len; WCHAR Name[260]; } FRENAME;

static HANDLE reduced_h(HANDLE h, DWORD access)
{
    HANDLE d = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, access, FALSE, 0)) return NULL;
    return d;
}
static void mkpath(char *out, size_t cap, const char *leaf) { t_tmpfile(out, cap, leaf); }
static HANDLE mkfile(const char *leaf, DWORD access, DWORD share, WCHAR *wpath_out)
{
    char p[MAX_PATH]; mkpath(p, sizeof p, leaf);
    if (wpath_out) MultiByteToWideChar(CP_ACP, 0, p, -1, wpath_out, MAX_PATH);
    HANDLE h = CreateFileA(p, access, share, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    return h == INVALID_HANDLE_VALUE ? NULL : h;
}
static void nt_name(const WCHAR *w, FRENAME *r, BOOLEAN replace)
{
    memset(r, 0, sizeof *r);
    r->Replace = replace;
    lstrcpyW(r->Name, L"\\??\\"); lstrcatW(r->Name, w);
    r->Len = lstrlenW(r->Name) * 2;
}
#define RENAME_LEN(r) ((ULONG)(offsetof(FRENAME, Name) + (r).Len))

TEST(set_info_file_position)
{
    REQUIRE(UN(NtSetInformationFile)); REQUIRE(UN(NtQueryInformationFile));
    CHECK(t_proc("NtSetInformationFile") == t_proc("ZwSetInformationFile"));
    HANDLE h = mkfile("pos.tmp", GENERIC_READ | GENERIC_WRITE, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    IO_STATUS_BLOCK io; LARGE_INTEGER pos; pos.QuadPart = 1234;
    memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &pos, sizeof pos, FPosition), 0);
    EXPECT_EQ(io.Status, 0);
    EXPECT_EQ(io.Information, 0);
    LARGE_INTEGER q; q.QuadPart = -1;
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &q, sizeof q, FPosition), 0);
    EXPECT_EQ(q.QuadPart, 1234);
    EXPECT_EQ(SetFilePointer(h, 0, NULL, FILE_CURRENT), 1234);
    memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &pos, sizeof pos - 1, FPosition), ST_LEN_MISM);
    pos.QuadPart = -5;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &pos, sizeof pos, FPosition), ST_INV_PARAM);
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &pos, sizeof pos, 0), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &pos, sizeof pos, 200), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetInformationFile)(NULL, &io, &pos, sizeof pos, FPosition), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetInformationFile)((HANDLE)(LONG_PTR)-1, &io, &pos, sizeof pos, FPosition), ST_TYPE_MISM);
    CloseHandle(h);
}
TEST(set_info_file_eof_alloc)
{
    REQUIRE(UN(NtSetInformationFile)); REQUIRE(UN(NtQueryInformationFile));
    HANDLE h = mkfile("eof.tmp", GENERIC_READ | GENERIC_WRITE, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    IO_STATUS_BLOCK io; LARGE_INTEGER v; FSTANDARD st;
    v.QuadPart = 5000;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &v, sizeof v, FEndOfFile), 0);
    EXPECT_EQ(GetFileSize(h, NULL), 5000);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &st, sizeof st, FStandard), 0);
    EXPECT_EQ(st.EOFile.QuadPart, 5000);
    CHECK(st.Alloc.QuadPart >= 5000);
    v.QuadPart = 100;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &v, sizeof v, FEndOfFile), 0);
    EXPECT_EQ(GetFileSize(h, NULL), 100);
    v.QuadPart = 65536;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &v, sizeof v, FAllocation), 0);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &st, sizeof st, FStandard), 0);
    EXPECT_EQ(st.Alloc.QuadPart, 65536);
    EXPECT_EQ(st.EOFile.QuadPart, 100);                      /* allocation does not change EOF */
    v.QuadPart = 100;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &v, sizeof v - 4, FEndOfFile), ST_LEN_MISM);
    v.QuadPart = -1;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &v, sizeof v, FEndOfFile), ST_INV_PARAM);
    CloseHandle(h);
    /* write access is required */
    h = CreateFileA(NULL, 0, 0, NULL, 0, 0, NULL);
    char p[MAX_PATH]; mkpath(p, sizeof p, "eof.tmp");
    h = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        v.QuadPart = 10;
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &v, sizeof v, FEndOfFile), ST_DENIED);
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &v, sizeof v, FAllocation), ST_DENIED);
        CloseHandle(h);
    }
    DeleteFileA(p);
}
TEST(set_info_file_basic)
{
    REQUIRE(UN(NtSetInformationFile)); REQUIRE(UN(NtQueryInformationFile));
    char p[MAX_PATH]; mkpath(p, sizeof p, "basic.tmp");
    HANDLE h = mkfile("basic.tmp", GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL);
    CHECK(h != NULL); if (!h) return;
    IO_STATUS_BLOCK io; FBASIC b, q;
    memset(&b, 0, sizeof b);                                  /* zero times: unchanged */
    b.Write.QuadPart = 132000000000000000LL;                  /* 2019-ish, multiple of 100ns */
    b.Attr = 0;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &b, sizeof b, FBasic), 0);
    EXPECT_EQ(io.Information, 0);
    memset(&q, 0, sizeof q);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &q, sizeof q, FBasic), 0);
    EXPECT_EQ(q.Write.QuadPart, 132000000000000000LL);
    CHECK(q.Create.QuadPart != 132000000000000000LL && q.Create.QuadPart != 0);
    /* last-write time of -1 / -2 sticky semantics are not asserted; attribute change: */
    memset(&b, 0, sizeof b);
    b.Attr = FILE_ATTRIBUTE_READONLY;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &b, sizeof b, FBasic), 0);
    EXPECT_EQ(GetFileAttributesA(p) & FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_READONLY);
    ULONG disp = 1;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &disp, 1, FDisposition), S(0xC0000121)); /* STATUS_CANNOT_DELETE */
    b.Attr = FILE_ATTRIBUTE_NORMAL;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &b, sizeof b, FBasic), 0);
    EXPECT_EQ(GetFileAttributesA(p) & FILE_ATTRIBUTE_READONLY, 0);
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &b, sizeof b - 8, FBasic), ST_LEN_MISM);
    CloseHandle(h);
    DeleteFileA(p);
}
TEST(set_info_file_disposition)
{
    REQUIRE(UN(NtSetInformationFile));
    char p[MAX_PATH]; mkpath(p, sizeof p, "disp.tmp");
    HANDLE h = mkfile("disp.tmp", GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL);
    CHECK(h != NULL); if (!h) return;
    IO_STATUS_BLOCK io; BOOLEAN d = TRUE;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &d, 1, FDisposition), 0);
    FSTANDARD fs; memset(&fs, 0, sizeof fs);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &fs, sizeof fs, FStandard), 0);
    EXPECT_EQ(fs.DelPending, 1);                              /* delete pending until the last handle closes */
    d = FALSE;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &d, 1, FDisposition), 0);   /* revoke */
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &fs, sizeof fs, FStandard), 0);
    EXPECT_EQ(fs.DelPending, 0);
    CloseHandle(h);
    CHECK(GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES);
    h = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {                          /* no DELETE access */
        d = TRUE;
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &d, 1, FDisposition), ST_DENIED);
        CloseHandle(h);
    }
    h = CreateFileA(p, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    d = TRUE;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &d, 1, FDisposition), 0);
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &d, 0, FDisposition), ST_LEN_MISM);
    CloseHandle(h);
    CHECK(GetFileAttributesA(p) == INVALID_FILE_ATTRIBUTES);  /* deleted on close */
    DeleteFileA(p);
}
TEST(set_info_file_rename)
{
    REQUIRE(UN(NtSetInformationFile));
    WCHAR w1[MAX_PATH], w2[MAX_PATH]; char p1[MAX_PATH], p2[MAX_PATH];
    mkpath(p1, sizeof p1, "ren_a.tmp"); mkpath(p2, sizeof p2, "ren_b.tmp");
    MultiByteToWideChar(CP_ACP, 0, p2, -1, w2, MAX_PATH);
    HANDLE h = mkfile("ren_a.tmp", GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, w1);
    CHECK(h != NULL); if (!h) return;
    DWORD wr; WriteFile(h, "abc", 3, &wr, NULL);
    FRENAME r; IO_STATUS_BLOCK io;
    nt_name(w2, &r, FALSE);
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &r, RENAME_LEN(r), FRename), 0);
    CHECK(GetFileAttributesA(p1) == INVALID_FILE_ATTRIBUTES);
    CHECK(GetFileAttributesA(p2) != INVALID_FILE_ATTRIBUTES);
    /* collision */
    HANDLE c = CreateFileA(p1, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(c != INVALID_HANDLE_VALUE);
    CloseHandle(c);
    nt_name(w1, &r, FALSE);
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &r, RENAME_LEN(r), FRename), S(0xC0000035)); /* OBJECT_NAME_COLLISION */
    nt_name(w1, &r, TRUE);
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &r, RENAME_LEN(r), FRename), 0);
    CHECK(GetFileAttributesA(p2) == INVALID_FILE_ATTRIBUTES);
    EXPECT_EQ(GetFileSize(h, NULL), 3);                       /* the renamed file is the one we wrote */
    /* length too small for header */
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &r, 8, FRename), ST_LEN_MISM);
    /* FileNameLength claims more than supplied */
    r.Len = 4000;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &r, offsetof(FRENAME, Name) + 8, FRename), ST_INV_PARAM);
    CloseHandle(h);
    DeleteFileA(p1); DeleteFileA(p2);
}
TEST(set_info_file_link)
{
    REQUIRE(UN(NtSetInformationFile)); REQUIRE(UN(NtQueryInformationFile));
    WCHAR w1[MAX_PATH], w2[MAX_PATH]; char p1[MAX_PATH], p2[MAX_PATH];
    mkpath(p1, sizeof p1, "lnk_a.tmp"); mkpath(p2, sizeof p2, "lnk_b.tmp");
    MultiByteToWideChar(CP_ACP, 0, p2, -1, w2, MAX_PATH);
    HANDLE h = mkfile("lnk_a.tmp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, w1);
    CHECK(h != NULL); if (!h) return;
    FRENAME r; IO_STATUS_BLOCK io; FSTANDARD st;
    nt_name(w2, &r, FALSE);
    NTSTATUS s = UN(NtSetInformationFile)(h, &io, &r, RENAME_LEN(r), FLink);
    if (s == S(0xC00000BB) || s == S(0xC0000002)) { t_skip("hard links not supported on this volume: %08lx", (unsigned long)s); }
    else {
        EXPECT_EQ(s, 0);
        EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &st, sizeof st, FStandard), 0);
        EXPECT_EQ(st.Links, 2);
        CHECK(GetFileAttributesA(p2) != INVALID_FILE_ATTRIBUTES);
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &r, RENAME_LEN(r), FLink), S(0xC0000035));  /* name exists */
        nt_name(w2, &r, TRUE);
        EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &r, RENAME_LEN(r), FLink), 0);   /* replace with itself */
    }
    CloseHandle(h);
    DeleteFileA(p1); DeleteFileA(p2);
}
TEST(set_info_file_mode)
{
    REQUIRE(UN(NtSetInformationFile)); REQUIRE(UN(NtQueryInformationFile));
    HANDLE h = mkfile("mode.tmp", GENERIC_READ | GENERIC_WRITE, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    IO_STATUS_BLOCK io; ULONG m = 0;
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &m, sizeof m, FMode), 0);
    EXPECT_EQ(m & 0x20, 0x20);                                /* FILE_SYNCHRONOUS_IO_NONALIGNMENT is 0x10; 0x20 = SYNCHRONOUS_IO_NONALERT */
    ULONG nm = m | 0x2;                                       /* FILE_WRITE_THROUGH */
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &nm, sizeof nm, FMode), 0);
    EXPECT_EQ(UN(NtQueryInformationFile)(h, &io, &m, sizeof m, FMode), 0);
    EXPECT_EQ(m & 0x2, 0x2);
    nm = 0x40000000;                                          /* unsupported bit */
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &nm, sizeof nm, FMode), ST_INV_PARAM);
    nm = 0;
    EXPECT_EQ(UN(NtSetInformationFile)(h, &io, &nm, sizeof nm - 1, FMode), ST_LEN_MISM);
    CloseHandle(h);
}

/* ---- extended attributes ---------------------------------------------- */
#pragma pack(push, 4)
typedef struct { ULONG Next; UCHAR Flags; UCHAR NameLen; USHORT ValueLen; char Name[8]; char Value[4]; } EA1;
#pragma pack(pop)
TEST(set_ea_file)
{
    REQUIRE(UN(NtSetEaFile)); REQUIRE(UN(NtQueryEaFile));
    CHECK(t_proc("NtSetEaFile") == t_proc("ZwSetEaFile"));
    char p[MAX_PATH]; mkpath(p, sizeof p, "ea.tmp");
    HANDLE h = mkfile("ea.tmp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL);
    CHECK(h != NULL); if (!h) return;
    EA1 ea; IO_STATUS_BLOCK io;
    memset(&ea, 0, sizeof ea);
    ea.NameLen = 6; ea.ValueLen = 3;
    memcpy(ea.Name, "TESTEA", 7); memcpy(ea.Name + 7, "abc", 3);   /* name NUL-terminated, then value */
    ULONG len = (ULONG)(8 + 6 + 1 + 3);
    NTSTATUS st = UN(NtSetEaFile)(h, &io, &ea, len);
    if (st == S(0xC000004F)) { t_skip("extended attributes not supported on this volume"); CloseHandle(h); DeleteFileA(p); return; }
    EXPECT_EQ(st, 0);
    BYTE out[256]; memset(out, 0, sizeof out);
    memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE), 0);
    CHECK(io.Information >= 8 + 6 + 1 + 3);
    CHECK(out[5] == 6 && *(USHORT *)(out + 6) == 3);
    CHECK(memcmp(out + 8, "TESTEA", 7) == 0 && memcmp(out + 15, "abc", 3) == 0);
    /* a zero-length value removes the EA */
    ea.ValueLen = 0;
    EXPECT_EQ(UN(NtSetEaFile)(h, &io, &ea, 8 + 6 + 1), 0);
    memset(out, 0, sizeof out);
    EXPECT_EQ(UN(NtQueryEaFile)(h, &io, out, sizeof out, FALSE, NULL, 0, NULL, TRUE), S(0xC0000052)); /* STATUS_NO_EAS_ON_FILE */
    /* illegal EA name character */
    memset(&ea, 0, sizeof ea);
    ea.NameLen = 3; ea.ValueLen = 1; memcpy(ea.Name, "A<B", 4); ea.Name[4] = 'x';
    EXPECT_EQ(UN(NtSetEaFile)(h, &io, &ea, 8 + 3 + 1 + 1), S(0x80000013));   /* STATUS_INVALID_EA_NAME */
    /* truncated list */
    memset(&ea, 0, sizeof ea);
    ea.NameLen = 6; ea.ValueLen = 3; memcpy(ea.Name, "TESTEA", 7);
    EXPECT_EQ(UN(NtSetEaFile)(h, &io, &ea, 6), S(0x80000014));                /* STATUS_EA_LIST_INCONSISTENT */
    EXPECT_EQ(UN(NtSetEaFile)(h, &io, &ea, 0), S(0x80000014));
    EXPECT_EQ(UN(NtSetEaFile)((HANDLE)(LONG_PTR)0x7ff0, &io, &ea, 8 + 7 + 3), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetEaFile)(NULL, &io, &ea, 8 + 7 + 3), ST_INV_HANDLE);
    CloseHandle(h);
    h = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        ea.ValueLen = 3; memcpy(ea.Name + 7, "abc", 3);
        EXPECT_EQ(UN(NtSetEaFile)(h, &io, &ea, 8 + 7 + 3), ST_DENIED);
        CloseHandle(h);
    }
    DeleteFileA(p);
}

/* ---- quota / volume information --------------------------------------- */
TEST(set_quota_volume_errors)
{
    REQUIRE(UN(NtSetQuotaInformationFile)); REQUIRE(UN(NtSetVolumeInformationFile));
    CHECK(t_proc("NtSetQuotaInformationFile") == t_proc("ZwSetQuotaInformationFile"));
    CHECK(t_proc("NtSetVolumeInformationFile") == t_proc("ZwSetVolumeInformationFile"));
    IO_STATUS_BLOCK io; BYTE buf[64]; memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtSetQuotaInformationFile)(NULL, &io, buf, sizeof buf), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetQuotaInformationFile)((HANDLE)(LONG_PTR)0x7ff0, &io, buf, sizeof buf), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetVolumeInformationFile)(NULL, &io, buf, sizeof buf, 2), ST_INV_HANDLE);
    HANDLE h = mkfile("vol.tmp", GENERIC_READ | GENERIC_WRITE, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(UN(NtSetQuotaInformationFile)(h, &io, buf, sizeof buf), ST_DENIED);   /* file handle has no write access to the volume */
    EXPECT_EQ(UN(NtSetQuotaInformationFile)(h, &io, buf, 0), ST_INV_PARAM);
    EXPECT_EQ(UN(NtSetVolumeInformationFile)(h, &io, buf, sizeof buf, 2), ST_DENIED);
    EXPECT_EQ(UN(NtSetVolumeInformationFile)(h, &io, buf, sizeof buf, 0), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetVolumeInformationFile)(h, &io, buf, sizeof buf, 99), ST_INV_CLASS);
    EXPECT_EQ(UN(NtSetVolumeInformationFile)(h, &io, buf, 2, 2), ST_LEN_MISM);
    CloseHandle(h);
    char p[MAX_PATH]; mkpath(p, sizeof p, "vol.tmp"); DeleteFileA(p);
}

/* ---- security --------------------------------------------------------- */
static BYTE g_everyone[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };   /* S-1-1-0 */
TEST(set_security_object)
{
    REQUIRE(UN(NtSetSecurityObject)); REQUIRE(UN(NtQuerySecurityObject)); REQUIRE(UN(NtCreateEvent));
    REQUIRE(UN(RtlCreateSecurityDescriptor)); REQUIRE(UN(RtlSetDaclSecurityDescriptor));
    REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAce));
    CHECK(t_proc("NtSetSecurityObject") == t_proc("ZwSetSecurityObject"));
    /* A nameless object has no security descriptor at all. */
    HANDLE ev = NULL;
    EXPECT_EQ(UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE), 0);
    if (ev) {
        BYTE tiny[32]; memset(tiny, 0, sizeof tiny); ((BYTE *)tiny)[0] = 1; *(USHORT *)(tiny + 2) = 0x8000;
        EXPECT_EQ(UN(NtSetSecurityObject)(ev, DACL_SECURITY_INFORMATION, tiny), S(0xC00000D7)); /* STATUS_NO_SECURITY_ON_OBJECT */
        UN(NtClose)(ev);
    }
    WCHAR evname[64]; wsprintfW(evname, L"Local\\NtdllConfSibEv_%lu", GetCurrentProcessId());
    ev = CreateEventW(NULL, TRUE, FALSE, evname);
    CHECK(ev != NULL); if (!ev) return;
    /* kernel callers must pass a self-relative SD, so convert the absolute one built with Rtl */
    BYTE acl[64], absd[64], sd[128]; ULONG sdlen = sizeof sd;
    memset(sd, 0, sizeof sd);
    EXPECT_EQ(UN(RtlCreateAcl)(acl, sizeof acl, 2), 0);
    EXPECT_EQ(UN(RtlAddAccessAllowedAce)(acl, 2, SYNCHRONIZE | EVENT_MODIFY_STATE | READ_CONTROL | WRITE_DAC, g_everyone), 0);
    EXPECT_EQ(UN(RtlCreateSecurityDescriptor)(absd, 1), 0);
    EXPECT_EQ(UN(RtlSetDaclSecurityDescriptor)(absd, TRUE, acl, FALSE), 0);
    REQUIRE(UN(RtlAbsoluteToSelfRelativeSD));
    EXPECT_EQ(UN(RtlAbsoluteToSelfRelativeSD)(absd, sd, &sdlen), 0);
    EXPECT_EQ(UN(NtSetSecurityObject)(ev, DACL_SECURITY_INFORMATION, absd), 0);   /* an absolute SD is captured too */
    EXPECT_EQ(UN(NtSetSecurityObject)(ev, DACL_SECURITY_INFORMATION, sd), 0);
    BYTE out[256]; ULONG need = 0;
    memset(out, 0, sizeof out);
    EXPECT_EQ(UN(NtQuerySecurityObject)(ev, DACL_SECURITY_INFORMATION, out, sizeof out, &need), 0);
    CHECK(((PISECURITY_DESCRIPTOR)out)->Control & SE_SELF_RELATIVE);
    {
        ULONG off = *(ULONG *)(out + 16);                      /* SECURITY_DESCRIPTOR_RELATIVE.Dacl */
        CHECK(off != 0);
        if (off) {
            ACL *a = (ACL *)(out + off);
            EXPECT_EQ(a->AceCount, 1);
            ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)(a + 1);
            EXPECT_EQ(ace->Mask, SYNCHRONIZE | EVENT_MODIFY_STATE | READ_CONTROL | WRITE_DAC);
            CHECK(memcmp(&ace->SidStart, g_everyone, 12) == 0);
        }
    }
    /* errors */
    EXPECT_EQ(UN(NtSetSecurityObject)(NULL, DACL_SECURITY_INFORMATION, sd), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetSecurityObject)(ev, 0, sd), 0);                        /* nothing selected: success, nothing changed */
    EXPECT_EQ(UN(NtSetSecurityObject)(ev, 0x40000000, sd), 0);               /* unknown selector bits are ignored */
    EXPECT_EQ(UN(NtSetSecurityObject)(ev, OWNER_SECURITY_INFORMATION, sd), S(0xC0000079));  /* STATUS_INVALID_SECURITY_DESCR: no owner in SD */
    BYTE bad[64]; memset(bad, 0, sizeof bad);
    EXPECT_EQ(UN(NtSetSecurityObject)(ev, DACL_SECURITY_INFORMATION, bad), S(0xC0000058));   /* STATUS_UNKNOWN_REVISION */
    BYTE bad2[64]; memcpy(bad2, sd, sizeof sd > 64 ? 64 : sizeof sd); bad2[0] = 7;
    EXPECT_EQ(UN(NtSetSecurityObject)(ev, DACL_SECURITY_INFORMATION, bad2), S(0xC0000058));
    HANDLE ro = reduced_h(ev, SYNCHRONIZE);
    if (ro) { EXPECT_EQ(UN(NtSetSecurityObject)(ro, DACL_SECURITY_INFORMATION, sd), ST_DENIED); CloseHandle(ro); }
    UN(NtClose)(ev);
}

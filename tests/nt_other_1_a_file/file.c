/* File-system and memory services: NtDeleteFile, NtFlushBuffersFileEx, NtDeviceIoControlFile, NtCopyFileChunk,
 * NtAreMappedFilesTheSame, NtExtendSection, NtAllocateVirtualMemoryEx, NtAllocateUserPhysicalPages(Ex). */
#include "t.h"

UDECL(NTSTATUS, NtDeleteFile, (POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtFlushBuffersFileEx, (HANDLE, ULONG, PVOID, ULONG, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtDeviceIoControlFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtCopyFileChunk, (HANDLE, HANDLE, HANDLE, PIO_STATUS_BLOCK, ULONG, PLARGE_INTEGER, PLARGE_INTEGER, PULONG, PULONG, ULONG));
UDECL(NTSTATUS, NtAreMappedFilesTheSame, (PVOID, PVOID));
UDECL(NTSTATUS, NtExtendSection, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtAllocateVirtualMemoryEx, (HANDLE, PVOID *, PSIZE_T, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtFreeVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtAllocateUserPhysicalPages, (HANDLE, PULONG_PTR, PULONG_PTR));
UDECL(NTSTATUS, NtAllocateUserPhysicalPagesEx, (HANDLE, PULONG_PTR, PULONG_PTR, PVOID, ULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE));
UDECL(NTSTATUS, NtQuerySection, (HANDLE, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));

#define S(x) ((NTSTATUS)(x))
#define ST_INVHANDLE    S(0xC0000008)
#define ST_INVPARAM     S(0xC000000D)
#define ST_DENIED       S(0xC0000022)
#define ST_TYPEMISM     S(0xC0000024)
#define ST_NAME_NF      S(0xC0000034)
#define ST_PATH_NF      S(0xC000003A)
#define ST_SHARING      S(0xC0000043)
#define ST_AV           S(0xC0000005)
#define ST_NOT_EMPTY    S(0xC0000101)
#define ST_CANNOT_DEL   S(0xC0000121)

#define FILE_PIPE_PEEK 0x11400C
#define FSCTL_GET_COMPRESSION_ 0x9003C
#define FSCTL_SET_SPARSE_ 0x900C4
#define FSCTL_NOT_A_CODE 0x00FF0003

/* Build "\??\<tmpdir><leaf>" as a UNICODE_STRING over buf */
static void nt_path(WCHAR *buf, size_t cap, const char *leaf, UNICODE_STRING *u, OBJECT_ATTRIBUTES *oa)
{
    swprintf(buf, cap, L"\\??\\%hs%hs", t_tmpdir(), leaf);
    u->Buffer = buf; u->Length = (USHORT)(lstrlenW(buf) * 2); u->MaximumLength = u->Length + 2;
    InitializeObjectAttributes(oa, u, OBJ_CASE_INSENSITIVE, NULL, NULL);
}
static void tmpfile_(char *out, const char *leaf) { t_tmpfile(out, MAX_PATH, leaf); }
static BOOL mkfile(const char *path, const char *data)
{
    DWORD n; HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (data) WriteFile(h, data, (DWORD)strlen(data), &n, NULL);
    CloseHandle(h); return TRUE;
}

TEST(file_aliases)
{
    static const char *n[] = { "DeleteFile", "FlushBuffersFileEx", "DeviceIoControlFile", "CopyFileChunk", "AreMappedFilesTheSame",
        "ExtendSection", "AllocateVirtualMemoryEx", "AllocateUserPhysicalPages", "AllocateUserPhysicalPagesEx" };
    char a[64], b[64];
    for (size_t i = 0; i < sizeof n / sizeof *n; i++) {
        snprintf(a, sizeof a, "Nt%s", n[i]); snprintf(b, sizeof b, "Zw%s", n[i]);
        CHECKF(t_proc(a) != NULL && t_proc(a) == t_proc(b), "alias %s", a);
    }
}

/* ---- NtDeleteFile ------------------------------------------------------------------- */
TEST(delete_file)
{
    char p[MAX_PATH]; WCHAR w[MAX_PATH]; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; NTSTATUS s; HANDLE h;
    REQUIRE(UN(NtDeleteFile));
    tmpfile_(p, "del1.txt"); CHECK(mkfile(p, "abc"));
    nt_path(w, MAX_PATH, "del1.txt", &u, &oa);
    s = UN(NtDeleteFile)(&oa);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(GetFileAttributesA(p), INVALID_FILE_ATTRIBUTES);
    s = UN(NtDeleteFile)(&oa);
    EXPECT_EQ(s, ST_NAME_NF);
    /* missing parent directory */
    nt_path(w, MAX_PATH, "no_such_dir\\x.txt", &u, &oa);
    EXPECT_EQ(UN(NtDeleteFile)(&oa), ST_PATH_NF);
    /* read-only file cannot be deleted */
    tmpfile_(p, "del_ro.txt"); CHECK(mkfile(p, "x")); SetFileAttributesA(p, FILE_ATTRIBUTE_READONLY);
    nt_path(w, MAX_PATH, "del_ro.txt", &u, &oa);
    EXPECT_EQ(UN(NtDeleteFile)(&oa), ST_CANNOT_DEL);
    CHECK(GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES);
    SetFileAttributesA(p, FILE_ATTRIBUTE_NORMAL);
    EXPECT_EQ(UN(NtDeleteFile)(&oa), 0);
    /* open without FILE_SHARE_DELETE: sharing violation */
    tmpfile_(p, "del_open.txt"); CHECK(mkfile(p, "x"));
    h = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    nt_path(w, MAX_PATH, "del_open.txt", &u, &oa);
    if (h != INVALID_HANDLE_VALUE) {
        EXPECT_EQ(UN(NtDeleteFile)(&oa), ST_SHARING);
        CloseHandle(h);
    }
    EXPECT_EQ(UN(NtDeleteFile)(&oa), 0);
    /* directories: non-empty fails, empty succeeds */
    tmpfile_(p, "deldir"); CHECK(CreateDirectoryA(p, NULL));
    { char q[MAX_PATH]; snprintf(q, sizeof q, "%s%s", p, "\\inner.txt"); CHECK(mkfile(q, "x"));
      nt_path(w, MAX_PATH, "deldir", &u, &oa);
      /* the open succeeds; the delete-on-close fails silently while the directory has children */
      EXPECT_EQ(UN(NtDeleteFile)(&oa), 0);
      CHECK(GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES);
      DeleteFileA(q); }
    EXPECT_EQ(UN(NtDeleteFile)(&oa), 0);
    EXPECT_EQ(GetFileAttributesA(p), INVALID_FILE_ATTRIBUTES);
    /* invalid object attributes */
    EXPECT_EQ(UN(NtDeleteFile)(NULL), ST_INVPARAM);
    { UNICODE_STRING e = { 0, 0, NULL }; OBJECT_ATTRIBUTES oe; InitializeObjectAttributes(&oe, &e, 0, NULL, NULL);
      s = UN(NtDeleteFile)(&oe); EXPECT_EQ(s, S(0xC000003B)); }          /* empty name: STATUS_OBJECT_PATH_SYNTAX_BAD */
    /* relative delete through a root directory handle */
    tmpfile_(p, "del_rel.txt"); CHECK(mkfile(p, "x"));
    {
        char d[MAX_PATH]; HANDLE dir; strcpy(d, t_tmpdir());
        dir = CreateFileA(d, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (dir != INVALID_HANDLE_VALUE) {
            WCHAR leaf[] = L"del_rel.txt"; UNICODE_STRING ul; OBJECT_ATTRIBUTES or_;
            ul.Buffer = leaf; ul.Length = sizeof leaf - 2; ul.MaximumLength = sizeof leaf;
            InitializeObjectAttributes(&or_, &ul, OBJ_CASE_INSENSITIVE, dir, NULL);
            EXPECT_EQ(UN(NtDeleteFile)(&or_), 0);
            EXPECT_EQ(GetFileAttributesA(p), INVALID_FILE_ATTRIBUTES);
            CloseHandle(dir);
        }
    }
}

/* ---- NtFlushBuffersFileEx ----------------------------------------------------------- */
TEST(flush_buffers_ex)
{
    char p[MAX_PATH]; HANDLE h, ro; IO_STATUS_BLOCK io; NTSTATUS s; DWORD n;
    REQUIRE(UN(NtFlushBuffersFileEx));
    tmpfile_(p, "flush.bin");
    h = CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(h != INVALID_HANDLE_VALUE); if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, "0123456789", 10, &n, NULL);
    memset(&io, 0xcc, sizeof io);
    s = UN(NtFlushBuffersFileEx)(h, 0, NULL, 0, &io);
    EXPECT_EQ(s, 0); EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 0);
    memset(&io, 0xcc, sizeof io);
    s = UN(NtFlushBuffersFileEx)(h, 1 /* FLUSH_FLAGS_FILE_DATA_ONLY */, NULL, 0, &io);
    EXPECT_EQ(s, 0); EXPECT_EQ(io.Information, 0);
    memset(&io, 0xcc, sizeof io);
    s = UN(NtFlushBuffersFileEx)(h, 2 /* FLUSH_FLAGS_NO_SYNC */, NULL, 0, &io);
    EXPECT_EQ(s, 0);
    s = UN(NtFlushBuffersFileEx)(h, 4 /* FLUSH_FLAGS_FILE_DATA_SYNC_ONLY */, NULL, 0, &io);
    EXPECT_EQ(s, 0);
    /* undefined flag bits */
    EXPECT_EQ(UN(NtFlushBuffersFileEx)(h, 0x80, NULL, 0, &io), 0);          /* observed: bits above the defined flags are ignored for a file */
    /* a parameter length without a parameter block */
    s = UN(NtFlushBuffersFileEx)(h, 0, NULL, 4, &io);
    EXPECT_EQ(s, ST_INVPARAM);
    /* read-only handle */
    ro = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (ro != INVALID_HANDLE_VALUE) {
        s = UN(NtFlushBuffersFileEx)(ro, 0, NULL, 0, &io);
        EXPECT_EQ(s, ST_DENIED);
        CloseHandle(ro);
    }
    EXPECT_EQ(UN(NtFlushBuffersFileEx)(NULL, 0, NULL, 0, &io), ST_INVHANDLE);
    EXPECT_EQ(UN(NtFlushBuffersFileEx)((HANDLE)(ULONG_PTR)0xdeadbee0, 0, NULL, 0, &io), ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtFlushBuffersFileEx)(ev, 0, NULL, 0, &io), ST_TYPEMISM); CloseHandle(ev); }
    EXPECT_EQ(UN(NtFlushBuffersFileEx)(h, 0, NULL, 0, NULL), ST_AV);
    CloseHandle(h);
    DeleteFileA(p);
}

/* ---- NtDeviceIoControlFile ------------------------------------------------------------- */
TEST(device_io_control_file)
{
    char p[MAX_PATH], vol[8]; HANDLE h, rd = NULL, wr = NULL, ev; IO_STATUS_BLOCK io; NTSTATUS s; DWORD n;
    struct { ULONG type, dev, part; ULONG guard; } sdn;
    REQUIRE(UN(NtDeviceIoControlFile));
    /* IOCTL_STORAGE_GET_DEVICE_NUMBER on the system volume, opened with no access rights (FILE_ANY_ACCESS code) */
    GetSystemDirectoryA(p, sizeof p);
    snprintf(vol, sizeof vol, "\\\\.\\%c:", p[0]);
    snprintf(p, sizeof p, "\\\\.\\%c:", p[0]);
    h = CreateFileA(p, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) t_note("cannot open volume without access (error %lu)", GetLastError());
    else {
        memset(&sdn, 0xcc, sizeof sdn); memset(&io, 0xcc, sizeof io);
        s = UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, &io, 0x2D1080 /* IOCTL_STORAGE_GET_DEVICE_NUMBER */, NULL, 0, &sdn, 12);
        EXPECT_EQ(s, 0); EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 12);
        EXPECT_EQ(sdn.type, 7);                        /* FILE_DEVICE_DISK */
        EXPECT_EQ(sdn.guard, 0xcccccccc);              /* nothing written past the structure */
        /* the Win32 wrapper reports the same numbers */
        { struct { ULONG type, dev, part; } w; n = 0;
          if (DeviceIoControl(h, 0x2D1080, NULL, 0, &w, sizeof w, &n, NULL)) { EXPECT_EQ(n, 12); EXPECT_EQ(w.dev, sdn.dev); EXPECT_EQ(w.part, sdn.part); } }
        /* completion event is signalled for a synchronous handle */
        ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        memset(&io, 0xcc, sizeof io);
        s = UN(NtDeviceIoControlFile)(h, ev, NULL, NULL, &io, 0x2D1080, NULL, 0, &sdn, 12);
        EXPECT_EQ(s, 0); EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
        CloseHandle(ev);
        /* output too small */
        memset(&io, 0xcc, sizeof io);
        s = UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, &io, 0x2D1080, NULL, 0, &sdn, 11);
        EXPECT_EQ(s, S(0xC0000023));                   /* STATUS_BUFFER_TOO_SMALL */
        s = UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, &io, 0x2D1080, NULL, 0, NULL, 0);
        EXPECT_EQ(s, S(0xC0000023));
        /* bad IO_STATUS_BLOCK and output pointers */
        EXPECT_EQ(UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, NULL, 0x2D1080, NULL, 0, &sdn, 12), ST_AV);
        s = UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, &io, 0x2D1080, NULL, 0, (PVOID)(ULONG_PTR)8, 12);
        EXPECT_EQ(s, ST_AV);
        /* a code the storage stack does not implement */
        s = UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, &io, 0x2D1FFC, NULL, 0, &sdn, 12);
        EXPECT_EQ(s, S(0xC0000010));                   /* STATUS_INVALID_DEVICE_REQUEST */
        CloseHandle(h);
    }
    /* file-system control codes are not device control codes: a plain file rejects them */
    tmpfile_(p, "ioctl.bin"); CHECK(mkfile(p, "hello"));
    h = CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        USHORT comp = 0x5555;
        s = UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, &comp, sizeof comp);
        EXPECT_EQ(s, ST_INVPARAM); EXPECT_EQ(comp, 0x5555);
        EXPECT_EQ(UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, &io, 0x2D1080, NULL, 0, &comp, 2), ST_INVPARAM);
        CloseHandle(h);
    }
    DeleteFileA(p);
    EXPECT_EQ(UN(NtDeviceIoControlFile)(NULL, NULL, NULL, NULL, &io, 0x2D1080, NULL, 0, &sdn, 12), ST_INVHANDLE);
    EXPECT_EQ(UN(NtDeviceIoControlFile)((HANDLE)(ULONG_PTR)0xdeadbee0, NULL, NULL, NULL, &io, 0x2D1080, NULL, 0, &sdn, 12), ST_INVHANDLE);
    { HANDLE e2 = CreateEventW(NULL, 1, 0, NULL);
      EXPECT_EQ(UN(NtDeviceIoControlFile)(e2, NULL, NULL, NULL, &io, 0x2D1080, NULL, 0, &sdn, 12), ST_TYPEMISM); CloseHandle(e2); }
    /* pipe handle: control codes it does not implement through the device path */
    if (CreatePipe(&rd, &wr, NULL, 0)) {
        s = UN(NtDeviceIoControlFile)(rd, NULL, NULL, NULL, &io, FILE_PIPE_PEEK, NULL, 0, &sdn, sizeof sdn);
        EXPECT_EQ(s, S(0xC0000010));
        CloseHandle(rd); CloseHandle(wr);
    }
    /* the NUL device accepts no control codes */
    h = CreateFileA("\\\\.\\NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        s = UN(NtDeviceIoControlFile)(h, NULL, NULL, NULL, &io, 0x12345678, NULL, 0, NULL, 0);
        EXPECT_EQ(s, S(0xC0000010));
        CloseHandle(h);
    }
}

/* ---- NtCopyFileChunk ---------------------------------------------------------------------- */
TEST(copy_file_chunk)
{
    char p1[MAX_PATH], p2[MAX_PATH]; HANDLE a, b; IO_STATUS_BLOCK io; NTSTATUS s; LARGE_INTEGER so, doff; ULONG k1 = 0, k2 = 0;
    REQUIRE(UN(NtCopyFileChunk));
    tmpfile_(p1, "chunk_src.bin"); tmpfile_(p2, "chunk_dst.bin");
    CHECK(mkfile(p1, "0123456789abcdef"));
    a = CreateFileA(p1, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    b = CreateFileA(p2, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(a != INVALID_HANDLE_VALUE && b != INVALID_HANDLE_VALUE);
    so.QuadPart = 0; doff.QuadPart = 0;
    memset(&io, 0xcc, sizeof io);
    s = UN(NtCopyFileChunk)(a, b, NULL, &io, 16, &so, &doff, &k1, &k2, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(io.Information, 16);
    if (s == 0) {
        char buf[32] = {0}; DWORD n = 0;
        SetFilePointer(b, 0, NULL, FILE_BEGIN); ReadFile(b, buf, 16, &n, NULL);
        EXPECT_EQ(n, 16); CHECK(!memcmp(buf, "0123456789abcdef", 16));
    }
    EXPECT_EQ(UN(NtCopyFileChunk)(NULL, b, NULL, &io, 16, &so, &doff, &k1, &k2, 0), ST_INVHANDLE);
    EXPECT_EQ(UN(NtCopyFileChunk)(a, NULL, NULL, &io, 16, &so, &doff, &k1, &k2, 0), ST_INVHANDLE);
    s = UN(NtCopyFileChunk)(a, b, NULL, &io, 0, &so, &doff, &k1, &k2, 0);
    EXPECT_EQ(s, 0);
    CloseHandle(a); CloseHandle(b); DeleteFileA(p1); DeleteFileA(p2);
}

/* ---- NtAreMappedFilesTheSame ------------------------------------------------------------------- */
TEST(are_mapped_files_the_same)
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll"), k32 = GetModuleHandleW(L"kernel32.dll"); NTSTATUS s;
    char p[MAX_PATH], q[MAX_PATH]; HANDLE f1, f2, m1, m2; void *v1 = NULL, *v2 = NULL, *v3 = NULL, *priv;
    REQUIRE(UN(NtAreMappedFilesTheSame));
    EXPECT_EQ(UN(NtAreMappedFilesTheSame)(nt, nt), 0);
    EXPECT_EQ(UN(NtAreMappedFilesTheSame)(nt, (BYTE *)nt + 0x1000), 0);          /* two addresses inside the same image */
    s = UN(NtAreMappedFilesTheSame)(nt, k32);
    EXPECT_EQ(s, S(0xC00000D4));                                                 /* STATUS_NOT_SAME_DEVICE */
    s = UN(NtAreMappedFilesTheSame)(k32, nt);
    EXPECT_EQ(s, S(0xC00000D4));
    /* a private (not file-backed) page */
    priv = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (priv) {
        s = UN(NtAreMappedFilesTheSame)(priv, nt); EXPECT_EQ(s, S(0xC0000018));   /* STATUS_CONFLICTING_ADDRESSES */
        s = UN(NtAreMappedFilesTheSame)(nt, priv); EXPECT_EQ(s, S(0xC0000018));
        VirtualFree(priv, 0, MEM_RELEASE);
    }
    s = UN(NtAreMappedFilesTheSame)(NULL, nt); EXPECT_EQ(s, S(0xC0000141));    /* STATUS_INVALID_ADDRESS */
    s = UN(NtAreMappedFilesTheSame)((PVOID)(ULONG_PTR)0xFFFF0000000, nt); EXPECT_EQ(s, S(0xC0000141));
    /* data file mapped through two different views of two different sections of the same file */
    tmpfile_(p, "maps.bin"); tmpfile_(q, "maps2.bin"); CHECK(mkfile(p, "data")); CHECK(mkfile(q, "other"));
    f1 = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    f2 = CreateFileA(q, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    m1 = CreateFileMappingA(f1, NULL, PAGE_READONLY, 0, 0, NULL); m2 = CreateFileMappingA(f2, NULL, PAGE_READONLY, 0, 0, NULL);
    if (m1 && m2) {
        v1 = MapViewOfFile(m1, FILE_MAP_READ, 0, 0, 0); v2 = MapViewOfFile(m1, FILE_MAP_READ, 0, 0, 0); v3 = MapViewOfFile(m2, FILE_MAP_READ, 0, 0, 0);
        if (v1 && v2 && v3) {
            /* only image mappings can be compared: data views are "not the same device" */
            s = UN(NtAreMappedFilesTheSame)(v1, v2); EXPECT_EQ(s, S(0xC00000D4));
            s = UN(NtAreMappedFilesTheSame)(v1, v3); EXPECT_EQ(s, S(0xC00000D4));
        }
        if (v1) UnmapViewOfFile(v1);
        if (v2) UnmapViewOfFile(v2);
        if (v3) UnmapViewOfFile(v3);
    }
    if (m1) CloseHandle(m1);
    if (m2) CloseHandle(m2);
    CloseHandle(f1); CloseHandle(f2); DeleteFileA(p); DeleteFileA(q);
}

/* ---- NtExtendSection -------------------------------------------------------------------------------- */
TEST(extend_section)
{
    char p[MAX_PATH]; HANDLE f, sec = NULL, ro = NULL; LARGE_INTEGER sz, mx; NTSTATUS s; HANDLE pf;
    REQUIRE(UN(NtExtendSection)); REQUIRE(UN(NtCreateSection)); REQUIRE(UN(NtClose));
    tmpfile_(p, "ext.bin");
    f = CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE); if (f == INVALID_HANDLE_VALUE) return;
    mx.QuadPart = 0x4000;
    s = UN(NtCreateSection)(&sec, SECTION_ALL_ACCESS, NULL, &mx, PAGE_READWRITE, SEC_COMMIT, f);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        sz.QuadPart = 0x8000;
        s = UN(NtExtendSection)(sec, &sz);
        EXPECT_EQ(s, 0); EXPECT_EQ(sz.QuadPart, 0x8000);
        { LARGE_INTEGER fs; CHECK(GetFileSizeEx(f, &fs)); EXPECT_EQ(fs.QuadPart, 0x8000); }   /* the file grew with the section */
        sz.QuadPart = 0x1000;
        s = UN(NtExtendSection)(sec, &sz);
        EXPECT_EQ(s, 0); EXPECT_EQ(sz.QuadPart, 0x8000);        /* a smaller request reports the current size */
        /* handle without SECTION_EXTEND_SIZE */
        if (DuplicateHandle(GetCurrentProcess(), sec, GetCurrentProcess(), &ro, SECTION_MAP_READ, FALSE, 0)) {
            sz.QuadPart = 0x8000;
            EXPECT_EQ(UN(NtExtendSection)(ro, &sz), ST_DENIED);
            CloseHandle(ro);
        }
        UN(NtClose)(sec);
    }
    CloseHandle(f);
    sec = NULL; mx.QuadPart = 0x4000;
    s = UN(NtCreateSection)(&pf, SECTION_ALL_ACCESS, NULL, &mx, PAGE_READWRITE, SEC_COMMIT, NULL);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        sz.QuadPart = 0x8000;
        s = UN(NtExtendSection)(pf, &sz);
        EXPECT_EQ(s, S(0xC0000087));     /* STATUS_SECTION_NOT_EXTENDED */
        UN(NtClose)(pf);
    }
    sz.QuadPart = 0x8000;
    EXPECT_EQ(UN(NtExtendSection)(NULL, &sz), ST_INVHANDLE);
    { HANDLE ev = CreateEventW(NULL, 1, 0, NULL); EXPECT_EQ(UN(NtExtendSection)(ev, &sz), ST_TYPEMISM); CloseHandle(ev); }
    DeleteFileA(p);
}

/* ---- NtAllocateVirtualMemoryEx ----------------------------------------------------------------------------- */
typedef struct { PVOID Lowest, Highest; SIZE_T Alignment; } addr_req;
typedef struct { ULONG64 Type : 8; ULONG64 Reserved : 56; union { ULONG64 ULong64; PVOID Pointer; SIZE_T Size; HANDLE Handle; ULONG ULong; } u; } ext_param;

TEST(allocate_virtual_memory_ex)
{
    PVOID base; SIZE_T size; NTSTATUS s; MEMORY_BASIC_INFORMATION mbi; addr_req ar; ext_param ep;
    REQUIRE(UN(NtAllocateVirtualMemoryEx)); REQUIRE(UN(NtFreeVirtualMemory));
    /* no extended parameters: behaves like NtAllocateVirtualMemory */
    base = NULL; size = 0x3000;
    s = UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, NULL, 0);
    EXPECT_EQ(s, 0); CHECK(base != NULL); EXPECT_EQ(size, 0x3000);
    if (base) {
        EXPECT_EQ((ULONG_PTR)base & 0xFFFF, 0);                 /* allocation granularity */
        memset(base, 0x5a, size);
        CHECK(VirtualQuery(base, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE && mbi.RegionSize == 0x3000);
        size = 0; EXPECT_EQ(UN(NtFreeVirtualMemory)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RELEASE), 0);
    }
    /* size is rounded up to a page */
    base = NULL; size = 0x1001;
    s = UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, NULL, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(size, 0x2000);
    if (base) { size = 0; UN(NtFreeVirtualMemory)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RELEASE); }
    /* alignment requirement: 4 MiB aligned base */
    memset(&ar, 0, sizeof ar); ar.Alignment = 0x400000;
    memset(&ep, 0, sizeof ep); ep.Type = 1 /* MemExtendedParameterAddressRequirements */; ep.u.Pointer = &ar;
    base = NULL; size = 0x10000;
    s = UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &ep, 1);
    EXPECT_EQ(s, 0);
    if (s == 0) { EXPECT_EQ((ULONG_PTR)base & 0x3FFFFF, 0); size = 0; UN(NtFreeVirtualMemory)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RELEASE); }
    /* address range bound */
    memset(&ar, 0, sizeof ar); ar.Lowest = (PVOID)(ULONG_PTR)0x20000000; ar.Highest = (PVOID)(ULONG_PTR)0x2FFFFFFF;
    base = NULL; size = 0x10000;
    s = UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &ep, 1);
    EXPECT_EQ(s, 0);
    if (s == 0) { CHECK((ULONG_PTR)base >= 0x20000000 && (ULONG_PTR)base + size <= 0x30000000); size = 0; UN(NtFreeVirtualMemory)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RELEASE); }
    /* alignment that is not a power of two */
    memset(&ar, 0, sizeof ar); ar.Alignment = 0x30000;
    base = NULL; size = 0x10000;
    EXPECT_EQ(UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &ep, 1), ST_INVPARAM);
    /* alignment smaller than the allocation granularity but not a power of two ok? use 0x1000: invalid below 64 KiB? */
    memset(&ar, 0, sizeof ar); ar.Alignment = 0x1000;
    base = NULL; size = 0x10000;
    s = UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &ep, 1);
    EXPECT_EQ(s, ST_INVPARAM);        /* alignment below the allocation granularity is rejected */
    if (s == 0) { size = 0; UN(NtFreeVirtualMemory)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RELEASE); }
    /* invalid extended parameter type */
    ep.Type = 0; base = NULL; size = 0x10000; ar.Alignment = 0;
    s = UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &ep, 1);
    EXPECT_EQ(s, ST_INVPARAM);
    ep.Type = 0xFF; base = NULL; size = 0x10000;
    EXPECT_EQ(UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &ep, 1), ST_INVPARAM);
    /* count without a parameter array */
    base = NULL; size = 0x10000;
    EXPECT_EQ(UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, NULL, 1), ST_INVPARAM);
    /* zero size, bad protection, bad handle */
    base = NULL; size = 0;
    EXPECT_EQ(UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, NULL, 0), ST_INVPARAM);
    base = NULL; size = 0x1000;
    EXPECT_EQ(UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE | MEM_COMMIT, 0x3, NULL, 0), S(0xC0000045));  /* STATUS_INVALID_PAGE_PROTECTION */
    base = NULL; size = 0x1000;
    EXPECT_EQ(UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, 0, PAGE_READWRITE, NULL, 0), ST_INVPARAM);
    base = NULL; size = 0x1000;
    EXPECT_EQ(UN(NtAllocateVirtualMemoryEx)(NULL, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, NULL, 0), ST_INVHANDLE);
    EXPECT_EQ(UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, NULL, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, NULL, 0), ST_AV);
    /* reserve then commit in place */
    base = NULL; size = 0x10000;
    s = UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RESERVE, PAGE_READWRITE, NULL, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        PVOID b2 = base; SIZE_T sz2 = 0x1000;
        CHECK(VirtualQuery(base, &mbi, sizeof mbi) && mbi.State == MEM_RESERVE);
        s = UN(NtAllocateVirtualMemoryEx)((HANDLE)(LONG_PTR)-1, &b2, &sz2, MEM_COMMIT, PAGE_READWRITE, NULL, 0);
        EXPECT_EQ(s, 0); EXPECT_EQ(b2, base);
        CHECK(VirtualQuery(base, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT && mbi.RegionSize == 0x1000);
        size = 0; UN(NtFreeVirtualMemory)((HANDLE)(LONG_PTR)-1, &base, &size, MEM_RELEASE);
    }
}

/* ---- AWE ------------------------------------------------------------------------------------------------------ */
TEST(allocate_user_physical_pages)
{
    ULONG_PTR n = 4, pfn[4]; NTSTATUS s; BOOLEAN old = 0; NTSTATUS sp;
    REQUIRE(UN(NtAllocateUserPhysicalPages)); REQUIRE(UN(NtAllocateUserPhysicalPagesEx));
    /* The calling token does not hold SeLockMemoryPrivilege, which the service requires. */
    if (UN(RtlAdjustPrivilege)) {
        sp = UN(RtlAdjustPrivilege)(4 /* SeLockMemoryPrivilege */, TRUE, FALSE, &old);
        if (sp >= 0) { t_skip("token holds SeLockMemoryPrivilege: allocation would succeed"); UN(RtlAdjustPrivilege)(4, old, FALSE, &old); return; }
        EXPECT_EQ(sp, S(0xC0000061));    /* not held -> adjusting reports STATUS_PRIVILEGE_NOT_HELD */
    }
    n = 4; memset(pfn, 0, sizeof pfn);
    s = UN(NtAllocateUserPhysicalPages)((HANDLE)(LONG_PTR)-1, &n, pfn);
    EXPECT_EQ(s, S(0xC0000061));
    n = 4;
    s = UN(NtAllocateUserPhysicalPagesEx)((HANDLE)(LONG_PTR)-1, &n, pfn, NULL, 0);
    EXPECT_EQ(s, S(0xC0000061));
    n = 4; EXPECT_EQ(UN(NtAllocateUserPhysicalPages)(NULL, &n, pfn), ST_INVHANDLE);   /* observed */
}

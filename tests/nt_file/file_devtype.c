/* Native file API on non-disk handle kinds: NtQueryVolumeInformationFile (FileFsDeviceInformation,
 * FileFsAttributeInformation, FileFsVolumeInformation, FileFsSizeInformation) and a few
 * NtQueryInformationFile classes for a regular file, a directory, anonymous and named pipes, a
 * mailslot, the console and the NUL device; opening NUL through NtCreateFile; invalid and pseudo handles.
 * Evidence: values observed on Windows 10 22H2 (build 19045), standard user and elevated. The device
 * type and characteristics are what GetFileType and the C runtime classify std handles by:
 * DISK 0x07/0x20020, NAMED_PIPE 0x11/0x20000, CONSOLE 0x50/0x20000, NULL 0x15/0x100. */
#include "t.h"

UDECL(BOOLEAN, RtlDosPathNameToNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, void *));
UDECL(NTSTATUS, NtCreateFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtReadFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtWriteFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtQueryInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryVolumeInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));

#define DS(x) ((NTSTATUS)(x))
#define DOK(s) ((NTSTATUS)(s) >= 0)
#define DV_SYNC_NONDIR 0x60          /* FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE */
#define DV_SYNC_DIR 0x21             /* FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE */
#define DV_SHARE_ALL 7
#define DV_INVALID_DEVICE_REQUEST 0xC0000010
#define DV_INVALID_INFO_CLASS 0xC0000003
#define DV_INVALID_HANDLE 0xC0000008
#define DV_OBJECT_TYPE_MISMATCH 0xC0000024
#define DV_NEED() do { REQUIRE(UN(NtCreateFile)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtQueryInformationFile)); \
    REQUIRE(UN(NtQueryVolumeInformationFile)); REQUIRE(UN(RtlInitUnicodeString)); \
    REQUIRE(UIN("kernel32.dll", CreatePipe)); REQUIRE(UIN("kernel32.dll", CreateNamedPipeA)); \
    REQUIRE(UIN("kernel32.dll", CreateFileA)); REQUIRE(UIN("kernel32.dll", CreateMailslotA)); \
    REQUIRE(UIN("kernel32.dll", GetCurrentProcessId)); } while (0)

typedef struct { ULONG type, chars; } dv_device;
typedef struct { ULONG attrs, maxcomp, namelen; WCHAR name[16]; } dv_attr;
typedef struct { LARGE_INTEGER created; ULONG serial, labellen; BOOLEAN objects; WCHAR label[16]; } dv_volume;
typedef struct { LARGE_INTEGER total, avail; ULONG spau, bps; } dv_size;
typedef struct { LARGE_INTEGER alloc, eof; ULONG links; BOOLEAN deleting, directory; } dv_standard;
_Static_assert(sizeof(dv_device) == 8, "FILE_FS_DEVICE_INFORMATION");
_Static_assert(offsetof(dv_attr, name) == 12, "FILE_FS_ATTRIBUTE_INFORMATION");
_Static_assert(offsetof(dv_volume, label) == 18, "FILE_FS_VOLUME_INFORMATION");
_Static_assert(sizeof(dv_standard) == 24, "FILE_STANDARD_INFORMATION");

enum { K_FILE, K_DIR, K_ANON_READ, K_ANON_WRITE, K_PIPE_SERVER, K_PIPE_CLIENT, K_MAILSLOT, K_CONSOLE_OUT, K_CONSOLE_IN, K_NUL };

typedef struct { HANDLE h, extra; int own_nt; char path[MAX_PATH]; } dv_obj;

static NTSTATUS dv_nt_open(HANDLE *h, const WCHAR *name, ACCESS_MASK access, ULONG disp, ULONG opts, ULONG_PTR *info)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; NTSTATUS s;
    memset(&io, 0, sizeof io); *h = NULL;
    UN(RtlInitUnicodeString)(&us, name);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = UN(NtCreateFile)(h, access, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, DV_SHARE_ALL, disp, opts, NULL, 0);
    if (info) *info = io.Information;
    if (!DOK(s)) *h = NULL;
    return s;
}
static void dv_close(dv_obj *o)
{
    if (o->h) { if (o->own_nt) UN(NtClose)(o->h); else CloseHandle(o->h); }
    if (o->extra) CloseHandle(o->extra);
    if (o->path[0]) DeleteFileA(o->path);
    memset(o, 0, sizeof *o);
}
/* Opens one handle of the requested kind; FALSE (after a skip note) when the kind is unavailable here. */
static BOOL dv_make(dv_obj *o, int kind)
{
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, FALSE };
    char name[96]; HANDLE r, w; UNICODE_STRING nt; WCHAR dos[MAX_PATH]; NTSTATUS s; ULONG_PTR info;
    memset(o, 0, sizeof *o);
    switch (kind) {
    case K_FILE: {
        char leaf[64];
        snprintf(leaf, sizeof leaf, "nt_devtype_%lu.tmp", UIN("kernel32.dll", GetCurrentProcessId)());
        t_tmpfile(o->path, sizeof o->path, leaf);
        o->h = UIN("kernel32.dll", CreateFileA)(o->path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (o->h == INVALID_HANDLE_VALUE) { o->h = NULL; o->path[0] = 0; t_skip("scratch file create"); return FALSE; }
        return TRUE; }
    case K_DIR:
        if (!UIN("kernel32.dll", MultiByteToWideChar)(CP_ACP, 0, t_tmpdir(), -1, dos, MAX_PATH) ||
            !UN(RtlDosPathNameToNtPathName_U)(dos, &nt, NULL, NULL)) { t_skip("scratch directory conversion"); return FALSE; }
        s = dv_nt_open(&o->h, nt.Buffer, FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_OPEN, DV_SYNC_DIR, NULL);
        UN(RtlFreeUnicodeString)(&nt);
        if (!DOK(s)) { t_skip("scratch directory open %08lx", s); return FALSE; }
        o->own_nt = 1; return TRUE;
    case K_ANON_READ: case K_ANON_WRITE:
        if (!UIN("kernel32.dll", CreatePipe)(&r, &w, &sa, 0)) { t_skip("CreatePipe"); return FALSE; }
        o->h = kind == K_ANON_READ ? r : w; o->extra = kind == K_ANON_READ ? w : r; return TRUE;
    case K_PIPE_SERVER: case K_PIPE_CLIENT:
        snprintf(name, sizeof name, "\\\\.\\pipe\\nt_devtype_%lu_%d", UIN("kernel32.dll", GetCurrentProcessId)(), kind);
        r = UIN("kernel32.dll", CreateNamedPipeA)(name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
        if (r == INVALID_HANDLE_VALUE) { t_skip("CreateNamedPipe"); return FALSE; }
        w = UIN("kernel32.dll", CreateFileA)(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (w == INVALID_HANDLE_VALUE) { CloseHandle(r); t_skip("named pipe client open"); return FALSE; }
        o->h = kind == K_PIPE_SERVER ? r : w; o->extra = kind == K_PIPE_SERVER ? w : r; return TRUE;
    case K_MAILSLOT:
        snprintf(name, sizeof name, "\\\\.\\mailslot\\nt_devtype_%lu", UIN("kernel32.dll", GetCurrentProcessId)());
        o->h = UIN("kernel32.dll", CreateMailslotA)(name, 0, 0, NULL);
        if (o->h == INVALID_HANDLE_VALUE) { o->h = NULL; t_skip("CreateMailslot"); return FALSE; }
        return TRUE;
    case K_CONSOLE_OUT: case K_CONSOLE_IN:
        s = dv_nt_open(&o->h, kind == K_CONSOLE_OUT ? L"\\??\\CONOUT$" : L"\\??\\CONIN$", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, FILE_OPEN, 0x20, &info);
        if (!DOK(s)) { t_skip("no console in this process (open status %08lx)", s); return FALSE; }
        o->own_nt = 1; return TRUE;
    case K_NUL:
        s = dv_nt_open(&o->h, L"\\??\\NUL", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, FILE_OPEN, 0x20, &info);
        EXPECT_EQ(s, 0);
        if (!DOK(s)) return FALSE;
        o->own_nt = 1; return TRUE;
    }
    return FALSE;
}

#define VOLQ(h, cls, buf, len) UN(NtQueryVolumeInformationFile)((h), &io, (buf), (len), (cls))
#define INFQ(h, cls, buf, len) UN(NtQueryInformationFile)((h), &io, (buf), (len), (cls))

/* ---- FileFsDeviceInformation (class 4): device type and characteristics ------- */
static void device_case(int kind, ULONG type, ULONG chars)
{
    dv_obj o; dv_device d; IO_STATUS_BLOCK io; NTSTATUS s;
    DV_NEED(); if (!dv_make(&o, kind)) return;
    memset(&d, 0xcc, sizeof d); memset(&io, 0xcc, sizeof io);
    s = VOLQ(o.h, 4, &d, sizeof d);
    EXPECT_EQ(s, 0);
    if (DOK(s)) { EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 8); EXPECT_EQ(d.type, type); EXPECT_EQ(d.chars, chars); }
    memset(&d, 0xcc, sizeof d);
    EXPECT_EQ(VOLQ(o.h, 4, &d, sizeof d - 1), DS(0xC0000004));       /* STATUS_INFO_LENGTH_MISMATCH */
    dv_close(&o);
}
#define DEVICE(n, k, t, c) TEST(nt_file_devtype_device_##n) { device_case(k, t, c); }
DEVICE(file, K_FILE, 0x07, 0x20020)
DEVICE(directory, K_DIR, 0x07, 0x20020)
DEVICE(anonymous_pipe_read, K_ANON_READ, 0x11, 0x20000)
DEVICE(anonymous_pipe_write, K_ANON_WRITE, 0x11, 0x20000)
DEVICE(named_pipe_server, K_PIPE_SERVER, 0x11, 0x20000)
DEVICE(named_pipe_client, K_PIPE_CLIENT, 0x11, 0x20000)
DEVICE(mailslot, K_MAILSLOT, 0x0c, 0)
DEVICE(console_output, K_CONSOLE_OUT, 0x50, 0x20000)
DEVICE(console_input, K_CONSOLE_IN, 0x50, 0x20000)
DEVICE(nul, K_NUL, 0x15, 0x100)

/* ---- FileFsAttributeInformation (class 5) ---------------------------------------- */
static void attribute_case(int kind)
{
    dv_obj o; dv_attr a; IO_STATUS_BLOCK io; NTSTATUS s;
    DV_NEED(); if (!dv_make(&o, kind)) return;
    memset(&a, 0xcc, sizeof a); memset(&io, 0xcc, sizeof io);
    s = VOLQ(o.h, 5, &a, sizeof a);
    if (kind == K_FILE || kind == K_DIR) {
        EXPECT_EQ(s, 0);
        if (DOK(s)) { EXPECT_EQ(io.Information, 12 + a.namelen); EXPECT_EQ(a.namelen, 8); EXPECT_EQ(a.maxcomp, 255);
            CHECK(!memcmp(a.name, L"NTFS", 8)); CHECK(a.attrs & 0x2 /* FILE_CASE_PRESERVED_NAMES */); }
    } else if (kind == K_ANON_READ || kind == K_ANON_WRITE || kind == K_PIPE_SERVER || kind == K_PIPE_CLIENT) {
        EXPECT_EQ(s, 0);
        if (DOK(s)) { EXPECT_EQ(io.Information, 20); EXPECT_EQ(a.attrs, 0x2); EXPECT_EQ(a.maxcomp, 0xFFFFFFFF);
            EXPECT_EQ(a.namelen, 8); CHECK(!memcmp(a.name, L"NPFS", 8)); }
    } else if (kind == K_MAILSLOT) {
        EXPECT_EQ(s, DS(0xC000000D));                                 /* STATUS_INVALID_PARAMETER */
    } else {
        EXPECT_EQ(s, DS(DV_INVALID_DEVICE_REQUEST));                  /* console and NUL have no file system */
    }
    dv_close(&o);
}
#define ATTR(n, k) TEST(nt_file_devtype_attribute_##n) { attribute_case(k); }
ATTR(file, K_FILE) ATTR(directory, K_DIR) ATTR(anonymous_pipe_read, K_ANON_READ) ATTR(anonymous_pipe_write, K_ANON_WRITE)
ATTR(named_pipe_server, K_PIPE_SERVER) ATTR(named_pipe_client, K_PIPE_CLIENT) ATTR(mailslot, K_MAILSLOT)
ATTR(console_output, K_CONSOLE_OUT) ATTR(console_input, K_CONSOLE_IN) ATTR(nul, K_NUL)

TEST(nt_file_devtype_attribute_pipe_short_buffer)
{
    dv_obj o; dv_attr a; IO_STATUS_BLOCK io; NTSTATUS s;
    DV_NEED(); if (!dv_make(&o, K_ANON_READ)) return;
    memset(&a, 0xcc, sizeof a);
    EXPECT_EQ(VOLQ(o.h, 5, &a, 11), DS(0xC0000004));                  /* shorter than the fixed part */
    memset(&a, 0xcc, sizeof a); memset(&io, 0xcc, sizeof io);
    s = VOLQ(o.h, 5, &a, 16);                                         /* name cut after 4 bytes */
    EXPECT_EQ(s, DS(0x80000005));                                     /* STATUS_BUFFER_OVERFLOW */
    if (s == DS(0x80000005)) { EXPECT_EQ(io.Information, 16); EXPECT_EQ(a.namelen, 8); EXPECT_EQ(a.maxcomp, 0xFFFFFFFF); CHECK(!memcmp(a.name, L"NP", 4)); }
    dv_close(&o);
}

/* ---- FileFsVolumeInformation (1) and FileFsSizeInformation (3) ------------------- */
static void volume_case(int kind)
{
    dv_obj o; dv_volume v; dv_size z; IO_STATUS_BLOCK io; NTSTATUS s;
    DV_NEED(); if (!dv_make(&o, kind)) return;
    memset(&v, 0xcc, sizeof v); memset(&io, 0xcc, sizeof io);
    s = VOLQ(o.h, 1, &v, sizeof v);
    if (kind == K_FILE || kind == K_DIR) { EXPECT_EQ(s, 0); CHECK(io.Information > 18); }
    else if (kind == K_MAILSLOT) EXPECT_EQ(s, DS(0xC000000D));
    else if (kind == K_CONSOLE_OUT || kind == K_CONSOLE_IN || kind == K_NUL) EXPECT_EQ(s, DS(DV_INVALID_DEVICE_REQUEST));
    else {
        EXPECT_EQ(s, 0);
        if (DOK(s)) { EXPECT_EQ(io.Information, 36); EXPECT_EQ(v.labellen, 18); EXPECT_EQ(v.serial, 0); EXPECT_EQ(v.objects, 0); }
    }
    memset(&z, 0xcc, sizeof z); memset(&io, 0xcc, sizeof io);
    s = VOLQ(o.h, 3, &z, sizeof z);
    if (kind == K_FILE || kind == K_DIR) { EXPECT_EQ(s, 0); EXPECT_EQ(io.Information, 24); CHECK(z.spau >= 1 && z.bps >= 512); }
    else if (kind == K_MAILSLOT) EXPECT_EQ(s, DS(0xC000000D));
    else if (kind == K_CONSOLE_OUT || kind == K_CONSOLE_IN || kind == K_NUL) EXPECT_EQ(s, DS(DV_INVALID_DEVICE_REQUEST));
    else {
        EXPECT_EQ(s, 0);
        if (DOK(s)) { EXPECT_EQ(io.Information, 24); EXPECT_EQ(z.total.QuadPart, 0); EXPECT_EQ(z.avail.QuadPart, 0); EXPECT_EQ(z.spau, 1); EXPECT_EQ(z.bps, 1); }
    }
    dv_close(&o);
}
#define VOLU(n, k) TEST(nt_file_devtype_volume_##n) { volume_case(k); }
VOLU(file, K_FILE) VOLU(anonymous_pipe_read, K_ANON_READ) VOLU(anonymous_pipe_write, K_ANON_WRITE)
VOLU(named_pipe_server, K_PIPE_SERVER) VOLU(named_pipe_client, K_PIPE_CLIENT) VOLU(mailslot, K_MAILSLOT)
VOLU(console_output, K_CONSOLE_OUT) VOLU(console_input, K_CONSOLE_IN) VOLU(nul, K_NUL)

TEST(nt_file_devtype_full_size_console_nul)
{
    int kinds[] = { K_CONSOLE_OUT, K_NUL }; dv_obj o; struct { LARGE_INTEGER a, b, c; ULONG spau, bps; } fs; IO_STATUS_BLOCK io;
    DV_NEED();
    for (int i = 0; i < 2; i++) {
        if (!dv_make(&o, kinds[i])) continue;
        EXPECT_EQ(VOLQ(o.h, 7, &fs, sizeof fs), DS(DV_INVALID_DEVICE_REQUEST));
        dv_close(&o);
    }
}

/* ---- invalid and pseudo handles ---------------------------------------------------- */
TEST(nt_file_devtype_invalid_handles)
{
    IO_STATUS_BLOCK io; BYTE buf[64]; HANDLE closed, w; ULONG classes[] = { 1, 3, 4, 5 };
    DV_NEED();
    if (!UIN("kernel32.dll", CreatePipe)(&closed, &w, NULL, 0)) { t_skip("CreatePipe"); return; }
    CloseHandle(w); CloseHandle(closed);
    for (int i = 0; i < 4; i++) {
        ULONG c = classes[i];
        EXPECT_EQ(VOLQ(NULL, c, buf, sizeof buf), DS(DV_INVALID_HANDLE));
        EXPECT_EQ(VOLQ((HANDLE)(ULONG_PTR)0x1234, c, buf, sizeof buf), DS(DV_INVALID_HANDLE));
        EXPECT_EQ(VOLQ(closed, c, buf, sizeof buf), DS(DV_INVALID_HANDLE));
        EXPECT_EQ(VOLQ((HANDLE)(LONG_PTR)-1, c, buf, sizeof buf), DS(DV_OBJECT_TYPE_MISMATCH));   /* current process */
        EXPECT_EQ(VOLQ((HANDLE)(LONG_PTR)-2, c, buf, sizeof buf), DS(DV_OBJECT_TYPE_MISMATCH));   /* current thread */
    }
}
TEST(nt_file_devtype_non_file_object_handle)
{
    IO_STATUS_BLOCK io; BYTE buf[64]; HANDLE ev;
    DV_NEED(); REQUIRE(UIN("kernel32.dll", CreateEventA));
    ev = UIN("kernel32.dll", CreateEventA)(NULL, TRUE, FALSE, NULL);
    CHECK(ev != NULL);
    if (ev) { EXPECT_EQ(VOLQ(ev, 4, buf, 8), DS(DV_OBJECT_TYPE_MISMATCH)); EXPECT_EQ(VOLQ(ev, 5, buf, sizeof buf), DS(DV_OBJECT_TYPE_MISMATCH)); CloseHandle(ev); }
}

/* ---- NtQueryInformationFile on pipes, NUL and console ------------------------------ */
TEST(nt_file_devtype_info_pipe)
{
    dv_obj o; IO_STATUS_BLOCK io; ULONG attrs[10]; dv_standard st; LARGE_INTEGER pos; NTSTATUS s;
    DV_NEED(); if (!dv_make(&o, K_ANON_READ)) return;
    memset(attrs, 0xcc, sizeof attrs);
    s = INFQ(o.h, 4, attrs, 40);
    EXPECT_EQ(s, 0); if (DOK(s)) { EXPECT_EQ(io.Information, 40); EXPECT_EQ(attrs[8], 0x80); }   /* FILE_BASIC_INFORMATION.FileAttributes */
    memset(&st, 0xcc, sizeof st);
    s = INFQ(o.h, 5, &st, sizeof st);
    EXPECT_EQ(s, 0);
    if (DOK(s)) { EXPECT_EQ(io.Information, 24); EXPECT_EQ(st.alloc.QuadPart, 8192); EXPECT_EQ(st.eof.QuadPart, 0); EXPECT_EQ(st.links, 1); EXPECT_EQ(st.deleting, 1); EXPECT_EQ(st.directory, 0); }
    s = INFQ(o.h, 14, &pos, sizeof pos);
    EXPECT_EQ(s, 0); if (DOK(s)) { EXPECT_EQ(io.Information, 8); EXPECT_EQ(pos.QuadPart, 0); }
    dv_close(&o);
}
TEST(nt_file_devtype_info_nul)
{
    dv_obj o; IO_STATUS_BLOCK io; ULONG buf[16]; dv_standard st; LARGE_INTEGER pos; NTSTATUS s;
    DV_NEED(); if (!dv_make(&o, K_NUL)) return;
    EXPECT_EQ(INFQ(o.h, 4, buf, 40), DS(DV_INVALID_INFO_CLASS));
    EXPECT_EQ(INFQ(o.h, 9, buf, sizeof buf), DS(DV_INVALID_INFO_CLASS));
    memset(&st, 0xcc, sizeof st);
    s = INFQ(o.h, 5, &st, sizeof st);
    EXPECT_EQ(s, 0);
    if (DOK(s)) { EXPECT_EQ(io.Information, 24); EXPECT_EQ(st.alloc.QuadPart, 0); EXPECT_EQ(st.eof.QuadPart, 0); EXPECT_EQ(st.links, 1); EXPECT_EQ(st.deleting, 0); EXPECT_EQ(st.directory, 0); }
    s = INFQ(o.h, 14, &pos, sizeof pos);
    EXPECT_EQ(s, 0); if (DOK(s)) { EXPECT_EQ(io.Information, 8); EXPECT_EQ(pos.QuadPart, 0); }
    s = INFQ(o.h, 8, buf, 4);
    EXPECT_EQ(s, 0); if (DOK(s)) { EXPECT_EQ(io.Information, 4); CHECK(buf[0] & FILE_READ_DATA); CHECK(buf[0] & FILE_WRITE_DATA); }
    s = INFQ(o.h, 16, buf, 4);
    EXPECT_EQ(s, 0); if (DOK(s)) { EXPECT_EQ(io.Information, 4); EXPECT_EQ(buf[0], 0x20); }   /* FILE_SYNCHRONOUS_IO_NONALERT */
    dv_close(&o);
}
TEST(nt_file_devtype_info_console)
{
    int kinds[] = { K_CONSOLE_OUT, K_CONSOLE_IN }; dv_obj o; IO_STATUS_BLOCK io; ULONG buf[16]; dv_standard st; LARGE_INTEGER pos; NTSTATUS s;
    DV_NEED();
    for (int i = 0; i < 2; i++) {
        if (!dv_make(&o, kinds[i])) continue;
        EXPECT_EQ(INFQ(o.h, 4, buf, 40), DS(DV_INVALID_DEVICE_REQUEST));
        EXPECT_EQ(INFQ(o.h, 5, &st, sizeof st), DS(DV_INVALID_DEVICE_REQUEST));
        EXPECT_EQ(INFQ(o.h, 9, buf, sizeof buf), DS(DV_INVALID_DEVICE_REQUEST));
        s = INFQ(o.h, 14, &pos, sizeof pos);
        EXPECT_EQ(s, 0); if (DOK(s)) EXPECT_EQ(pos.QuadPart, 0);
        s = INFQ(o.h, 16, buf, 4);
        EXPECT_EQ(s, 0); if (DOK(s)) EXPECT_EQ(buf[0], 0x20);
        dv_close(&o);
    }
}

/* ---- opening the NUL device through NtCreateFile ------------------------------------ */
static void nul_open(const WCHAR *name, ACCESS_MASK access, ULONG disp, ULONG opts)
{
    HANDLE h; ULONG_PTR info = 0xcc; NTSTATUS s; IO_STATUS_BLOCK io; dv_device d; BYTE buf[8]; LARGE_INTEGER pos;
    DV_NEED(); REQUIRE(UN(NtReadFile)); REQUIRE(UN(NtWriteFile));
    s = dv_nt_open(&h, name, access, disp, opts, &info);
    EXPECT_EQ(s, 0);
    if (!DOK(s)) return;
    EXPECT_EQ(info, 0);                                               /* neither FILE_OPENED nor FILE_CREATED */
    EXPECT_EQ(VOLQ(h, 4, &d, sizeof d), 0);
    EXPECT_EQ(d.type, 0x15); EXPECT_EQ(d.chars, 0x100);
    if ((opts & 0x20) && (access & FILE_READ_DATA)) {
        memset(buf, 0xcc, sizeof buf); memset(&io, 0xcc, sizeof io);
        s = UN(NtReadFile)(h, NULL, NULL, NULL, &io, buf, sizeof buf, NULL, NULL);
        EXPECT_EQ(s, DS(0xC0000011));                                 /* STATUS_END_OF_FILE */
        EXPECT_EQ(io.Information, 0); EXPECT_EQ(buf[0], 0xcc);
    }
    if ((opts & 0x20) && (access & FILE_WRITE_DATA)) {
        pos.QuadPart = 0; memset(&io, 0xcc, sizeof io);
        s = UN(NtWriteFile)(h, NULL, NULL, NULL, &io, (PVOID)"abc", 3, &pos, NULL);
        EXPECT_EQ(s, 0); EXPECT_EQ(io.Information, 3);
        memset(&io, 0xcc, sizeof io);
        s = UN(NtWriteFile)(h, NULL, NULL, NULL, &io, (PVOID)"abc", 3, NULL, NULL);
        EXPECT_EQ(s, 0); EXPECT_EQ(io.Information, 3);
    }
    EXPECT_EQ(UN(NtClose)(h), 0);
}
#define NULOPEN(n, name, acc, disp, opts) TEST(nt_file_nul_open_##n) { nul_open(name, acc, disp, opts); }
#define RW (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE)
NULOPEN(dos_name, L"\\??\\NUL", RW, FILE_OPEN, 0x20)
NULOPEN(dos_name_lower, L"\\??\\nul", RW, FILE_OPEN, 0x20)
NULOPEN(dos_name_mixed, L"\\??\\NuL", RW, FILE_OPEN, 0x20)
NULOPEN(device_name, L"\\Device\\Null", RW, FILE_OPEN, 0x20)
NULOPEN(access_win32_rw, L"\\??\\NUL", 0xc0100080, FILE_OPEN, 0x20)           /* GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE|FILE_READ_ATTRIBUTES */
NULOPEN(access_read, L"\\??\\NUL", 0x100003, FILE_OPEN, 0x20)                 /* SYNCHRONIZE|FILE_READ_DATA|FILE_WRITE_DATA */
NULOPEN(access_data, L"\\??\\NUL", 0x120089, FILE_OPEN, 0x20)                 /* FILE_GENERIC_READ */
NULOPEN(generic_read, L"\\??\\NUL", GENERIC_READ | SYNCHRONIZE, FILE_OPEN, 0x20)
NULOPEN(generic_write, L"\\??\\NUL", GENERIC_WRITE | SYNCHRONIZE, FILE_OPEN, 0x20)
NULOPEN(options_non_directory, L"\\??\\NUL", RW, FILE_OPEN, 0x60)
NULOPEN(open_if, L"\\??\\NUL", RW, FILE_OPEN_IF, 0x20)
NULOPEN(overwrite_if, L"\\??\\NUL", RW, FILE_OVERWRITE_IF, 0x20)

TEST(nt_file_nul_open_asynchronous)
{
    HANDLE h; ULONG_PTR info = 0xcc; NTSTATUS s; IO_STATUS_BLOCK io; dv_device d; ULONG mode = 0xcc;
    DV_NEED();
    s = dv_nt_open(&h, L"\\??\\NUL", GENERIC_READ | GENERIC_WRITE, FILE_OPEN, 0, &info);   /* no FILE_SYNCHRONOUS_IO_*: overlapped */
    EXPECT_EQ(s, 0);
    if (!DOK(s)) return;
    EXPECT_EQ(info, 0);
    EXPECT_EQ(VOLQ(h, 4, &d, sizeof d), 0); EXPECT_EQ(d.type, 0x15); EXPECT_EQ(d.chars, 0x100);
    EXPECT_EQ(INFQ(h, 16, &mode, sizeof mode), 0); EXPECT_EQ(mode, 0);
    UN(NtClose)(h);
}
TEST(nt_file_nul_open_win32)
{
    HANDLE h; DWORD n = 0xcc; char buf[4]; DWORD t, gle;
    DV_NEED();
    h = UIN("kernel32.dll", CreateFileA)("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) return;
    EXPECT_EQ(GetFileType(h), FILE_TYPE_CHAR);
    CHECK(ReadFile(h, buf, sizeof buf, &n, NULL)); EXPECT_EQ(n, 0);
    n = 0xcc; CHECK(WriteFile(h, "abcd", 4, &n, NULL)); EXPECT_EQ(n, 4);
    SetLastError(0); t = GetConsoleMode(h, &n); gle = GetLastError(); EXPECT_EQ(t, 0); EXPECT_EQ(gle, ERROR_INVALID_HANDLE);
    CloseHandle(h);
}
/* \??\<scratch dir>\nul built by hand: RtlDosPathNameToNtPathName_U maps a final "nul" component to the device. */
static void dv_scratch_nul_path(WCHAR *out)
{
    WCHAR dir[MAX_PATH];
    UIN("kernel32.dll", MultiByteToWideChar)(CP_ACP, 0, t_tmpdir(), -1, dir, MAX_PATH);
    wcscpy(out, L"\\??\\"); wcscat(out, dir); wcscat(out, L"nul");
}
TEST(nt_file_nul_open_other_names_not_device)
{
    HANDLE h; NTSTATUS s; WCHAR nt[MAX_PATH + 16]; ULONG_PTR info;
    DV_NEED();
    /* a name under a real directory is an ordinary file name at this layer */
    dv_scratch_nul_path(nt);
    s = dv_nt_open(&h, nt, GENERIC_READ | SYNCHRONIZE, FILE_OPEN, 0x20, &info);
    EXPECT_EQ(s, DS(0xC0000034));                                     /* STATUS_OBJECT_NAME_NOT_FOUND */
    if (DOK(s)) UN(NtClose)(h);
    /* the device name with a suffix is not the device */
    s = dv_nt_open(&h, L"\\??\\NUL.txt", GENERIC_READ | SYNCHRONIZE, FILE_OPEN, 0x20, &info);
    CHECK(!DOK(s)); if (DOK(s)) UN(NtClose)(h);
    /* NUL with a trailing component: the null device ignores the remainder, so this opens it (observation, not a contract) */
    s = dv_nt_open(&h, L"\\??\\NUL\\x", GENERIC_READ | SYNCHRONIZE, FILE_OPEN, 0x20, &info);
    t_note("\\??\\NUL\\x open status=%08lx", s);
    if (DOK(s)) UN(NtClose)(h);
}
TEST(nt_file_nul_created_file_is_disk_file)
{
    HANDLE h; NTSTATUS s; WCHAR nt[MAX_PATH + 16]; ULONG_PTR info = 0xcc; dv_device d; IO_STATUS_BLOCK io;
    DV_NEED();
    dv_scratch_nul_path(nt);
    /* FILE_CREATE of <dir>\nul at the NT layer makes a disk file (DELETE_ON_CLOSE keeps the scratch tree clean) */
    s = dv_nt_open(&h, nt, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, FILE_CREATE, 0x1060, &info);
    if (!DOK(s)) { t_skip("create of <dir>\\nul status %08lx", s); return; }
    EXPECT_EQ(info, FILE_CREATED);
    EXPECT_EQ(VOLQ(h, 4, &d, sizeof d), 0); EXPECT_EQ(d.type, 0x07); EXPECT_EQ(d.chars, 0x20020);
    UN(NtClose)(h);
}

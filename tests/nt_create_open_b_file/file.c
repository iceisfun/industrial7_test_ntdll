/* ZwCreateFile / ZwOpenFile dispositions and option validation, plus mailslot and named pipe creation. */
#include "cob.h"

UDECL(NTSTATUS, ZwCreateFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, ZwOpenFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG));
UDECL(NTSTATUS, ZwCreateMailslotFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwCreateNamedPipeFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PLARGE_INTEGER));
UDECL(NTSTATUS, NtQueryInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, NtWriteFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtReadFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));

#define F_SUPERSEDE 0
#define F_OPEN 1
#define F_CREATE 2
#define F_OPEN_IF 3
#define F_OVERWRITE 4
#define F_OVERWRITE_IF 5
/* IoStatus.Information values */
#define I_SUPERSEDED 0
#define I_OPENED 1
#define I_CREATED 2
#define I_OVERWRITTEN 3
#define I_EXISTS 4
#define I_DOESNOTEXIST 5
#define O_DIRFILE 0x1
#define O_SYNC 0x20
#define O_NONDIR 0x40
#define O_DELCLOSE 0x1000
#define FILE_SYNC_FLAGS (O_SYNC)
#define S_NOTADIR ((NTSTATUS)0xC0000103)
#define S_SHARING ((NTSTATUS)0xC0000043)
#define S_INSTANCE ((NTSTATUS)0xC00000AB)
#define S_PIPEBUSY ((NTSTATUS)0xC00000AE)
#define NEED2() do { REQUIRE(UN(ZwCreateFile)); REQUIRE(UN(ZwOpenFile)); REQUIRE(UN(NtClose)); } while (0)

/* Builds "\??\<tmpdir><leaf>" */
static void nt_path(WCHAR *out, size_t cap, const char *leaf)
{
    char p[300]; size_t k = 0, i; t_tmpfile(p, sizeof p, leaf);
    out[k++] = '\\'; out[k++] = '?'; out[k++] = '?'; out[k++] = '\\';
    for (i = 0; p[i] && k + 1 < cap; i++) out[k++] = (WCHAR)(unsigned char)p[i];
    out[k] = 0;
}
static NTSTATUS cf(const WCHAR *path, ACCESS_MASK acc, ULONG attrs, ULONG share, ULONG disp, ULONG opts, HANDLE *h, ULONG_PTR *info)
{
    UNICODE_STRING u; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; NTSTATUS s; HANDLE tmp = NULL;
    cob_us(&u, path); cob_oa(&oa, &u, 0x40 /* OBJ_CASE_INSENSITIVE */, NULL);
    memset(&iosb, 0x55, sizeof iosb);
    s = UN(ZwCreateFile)(&tmp, acc, &oa, &iosb, NULL, attrs, share, disp, opts, NULL, 0);
    if (h) *h = tmp; else cob_close(tmp);
    if (info) *info = iosb.Information;
    return s;
}

TEST(nt_create_open_b_createfile_dispositions)
{
    WCHAR p[400]; HANDLE h = NULL; ULONG_PTR info; NTSTATUS s; ACCESS_MASK rw = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE;
    NEED2(); COB_ALIAS("CreateFile"); COB_ALIAS("OpenFile");
    nt_path(p, 400, "cob_disp.dat");
    /* missing file */
    s = cf(p, rw, 0, 3, F_OPEN, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_NOTFOUND); EXPECT_EQ(h, NULL);
    s = cf(p, rw, 0, 3, F_OVERWRITE, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_NOTFOUND);
    /* create */
    s = cf(p, rw, 0x80, 3, F_CREATE, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_OK_); EXPECT_EQ(info, I_CREATED);
    if (!h) return;
    { DWORD wr; CHECK(WriteFile(h, "0123456789", 10, &wr, NULL) && wr == 10); }
    cob_close(h); h = NULL;
    s = cf(p, rw, 0x80, 3, F_CREATE, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_COLLIDE); EXPECT_EQ(h, NULL);
    /* open */
    s = cf(p, rw, 0, 3, F_OPEN, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_OK_); EXPECT_EQ(info, I_OPENED);
    { LARGE_INTEGER sz = {{0}}; if (h) { sz.LowPart = GetFileSize(h, (DWORD *)&sz.HighPart); EXPECT_EQ(sz.LowPart, 10); } }
    cob_close(h); h = NULL;
    s = cf(p, rw, 0, 3, F_OPEN_IF, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_OK_); EXPECT_EQ(info, I_OPENED); cob_close(h); h = NULL;
    /* overwrite keeps the file, truncates it */
    s = cf(p, rw, 0, 3, F_OVERWRITE, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_OK_); EXPECT_EQ(info, I_OVERWRITTEN);
    if (h) { EXPECT_EQ(GetFileSize(h, NULL), 0); { DWORD wr; WriteFile(h, "abc", 3, &wr, NULL); } } cob_close(h); h = NULL;
    s = cf(p, rw, 0, 3, F_OVERWRITE_IF, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_OK_); EXPECT_EQ(info, I_OVERWRITTEN);
    if (h) { EXPECT_EQ(GetFileSize(h, NULL), 0); } cob_close(h); h = NULL;
    s = cf(p, rw, 0, 3, F_SUPERSEDE, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_OK_); EXPECT_EQ(info, I_SUPERSEDED); cob_close(h); h = NULL;
    /* invalid disposition */
    s = cf(p, rw, 0, 3, 6, O_SYNC, &h, &info); EXPECT_EQ(s, S_INVPARAM);
    s = cf(p, rw, 0, 3, 0xffffffff, O_SYNC, &h, &info); EXPECT_EQ(s, S_INVPARAM);
    /* invalid share flags */
    s = cf(p, rw, 0, 0x8, F_OPEN, O_SYNC, &h, &info); EXPECT_EQ(s, S_INVPARAM);
    /* directory and non-directory flags together */
    s = cf(p, rw, 0, 3, F_OPEN, O_DIRFILE | O_NONDIR | O_SYNC, &h, &info); EXPECT_EQ(s, S_INVPARAM);
    /* a regular file opened as directory */
    s = cf(p, rw, 0, 3, F_OPEN, O_DIRFILE | O_SYNC, &h, &info); EXPECT_EQ(s, S_NOTADIR);
    /* missing parent directory */
    { WCHAR q[500]; lstrcpyW(q, p); lstrcatW(q, L"_nodir\\child"); s = cf(q, rw, 0, 3, F_CREATE, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_PATHNF); }
    /* delete on close */
    s = cf(p, DELETE | GENERIC_READ | SYNCHRONIZE, 0, 3, F_OPEN, O_SYNC | O_DELCLOSE | O_NONDIR, &h, &info); EXPECT_EQ(s, S_OK_); cob_close(h); h = NULL;
    s = cf(p, rw, 0, 3, F_OPEN, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_NOTFOUND);
}

TEST(nt_create_open_b_createfile_sharing_and_dirs)
{
    WCHAR p[400], d[400]; HANDLE h = NULL, h2 = NULL; ULONG_PTR info; NTSTATUS s; ACCESS_MASK rw = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE;
    NEED2();
    nt_path(p, 400, "cob_share.dat");
    s = cf(p, rw, 0x80, 0, F_CREATE, O_SYNC | O_NONDIR, &h, &info); EXPECT_EQ(s, S_OK_); if (!h) return;
    s = cf(p, GENERIC_READ | SYNCHRONIZE, 0, 7, F_OPEN, O_SYNC, &h2, &info); EXPECT_EQ(s, S_SHARING); EXPECT_EQ(h2, NULL);
    s = cf(p, SYNCHRONIZE | FILE_READ_ATTRIBUTES, 0, 7, F_OPEN, O_SYNC, &h2, &info); EXPECT_EQ(s, S_OK_); cob_close(h2); h2 = NULL; /* attribute-only open ignores sharing */
    cob_close(h);
    s = cf(p, DELETE | SYNCHRONIZE, 0, 7, F_OPEN, O_SYNC | O_DELCLOSE, &h, &info); EXPECT_EQ(s, S_OK_); cob_close(h); h = NULL;
    /* directory create / open */
    nt_path(d, 400, "cob_dir");
    s = cf(d, rw, FILE_ATTRIBUTE_DIRECTORY, 7, F_CREATE, O_DIRFILE | O_SYNC, &h, &info); EXPECT_EQ(s, S_OK_); EXPECT_EQ(info, I_CREATED);
    if (h) {
        BY_HANDLE_FILE_INFORMATION bi; memset(&bi, 0, sizeof bi);
        CHECK(GetFileInformationByHandle(h, &bi)); CHECK(bi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        cob_close(h); h = NULL;
        s = cf(d, rw, 0, 7, F_OPEN, O_NONDIR | O_SYNC, &h, &info); EXPECT_EQ(s, S_ISDIR); EXPECT_EQ(h, NULL);
        s = cf(d, rw, 0, 7, F_OPEN, O_DIRFILE | O_SYNC, &h, &info); EXPECT_EQ(s, S_OK_); EXPECT_EQ(info, I_OPENED); cob_close(h); h = NULL;
        /* ZwOpenFile relative to the directory handle */
        { UNICODE_STRING u; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; HANDLE dh = NULL, fh = NULL; WCHAR *leaf = L"inner.txt";
          s = cf(d, FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE | GENERIC_WRITE, 0, 7, F_OPEN, O_DIRFILE | O_SYNC, &dh, &info); EXPECT_EQ(s, S_OK_);
          if (dh) {
            cob_us(&u, leaf); cob_oa(&oa, &u, 0x40, dh);
            memset(&iosb, 0x55, sizeof iosb);
            EXPECT_EQ(UN(ZwOpenFile)(&fh, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 7, O_SYNC), S_NOTFOUND);
            memset(&iosb, 0x55, sizeof iosb);
            s = UN(ZwCreateFile)(&fh, GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, NULL, 0x80, 7, F_CREATE, O_SYNC | O_NONDIR, NULL, 0);
            EXPECT_EQ(s, S_OK_); EXPECT_EQ(iosb.Information, I_CREATED); cob_close(fh); fh = NULL;
            memset(&iosb, 0x55, sizeof iosb);
            EXPECT_EQ(UN(ZwOpenFile)(&fh, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 7, O_SYNC | O_NONDIR), S_OK_); EXPECT_EQ(iosb.Information, I_OPENED); cob_close(fh); fh = NULL;
            s = UN(ZwCreateFile)(&fh, DELETE | SYNCHRONIZE, &oa, &iosb, NULL, 0, 7, F_OPEN, O_SYNC | O_DELCLOSE, NULL, 0); EXPECT_EQ(s, S_OK_); cob_close(fh);
            cob_close(dh);
          } }
        s = cf(d, DELETE | SYNCHRONIZE, 0, 7, F_OPEN, O_DIRFILE | O_SYNC | O_DELCLOSE, &h, &info); EXPECT_EQ(s, S_OK_); cob_close(h);
    }
}

TEST(nt_create_open_b_openfile_errors)
{
    HANDLE h = (HANDLE)0x1234; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; WCHAR p[400];
    NEED2(); nt_path(p, 400, "cob_openfile_none.dat"); cob_us(&u, p); cob_oa(&oa, &u, 0x40, NULL);
    memset(&iosb, 0x55, sizeof iosb);
    EXPECT_EQ(UN(ZwOpenFile)(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 7, O_SYNC), S_NOTFOUND);
    EXPECT_EQ(UN(ZwOpenFile)(&h, GENERIC_READ | SYNCHRONIZE, NULL, &iosb, 7, O_SYNC), S_INVPARAM);
    EXPECT_EQ(UN(ZwOpenFile)(&h, GENERIC_READ | SYNCHRONIZE, &oa, NULL, 7, O_SYNC), S_AV);
    EXPECT_EQ(UN(ZwOpenFile)(NULL, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 7, O_SYNC), S_AV);
    EXPECT_EQ(UN(ZwOpenFile)(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 0x10, O_SYNC), S_INVPARAM);
    EXPECT_EQ(UN(ZwOpenFile)(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 7, 0xff000000), S_INVPARAM);
    cob_oa(&oa, NULL, 0, NULL); EXPECT_EQ(UN(ZwOpenFile)(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 7, O_SYNC), S_PATHSYN);
    /* device open without a trailing name */
    { UNICODE_STRING nu; OBJECT_ATTRIBUTES noa; HANDLE nh = NULL; cob_us(&nu, L"\\Device\\Null"); cob_oa(&noa, &nu, 0x40, NULL); memset(&iosb, 0x55, sizeof iosb);
      EXPECT_EQ(UN(ZwOpenFile)(&nh, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &noa, &iosb, 3, O_SYNC), S_OK_); cob_close(nh); }
}

TEST(nt_create_open_b_mailslot)
{
    HANDLE ms = NULL, cl; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; NTSTATUS s; WCHAR nt[200]; char win[200]; LARGE_INTEGER to; DWORD n, rd; char buf[64]; static LONG ctr;
    NEED2(); REQUIRE(UN(ZwCreateMailslotFile));
    COB_ALIAS("CreateMailslotFile");
    wsprintfW(nt, L"\\Device\\Mailslot\\cob_%lu_%ld", (unsigned long)GetCurrentProcessId(), InterlockedIncrement(&ctr));
    wsprintfA(win, "\\\\.\\mailslot\\cob_%lu_%ld", (unsigned long)GetCurrentProcessId(), ctr);
    cob_us(&u, nt); cob_oa(&oa, &u, 0x40, NULL); to.QuadPart = 0;
    memset(&iosb, 0x55, sizeof iosb);
    s = UN(ZwCreateMailslotFile)(&ms, GENERIC_READ | SYNCHRONIZE | WRITE_DAC, &oa, &iosb, O_SYNC, 0, 0x100, &to);
    EXPECT_EQ(s, S_OK_); EXPECT_EQ(iosb.Information, I_CREATED); if (!ms) return;
    { WCHAR tn[40]; CHECK(cob_typename(ms, tn, 40)); EXPECT_WSTR(tn, L"File"); }
    /* a writer can send a message and the server reads it back */
    cl = CreateFileA(win, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(cl != INVALID_HANDLE_VALUE);
    if (cl != INVALID_HANDLE_VALUE) {
        CHECK(WriteFile(cl, "hello", 5, &n, NULL) && n == 5);
        { DWORD next = 0, cnt = 0, mt = 0; CHECK(GetMailslotInfo(ms, &mt, &next, &cnt, NULL)); EXPECT_EQ(mt, 0x100); EXPECT_EQ(next, 5); EXPECT_EQ(cnt, 1); }
        memset(buf, 0, sizeof buf); CHECK(ReadFile(ms, buf, sizeof buf, &rd, NULL)); EXPECT_EQ(rd, 5); CHECK(!memcmp(buf, "hello", 5));
        /* message larger than the maximum is refused at write time */
        { char big[0x200]; memset(big, 'x', sizeof big); SET_ERR(0); CHECK(!WriteFile(cl, big, sizeof big, &n, NULL)); }
        CloseHandle(cl);
    }
    /* same name again */
    { HANDLE ms2 = (HANDLE)0x1234; s = UN(ZwCreateMailslotFile)(&ms2, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, O_SYNC, 0, 0x100, &to); EXPECT_EQ(s, S_COLLIDE); }
    cob_close(ms);
    /* validation */
    { HANDLE m = (HANDLE)0x1234;
      s = UN(ZwCreateMailslotFile)(&m, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, O_SYNC, 0, 0x100, NULL); EXPECT_EQ(s, S_OK_); cob_close(m);
      EXPECT_EQ(UN(ZwCreateMailslotFile)(NULL, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, O_SYNC, 0, 0x100, &to), S_AV);
      EXPECT_EQ(UN(ZwCreateMailslotFile)(&m, GENERIC_READ | SYNCHRONIZE, NULL, &iosb, O_SYNC, 0, 0x100, &to), S_INVPARAM);
      EXPECT_EQ(UN(ZwCreateMailslotFile)(&m, GENERIC_READ | SYNCHRONIZE, &oa, NULL, O_SYNC, 0, 0x100, &to), S_AV);
      /* a device name that is not the mailslot filesystem */
      { UNICODE_STRING bu; OBJECT_ATTRIBUTES boa; cob_us(&bu, L"\\Device\\NamedPipe\\cob_ms_wrongfs"); cob_oa(&boa, &bu, 0x40, NULL);
        s = UN(ZwCreateMailslotFile)(&m, GENERIC_READ | SYNCHRONIZE, &boa, &iosb, O_SYNC, 0, 0x100, &to); CHECK(s < 0); cob_close(m); } }
}

TEST(nt_create_open_b_named_pipe)
{
    HANDLE srv = NULL, srv2 = NULL, cl; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; NTSTATUS s; WCHAR nt[200]; char win[200]; LARGE_INTEGER to; DWORD n; char buf[32]; static LONG ctr;
    NEED2(); REQUIRE(UN(ZwCreateNamedPipeFile));
    COB_ALIAS("CreateNamedPipeFile");
    wsprintfW(nt, L"\\Device\\NamedPipe\\cobp_%lu_%ld", (unsigned long)GetCurrentProcessId(), InterlockedIncrement(&ctr));
    wsprintfA(win, "\\\\.\\pipe\\cobp_%lu_%ld", (unsigned long)GetCurrentProcessId(), ctr);
    cob_us(&u, nt); cob_oa(&oa, &u, 0x40, NULL); to.QuadPart = -500000;
    memset(&iosb, 0x55, sizeof iosb);
    /* byte-mode duplex pipe, one instance */
    s = UN(ZwCreateNamedPipeFile)(&srv, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, 3, F_CREATE, O_SYNC, 0, 0, 0, 1, 0x1000, 0x1000, &to);
    EXPECT_EQ(s, S_OK_); EXPECT_EQ(iosb.Information, I_CREATED); if (!srv) return;
    { DWORD flags = 0, out = 0, in = 0, max = 0; CHECK(GetNamedPipeInfo(srv, &flags, &out, &in, &max)); EXPECT_EQ(max, 1); EXPECT_EQ(flags & PIPE_TYPE_MESSAGE, 0); EXPECT_EQ(flags & PIPE_SERVER_END, PIPE_SERVER_END); }
    /* second instance refused: MaximumInstances is 1 */
    memset(&iosb, 0x55, sizeof iosb);
    s = UN(ZwCreateNamedPipeFile)(&srv2, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, 3, F_OPEN_IF, O_SYNC, 0, 0, 0, 1, 0x1000, 0x1000, &to);
    EXPECT_EQ(s, S_INSTANCE); EXPECT_EQ(srv2, NULL);
    /* FILE_CREATE of an existing name: the instance limit is reported first */
    s = UN(ZwCreateNamedPipeFile)(&srv2, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, 3, F_CREATE, O_SYNC, 0, 0, 0, 1, 0x1000, 0x1000, &to);
    EXPECT_EQ(s, S_INSTANCE); cob_close(srv2); srv2 = NULL;
    /* client connects and exchanges data */
    cl = CreateFileA(win, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(cl != INVALID_HANDLE_VALUE);
    if (cl != INVALID_HANDLE_VALUE) {
        CHECK(WriteFile(cl, "ping", 4, &n, NULL) && n == 4);
        memset(buf, 0, sizeof buf); CHECK(ReadFile(srv, buf, 4, &n, NULL) && n == 4); CHECK(!memcmp(buf, "ping", 4));
        CHECK(WriteFile(srv, "pong", 4, &n, NULL) && n == 4);
        memset(buf, 0, sizeof buf); CHECK(ReadFile(cl, buf, 4, &n, NULL) && n == 4); CHECK(!memcmp(buf, "pong", 4));
        CloseHandle(cl);
    }
    cob_close(srv);
    /* two instances allowed; open of an unknown pipe fails */
    cob_close(srv); srv = NULL;
    s = UN(ZwCreateNamedPipeFile)(&srv, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, 3, F_OPEN_IF, O_SYNC, 1, 1, 0, 2, 0x1000, 0x1000, &to);
    EXPECT_EQ(s, S_OK_); EXPECT_EQ(iosb.Information, I_CREATED);
    s = UN(ZwCreateNamedPipeFile)(&srv2, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, 3, F_OPEN_IF, O_SYNC, 1, 1, 0, 2, 0x1000, 0x1000, &to);
    EXPECT_EQ(s, S_OK_); EXPECT_EQ(iosb.Information, I_OPENED);
    if (srv) { DWORD flags = 0; CHECK(GetNamedPipeInfo(srv, &flags, NULL, NULL, NULL)); EXPECT_EQ(flags & PIPE_TYPE_MESSAGE, PIPE_TYPE_MESSAGE); }
    cob_close(srv2); cob_close(srv); srv = srv2 = NULL;
    s = UN(ZwCreateNamedPipeFile)(&srv, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 3, F_OPEN, O_SYNC, 0, 0, 0, 1, 0, 0, &to);
    EXPECT_EQ(s, S_NOTFOUND); cob_close(srv); srv = NULL;
    /* validation */
    s = UN(ZwCreateNamedPipeFile)(&srv, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 3, F_CREATE, O_SYNC, 0, 0, 0, 0, 0x1000, 0x1000, &to); EXPECT_EQ(s, S_INVPARAM); cob_close(srv); srv = NULL;
    s = UN(ZwCreateNamedPipeFile)(&srv, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 3, F_CREATE, O_SYNC, 2, 0, 0, 1, 0x1000, 0x1000, &to); t_note("pipe type 2 status 0x%08lx", (unsigned long)s); cob_close(srv); srv = NULL;
    s = UN(ZwCreateNamedPipeFile)(&srv, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 3, F_CREATE, O_SYNC, 0, 2, 0, 1, 0x1000, 0x1000, &to); EXPECT_EQ(s, S_INVPARAM);
    s = UN(ZwCreateNamedPipeFile)(&srv, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 3, F_CREATE, O_SYNC, 0, 0, 2, 1, 0x1000, 0x1000, &to); EXPECT_EQ(s, S_INVPARAM);
    s = UN(ZwCreateNamedPipeFile)(&srv, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 3, F_CREATE, O_SYNC, 0, 1, 0, 1, 0x1000, 0x1000, &to); EXPECT_EQ(s, S_INVPARAM);   /* message read mode needs message type */
    EXPECT_EQ(UN(ZwCreateNamedPipeFile)(NULL, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 3, F_CREATE, O_SYNC, 0, 0, 0, 1, 0, 0, &to), S_AV);
    EXPECT_EQ(UN(ZwCreateNamedPipeFile)(&srv, GENERIC_READ | SYNCHRONIZE, NULL, &iosb, 3, F_CREATE, O_SYNC, 0, 0, 0, 1, 0, 0, &to), S_INVPARAM);
    cob_close(srv);
}

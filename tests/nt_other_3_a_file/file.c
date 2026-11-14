/* File I/O services: NtReadFile, NtReadFileScatter, NtLockFile, NtFsControlFile,
 * NtNotifyChangeDirectoryFile(Ex). Throwaway files and a throwaway directory under the
 * process scratch directory only. */
#include "t.h"

UDECL(NTSTATUS, NtReadFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtReadFileScatter, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PFILE_SEGMENT_ELEMENT, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtLockFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG, BOOLEAN, BOOLEAN));
UDECL(NTSTATUS, NtUnlockFile, (HANDLE, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG));
UDECL(NTSTATUS, NtFsControlFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtNotifyChangeDirectoryFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtNotifyChangeDirectoryFileEx, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN, ULONG));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define XS(x) ((NTSTATUS)(x))
#define N(f) UN(f)
#define BADH ((HANDLE)(LONG_PTR)-77)
#define ST_PENDING 0x103

static HANDLE mkevent(void) { HANDLE h = NULL; if (N(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 1 /* NotificationEvent */, FALSE) < 0) return NULL; return h; }
static HANDLE mkfile(const char *leaf, DWORD access, DWORD flags, DWORD size)
{
    char p[MAX_PATH]; HANDLE h; DWORD i; BYTE buf[4096], *tmp;
    strcpy(p, t_tmpdir()); strcat(p, leaf);
    h = CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    for (i = 0; i < size; i += sizeof buf) { DWORD w, k; for (k = 0; k < sizeof buf; k++) buf[k] = (BYTE)((i + k) * 7 + (i + k) / 251); WriteFile(h, buf, (size - i < sizeof buf) ? size - i : sizeof buf, &w, NULL); }
    CloseHandle(h); (void)tmp;
    h = CreateFileA(p, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | flags, NULL);
    return h == INVALID_HANDLE_VALUE ? NULL : h;
}
static BYTE pat(DWORD o) { return (BYTE)(o * 7 + o / 251); }
static int pat_ok(const BYTE *b, DWORD base, DWORD n) { for (DWORD i = 0; i < n; i++) if (b[i] != pat(base + i)) return 0; return 1; }
#define NEED_RF() do { REQUIRE(N(NtReadFile)); REQUIRE(N(NtClose)); } while (0)

TEST(other3a_file_nt_zw_aliases)
{
    static const char *n[] = { "ReadFile", "ReadFileScatter", "LockFile", "FsControlFile", "NotifyChangeDirectoryFile", "NotifyChangeDirectoryFileEx" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64]; wsprintfA(a, "Nt%s", n[i]); wsprintfA(b, "Zw%s", n[i]);
        CHECKF(t_proc(a) != NULL && t_proc(a) == t_proc(b), "%s / %s", a, b);
    }
}

/* ---- NtReadFile ---------------------------------------------------------- */
TEST(other3a_readfile_sync_position_and_offset)
{
    HANDLE h; IO_STATUS_BLOCK io; BYTE buf[256]; LARGE_INTEGER off; NEED_RF();
    h = mkfile("rf1.bin", GENERIC_READ, 0, 10000); CHECK(h != NULL); if (!h) return;
    memset(&io, 0xcc, sizeof io); memset(buf, 0, sizeof buf);
    EXPECT_EQ(N(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 100, NULL, NULL), 0);   /* sync handle: current file position */
    EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 100); CHECK(pat_ok(buf, 0, 100));
    EXPECT_EQ(N(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 50, NULL, NULL), 0);
    EXPECT_EQ(io.Information, 50); CHECK(pat_ok(buf, 100, 50));                    /* position advanced */
    off.QuadPart = 5000;
    EXPECT_EQ(N(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 64, &off, NULL), 0);
    EXPECT_EQ(io.Information, 64); CHECK(pat_ok(buf, 5000, 64));
    EXPECT_EQ(N(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 8, NULL, NULL), 0);    /* explicit offset moves the position on sync handles */
    CHECK(pat_ok(buf, 5064, 8));
    /* FILE_USE_FILE_POINTER_POSITION is {0xfffffffe,-1} */
    off.HighPart = -1; off.LowPart = 0xfffffffe;
    EXPECT_EQ(N(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 8, &off, NULL), 0);
    CHECK(pat_ok(buf, 5072, 8));
    N(NtClose)(h);
}
TEST(other3a_readfile_eof_and_partial)
{
    HANDLE h; IO_STATUS_BLOCK io; BYTE buf[256]; LARGE_INTEGER off; NEED_RF();
    h = mkfile("rf2.bin", GENERIC_READ, 0, 1000); CHECK(h != NULL); if (!h) return;
    off.QuadPart = 900; memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(N(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 256, &off, NULL), 0);
    EXPECT_EQ(io.Information, 100); EXPECT_EQ(io.Status, 0); CHECK(pat_ok(buf, 900, 100));
    off.QuadPart = 1000; memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(N(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 16, &off, NULL), XS(0xC0000011));   /* STATUS_END_OF_FILE */
    EXPECT_EQ(io.Status, XS(0xC0000011)); EXPECT_EQ(io.Information, 0);
    off.QuadPart = 5000; memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(N(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 16, &off, NULL), XS(0xC0000011));
    off.QuadPart = 0; memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(N(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 0, &off, NULL), 0);                  /* zero length */
    EXPECT_EQ(io.Information, 0);
    N(NtClose)(h);
}
TEST(other3a_readfile_signals_event_and_runs_no_apc_on_sync)
{
    HANDLE h, ev; IO_STATUS_BLOCK io; BYTE buf[16]; NEED_RF(); REQUIRE(N(NtCreateEvent));
    h = mkfile("rf3.bin", GENERIC_READ, 0, 100); ev = mkevent(); CHECK(h && ev);
    if (h && ev) {
        EXPECT_EQ(N(NtReadFile)(h, ev, NULL, NULL, &io, buf, 16, NULL, NULL), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
    }
    if (h) N(NtClose)(h);
    if (ev) N(NtClose)(ev);
}
TEST(other3a_readfile_async_handle_completes)
{
    HANDLE h, ev; IO_STATUS_BLOCK io; BYTE buf[512]; LARGE_INTEGER off; NTSTATUS s; NEED_RF(); REQUIRE(N(NtCreateEvent));
    h = mkfile("rf4.bin", GENERIC_READ, FILE_FLAG_OVERLAPPED, 4096); ev = mkevent(); CHECK(h && ev);
    if (h && ev) {
        off.QuadPart = 1000; memset(&io, 0xcc, sizeof io);
        s = N(NtReadFile)(h, ev, NULL, NULL, &io, buf, 512, &off, NULL);
        CHECK(s == 0 || s == ST_PENDING);
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 512); CHECK(pat_ok(buf, 1000, 512));
        off.QuadPart = 4096; ResetEvent(ev); memset(&io, 0xcc, sizeof io);
        s = N(NtReadFile)(h, ev, NULL, NULL, &io, buf, 16, &off, NULL);
        CHECK(s == ST_PENDING || s == XS(0xC0000011));                              /* async handle: EOF may be reported on completion */
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, XS(0xC0000011)); EXPECT_EQ(io.Information, 0);
    }
    if (h) N(NtClose)(h);
    if (ev) N(NtClose)(ev);
}
TEST(other3a_readfile_errors)
{
    HANDLE h, hw, hd; IO_STATUS_BLOCK io; BYTE buf[64]; LARGE_INTEGER off; NTSTATUS s; char p[MAX_PATH]; NEED_RF();
    EXPECT_EQ(N(NtReadFile)(BADH, NULL, NULL, NULL, &io, buf, 8, NULL, NULL), XS(0xC0000008));
    EXPECT_EQ(N(NtReadFile)(NULL, NULL, NULL, NULL, &io, buf, 8, NULL, NULL), XS(0xC0000008));
    h = mkfile("rf5.bin", GENERIC_READ, 0, 200); CHECK(h != NULL);
    if (h) {
        off.QuadPart = -5;
        s = N(NtReadFile)(h, NULL, NULL, NULL, &io, buf, 8, &off, NULL);
        EXPECT_EQ(s, XS(0xC000000D));                                              /* negative offset other than the specials */
        N(NtClose)(h);
    }
    hw = mkfile("rf6.bin", GENERIC_WRITE, 0, 200); CHECK(hw != NULL);
    if (hw) {
        EXPECT_EQ(N(NtReadFile)(hw, NULL, NULL, NULL, &io, buf, 8, NULL, NULL), XS(0xC0000022));  /* no FILE_READ_DATA */
        N(NtClose)(hw);
    }
    strcpy(p, t_tmpdir());
    hd = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hd != INVALID_HANDLE_VALUE) {
        s = N(NtReadFile)(hd, NULL, NULL, NULL, &io, buf, 8, NULL, NULL);
        EXPECT_EQ(s, XS(0xC0000010));                                              /* STATUS_INVALID_DEVICE_REQUEST */
        N(NtClose)(hd);
    } else t_skip("cannot open directory handle");
}

/* ---- NtReadFileScatter ---------------------------------------------------- */
TEST(other3a_readfile_scatter_reads_into_segments)
{
    HANDLE h, ev; IO_STATUS_BLOCK io; BYTE *mem; FILE_SEGMENT_ELEMENT seg[3]; LARGE_INTEGER off; NTSTATUS s; NEED_RF();
    REQUIRE(N(NtReadFileScatter)); REQUIRE(N(NtCreateEvent));
    h = mkfile("sc1.bin", GENERIC_READ, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, 3 * 4096 + 100); ev = mkevent();
    mem = VirtualAlloc(NULL, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(h && ev && mem);
    if (h && ev && mem) {
        memset(mem, 0xee, 0x4000);
        memset(seg, 0, sizeof seg);
        seg[0].Buffer = mem + 0x2000; seg[1].Buffer = mem; seg[2].Buffer = NULL;      /* second page-sized segment, order scattered, NULL terminator */
        off.QuadPart = 0; memset(&io, 0xcc, sizeof io);
        s = N(NtReadFileScatter)(h, ev, NULL, NULL, &io, seg, 8192, &off, NULL);
        CHECK(s == 0 || s == ST_PENDING);
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 8192);
        CHECK(pat_ok(mem + 0x2000, 0, 4096)); CHECK(pat_ok(mem, 4096, 4096));
        CHECK(mem[0x1000] == 0xee);                                                    /* untouched page */
    }
    if (mem) VirtualFree(mem, 0, MEM_RELEASE);
    if (h) N(NtClose)(h);
    if (ev) N(NtClose)(ev);
}
TEST(other3a_readfile_scatter_errors)
{
    HANDLE h, hs; IO_STATUS_BLOCK io; BYTE *mem; FILE_SEGMENT_ELEMENT seg[2]; LARGE_INTEGER off; NTSTATUS s; NEED_RF(); REQUIRE(N(NtReadFileScatter));
    mem = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); CHECK(mem != NULL);
    memset(seg, 0, sizeof seg); seg[0].Buffer = mem; off.QuadPart = 0;
    EXPECT_EQ(N(NtReadFileScatter)(BADH, NULL, NULL, NULL, &io, seg, 4096, &off, NULL), XS(0xC0000008));
    h = mkfile("sc2.bin", GENERIC_READ, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, 8192); CHECK(h != NULL);
    if (h && mem) {
        s = N(NtReadFileScatter)(h, NULL, NULL, NULL, &io, seg, 100, &off, NULL);            /* length not sector multiple */
        EXPECT_EQ(s, XS(0xC000000D));
        s = N(NtReadFileScatter)(h, NULL, NULL, NULL, &io, seg, 4096, NULL, NULL);            /* ByteOffset required on overlapped handle */
        EXPECT_EQ(s, XS(0xC000000D));
        off.QuadPart = 100;
        s = N(NtReadFileScatter)(h, NULL, NULL, NULL, &io, seg, 4096, &off, NULL);            /* offset not sector aligned */
        EXPECT_EQ(s, XS(0xC000000D));
    }
    if (h) N(NtClose)(h);
    hs = mkfile("sc3.bin", GENERIC_READ, 0, 8192); CHECK(hs != NULL);                         /* buffered synchronous handle */
    if (hs && mem) {
        off.QuadPart = 0;
        s = N(NtReadFileScatter)(hs, NULL, NULL, NULL, &io, seg, 4096, &off, NULL);
        EXPECT_EQ(s, XS(0xC000000D));
    }
    if (hs) N(NtClose)(hs);
    if (mem) VirtualFree(mem, 0, MEM_RELEASE);
}

/* ---- NtLockFile ------------------------------------------------------------ */
static NTSTATUS lock(HANDLE h, LONGLONG o, LONGLONG l, ULONG key, BOOLEAN excl)
{
    IO_STATUS_BLOCK io; LARGE_INTEGER off, len; off.QuadPart = o; len.QuadPart = l;
    return N(NtLockFile)(h, NULL, NULL, NULL, &io, &off, &len, key, TRUE, excl);
}
static NTSTATUS unlock(HANDLE h, LONGLONG o, LONGLONG l, ULONG key)
{
    IO_STATUS_BLOCK io; LARGE_INTEGER off, len; off.QuadPart = o; len.QuadPart = l;
    return N(NtUnlockFile)(h, &io, &off, &len, key);
}
#define NEED_LK() do { REQUIRE(N(NtLockFile)); REQUIRE(N(NtUnlockFile)); REQUIRE(N(NtClose)); } while (0)
TEST(other3a_lockfile_exclusive_conflicts_across_handles)
{
    HANDLE a, b; IO_STATUS_BLOCK io; BYTE buf[16]; LARGE_INTEGER off; NEED_LK(); REQUIRE(N(NtReadFile));
    a = mkfile("lk1.bin", GENERIC_READ | GENERIC_WRITE, 0, 4096); b = mkfile("lk1.bin", GENERIC_READ | GENERIC_WRITE, 0, 0);
    CHECK(a && b);
    if (a && b) {
        EXPECT_EQ(lock(a, 100, 50, 1, TRUE), 0);
        EXPECT_EQ(lock(b, 100, 50, 1, TRUE), XS(0xC0000055));       /* STATUS_LOCK_NOT_GRANTED */
        EXPECT_EQ(lock(b, 120, 10, 1, FALSE), XS(0xC0000055));      /* overlap, shared against exclusive */
        EXPECT_EQ(lock(b, 150, 10, 1, TRUE), 0);                    /* adjacent range is free */
        off.QuadPart = 110;
        EXPECT_EQ(N(NtReadFile)(b, NULL, NULL, NULL, &io, buf, 4, &off, NULL), XS(0xC0000054));   /* STATUS_FILE_LOCK_CONFLICT: reads through a lock conflict too */
        EXPECT_EQ(unlock(b, 150, 10, 1), 0);
        EXPECT_EQ(unlock(a, 100, 50, 1), 0);
        EXPECT_EQ(lock(b, 100, 50, 1, TRUE), 0);                    /* free after unlock */
        EXPECT_EQ(unlock(b, 100, 50, 1), 0);
    }
    if (a) N(NtClose)(a);
    if (b) N(NtClose)(b);
}
TEST(other3a_lockfile_shared_locks_and_same_handle_overlap)
{
    HANDLE a, b; NEED_LK();
    a = mkfile("lk2.bin", GENERIC_READ | GENERIC_WRITE, 0, 4096); b = mkfile("lk2.bin", GENERIC_READ | GENERIC_WRITE, 0, 0);
    CHECK(a && b);
    if (a && b) {
        EXPECT_EQ(lock(a, 0, 100, 5, FALSE), 0);
        EXPECT_EQ(lock(b, 50, 100, 5, FALSE), 0);                   /* shared + shared is fine */
        EXPECT_EQ(lock(b, 50, 100, 5, TRUE), XS(0xC0000055));      /* upgrade attempt overlaps own shared lock */
        EXPECT_EQ(lock(a, 0, 100, 6, TRUE), XS(0xC0000055));        /* exclusive over others' shared range */
        EXPECT_EQ(lock(a, 20, 10, 7, FALSE), 0);                    /* same handle may take overlapping shared lock */
        EXPECT_EQ(unlock(a, 20, 10, 7), 0);
        EXPECT_EQ(unlock(a, 0, 100, 5), 0);
        EXPECT_EQ(unlock(b, 50, 100, 5), 0);
    }
    if (a) N(NtClose)(a);
    if (b) N(NtClose)(b);
}
TEST(other3a_lockfile_beyond_eof_and_unlock_errors)
{
    HANDLE a; IO_STATUS_BLOCK io; LARGE_INTEGER off, len; NEED_LK();
    a = mkfile("lk3.bin", GENERIC_READ | GENERIC_WRITE, 0, 100); CHECK(a != NULL); if (!a) return;
    EXPECT_EQ(lock(a, 1000000, 10, 1, TRUE), 0);                    /* locking past EOF is allowed */
    EXPECT_EQ(unlock(a, 1000000, 10, 1), 0);
    EXPECT_EQ(unlock(a, 1000000, 10, 1), XS(0xC000007E));           /* STATUS_RANGE_NOT_LOCKED */
    EXPECT_EQ(lock(a, 10, 20, 3, TRUE), 0);
    EXPECT_EQ(unlock(a, 10, 20, 4), XS(0xC000007E));                /* wrong key */
    EXPECT_EQ(unlock(a, 10, 10, 3), XS(0xC000007E));                /* ranges must match exactly */
    EXPECT_EQ(unlock(a, 10, 20, 3), 0);
    off.QuadPart = 0; len.QuadPart = 10;
    EXPECT_EQ(N(NtLockFile)(BADH, NULL, NULL, NULL, &io, &off, &len, 1, TRUE, TRUE), XS(0xC0000008));
    EXPECT_EQ(N(NtUnlockFile)(BADH, &io, &off, &len, 1), XS(0xC0000008));
    N(NtClose)(a);
}
TEST(other3a_lockfile_requires_read_or_write_access)
{
    HANDLE a; NTSTATUS s; NEED_LK();
    a = CreateFileA("NUL", FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (a == INVALID_HANDLE_VALUE) { t_skip("cannot open NUL"); return; }
    s = lock(a, 0, 10, 1, TRUE);
    EXPECT_EQ(s, XS(0xC0000022));                                                    /* handle holds neither read nor write data access */
    N(NtClose)(a);
}

/* ---- NtFsControlFile ------------------------------------------------------- */
#define FSCTL_GET_COMPRESSION_ 0x9003C
#define FSCTL_GET_REPARSE_POINT_ 0x900A8
#define FSCTL_PIPE_PEEK_ 0x11400C
#define FSCTL_SET_SPARSE_ 0x900C4
#define FSCTL_QUERY_ALLOCATED_RANGES_ 0x940CF
#define NEED_FS() do { REQUIRE(N(NtFsControlFile)); REQUIRE(N(NtClose)); } while (0)
TEST(other3a_fsctl_get_compression_and_buffer_checks)
{
    HANDLE h; IO_STATUS_BLOCK io; USHORT fmt; NTSTATUS s; NEED_FS();
    h = mkfile("fs1.bin", GENERIC_READ, 0, 100); CHECK(h != NULL); if (!h) return;
    memset(&io, 0xcc, sizeof io); fmt = 0xffff;
    s = N(NtFsControlFile)(h, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, &fmt, sizeof fmt);
    if (s == XS(0xC0000010) || s == XS(0xC00000BB)) { t_skip("file system does not implement compression state: 0x%08lx", (unsigned long)s); N(NtClose)(h); return; }
    EXPECT_EQ(s, 0); EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 2); EXPECT_EQ(fmt, 0);   /* COMPRESSION_FORMAT_NONE */
    memset(&io, 0xcc, sizeof io);
    s = N(NtFsControlFile)(h, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, &fmt, 1);
    EXPECT_EQ(s, XS(0xC000000D));                                                              /* output buffer shorter than a USHORT: invalid parameter */
    N(NtClose)(h);
}
TEST(other3a_fsctl_reparse_and_invalid_requests)
{
    HANDLE h; IO_STATUS_BLOCK io; BYTE buf[1024]; NTSTATUS s; NEED_FS();
    h = mkfile("fs2.bin", GENERIC_READ, 0, 100); CHECK(h != NULL); if (!h) return;
    s = N(NtFsControlFile)(h, NULL, NULL, NULL, &io, FSCTL_GET_REPARSE_POINT_, NULL, 0, buf, sizeof buf);
    if (s == XS(0xC0000010) || s == XS(0xC00000BB)) t_skip("file system lacks reparse support: 0x%08lx", (unsigned long)s);
    else EXPECT_EQ(s, XS(0xC0000275));                                                         /* STATUS_NOT_A_REPARSE_POINT */
    s = N(NtFsControlFile)(h, NULL, NULL, NULL, &io, 0x00090003 /* device 9, function 0 not defined */, NULL, 0, buf, sizeof buf);
    EXPECT_EQ(s, XS(0xC0000010));                                                              /* STATUS_INVALID_DEVICE_REQUEST */
    EXPECT_EQ(N(NtFsControlFile)(BADH, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, buf, 2), XS(0xC0000008));
    EXPECT_EQ(N(NtFsControlFile)(NULL, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, buf, 2), XS(0xC0000008));
    N(NtClose)(h);
}
TEST(other3a_fsctl_sparse_file_allocated_ranges)
{
    HANDLE h; IO_STATUS_BLOCK io; struct { LONGLONG off, len; } in, out[4]; NTSTATUS s; LARGE_INTEGER pos; BYTE b = 1; NEED_FS(); REQUIRE(N(NtReadFile));
    h = mkfile("fs3.bin", GENERIC_READ | GENERIC_WRITE, 0, 0); CHECK(h != NULL); if (!h) return;
    s = N(NtFsControlFile)(h, NULL, NULL, NULL, &io, FSCTL_SET_SPARSE_, NULL, 0, NULL, 0);
    if (s < 0) { t_skip("sparse files unsupported on the scratch volume: 0x%08lx", (unsigned long)s); N(NtClose)(h); return; }
    EXPECT_EQ(io.Information, 0);
    SetFilePointer(h, 0x10000, NULL, FILE_BEGIN); WriteFile(h, &b, 1, (DWORD *)&pos.LowPart, NULL);
    SetEndOfFile(h);
    in.off = 0; in.len = 0x20000; memset(&io, 0xcc, sizeof io); memset(out, 0, sizeof out);
    s = N(NtFsControlFile)(h, NULL, NULL, NULL, &io, FSCTL_QUERY_ALLOCATED_RANGES_, &in, sizeof in, out, sizeof out);
    EXPECT_EQ(s, 0);
    CHECK(io.Information >= sizeof out[0] && io.Information % sizeof out[0] == 0);
    if (io.Information >= sizeof out[0]) { CHECK(out[0].off <= 0x10000 && out[0].off + out[0].len > 0x10000); }
    s = N(NtFsControlFile)(h, NULL, NULL, NULL, &io, FSCTL_QUERY_ALLOCATED_RANGES_, &in, 8, out, sizeof out);   /* short input */
    EXPECT_EQ(s, XS(0xC000000D));
    N(NtClose)(h);
}
TEST(other3a_fsctl_pipe_peek)
{
    HANDLE srv, cli; IO_STATUS_BLOCK io; struct { ULONG state, avail, msgs, msglen; BYTE data[64]; } pk; NTSTATUS s; DWORD w; NEED_FS();
    srv = CreateNamedPipeA("\\\\.\\pipe\\other3a_peek", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 256, 256, 0, NULL);
    if (srv == INVALID_HANDLE_VALUE) { t_skip("cannot create pipe"); return; }
    cli = CreateFileA("\\\\.\\pipe\\other3a_peek", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(cli != INVALID_HANDLE_VALUE);
    if (cli != INVALID_HANDLE_VALUE) {
        memset(&pk, 0xcc, sizeof pk); memset(&io, 0xcc, sizeof io);
        s = N(NtFsControlFile)(srv, NULL, NULL, NULL, &io, FSCTL_PIPE_PEEK_, NULL, 0, &pk, sizeof pk);
        EXPECT_EQ(s, 0); EXPECT_EQ(pk.state, 3);                                              /* FILE_PIPE_CONNECTED_STATE */
        EXPECT_EQ(pk.avail, 0); EXPECT_EQ(io.Information, 16);
        WriteFile(cli, "hello", 5, &w, NULL);
        memset(&pk, 0xcc, sizeof pk);
        s = N(NtFsControlFile)(srv, NULL, NULL, NULL, &io, FSCTL_PIPE_PEEK_, NULL, 0, &pk, sizeof pk);
        EXPECT_EQ(s, 0); EXPECT_EQ(pk.avail, 5); EXPECT_EQ(io.Information, 16 + 5); CHECK(!memcmp(pk.data, "hello", 5));
        s = N(NtFsControlFile)(srv, NULL, NULL, NULL, &io, FSCTL_PIPE_PEEK_, NULL, 0, &pk, 8);
        EXPECT_EQ(s, XS(0xC000000D));                                                         /* smaller than the fixed header: invalid parameter */
        CloseHandle(cli);
    }
    CloseHandle(srv);
}

/* ---- NtNotifyChangeDirectoryFile(Ex) ---------------------------------------- */
typedef struct { ULONG next, action, namelen; WCHAR name[1]; } fni;
static HANDLE opendir(const char *leaf)
{
    char p[MAX_PATH]; HANDLE h; strcpy(p, t_tmpdir()); strcat(p, leaf); CreateDirectoryA(p, NULL);
    h = CreateFileA(p, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    return h == INVALID_HANDLE_VALUE ? NULL : h;
}
static void touch(const char *dir, const char *leaf)
{
    char p[MAX_PATH]; HANDLE h; strcpy(p, t_tmpdir()); strcat(p, dir); strcat(p, "\\"); strcat(p, leaf);
    h = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL); if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}
#define NEED_NC() do { REQUIRE(N(NtNotifyChangeDirectoryFile)); REQUIRE(N(NtClose)); REQUIRE(N(NtCreateEvent)); } while (0)
TEST(other3a_notify_dir_reports_created_file)
{
    HANDLE d, ev; IO_STATUS_BLOCK io; union { ULONGLONG a; BYTE b[1024]; } buf; fni *f = (fni *)buf.b; NTSTATUS s; NEED_NC();
    d = opendir("nd1"); ev = mkevent(); CHECK(d && ev); if (!d || !ev) goto out;
    memset(&io, 0xcc, sizeof io); io.Status = 0x103 + 0; memset(&buf, 0, sizeof buf);
    s = N(NtNotifyChangeDirectoryFile)(d, ev, NULL, NULL, &io, buf.b, sizeof buf.b, 0x1 /* FILE_NAME */, FALSE);
    EXPECT_EQ(s, ST_PENDING);
    EXPECT_EQ(WaitForSingleObject(ev, 50), WAIT_TIMEOUT);                                   /* nothing changed yet */
    touch("nd1", "added.txt");
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Status, 0);
    EXPECT_EQ(io.Information, 12 + 9 * 2);
    EXPECT_EQ(f->next, 0); EXPECT_EQ(f->action, 1); EXPECT_EQ(f->namelen, 18);              /* FILE_ACTION_ADDED */
    CHECK(!memcmp(f->name, L"added.txt", 18));
out:
    if (d) N(NtClose)(d);
    if (ev) N(NtClose)(ev);
}
TEST(other3a_notify_dir_close_completes_with_cleanup)
{
    HANDLE d, ev; IO_STATUS_BLOCK io; BYTE buf[256]; NTSTATUS s; NEED_NC();
    d = opendir("nd2"); ev = mkevent(); CHECK(d && ev); if (!d || !ev) goto out;
    memset(&io, 0xcc, sizeof io);
    s = N(NtNotifyChangeDirectoryFile)(d, ev, NULL, NULL, &io, buf, sizeof buf, 0x1, TRUE);
    EXPECT_EQ(s, ST_PENDING);
    N(NtClose)(d); d = NULL;
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Status, XS(0x0000010B));                                                    /* STATUS_NOTIFY_CLEANUP */
    EXPECT_EQ(io.Information, 0);
out:
    if (d) N(NtClose)(d);
    if (ev) N(NtClose)(ev);
}
TEST(other3a_notify_dir_watch_tree_and_filter)
{
    HANDLE d, ev; IO_STATUS_BLOCK io; union { ULONGLONG a; BYTE b[1024]; } buf; fni *f = (fni *)buf.b; char p[MAX_PATH]; NTSTATUS s; NEED_NC();
    d = opendir("nd3"); ev = mkevent(); CHECK(d && ev); if (!d || !ev) goto out;
    strcpy(p, t_tmpdir()); strcat(p, "nd3\\sub"); CreateDirectoryA(p, NULL);
    memset(&buf, 0, sizeof buf);
    s = N(NtNotifyChangeDirectoryFile)(d, ev, NULL, NULL, &io, buf.b, sizeof buf.b, 0x1, TRUE);
    EXPECT_EQ(s, ST_PENDING);
    touch("nd3\\sub", "deep.txt");
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Status, 0); EXPECT_EQ(f->action, 1); EXPECT_EQ(f->namelen, 2 * 12);
    CHECK(!memcmp(f->name, L"sub\\deep.txt", 24));
out:
    if (d) N(NtClose)(d);
    if (ev) N(NtClose)(ev);
}
TEST(other3a_notify_dir_non_recursive_ignores_subtree)
{
    HANDLE d, ev; IO_STATUS_BLOCK io; union { ULONGLONG a; BYTE b[1024]; } buf; fni *f = (fni *)buf.b; char p[MAX_PATH]; NTSTATUS s; NEED_NC();
    d = opendir("nd9"); ev = mkevent(); CHECK(d && ev); if (!d || !ev) goto out;
    strcpy(p, t_tmpdir()); strcat(p, "nd9\\sub"); CreateDirectoryA(p, NULL);
    memset(&buf, 0, sizeof buf);
    s = N(NtNotifyChangeDirectoryFile)(d, ev, NULL, NULL, &io, buf.b, sizeof buf.b, 0x1, FALSE);
    EXPECT_EQ(s, ST_PENDING);
    touch("nd9\\sub", "deeper.txt");
    EXPECT_EQ(WaitForSingleObject(ev, 300), WAIT_TIMEOUT);                          /* change below the watched directory is invisible */
    touch("nd9", "top.txt");
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Status, 0); EXPECT_EQ(f->action, 1); CHECK(f->namelen == 14 && !memcmp(f->name, L"top.txt", 14));
out:
    if (d) N(NtClose)(d);
    if (ev) N(NtClose)(ev);
}
TEST(other3a_notify_dir_overflow_returns_enum_dir)
{
    HANDLE d, ev; IO_STATUS_BLOCK io; BYTE buf[16]; NTSTATUS s; NEED_NC();
    d = opendir("nd4"); ev = mkevent(); CHECK(d && ev); if (!d || !ev) goto out;
    s = N(NtNotifyChangeDirectoryFile)(d, ev, NULL, NULL, &io, buf, sizeof buf, 0x1, FALSE);
    EXPECT_EQ(s, ST_PENDING);
    touch("nd4", "a_rather_long_name_overflowing_the_buffer.txt");
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Status, XS(0x0000010C));                                                    /* STATUS_NOTIFY_ENUM_DIR */
    EXPECT_EQ(io.Information, 0);
out:
    if (d) N(NtClose)(d);
    if (ev) N(NtClose)(ev);
}
TEST(other3a_notify_dir_errors)
{
    HANDLE d, f; IO_STATUS_BLOCK io; BYTE buf[64]; NTSTATUS s; NEED_NC();
    EXPECT_EQ(N(NtNotifyChangeDirectoryFile)(BADH, NULL, NULL, NULL, &io, buf, sizeof buf, 1, FALSE), XS(0xC0000008));
    d = opendir("nd5"); CHECK(d != NULL);
    if (d) {
        s = N(NtNotifyChangeDirectoryFile)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 0, FALSE);               /* empty filter */
        EXPECT_EQ(s, XS(0xC000000D));
        s = N(NtNotifyChangeDirectoryFile)(d, NULL, NULL, NULL, &io, buf, sizeof buf, 0x80000000u, FALSE);     /* unknown filter bits */
        EXPECT_EQ(s, XS(0xC000000D));
        N(NtClose)(d);
    }
    f = mkfile("nd6.bin", GENERIC_READ, FILE_FLAG_OVERLAPPED, 10); CHECK(f != NULL);
    if (f) {
        s = N(NtNotifyChangeDirectoryFile)(f, NULL, NULL, NULL, &io, buf, sizeof buf, 1, FALSE);              /* not a directory */
        EXPECT_EQ(s, XS(0xC000000D));                                                                         /* not a directory: invalid parameter */
        N(NtClose)(f);
    }
}
TEST(other3a_notify_dir_ex_extended_information)
{
    HANDLE d, ev; IO_STATUS_BLOCK io; union { ULONGLONG a; BYTE b[1024]; } buf; NTSTATUS s; ULONG nl; WCHAR *nm; NEED_NC(); REQUIRE(N(NtNotifyChangeDirectoryFileEx));
    d = opendir("nd7"); ev = mkevent(); CHECK(d && ev); if (!d || !ev) goto out;
    memset(&buf, 0, sizeof buf);
    s = N(NtNotifyChangeDirectoryFileEx)(d, ev, NULL, NULL, &io, buf.b, sizeof buf.b, 0x1, FALSE, 2 /* DirectoryNotifyExtendedInformation */);
    if (s == XS(0xC0000003) || s == XS(0xC000000D) || s == XS(0xC0000002)) { t_skip("extended notify class unsupported: 0x%08lx", (unsigned long)s); goto out; }
    EXPECT_EQ(s, ST_PENDING);
    touch("nd7", "ext.txt");
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Status, 0);
    /* FILE_NOTIFY_EXTENDED_INFORMATION: NextEntryOffset, Action, 4 FILETIMEs, AllocationSize, FileSize, FileAttributes, ReparseTag, FileId(8), ParentFileId(8), FileNameLength at 0x50, FileName at 0x54 */
    EXPECT_EQ(*(ULONG *)(buf.b + 0), 0); EXPECT_EQ(*(ULONG *)(buf.b + 4), 1);
    nl = *(ULONG *)(buf.b + 0x50); nm = (WCHAR *)(buf.b + 0x54);
    EXPECT_EQ(nl, 14); CHECK(!memcmp(nm, L"ext.txt", 14));
    EXPECT_EQ(io.Information, 0x54 + 14);
    N(NtClose)(d); d = NULL;
out:
    if (d) N(NtClose)(d);
    if (ev) N(NtClose)(ev);
}
TEST(other3a_notify_dir_ex_basic_class_matches_plain_and_errors)
{
    HANDLE d, ev; IO_STATUS_BLOCK io; union { ULONGLONG a; BYTE b[256]; } buf; NTSTATUS s; NEED_NC(); REQUIRE(N(NtNotifyChangeDirectoryFileEx));
    d = opendir("nd8"); ev = mkevent(); CHECK(d && ev); if (!d || !ev) goto out;
    s = N(NtNotifyChangeDirectoryFileEx)(d, ev, NULL, NULL, &io, buf.b, sizeof buf.b, 0x1, FALSE, 1 /* DirectoryNotifyInformation */);
    EXPECT_EQ(s, ST_PENDING);
    touch("nd8", "basic.txt");
    EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Information, 12 + 9 * 2);
    EXPECT_EQ(N(NtNotifyChangeDirectoryFileEx)(BADH, NULL, NULL, NULL, &io, buf.b, sizeof buf.b, 0x1, FALSE, 1), XS(0xC0000008));
out:
    if (d) N(NtClose)(d);
    if (ev) N(NtClose)(ev);
}

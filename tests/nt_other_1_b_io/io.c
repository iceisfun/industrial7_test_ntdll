/* I/O and object natives: NtFsControlFile, NtLockFile, NtReadFileScatter, NtNotifyChangeDirectoryFile(Ex),
 * NtNotifyChangeKey, NtFlushKey, NtMakeTemporaryObject, NtMakePermanentObject. */
#include "t.h"

UDECL(NTSTATUS, NtFsControlFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtLockFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG, BOOLEAN, BOOLEAN));
UDECL(NTSTATUS, NtUnlockFile, (HANDLE, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER, ULONG));
UDECL(NTSTATUS, NtReadFileScatter, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtNotifyChangeDirectoryFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtNotifyChangeDirectoryFileEx, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN, ULONG));
UDECL(NTSTATUS, NtCancelIoFile, (HANDLE, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtFlushKey, (HANDLE));
UDECL(NTSTATUS, NtNotifyChangeKey, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, RtlOpenCurrentUser, (ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtMakeTemporaryObject, (HANDLE));
UDECL(NTSTATUS, NtMakePermanentObject, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define XS(x) ((NTSTATUS)(x))
#define BADH ((HANDLE)(LONG_PTR)0x7777c)
#define PEND XS(0x103)

TEST(alias_pairs)
{
    const char *n[] = { "FsControlFile", "LockFile", "ReadFileScatter", "NotifyChangeDirectoryFile", "NotifyChangeDirectoryFileEx",
        "NotifyChangeKey", "FlushKey", "MakeTemporaryObject", "MakePermanentObject" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64]; wsprintfA(a, "Nt%s", n[i]); wsprintfA(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a), pb = t_proc(b);
        if (!pa || !pb) { t_skip("missing %s", pa ? b : a); return; }
        CHECKF(pa == pb, "%s and %s differ", a, b);
    }
}

#define FSCTL_GET_COMPRESSION_ 0x9003C
#define FSCTL_PIPE_PEEK_ 0x11400C

static HANDLE mkfile(const char *leaf, DWORD flags, DWORD share, const void *data, DWORD len, char *path, size_t cap)
{
    t_tmpfile(path, cap, leaf);
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, share, NULL, CREATE_ALWAYS, flags, NULL);
    if (h != INVALID_HANDLE_VALUE && len) { DWORD n; WriteFile(h, data, len, &n, NULL); SetFilePointer(h, 0, NULL, FILE_BEGIN); }
    return h;
}

TEST(fs_control_file)
{
    REQUIRE(UN(NtFsControlFile));
    char path[MAX_PATH]; IO_STATUS_BLOCK io; USHORT comp; NTSTATUS s;
    HANDLE f = mkfile("fsc.bin", FILE_ATTRIBUTE_NORMAL, 0, "hello", 5, path, sizeof path);
    CHECK(f != INVALID_HANDLE_VALUE); if (f == INVALID_HANDLE_VALUE) return;
    comp = 0xffff; memset(&io, 0xcc, sizeof io);
    s = UN(NtFsControlFile)(f, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, &comp, sizeof comp);
    EXPECT_EQ(s, 0); EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 2); EXPECT_EQ(comp, 0);
    /* output buffer too small */
    memset(&io, 0xcc, sizeof io); comp = 0xffff;
    s = UN(NtFsControlFile)(f, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, &comp, 1);
    EXPECT_EQ(s, XS(0xC000000D)); /* STATUS_INVALID_PARAMETER */
    s = UN(NtFsControlFile)(f, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, NULL, 0);
    EXPECT_EQ(s, XS(0xC00000E8)); /* STATUS_INVALID_USER_BUFFER */
    /* unknown control code */
    s = UN(NtFsControlFile)(f, NULL, NULL, NULL, &io, 0x00090FFC, NULL, 0, NULL, 0);
    t_note("unknown fsctl on file: %08lx", s);
    EXPECT_EQ(s, XS(0xC0000010)); /* STATUS_INVALID_DEVICE_REQUEST */
    /* invalid handle */
    EXPECT_EQ(UN(NtFsControlFile)(BADH, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, &comp, sizeof comp), XS(0xC0000008));
    EXPECT_EQ(UN(NtFsControlFile)(NULL, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, &comp, sizeof comp), XS(0xC0000008));
    /* event signalled on completion */
    {
        HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
        comp = 0xffff;
        s = UN(NtFsControlFile)(f, ev, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, &comp, sizeof comp);
        EXPECT_EQ(s, 0);
        EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
        CloseHandle(ev);
    }
    CloseHandle(f);
    /* handle without the needed access: GET_COMPRESSION needs FILE_READ_DATA|FILE_WRITE_DATA? observe */
    f = CreateFileA(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        s = UN(NtFsControlFile)(f, NULL, NULL, NULL, &io, FSCTL_GET_COMPRESSION_, NULL, 0, &comp, sizeof comp);
        t_note("GET_COMPRESSION with attribute-only access: %08lx", s);
        CloseHandle(f);
    }
    DeleteFileA(path);
}

TEST(fs_control_file_pipe_peek)
{
    REQUIRE(UN(NtFsControlFile));
    HANDLE r, w; IO_STATUS_BLOCK io; struct { ULONG state, avail, msgs, msglen; BYTE data[32]; } pk; NTSTATUS s;
    CHECK(CreatePipe(&r, &w, NULL, 0)); 
    memset(&pk, 0xcc, sizeof pk); memset(&io, 0xcc, sizeof io);
    s = UN(NtFsControlFile)(r, NULL, NULL, NULL, &io, FSCTL_PIPE_PEEK_, NULL, 0, &pk, sizeof pk);
    EXPECT_EQ(s, 0); EXPECT_EQ(io.Information, 16);
    EXPECT_EQ(pk.state, 3); /* FILE_PIPE_CONNECTED_STATE */
    EXPECT_EQ(pk.avail, 0);
    DWORD n; WriteFile(w, "abcdefgh", 8, &n, NULL);
    memset(&pk, 0xcc, sizeof pk); memset(&io, 0xcc, sizeof io);
    s = UN(NtFsControlFile)(r, NULL, NULL, NULL, &io, FSCTL_PIPE_PEEK_, NULL, 0, &pk, sizeof pk);
    EXPECT_EQ(s, 0); EXPECT_EQ(io.Information, 16 + 8);
    EXPECT_EQ(pk.avail, 8);
    CHECK(!memcmp(pk.data, "abcdefgh", 8));
    /* data was only peeked */
    BYTE b[16]; CHECK(ReadFile(r, b, 16, &n, NULL)); EXPECT_EQ(n, 8);
    /* buffer holds only the header: data truncated -> STATUS_BUFFER_OVERFLOW */
    WriteFile(w, "xyz", 3, &n, NULL);
    memset(&io, 0xcc, sizeof io);
    s = UN(NtFsControlFile)(r, NULL, NULL, NULL, &io, FSCTL_PIPE_PEEK_, NULL, 0, &pk, 16);
    EXPECT_EQ(s, XS(0x80000005)); EXPECT_EQ(io.Information, 16);
    /* buffer smaller than the header */
    EXPECT_EQ(UN(NtFsControlFile)(r, NULL, NULL, NULL, &io, FSCTL_PIPE_PEEK_, NULL, 0, &pk, 8), XS(0xC000000D));
    /* peek on a file handle */
    CloseHandle(w);
    CloseHandle(r);
}

TEST(lock_file)
{
    REQUIRE(UN(NtLockFile)); REQUIRE(UN(NtUnlockFile));
    char path[MAX_PATH]; BYTE data[8192]; memset(data, 7, sizeof data);
    HANDLE a = mkfile("lock.bin", FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, data, sizeof data, path, sizeof path);
    CHECK(a != INVALID_HANDLE_VALUE); if (a == INVALID_HANDLE_VALUE) return;
    HANDLE b = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(b != INVALID_HANDLE_VALUE);
    IO_STATUS_BLOCK io; LARGE_INTEGER off, len; NTSTATUS s;
    off.QuadPart = 100; len.QuadPart = 200;
    memset(&io, 0xcc, sizeof io);
    s = UN(NtLockFile)(a, NULL, NULL, NULL, &io, &off, &len, 1, TRUE, TRUE);
    EXPECT_EQ(s, 0); EXPECT_EQ(io.Status, 0);
    /* conflicting exclusive lock from another handle, fail immediately */
    LARGE_INTEGER off2; off2.QuadPart = 250; len.QuadPart = 10;
    s = UN(NtLockFile)(b, NULL, NULL, NULL, &io, &off2, &len, 2, TRUE, TRUE);
    EXPECT_EQ(s, XS(0xC0000055)); /* STATUS_LOCK_NOT_GRANTED */
    /* same handle, overlapping range also conflicts */
    s = UN(NtLockFile)(a, NULL, NULL, NULL, &io, &off2, &len, 1, TRUE, TRUE);
    EXPECT_EQ(s, XS(0xC0000055));
    /* shared lock against exclusive */
    s = UN(NtLockFile)(b, NULL, NULL, NULL, &io, &off2, &len, 2, TRUE, FALSE);
    EXPECT_EQ(s, XS(0xC0000055));
    /* non-overlapping range from the other handle is fine */
    LARGE_INTEGER off3; off3.QuadPart = 1000; len.QuadPart = 50;
    s = UN(NtLockFile)(b, NULL, NULL, NULL, &io, &off3, &len, 2, TRUE, TRUE);
    EXPECT_EQ(s, 0);
    /* unlock with the wrong key / range */
    LARGE_INTEGER ul; ul.QuadPart = 199;
    s = UN(NtUnlockFile)(a, &io, &off, &ul, 1);
    EXPECT_EQ(s, XS(0xC000007E)); /* STATUS_RANGE_NOT_LOCKED */
    ul.QuadPart = 200;
    s = UN(NtUnlockFile)(a, &io, &off, &ul, 9);   /* right range, wrong key */
    EXPECT_EQ(s, XS(0xC000007E));
    /* a read through the other handle in the locked range fails, outside succeeds */
    { BYTE tmp[16]; DWORD n = 0; SetFilePointer(b, 150, NULL, FILE_BEGIN);
      CHECK(!ReadFile(b, tmp, 16, &n, NULL)); EXPECT_EQ(GetLastError(), ERROR_LOCK_VIOLATION);
      SetFilePointer(b, 5000, NULL, FILE_BEGIN);
      CHECK(ReadFile(b, tmp, 16, &n, NULL)); EXPECT_EQ(n, 16); }
    len.QuadPart = 200;
    EXPECT_EQ(UN(NtUnlockFile)(a, &io, &off, &len, 1), 0);
    len.QuadPart = 50;
    EXPECT_EQ(UN(NtUnlockFile)(b, &io, &off3, &len, 2), 0);
    /* now the previously conflicting lock is grantable */
    len.QuadPart = 10;
    EXPECT_EQ(UN(NtLockFile)(b, NULL, NULL, NULL, &io, &off2, &len, 2, TRUE, TRUE), 0);
    EXPECT_EQ(UN(NtUnlockFile)(b, &io, &off2, &len, 2), 0);
    /* lock beyond end of file is allowed */
    off.QuadPart = 1LL << 40; len.QuadPart = 4096;
    EXPECT_EQ(UN(NtLockFile)(a, NULL, NULL, NULL, &io, &off, &len, 3, TRUE, TRUE), 0);
    EXPECT_EQ(UN(NtUnlockFile)(a, &io, &off, &len, 3), 0);
    /* bad handles */
    off.QuadPart = 0; len.QuadPart = 1;
    EXPECT_EQ(UN(NtLockFile)(BADH, NULL, NULL, NULL, &io, &off, &len, 1, TRUE, TRUE), XS(0xC0000008));
    EXPECT_EQ(UN(NtLockFile)(NULL, NULL, NULL, NULL, &io, &off, &len, 1, TRUE, TRUE), XS(0xC0000008));
    /* handle opened without read/write data access */
    HANDLE c = CreateFileA(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (c != INVALID_HANDLE_VALUE) {
        s = UN(NtLockFile)(c, NULL, NULL, NULL, &io, &off, &len, 1, TRUE, TRUE);
        EXPECT_EQ(s, XS(0xC0000022)); /* STATUS_ACCESS_DENIED */
        CloseHandle(c);
    }
    /* length zero is a legal empty lock */
    len.QuadPart = 0; off.QuadPart = 10;
    s = UN(NtLockFile)(a, NULL, NULL, NULL, &io, &off, &len, 1, TRUE, TRUE);
    t_note("zero-length lock: %08lx", s);
    if (s == 0) UN(NtUnlockFile)(a, &io, &off, &len, 1);
    CloseHandle(b); CloseHandle(a);
    DeleteFileA(path);
}

TEST(read_file_scatter)
{
    REQUIRE(UN(NtReadFileScatter));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "scat.bin");
    BYTE *src = VirtualAlloc(NULL, 16384, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(src != NULL); if (!src) return;
    for (int i = 0; i < 16384; i++) src[i] = (BYTE)(i * 7 + i / 4096);
    HANDLE w = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD n; WriteFile(w, src, 16384, &n, NULL); CloseHandle(w);
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    BYTE *d1 = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BYTE *d2 = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BYTE *d3 = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (h != INVALID_HANDLE_VALUE && d1 && d2 && d3) {
        FILE_SEGMENT_ELEMENT seg[4]; memset(seg, 0, sizeof seg);
        seg[0].Buffer = d1; seg[1].Buffer = d2; seg[2].Buffer = d3;  /* seg[3] null terminator */
        IO_STATUS_BLOCK io; LARGE_INTEGER off; HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
        NTSTATUS s;
        /* two pages from offset 4096 */
        off.QuadPart = 4096; memset(&io, 0xcc, sizeof io); seg[2].Buffer = NULL;
        s = UN(NtReadFileScatter)(h, ev, NULL, NULL, &io, seg, 8192, &off, NULL);
        CHECKF(s == 0 || s == PEND, "status %08lx", s);
        EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 8192);
        CHECK(!memcmp(d1, src + 4096, 4096)); CHECK(!memcmp(d2, src + 8192, 4096));
        /* read crossing EOF: only the available bytes, still page multiple request */
        ResetEvent(ev); memset(d1, 0, 4096); memset(d2, 0, 4096);
        seg[0].Buffer = d1; seg[1].Buffer = d2; seg[2].Buffer = NULL;
        off.QuadPart = 12288; memset(&io, 0xcc, sizeof io);
        s = UN(NtReadFileScatter)(h, ev, NULL, NULL, &io, seg, 8192, &off, NULL);
        CHECKF(s == 0 || s == PEND, "status %08lx", s);
        WaitForSingleObject(ev, 10000);
        EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 4096);
        CHECK(!memcmp(d1, src + 12288, 4096));
        /* wholly beyond EOF */
        ResetEvent(ev); off.QuadPart = 16384; memset(&io, 0xcc, sizeof io);
        s = UN(NtReadFileScatter)(h, ev, NULL, NULL, &io, seg, 4096, &off, NULL);
        if (s == PEND) { WaitForSingleObject(ev, 10000); s = io.Status; }
        EXPECT_EQ(s, XS(0xC0000011)); /* STATUS_END_OF_FILE */
        /* length not a multiple of the page/sector size */
        ResetEvent(ev); off.QuadPart = 0; memset(&io, 0xcc, sizeof io);
        s = UN(NtReadFileScatter)(h, ev, NULL, NULL, &io, seg, 100, &off, NULL);
        EXPECT_EQ(s, XS(0xC000000D));
        /* unaligned file offset */
        off.QuadPart = 100;
        s = UN(NtReadFileScatter)(h, ev, NULL, NULL, &io, seg, 4096, &off, NULL);
        EXPECT_EQ(s, XS(0xC000000D));
        /* no offset on a non-sequential handle */
        s = UN(NtReadFileScatter)(h, ev, NULL, NULL, &io, seg, 4096, NULL, NULL);
        t_note("scatter read without offset: %08lx", s);
        if (s == PEND) WaitForSingleObject(ev, 10000);
        /* bad handle */
        off.QuadPart = 0;
        EXPECT_EQ(UN(NtReadFileScatter)(BADH, ev, NULL, NULL, &io, seg, 4096, &off, NULL), XS(0xC0000008));
        CloseHandle(ev);
    }
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    /* a handle opened without NO_BUFFERING|OVERLAPPED is not usable for scatter reads */
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE && d1) {
        FILE_SEGMENT_ELEMENT seg[2]; memset(seg, 0, sizeof seg); seg[0].Buffer = d1;
        IO_STATUS_BLOCK io; LARGE_INTEGER off; off.QuadPart = 0;
        EXPECT_EQ(UN(NtReadFileScatter)(h, NULL, NULL, NULL, &io, seg, 4096, &off, NULL), XS(0xC000000D));
        CloseHandle(h);
    }
    VirtualFree(src, 0, MEM_RELEASE);
    if (d1) VirtualFree(d1, 0, MEM_RELEASE);
    if (d2) VirtualFree(d2, 0, MEM_RELEASE);
    if (d3) VirtualFree(d3, 0, MEM_RELEASE);
    DeleteFileA(path);
}


static HANDLE open_dir_async(const char *path)
{
    return CreateFileA(path, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
}

TEST(notify_change_directory_file)
{
    REQUIRE(UN(NtNotifyChangeDirectoryFile));
    char dir[MAX_PATH], f[MAX_PATH];
    wsprintfA(dir, "%snd1", t_tmpdir()); CreateDirectoryA(dir, NULL);
    HANDLE h = open_dir_async(dir); CHECK(h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) { RemoveDirectoryA(dir); return; }
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    struct { ULONG next, action, namelen; WCHAR name[64]; } buf; IO_STATUS_BLOCK io; NTSTATUS s;
    memset(&io, 0xcc, sizeof io); memset(&buf, 0, sizeof buf);
    s = UN(NtNotifyChangeDirectoryFile)(h, ev, NULL, NULL, &io, &buf, sizeof buf, FILE_NOTIFY_CHANGE_FILE_NAME, FALSE);
    EXPECT_EQ(s, PEND);
    EXPECT_EQ(WaitForSingleObject(ev, 50), WAIT_TIMEOUT);
    wsprintfA(f, "%s\\newfile.txt", dir);
    HANDLE c = CreateFileA(f, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL); CloseHandle(c);
    EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Status, 0);
    EXPECT_EQ(io.Information, 12 + 2 * 11);
    EXPECT_EQ(buf.next, 0); EXPECT_EQ(buf.action, 1); /* FILE_ACTION_ADDED */
    EXPECT_EQ(buf.namelen, 22);
    CHECK(!memcmp(buf.name, L"newfile.txt", 22));
    /* second round: rename */
    ResetEvent(ev); memset(&io, 0xcc, sizeof io); memset(&buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtNotifyChangeDirectoryFile)(h, ev, NULL, NULL, &io, &buf, sizeof buf, FILE_NOTIFY_CHANGE_FILE_NAME, FALSE), PEND);
    DeleteFileA(f);
    EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(buf.action, 2); /* FILE_ACTION_REMOVED */
    /* invalid filter */
    EXPECT_EQ(UN(NtNotifyChangeDirectoryFile)(h, NULL, NULL, NULL, &io, &buf, sizeof buf, 0, FALSE), XS(0xC000000D));
    EXPECT_EQ(UN(NtNotifyChangeDirectoryFile)(h, NULL, NULL, NULL, &io, &buf, sizeof buf, 0x80000000, FALSE), XS(0xC000000D));
    /* bad handle, and a file handle that is not a directory */
    EXPECT_EQ(UN(NtNotifyChangeDirectoryFile)(BADH, NULL, NULL, NULL, &io, &buf, sizeof buf, 1, FALSE), XS(0xC0000008));
    /* cancel a pending request */
    if (UN(NtCancelIoFile)) {
        ResetEvent(ev);
        EXPECT_EQ(UN(NtNotifyChangeDirectoryFile)(h, ev, NULL, NULL, &io, &buf, sizeof buf, 1, TRUE), PEND);
        IO_STATUS_BLOCK cio;
        EXPECT_EQ(UN(NtCancelIoFile)(h, &cio), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, XS(0xC0000120));
    }
    CloseHandle(ev); CloseHandle(h); RemoveDirectoryA(dir);
}

TEST(notify_change_directory_file_ex)
{
    REQUIRE(UN(NtNotifyChangeDirectoryFileEx));
    char dir[MAX_PATH], f[MAX_PATH];
    wsprintfA(dir, "%snd2", t_tmpdir()); CreateDirectoryA(dir, NULL);
    HANDLE h = open_dir_async(dir); CHECK(h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) { RemoveDirectoryA(dir); return; }
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    BYTE buf[512]; IO_STATUS_BLOCK io; NTSTATUS s;
    memset(&io, 0xcc, sizeof io); memset(buf, 0, sizeof buf);
    /* class 1: same record layout as the non-Ex call */
    s = UN(NtNotifyChangeDirectoryFileEx)(h, ev, NULL, NULL, &io, buf, sizeof buf, FILE_NOTIFY_CHANGE_FILE_NAME, TRUE, 1);
    EXPECT_EQ(s, PEND);
    wsprintfA(f, "%s\\ex.txt", dir);
    HANDLE c = CreateFileA(f, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL); CloseHandle(c);
    EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Status, 0);
    EXPECT_EQ(io.Information, 12 + 2 * 6);
    EXPECT_EQ(*(ULONG *)(buf + 4), 1);
    /* class 2: FILE_NOTIFY_EXTENDED_INFORMATION (larger fixed header) */
    ResetEvent(ev); memset(&io, 0xcc, sizeof io); memset(buf, 0, sizeof buf);
    s = UN(NtNotifyChangeDirectoryFileEx)(h, ev, NULL, NULL, &io, buf, sizeof buf, FILE_NOTIFY_CHANGE_FILE_NAME, TRUE, 2);
    EXPECT_EQ(s, PEND);
    DeleteFileA(f);
    EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Status, 0);
    EXPECT_EQ(*(ULONG *)(buf + 4), 2);          /* FILE_ACTION_REMOVED */
    t_note("extended class record: information %llu filenamelen %lu", (unsigned long long)io.Information, *(ULONG *)(buf + 0x38));
    /* invalid class and filter */
    EXPECT_EQ(UN(NtNotifyChangeDirectoryFileEx)(h, NULL, NULL, NULL, &io, buf, sizeof buf, 0, FALSE, 1), XS(0xC000000D));
    EXPECT_EQ(UN(NtNotifyChangeDirectoryFileEx)(BADH, NULL, NULL, NULL, &io, buf, sizeof buf, 1, FALSE, 1), XS(0xC0000008));
    CloseHandle(ev); CloseHandle(h); RemoveDirectoryA(dir);
}

/* ---- registry ---- */
static HANDLE make_key(HANDLE *hcu, const char *tag)
{
    UNICODE_STRING n; OBJECT_ATTRIBUTES oa; WCHAR path[80]; HANDLE k = NULL;
    if (UN(RtlOpenCurrentUser)(KEY_ALL_ACCESS, hcu) < 0) return NULL;
    wsprintfW(path, L"Software\\NtdllConfB_%lu_%S", GetCurrentProcessId(), tag);
    n.Buffer = path; n.Length = n.MaximumLength = (USHORT)(lstrlenW(path) * 2);
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE, *hcu, NULL);
    if (UN(NtCreateKey)(&k, KEY_ALL_ACCESS | DELETE, &oa, 0, NULL, 0, NULL) < 0) { UN(NtClose)(*hcu); return NULL; }
    return k;
}

TEST(flush_key)
{
    REQUIRE(UN(NtFlushKey)); REQUIRE(UN(RtlOpenCurrentUser)); REQUIRE(UN(NtCreateKey)); REQUIRE(UN(NtDeleteKey)); REQUIRE(UN(NtClose));
    HANDLE hcu, k = make_key(&hcu, "flush");
    if (!k) { t_skip("cannot create scratch key"); return; }
    EXPECT_EQ(UN(NtFlushKey)(k), 0);
    EXPECT_EQ(UN(NtFlushKey)(k), 0);
    EXPECT_EQ(UN(NtFlushKey)(hcu), 0);
    EXPECT_EQ(UN(NtFlushKey)(BADH), XS(0xC0000008));
    EXPECT_EQ(UN(NtFlushKey)(NULL), XS(0xC0000008));
    EXPECT_EQ(UN(NtFlushKey)((HANDLE)(LONG_PTR)-1), XS(0xC0000024)); /* process pseudo handle: wrong type */
    /* a key opened with no rights still flushes? observe */
    UN(NtDeleteKey)(k); UN(NtClose)(k); UN(NtClose)(hcu);
}

TEST(notify_change_key)
{
    REQUIRE(UN(NtNotifyChangeKey)); REQUIRE(UN(NtSetValueKey)); REQUIRE(UN(RtlOpenCurrentUser)); REQUIRE(UN(NtCreateKey));
    HANDLE hcu, k, ev = CreateEventA(NULL, TRUE, FALSE, NULL); IO_STATUS_BLOCK io; NTSTATUS s;
    UNICODE_STRING vn; vn.Buffer = L"v"; vn.Length = vn.MaximumLength = 2; ULONG val = 5;
    /* value change completes a LAST_SET watch */
    k = make_key(&hcu, "n1");
    if (!k) { t_skip("cannot create scratch key"); CloseHandle(ev); return; }
    memset(&io, 0xcc, sizeof io);
    s = UN(NtNotifyChangeKey)(k, ev, NULL, NULL, &io, 4 /* REG_NOTIFY_CHANGE_LAST_SET */, FALSE, NULL, 0, TRUE);
    EXPECT_EQ(s, PEND);
    EXPECT_EQ(WaitForSingleObject(ev, 50), WAIT_TIMEOUT);
    EXPECT_EQ(UN(NtSetValueKey)(k, &vn, 0, REG_DWORD, &val, 4), 0);
    EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(io.Status, XS(0x10C)); /* STATUS_NOTIFY_ENUM_DIR */
    UN(NtDeleteKey)(k); UN(NtClose)(k); UN(NtClose)(hcu);
    /* a subtree watch on NAME sees a child key creation */
    k = make_key(&hcu, "n2");
    if (k) {
        UNICODE_STRING cn; OBJECT_ATTRIBUTES oa; HANDLE ck = NULL; cn.Buffer = L"child"; cn.Length = cn.MaximumLength = 10;
        ResetEvent(ev); memset(&io, 0xcc, sizeof io);
        EXPECT_EQ(UN(NtNotifyChangeKey)(k, ev, NULL, NULL, &io, 1 /* NAME */, TRUE, NULL, 0, TRUE), PEND);
        InitializeObjectAttributes(&oa, &cn, OBJ_CASE_INSENSITIVE, k, NULL);
        EXPECT_EQ(UN(NtCreateKey)(&ck, KEY_ALL_ACCESS | DELETE, &oa, 0, NULL, 0, NULL), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, XS(0x10C));
        if (ck) { UN(NtDeleteKey)(ck); UN(NtClose)(ck); }
        UN(NtDeleteKey)(k); UN(NtClose)(k); UN(NtClose)(hcu);
    }
    /* a change outside the filter does not fire; deleting and closing the key completes the request */
    k = make_key(&hcu, "n3");
    if (k) {
        ResetEvent(ev); memset(&io, 0xcc, sizeof io);
        EXPECT_EQ(UN(NtNotifyChangeKey)(k, ev, NULL, NULL, &io, 2 /* ATTRIBUTES */, FALSE, NULL, 0, TRUE), PEND);
        EXPECT_EQ(UN(NtSetValueKey)(k, &vn, 0, REG_DWORD, &val, 4), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 200), WAIT_TIMEOUT);
        UN(NtDeleteKey)(k); UN(NtClose)(k);
        EXPECT_EQ(WaitForSingleObject(ev, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, XS(0x10B)); /* STATUS_NOTIFY_CLEANUP */
        UN(NtClose)(hcu);
    }
    EXPECT_EQ(UN(NtNotifyChangeKey)(BADH, NULL, NULL, NULL, &io, 1, FALSE, NULL, 0, FALSE), XS(0xC0000008));
    CloseHandle(ev);
}

TEST(make_temporary_permanent_object)
{
    REQUIRE(UN(NtMakeTemporaryObject)); REQUIRE(UN(NtMakePermanentObject)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtClose));
    HANDLE e = NULL; NTSTATUS s;
    s = UN(NtCreateEvent)(&e, EVENT_ALL_ACCESS | DELETE, NULL, 0, FALSE);
    EXPECT_EQ(s, 0); if (s) return;
    /* temporary object made temporary again: no-op success */
    EXPECT_EQ(UN(NtMakeTemporaryObject)(e), 0);
    EXPECT_EQ(UN(NtMakeTemporaryObject)(e), 0);
    /* permanence needs SeCreatePermanentPrivilege, which neither admins nor users hold by default */
    s = UN(NtMakePermanentObject)(e);
    t_note("NtMakePermanentObject: %08lx", s);
    EXPECT_EQ(s, XS(0xC0000061)); /* STATUS_PRIVILEGE_NOT_HELD */
    UN(NtClose)(e);
    /* handle without DELETE access */
    s = UN(NtCreateEvent)(&e, EVENT_ALL_ACCESS, NULL, 0, FALSE);
    if (s == 0) {
        EXPECT_EQ(UN(NtMakeTemporaryObject)(e), 0);   /* no DELETE access needed on a temporary object (observed) */
        UN(NtClose)(e);
    }
    EXPECT_EQ(UN(NtMakeTemporaryObject)(BADH), XS(0xC0000008));
    EXPECT_EQ(UN(NtMakePermanentObject)(BADH), XS(0xC0000061)); /* the privilege is checked before the handle */
    EXPECT_EQ(UN(NtMakeTemporaryObject)(NULL), XS(0xC0000008));
}


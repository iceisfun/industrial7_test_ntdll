/* Zw-named file, registry, transaction, port, debug and privileged-system services:
 * ZwDeleteFile, ZwFlushBuffersFile(Ex), ZwDeviceIoControlFile, ZwCopyFileChunk, ZwExtendSection,
 * ZwCancelIoFile(Ex), ZwCancelSynchronousIoFile, ZwEnumerateKey, ZwEnumerateValueKey, ZwDeleteKey,
 * ZwDeleteValueKey, ZwCompactKeys, ZwCompressKey, ZwCommit*, ZwEnumerateTransactionObject,
 * ZwConnectPort, ZwCompleteConnectPort, ZwDebug*, WNF deletes, audit alarms, boot/driver entry services,
 * ZwAssignProcessToJobObject, ZwAllocateUserPhysicalPages(Ex), signing-level and counter conversions. */
#include "t.h"
#include <stdlib.h>

#define S(x) ((NTSTATUS)(x))
#define ST_INVALID_HANDLE S(0xC0000008)
#define ST_INVALID_PARAMETER S(0xC000000D)
#define ST_NAME_NOT_FOUND S(0xC0000034)
#define ST_TYPE_MISMATCH S(0xC0000024)
#define ST_ACCESS_DENIED S(0xC0000022)
#define ST_BUFFER_TOO_SMALL S(0xC0000023)
#define ST_BUFFER_OVERFLOW S(0x80000005)
#define ST_NO_MORE_ENTRIES S(0x8000001A)
#define ST_PRIV_NOT_HELD S(0xC0000061)
#define PROBE(what, st) t_note("%s -> 0x%08lx", what, (unsigned long)(st))
#define BADH ((HANDLE)(ULONG_PTR)0x7777770)

UDECL(NTSTATUS, ZwDeleteFile, (POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwFlushBuffersFile, (HANDLE, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, ZwFlushBuffersFileEx, (HANDLE, ULONG, PVOID, ULONG, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, ZwDeviceIoControlFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, ZwCopyFileChunk, (HANDLE, HANDLE, HANDLE, PIO_STATUS_BLOCK, ULONG, PLARGE_INTEGER, PLARGE_INTEGER, PULONG, PULONG, ULONG));
UDECL(NTSTATUS, ZwExtendSection, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwCancelIoFile, (HANDLE, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, ZwCancelIoFileEx, (HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, ZwCancelSynchronousIoFile, (HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtCreateSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE));
UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, RtlOpenCurrentUser, (ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, ZwEnumerateKey, (HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, ZwEnumerateValueKey, (HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, ZwDeleteKey, (HANDLE));
UDECL(NTSTATUS, ZwDeleteValueKey, (HANDLE, PUNICODE_STRING));
UDECL(NTSTATUS, ZwCompactKeys, (ULONG, PHANDLE));
UDECL(NTSTATUS, ZwCompressKey, (HANDLE));
UDECL(NTSTATUS, ZwCommitTransaction, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, ZwCommitComplete, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwCommitEnlistment, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwCommitRegistryTransaction, (HANDLE, ULONG));
UDECL(NTSTATUS, ZwEnumerateTransactionObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateRegistryTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, ZwConnectPort, (PHANDLE, PUNICODE_STRING, PSECURITY_QUALITY_OF_SERVICE, PVOID, PVOID, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, ZwCompleteConnectPort, (HANDLE));
UDECL(NTSTATUS, ZwDebugActiveProcess, (HANDLE, HANDLE));
UDECL(NTSTATUS, ZwDebugContinue, (HANDLE, PCLIENT_ID, NTSTATUS));
UDECL(NTSTATUS, NtCreateDebugObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, ZwDeleteWnfStateData, (PVOID, PVOID));
UDECL(NTSTATUS, ZwDeleteWnfStateName, (PVOID));
UDECL(NTSTATUS, ZwDeletePrivateNamespace, (HANDLE));
UDECL(NTSTATUS, ZwCloseObjectAuditAlarm, (PUNICODE_STRING, PVOID, BOOLEAN));
UDECL(NTSTATUS, ZwDeleteObjectAuditAlarm, (PUNICODE_STRING, PVOID, BOOLEAN));
UDECL(NTSTATUS, ZwAddBootEntry, (PVOID, PULONG));
UDECL(NTSTATUS, ZwDeleteBootEntry, (ULONG));
UDECL(NTSTATUS, ZwEnumerateBootEntries, (PVOID, PULONG));
UDECL(NTSTATUS, ZwFilterBootOption, (ULONG, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, ZwAddDriverEntry, (PVOID, PULONG));
UDECL(NTSTATUS, ZwDeleteDriverEntry, (ULONG));
UDECL(NTSTATUS, ZwEnumerateDriverEntries, (PVOID, PULONG));
UDECL(NTSTATUS, ZwEnumerateSystemEnvironmentValuesEx, (ULONG, PVOID, PULONG));
UDECL(NTSTATUS, ZwDisableLastKnownGood, (void));
UDECL(NTSTATUS, ZwEnableLastKnownGood, (void));
UDECL(NTSTATUS, ZwAssignProcessToJobObject, (HANDLE, HANDLE));
UDECL(NTSTATUS, ZwAllocateUserPhysicalPages, (HANDLE, PULONG_PTR, PULONG_PTR));
UDECL(NTSTATUS, ZwAllocateUserPhysicalPagesEx, (HANDLE, PULONG_PTR, PULONG_PTR, PVOID, ULONG));
UDECL(NTSTATUS, ZwCompareSigningLevels, (ULONG, ULONG));
UDECL(NTSTATUS, ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter, (BOOLEAN, PULONGLONG, PULONGLONG, PULONGLONG));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, PVOID, ULONG, BOOLEAN));

TEST(alias_pairs)
{
    static const char *n[] = {"DeleteFile","FlushBuffersFile","FlushBuffersFileEx","DeviceIoControlFile","CopyFileChunk",
        "ExtendSection","CancelIoFile","CancelIoFileEx","CancelSynchronousIoFile","EnumerateKey","EnumerateValueKey",
        "DeleteKey","DeleteValueKey","CompactKeys","CompressKey","CommitTransaction","CommitComplete","CommitEnlistment",
        "CommitRegistryTransaction","EnumerateTransactionObject","ConnectPort","CompleteConnectPort","DebugActiveProcess",
        "DebugContinue","DeleteWnfStateData","DeleteWnfStateName","DeletePrivateNamespace","CloseObjectAuditAlarm",
        "DeleteObjectAuditAlarm","AddBootEntry","DeleteBootEntry","EnumerateBootEntries","FilterBootOption","AddDriverEntry",
        "DeleteDriverEntry","EnumerateDriverEntries","EnumerateSystemEnvironmentValuesEx","DisableLastKnownGood",
        "EnableLastKnownGood","AssignProcessToJobObject","AllocateUserPhysicalPages","AllocateUserPhysicalPagesEx",
        "CompareSigningLevels","ConvertBetweenAuxiliaryCounterAndPerformanceCounter"};
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[96], b[96];
        wsprintfA(a, "Nt%s", n[i]); wsprintfA(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a), pb = t_proc(b);
        if (!pa && !pb) { t_note("%s absent", n[i]); continue; }
        CHECKF(pa == pb, "%s: Nt/Zw differ", n[i]);
    }
}

/* ---- files ------------------------------------------------------------ */
static void nt_path(WCHAR *out, const char *leaf)
{
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, leaf);
    wsprintfW(out, L"\\??\\%S", p);
}
static void init_oa(OBJECT_ATTRIBUTES *oa, UNICODE_STRING *us, WCHAR *w)
{
    us->Buffer = w; us->Length = (USHORT)(lstrlenW(w) * 2); us->MaximumLength = us->Length + 2;
    memset(oa, 0, sizeof *oa); oa->Length = sizeof *oa; oa->ObjectName = us; oa->Attributes = OBJ_CASE_INSENSITIVE;
}
static HANDLE mk_file(const char *leaf, DWORD access, DWORD share)
{
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, leaf);
    return CreateFileA(p, access, share, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

TEST(delete_file)
{
    REQUIRE(UN(ZwDeleteFile));
    WCHAR w[MAX_PATH + 8]; UNICODE_STRING us; OBJECT_ATTRIBUTES oa;
    nt_path(w, "no2b_del.tmp"); init_oa(&oa, &us, w);
    HANDLE h = mk_file("no2b_del.tmp", GENERIC_WRITE, 0);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    EXPECT_EQ(UN(ZwDeleteFile)(&oa), S(0xC0000043));          /* sharing violation: handle open without FILE_SHARE_DELETE */
    CloseHandle(h);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "no2b_del.tmp");
    CHECK(GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES);
    EXPECT_EQ(UN(ZwDeleteFile)(&oa), 0);
    CHECK(GetFileAttributesA(p) == INVALID_FILE_ATTRIBUTES);
    EXPECT_EQ(UN(ZwDeleteFile)(&oa), ST_NAME_NOT_FOUND);
    /* a handle with share-delete: delete succeeds and the name disappears */
    h = mk_file("no2b_del.tmp", GENERIC_WRITE, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE);
    if (h != INVALID_HANDLE_VALUE) {
        EXPECT_EQ(UN(ZwDeleteFile)(&oa), 0);
        CloseHandle(h);
        CHECK(GetFileAttributesA(p) == INVALID_FILE_ATTRIBUTES);
    }
    /* read-only file */
    h = mk_file("no2b_del.tmp", GENERIC_WRITE, 0);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h); SetFileAttributesA(p, FILE_ATTRIBUTE_READONLY);
        EXPECT_EQ(UN(ZwDeleteFile)(&oa), S(0xC0000121));      /* STATUS_CANNOT_DELETE */
        SetFileAttributesA(p, FILE_ATTRIBUTE_NORMAL); DeleteFileA(p);
    }
    /* non-empty directory */
    char d[MAX_PATH], f[MAX_PATH]; t_tmpfile(d, sizeof d, "no2b_dir");
    WCHAR dw[MAX_PATH + 8]; wsprintfW(dw, L"\\??\\%S", d);
    if (CreateDirectoryA(d, NULL)) {
        wsprintfA(f, "%s\\x", d); HANDLE fh = CreateFileA(f, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        OBJECT_ATTRIBUTES doa; UNICODE_STRING dus; init_oa(&doa, &dus, dw);
        NTSTATUS dst = UN(ZwDeleteFile)(&doa);                 /* delete-on-close of a non-empty directory fails silently */
        CHECK(dst == 0 || dst == S(0xC0000101));
        CHECK(GetFileAttributesA(d) != INVALID_FILE_ATTRIBUTES);
        if (fh != INVALID_HANDLE_VALUE) CloseHandle(fh);
        DeleteFileA(f);
        EXPECT_EQ(UN(ZwDeleteFile)(&doa), 0);
        RemoveDirectoryA(d);
    }
    EXPECT_EQ(UN(ZwDeleteFile)(NULL), ST_INVALID_PARAMETER);
}

TEST(flush_buffers)
{
    REQUIRE(UN(ZwFlushBuffersFile));
    HANDLE h = mk_file("no2b_fl.tmp", GENERIC_READ | GENERIC_WRITE, 0), ro;
    REQUIRE(h != INVALID_HANDLE_VALUE);
    DWORD n; WriteFile(h, "abc", 3, &n, NULL);
    IO_STATUS_BLOCK io; memset(&io, 0xCC, sizeof io);
    EXPECT_EQ(UN(ZwFlushBuffersFile)(h, &io), 0);
    EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 0);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "no2b_fl.tmp");
    ro = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (ro != INVALID_HANDLE_VALUE) {
        memset(&io, 0xCC, sizeof io);
        EXPECT_EQ(UN(ZwFlushBuffersFile)(ro, &io), ST_ACCESS_DENIED);
        CloseHandle(ro);
    }
    EXPECT_EQ(UN(ZwFlushBuffersFile)(NULL, &io), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwFlushBuffersFile)(BADH, &io), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwFlushBuffersFile)(h, NULL), S(0xC0000005));
    if (UN(ZwFlushBuffersFileEx)) {
        memset(&io, 0xCC, sizeof io);
        EXPECT_EQ(UN(ZwFlushBuffersFileEx)(h, 0, NULL, 0, &io), 0);
        EXPECT_EQ(io.Status, 0);
        EXPECT_EQ(UN(ZwFlushBuffersFileEx)(h, 1, NULL, 0, &io), 0);              /* FLUSH_FLAGS_FILE_DATA_ONLY */
        PROBE("FlushBuffersFileEx flags 0x80", UN(ZwFlushBuffersFileEx)(h, 0x80, NULL, 0, &io));
        EXPECT_EQ(UN(ZwFlushBuffersFileEx)(NULL, 0, NULL, 0, &io), ST_INVALID_HANDLE);
    } else t_note("NtFlushBuffersFileEx missing");
    CloseHandle(h); DeleteFileA(p);
}

/* ZwDeviceIoControlFile rejects FSCTL (FILE_DEVICE_FILE_SYSTEM) codes with STATUS_INVALID_PARAMETER; a real
 * device control (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS on the system volume) is used for the success path. */
TEST(device_io_control)
{
    REQUIRE(UN(ZwDeviceIoControlFile));
    char sys[MAX_PATH], vol[8] = "\\\\.\\C:";
    GetSystemDirectoryA(sys, sizeof sys); vol[4] = sys[0];
    HANDLE v = CreateFileA(vol, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    IO_STATUS_BLOCK io; BYTE out[256]; memset(&io, 0xCC, sizeof io);
    HANDLE f = mk_file("no2b_ioc.tmp", GENERIC_READ | GENERIC_WRITE, 0);
    if (f != INVALID_HANDLE_VALUE) {
        USHORT fmt = 0x5555;
        EXPECT_EQ(UN(ZwDeviceIoControlFile)(f, NULL, NULL, NULL, &io, 0x9003C, NULL, 0, &fmt, sizeof fmt), ST_INVALID_PARAMETER);
        EXPECT_EQ(fmt, 0x5555);
        EXPECT_EQ(UN(ZwDeviceIoControlFile)(NULL, NULL, NULL, NULL, &io, 0x560000, NULL, 0, out, sizeof out), ST_INVALID_HANDLE);
        EXPECT_EQ(UN(ZwDeviceIoControlFile)(BADH, NULL, NULL, NULL, &io, 0x560000, NULL, 0, out, sizeof out), ST_INVALID_HANDLE);
        HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
        EXPECT_EQ(UN(ZwDeviceIoControlFile)(ev, NULL, NULL, NULL, &io, 0x560000, NULL, 0, out, sizeof out), ST_TYPE_MISMATCH);
        CloseHandle(ev); CloseHandle(f);
        char p[MAX_PATH]; t_tmpfile(p, sizeof p, "no2b_ioc.tmp"); DeleteFileA(p);
    }
    if (v == INVALID_HANDLE_VALUE) { t_skip("cannot open system volume with zero access (%lu)", GetLastError()); return; }
    memset(&io, 0xCC, sizeof io); memset(out, 0xCC, sizeof out);
    NTSTATUS st = UN(ZwDeviceIoControlFile)(v, NULL, NULL, NULL, &io, 0x560000, NULL, 0, out, sizeof out);
    if (st == S(0xC0000010) || st == S(0xC00000BB)) { t_skip("volume has no disk extents ioctl (0x%08lx)", (unsigned long)st); CloseHandle(v); return; }
    EXPECT_EQ(st, 0);
    CHECK(*(ULONG *)out >= 1);
    EXPECT_EQ(io.Status, 0); CHECK(io.Information >= 32);
    EXPECT_EQ(io.Information, 8 + 24 * *(ULONG *)out);
    memset(&io, 0xCC, sizeof io); memset(out, 0xCC, sizeof out);
    /* short output buffers: the status is up to the volume stack (observed STATUS_INVALID_PARAMETER) */
    PROBE("disk extents, 4-byte output", UN(ZwDeviceIoControlFile)(v, NULL, NULL, NULL, &io, 0x560000, NULL, 0, out, 4));
    EXPECT_EQ(UN(ZwDeviceIoControlFile)(v, NULL, NULL, NULL, NULL, 0x560000, NULL, 0, out, sizeof out), S(0xC0000005));
    CloseHandle(v);
}

TEST(copy_file_chunk)
{
    REQUIRE(UN(ZwCopyFileChunk));
    HANDLE s = mk_file("no2b_cs.tmp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ), d = mk_file("no2b_cd.tmp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ);
    REQUIRE(s != INVALID_HANDLE_VALUE && d != INVALID_HANDLE_VALUE);
    DWORD n; char buf[4096]; memset(buf, 'q', sizeof buf); WriteFile(s, buf, sizeof buf, &n, NULL);
    IO_STATUS_BLOCK io; LARGE_INTEGER so = {{0}}, doff = {{0}}; memset(&io, 0xCC, sizeof io);
    NTSTATUS st = UN(ZwCopyFileChunk)(s, d, NULL, &io, 1024, &so, &doff, NULL, NULL, 0);
    EXPECT_EQ(st, 0); EXPECT_EQ(io.Information, 1024);
    { char rb[1024]; memset(rb, 0, sizeof rb); SetFilePointer(d, 0, NULL, FILE_BEGIN); DWORD rn = 0;
      CHECK(ReadFile(d, rb, sizeof rb, &rn, NULL)); EXPECT_EQ(rn, 1024); CHECK(rb[0] == 'q' && rb[1023] == 'q'); }
    EXPECT_EQ(UN(ZwCopyFileChunk)(NULL, d, NULL, &io, 1024, &so, &doff, NULL, NULL, 0), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwCopyFileChunk)(s, NULL, NULL, &io, 1024, &so, &doff, NULL, NULL, 0), ST_INVALID_HANDLE);
    CloseHandle(s); CloseHandle(d);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "no2b_cs.tmp"); DeleteFileA(p); t_tmpfile(p, sizeof p, "no2b_cd.tmp"); DeleteFileA(p);
}

TEST(extend_section)
{
    REQUIRE(UN(ZwExtendSection)); REQUIRE(UN(NtCreateSection));
    LARGE_INTEGER sz; HANDLE sec = NULL; sz.QuadPart = 0x2000;
    EXPECT_EQ(UN(NtCreateSection)(&sec, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT, NULL), 0);
    LARGE_INTEGER ns; ns.QuadPart = 0x4000;
    NTSTATUS st = UN(ZwExtendSection)(sec, &ns);
    EXPECT_EQ(st, S(0xC0000087));          /* STATUS_SECTION_NOT_EXTENDED: only file-backed sections extend */
    EXPECT_EQ(UN(ZwExtendSection)(NULL, &ns), ST_INVALID_HANDLE);
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwExtendSection)(ev, &ns), ST_TYPE_MISMATCH);
    CloseHandle(ev);
    EXPECT_EQ(UN(ZwExtendSection)(sec, NULL), S(0xC0000005));
    CloseHandle(sec);
}

TEST(cancel_io_idle)
{
    REQUIRE(UN(ZwCancelIoFile)); REQUIRE(UN(ZwCancelIoFileEx)); REQUIRE(UN(ZwCancelSynchronousIoFile));
    HANDLE h = mk_file("no2b_ci.tmp", GENERIC_READ | GENERIC_WRITE, 0);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    IO_STATUS_BLOCK io; memset(&io, 0xCC, sizeof io);
    EXPECT_EQ(UN(ZwCancelIoFile)(h, &io), 0); EXPECT_EQ(io.Status, 0); EXPECT_EQ(io.Information, 0);
    memset(&io, 0xCC, sizeof io);
    EXPECT_EQ(UN(ZwCancelIoFileEx)(h, NULL, &io), S(0xC0000225));
    EXPECT_EQ(io.Status, S(0xC0000225));
    memset(&io, 0xCC, sizeof io);
    EXPECT_EQ(UN(ZwCancelSynchronousIoFile)((HANDLE)(LONG_PTR)-2, NULL, &io), S(0xC0000225));
    EXPECT_EQ(UN(ZwCancelIoFile)(NULL, &io), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwCancelIoFileEx)(BADH, NULL, &io), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwCancelSynchronousIoFile)(BADH, NULL, &io), ST_INVALID_HANDLE);
    CloseHandle(h);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "no2b_ci.tmp"); DeleteFileA(p);
}

/* ---- registry --------------------------------------------------------- */
static HANDLE make_key(HANDLE root, const WCHAR *name, ACCESS_MASK acc)
{
    WCHAR w[128]; lstrcpyW(w, name);
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; init_oa(&oa, &us, w); oa.RootDirectory = root;
    HANDLE h = NULL; ULONG disp;
    NTSTATUS st = UN(NtCreateKey)(&h, acc, &oa, 0, NULL, 0, &disp);
    EXPECT_EQ(st, 0);
    return st == 0 ? h : NULL;
}
static void setval(HANDLE k, const WCHAR *name, ULONG type, void *d, ULONG n)
{
    UNICODE_STRING us; us.Buffer = (PWSTR)name; us.Length = (USHORT)(lstrlenW(name) * 2); us.MaximumLength = us.Length + 2;
    EXPECT_EQ(UN(NtSetValueKey)(k, &us, 0, type, d, n), 0);
}

static HANDLE open_hkcu(void)
{
    HANDLE h = NULL;
    if (!UN(RtlOpenCurrentUser) || UN(RtlOpenCurrentUser)(KEY_ALL_ACCESS, &h) != 0) return NULL;
    return h;
}

#define NEEDREG() do { REQUIRE(UN(NtCreateKey)); REQUIRE(UN(NtSetValueKey)); REQUIRE(UN(RtlOpenCurrentUser)); } while (0)

static void us_set(UNICODE_STRING *us, const WCHAR *w) { us->Buffer = (PWSTR)w; us->Length = (USHORT)(lstrlenW(w) * 2); us->MaximumLength = us->Length + 2; }

/* KEY_BASIC_INFORMATION: LastWriteTime(8) TitleIndex(4) NameLength(4) Name */
static int key_name_is(BYTE *b, const WCHAR *want)
{
    ULONG len = *(ULONG *)(b + 12);
    return len == (ULONG)lstrlenW(want) * 2 && !memcmp(b + 16, want, len);
}

TEST(registry_enum_delete)
{
    NEEDREG(); REQUIRE(UN(ZwEnumerateKey)); REQUIRE(UN(ZwEnumerateValueKey)); REQUIRE(UN(ZwDeleteKey)); REQUIRE(UN(ZwDeleteValueKey));
    HANDLE root = open_hkcu();
    REQUIRE(root);
    WCHAR kn[64]; wsprintfW(kn, L"Software\\NO2B_%lu", GetCurrentProcessId());
    HANDLE k = make_key(root, kn, KEY_ALL_ACCESS);
    if (!k) { CloseHandle(root); return; }
    HANDLE s1 = make_key(k, L"s1", KEY_ALL_ACCESS), s2 = make_key(k, L"s2", KEY_ALL_ACCESS);
    ULONG dw = 0x1234; static const WCHAR str[] = L"hello";
    setval(k, L"a", REG_DWORD, &dw, 4);
    setval(k, L"bb", REG_SZ, (void *)str, sizeof str);

    BYTE buf[512]; ULONG rl;
    /* subkeys: s1, s2 in some order */
    int seen1 = 0, seen2 = 0;
    for (ULONG i = 0; i < 2; i++) {
        memset(buf, 0xCC, sizeof buf); rl = 0;
        EXPECT_EQ(UN(ZwEnumerateKey)(k, i, 0, buf, sizeof buf, &rl), 0);
        EXPECT_EQ(rl, 16 + 4);
        if (key_name_is(buf, L"s1")) seen1++; else if (key_name_is(buf, L"s2")) seen2++;
    }
    EXPECT_EQ(seen1, 1); EXPECT_EQ(seen2, 1);
    EXPECT_EQ(UN(ZwEnumerateKey)(k, 2, 0, buf, sizeof buf, &rl), ST_NO_MORE_ENTRIES);
    /* buffer handling */
    rl = 0; EXPECT_EQ(UN(ZwEnumerateKey)(k, 0, 0, buf, 0, &rl), ST_BUFFER_TOO_SMALL); EXPECT_EQ(rl, 20);
    memset(buf, 0xCC, sizeof buf); rl = 0;
    EXPECT_EQ(UN(ZwEnumerateKey)(k, 0, 0, buf, 17, &rl), ST_BUFFER_OVERFLOW); EXPECT_EQ(rl, 20);
    EXPECT_EQ(*(ULONG *)(buf + 12), 4);
    /* node information (class 1): adds ClassOffset/ClassLength */
    rl = 0; EXPECT_EQ(UN(ZwEnumerateKey)(k, 0, 1, buf, sizeof buf, &rl), 0); CHECK(rl >= 24 + 4);
    /* full information (class 2) is not valid for enumeration */
    rl = 0; NTSTATUS st = UN(ZwEnumerateKey)(k, 0, 2, buf, sizeof buf, &rl);
    EXPECT_EQ(st, 0);                                              /* observed: accepted */
    st = UN(ZwEnumerateKey)(k, 0, 99, buf, sizeof buf, &rl); EXPECT_EQ(st, ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(ZwEnumerateKey)(NULL, 0, 0, buf, sizeof buf, &rl), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwEnumerateKey)(k, 0, 0, buf, sizeof buf, NULL), S(0xC0000005));

    /* values: a (DWORD) and bb (SZ) */
    int sa = 0, sb = 0;
    for (ULONG i = 0; i < 2; i++) {
        memset(buf, 0xCC, sizeof buf); rl = 0;
        EXPECT_EQ(UN(ZwEnumerateValueKey)(k, i, 0, buf, sizeof buf, &rl), 0);    /* KeyValueBasicInformation: TitleIndex Type NameLength Name */
        ULONG type = *(ULONG *)(buf + 4), nl = *(ULONG *)(buf + 8); WCHAR *nm = (WCHAR *)(buf + 12);
        EXPECT_EQ(rl, 12 + nl);
        if (nl == 2 && nm[0] == L'a') { sa++; EXPECT_EQ(type, REG_DWORD); }
        else if (nl == 4 && nm[0] == L'b' && nm[1] == L'b') { sb++; EXPECT_EQ(type, REG_SZ); }
    }
    EXPECT_EQ(sa, 1); EXPECT_EQ(sb, 1);
    EXPECT_EQ(UN(ZwEnumerateValueKey)(k, 2, 0, buf, sizeof buf, &rl), ST_NO_MORE_ENTRIES);
    /* partial information (class 2): TitleIndex Type DataLength Data */
    for (ULONG i = 0; i < 2; i++) {
        memset(buf, 0xCC, sizeof buf); rl = 0;
        EXPECT_EQ(UN(ZwEnumerateValueKey)(k, i, 2, buf, sizeof buf, &rl), 0);
        ULONG type = *(ULONG *)(buf + 4), dl = *(ULONG *)(buf + 8);
        EXPECT_EQ(rl, 12 + dl);
        if (type == REG_DWORD) { EXPECT_EQ(dl, 4); EXPECT_EQ(*(ULONG *)(buf + 12), 0x1234); }
        else { EXPECT_EQ(type, REG_SZ); EXPECT_EQ(dl, sizeof str); CHECK(!memcmp(buf + 12, str, sizeof str)); }
    }
    /* full information (class 1) */
    rl = 0; EXPECT_EQ(UN(ZwEnumerateValueKey)(k, 0, 1, buf, sizeof buf, &rl), 0); CHECK(rl >= 20);
    rl = 0; EXPECT_EQ(UN(ZwEnumerateValueKey)(k, 0, 1, buf, 8, &rl), ST_BUFFER_TOO_SMALL); CHECK(rl >= 20);
    rl = 0; EXPECT_EQ(UN(ZwEnumerateValueKey)(k, 0, 0, buf, 13, &rl), ST_BUFFER_OVERFLOW);
    EXPECT_EQ(UN(ZwEnumerateValueKey)(k, 0, 99, buf, sizeof buf, &rl), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(ZwEnumerateValueKey)(NULL, 0, 0, buf, sizeof buf, &rl), ST_INVALID_HANDLE);

    /* delete value */
    UNICODE_STRING un; us_set(&un, L"bb");
    EXPECT_EQ(UN(ZwDeleteValueKey)(k, &un), 0);
    EXPECT_EQ(UN(ZwDeleteValueKey)(k, &un), ST_NAME_NOT_FOUND);
    us_set(&un, L"A");                                               /* value names are case-insensitive */
    EXPECT_EQ(UN(ZwDeleteValueKey)(k, &un), 0);
    EXPECT_EQ(UN(ZwEnumerateValueKey)(k, 0, 0, buf, sizeof buf, &rl), ST_NO_MORE_ENTRIES);
    EXPECT_EQ(UN(ZwDeleteValueKey)(NULL, &un), ST_INVALID_HANDLE);
    /* value delete on a read-only handle */
    HANDLE ro = NULL; { WCHAR w[128]; lstrcpyW(w, kn); UNICODE_STRING us; OBJECT_ATTRIBUTES oa; init_oa(&oa, &us, w); oa.RootDirectory = root;
        EXPECT_EQ(UN(NtOpenKey)(&ro, KEY_READ, &oa), 0); }
    if (ro) { us_set(&un, L"zz"); EXPECT_EQ(UN(ZwDeleteValueKey)(ro, &un), ST_ACCESS_DENIED);
        EXPECT_EQ(UN(ZwDeleteKey)(ro), ST_ACCESS_DENIED); CloseHandle(ro); }

    /* delete key: refused while subkeys exist */
    EXPECT_EQ(UN(ZwDeleteKey)(k), S(0xC0000121));
    EXPECT_EQ(UN(ZwDeleteKey)(s1), 0);
    EXPECT_EQ(UN(ZwEnumerateKey)(s1, 0, 0, buf, sizeof buf, &rl), S(0xC000017C));   /* STATUS_KEY_DELETED */
    EXPECT_EQ(UN(ZwDeleteKey)(s1), 0);                                              /* observed: repeat is accepted */
    EXPECT_EQ(UN(ZwDeleteKey)(s2), 0);
    EXPECT_EQ(UN(ZwDeleteKey)(k), 0);
    EXPECT_EQ(UN(ZwDeleteKey)(NULL), ST_INVALID_HANDLE);
    CloseHandle(s1); CloseHandle(s2); CloseHandle(k); CloseHandle(root);
}

/* Both services check SeBackupPrivilege/SeRestorePrivilege-class rights before looking at any argument;
 * the privileges are never enabled here, so every call fails with STATUS_PRIVILEGE_NOT_HELD. */
TEST(registry_compact_compress)
{
    NEEDREG(); REQUIRE(UN(ZwCompactKeys)); REQUIRE(UN(ZwCompressKey));
    HANDLE root = open_hkcu(); REQUIRE(root);
    WCHAR kn[64]; wsprintfW(kn, L"Software\\NO2C_%lu", GetCurrentProcessId());
    HANDLE k = make_key(root, kn, KEY_ALL_ACCESS);
    if (k) {
        EXPECT_EQ(UN(ZwCompressKey)(k), ST_PRIV_NOT_HELD);
        HANDLE hs[1] = {k};
        EXPECT_EQ(UN(ZwCompactKeys)(1, hs), ST_PRIV_NOT_HELD);
        EXPECT_EQ(UN(ZwCompactKeys)(0, hs), ST_PRIV_NOT_HELD);
        EXPECT_EQ(UN(ZwCompactKeys)(1, NULL), ST_PRIV_NOT_HELD);
        UN(ZwDeleteKey)(k); CloseHandle(k);
    }
    EXPECT_EQ(UN(ZwCompressKey)(NULL), ST_PRIV_NOT_HELD);
    CloseHandle(root);
}

/* ---- transactions ------------------------------------------------------ */
TEST(commit_transaction)
{
    REQUIRE(UN(ZwCommitTransaction)); REQUIRE(UN(ZwCommitComplete)); REQUIRE(UN(ZwCommitEnlistment));
    EXPECT_EQ(UN(ZwCommitTransaction)(NULL, TRUE), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwCommitTransaction)(BADH, FALSE), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwCommitComplete)(NULL, NULL), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwCommitEnlistment)(NULL, NULL), ST_INVALID_HANDLE);
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwCommitTransaction)(ev, TRUE), ST_TYPE_MISMATCH);
    EXPECT_EQ(UN(ZwCommitComplete)(ev, NULL), ST_TYPE_MISMATCH);
    EXPECT_EQ(UN(ZwCommitEnlistment)(ev, NULL), ST_TYPE_MISMATCH);
    CloseHandle(ev);
    if (UN(NtCreateTransaction)) {
        HANDLE tx = NULL;
        NTSTATUS st = UN(NtCreateTransaction)(&tx, 0x1F003F, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
        if (st != 0) t_note("NtCreateTransaction -> 0x%08lx", (unsigned long)st);
        if (st == 0) {
            st = UN(ZwCommitTransaction)(tx, TRUE); EXPECT_EQ(st, 0);
            st = UN(ZwCommitTransaction)(tx, TRUE); EXPECT_EQ(st, S(0xC0190016));   /* STATUS_TRANSACTION_ALREADY_COMMITTED */
            EXPECT_EQ(UN(ZwCommitComplete)(tx, NULL), ST_TYPE_MISMATCH);
            EXPECT_EQ(UN(ZwCommitEnlistment)(tx, NULL), ST_TYPE_MISMATCH);
            CloseHandle(tx);
        }
    }
}

TEST(commit_registry_transaction)
{
    REQUIRE(UN(ZwCommitRegistryTransaction));
    EXPECT_EQ(UN(ZwCommitRegistryTransaction)(NULL, 0), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwCommitRegistryTransaction)(BADH, 0), ST_INVALID_HANDLE);
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwCommitRegistryTransaction)(ev, 0), ST_TYPE_MISMATCH);
    CloseHandle(ev);
    if (UN(NtCreateRegistryTransaction)) {
        HANDLE tx = NULL; NTSTATUS st = UN(NtCreateRegistryTransaction)(&tx, 0x1F003F, NULL, 0);
        EXPECT_EQ(st, 0);
        if (st == 0) {
            EXPECT_EQ(UN(ZwCommitRegistryTransaction)(tx, 1), ST_INVALID_PARAMETER);
            EXPECT_EQ(UN(ZwCommitRegistryTransaction)(tx, 0), 0);
            EXPECT_EQ(UN(ZwCommitRegistryTransaction)(tx, 0), S(0xC0190003));   /* STATUS_TRANSACTION_NOT_ACTIVE */
            CloseHandle(tx);
        }
    }
}

TEST(enumerate_transaction_object)
{
    REQUIRE(UN(ZwEnumerateTransactionObject));
    BYTE b[64]; ULONG rl = 0xCC;
    EXPECT_EQ(UN(ZwEnumerateTransactionObject)(NULL, 0, b, sizeof b, &rl), ST_NO_MORE_ENTRIES);
    EXPECT_EQ(UN(ZwEnumerateTransactionObject)(BADH, 0, b, sizeof b, &rl), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwEnumerateTransactionObject)(NULL, 0, b, 0, &rl), ST_INVALID_PARAMETER);
}

/* ---- ports, debug objects, wnf, private namespace --------------------- */
TEST(connect_port)
{
    REQUIRE(UN(ZwConnectPort)); REQUIRE(UN(ZwCompleteConnectPort));
    HANDLE p = NULL; UNICODE_STRING us; WCHAR nm[] = L"\\NO2BNoSuchPort";
    us_set(&us, nm);
    SECURITY_QUALITY_OF_SERVICE q = {sizeof q, SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE};
    EXPECT_EQ(UN(ZwConnectPort)(&p, &us, &q, NULL, NULL, NULL, NULL, NULL), ST_NAME_NOT_FOUND);
    CHECK(p == NULL);
    WCHAR nm2[] = L"\\Windows\\ApiPort_NO2B_missing"; us_set(&us, nm2);
    EXPECT_EQ(UN(ZwConnectPort)(&p, &us, &q, NULL, NULL, NULL, NULL, NULL), ST_NAME_NOT_FOUND);
    WCHAR nm3[] = L"NO2BRelative"; us_set(&us, nm3);
    NTSTATUS st = UN(ZwConnectPort)(&p, &us, &q, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(st, S(0xC000003B));                                 /* STATUS_OBJECT_PATH_SYNTAX_BAD */
    /* observed: user-mode NtCompleteConnectPort is a no-op that never inspects the handle */
    EXPECT_EQ(UN(ZwCompleteConnectPort)(NULL), 0);
    EXPECT_EQ(UN(ZwCompleteConnectPort)(BADH), 0);
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwCompleteConnectPort)(ev), 0);
    CloseHandle(ev);
}

TEST(debug_services)
{
    REQUIRE(UN(ZwDebugActiveProcess)); REQUIRE(UN(ZwDebugContinue));
    CLIENT_ID cid; memset(&cid, 0, sizeof cid);
    EXPECT_EQ(UN(ZwDebugContinue)(NULL, &cid, 0x00010002), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwDebugContinue)(BADH, &cid, 0x00010002), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwDebugActiveProcess)(NULL, NULL), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwDebugActiveProcess)(BADH, BADH), ST_INVALID_HANDLE);
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwDebugContinue)(ev, &cid, 0x00010002), ST_TYPE_MISMATCH);
    EXPECT_EQ(UN(ZwDebugActiveProcess)(ev, ev), ST_TYPE_MISMATCH);
    CloseHandle(ev);
    if (UN(NtCreateDebugObject)) {
        HANDLE dbg = NULL;
        EXPECT_EQ(UN(NtCreateDebugObject)(&dbg, 0x1F000F, NULL, 0), 0);
        if (dbg) {
            EXPECT_EQ(UN(ZwDebugContinue)(dbg, &cid, 0x00010002), ST_INVALID_PARAMETER);   /* no such pending event */
            EXPECT_EQ(UN(ZwDebugContinue)(dbg, &cid, 5), ST_INVALID_PARAMETER);       /* not a DBG_* continue status */
            EXPECT_EQ(UN(ZwDebugContinue)(dbg, NULL, 0x00010002), S(0xC0000005));
            EXPECT_EQ(UN(ZwDebugActiveProcess)(BADH, dbg), ST_INVALID_HANDLE);
            CloseHandle(dbg);
        }
    }
}

TEST(wnf_deletes)
{
    REQUIRE(UN(ZwDeleteWnfStateData)); REQUIRE(UN(ZwDeleteWnfStateName));
    ULONG64 name = 0x41C64E6DA3BC0074ULL;      /* well-formed lifetime/scope bits but not a registered name */
    EXPECT_EQ(UN(ZwDeleteWnfStateData)(&name, NULL), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(ZwDeleteWnfStateName)(&name), ST_INVALID_PARAMETER);
    ULONG64 zero = 0;
    EXPECT_EQ(UN(ZwDeleteWnfStateData)(&zero, NULL), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(ZwDeleteWnfStateName)(&zero), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(ZwDeleteWnfStateData)(NULL, NULL), S(0xC0000005));
    EXPECT_EQ(UN(ZwDeleteWnfStateName)(NULL), S(0xC0000005));
}

TEST(private_namespace)
{
    REQUIRE(UN(ZwDeletePrivateNamespace));
    EXPECT_EQ(UN(ZwDeletePrivateNamespace)(NULL), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwDeletePrivateNamespace)(BADH), ST_INVALID_HANDLE);
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwDeletePrivateNamespace)(ev), ST_TYPE_MISMATCH);
    CloseHandle(ev);
}

/* ---- privileged / system services (never enable the privileges) -------- */
TEST(audit_alarm)
{
    REQUIRE(UN(ZwCloseObjectAuditAlarm)); REQUIRE(UN(ZwDeleteObjectAuditAlarm));
    UNICODE_STRING us; us_set(&us, L"NO2B");
    /* observed: success without the audit privilege (no auditing is configured for the unknown subsystem/handle) */
    EXPECT_EQ(UN(ZwCloseObjectAuditAlarm)(&us, (PVOID)1, FALSE), 0);
    EXPECT_EQ(UN(ZwDeleteObjectAuditAlarm)(&us, (PVOID)1, FALSE), 0);
    EXPECT_EQ(UN(ZwCloseObjectAuditAlarm)(NULL, NULL, FALSE), 0);
}

#define FAILS(call) do { NTSTATUS st_ = (call); CHECKF(((ULONG)st_ >> 30) == 3, "%s -> 0x%08lx", #call, (unsigned long)st_); } while (0)
/* Without SeSystemEnvironmentPrivilege (never enabled here) the boot/driver entry and firmware variable
 * services fail with an error status: STATUS_NOT_IMPLEMENTED on machines without such firmware services, or
 * STATUS_PRIVILEGE_NOT_HELD. The call arguments are invalid or inert so nothing could be changed anyway. */
TEST(boot_driver_entries)
{
    ULONG id = 0xCC; BYTE b[64]; ULONG len = sizeof b;
    if (UN(ZwAddBootEntry)) FAILS(UN(ZwAddBootEntry)(NULL, &id));
    if (UN(ZwDeleteBootEntry)) FAILS(UN(ZwDeleteBootEntry)(0xFFFFFFF0));
    if (UN(ZwEnumerateBootEntries)) FAILS(UN(ZwEnumerateBootEntries)(b, &len));
    if (UN(ZwAddDriverEntry)) FAILS(UN(ZwAddDriverEntry)(NULL, &id));
    if (UN(ZwDeleteDriverEntry)) FAILS(UN(ZwDeleteDriverEntry)(0xFFFFFFF0));
    len = sizeof b;
    if (UN(ZwEnumerateDriverEntries)) FAILS(UN(ZwEnumerateDriverEntries)(b, &len));
    len = sizeof b;
    if (UN(ZwEnumerateSystemEnvironmentValuesEx)) FAILS(UN(ZwEnumerateSystemEnvironmentValuesEx)(1, b, &len));
    if (UN(ZwFilterBootOption)) PROBE("FilterBootOption", UN(ZwFilterBootOption)(0, 0, 0, NULL, 0));
    CHECK(id == 0xCC);
}

/* The last-known-good controls need a shutdown-class privilege that is not enabled: no state is touched. */
TEST(last_known_good)
{
    REQUIRE(UN(ZwDisableLastKnownGood)); REQUIRE(UN(ZwEnableLastKnownGood));
    EXPECT_EQ(UN(ZwDisableLastKnownGood)(), ST_PRIV_NOT_HELD);
    EXPECT_EQ(UN(ZwEnableLastKnownGood)(), ST_PRIV_NOT_HELD);
}

TEST(physical_pages)
{
    REQUIRE(UN(ZwAllocateUserPhysicalPages)); REQUIRE(UN(ZwAllocateUserPhysicalPagesEx));
    ULONG_PTR n = 1, pfn[1] = {0};
    EXPECT_EQ(UN(ZwAllocateUserPhysicalPages)((HANDLE)(LONG_PTR)-1, &n, pfn), ST_PRIV_NOT_HELD);   /* SeLockMemoryPrivilege not enabled */
    n = 1; EXPECT_EQ(UN(ZwAllocateUserPhysicalPagesEx)((HANDLE)(LONG_PTR)-1, &n, pfn, NULL, 0), ST_PRIV_NOT_HELD);
    n = 1; EXPECT_EQ(UN(ZwAllocateUserPhysicalPages)(BADH, &n, pfn), ST_INVALID_HANDLE);
    n = 1; EXPECT_EQ(UN(ZwAllocateUserPhysicalPagesEx)(BADH, &n, pfn, NULL, 0), ST_INVALID_HANDLE);
}

TEST(signing_and_counters)
{
    if (UN(ZwCompareSigningLevels)) {
        EXPECT_EQ(UN(ZwCompareSigningLevels)(0, 0), 0);
        EXPECT_EQ(UN(ZwCompareSigningLevels)(8, 8), 0);
        EXPECT_EQ(UN(ZwCompareSigningLevels)(12, 8), 0);
        EXPECT_EQ(UN(ZwCompareSigningLevels)(8, 12), S(0xC0000428));      /* first level lower than the second */
    } else t_note("NtCompareSigningLevels missing");
    if (UN(ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter)) {
        ULONGLONG in = 1000, out = 0xCC, err = 0xCC;
        NTSTATUS st = UN(ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter)(TRUE, &in, &out, &err);
        if (st == S(0xC00000BB)) t_skip("no auxiliary counter on this platform (STATUS_NOT_SUPPORTED)");
        else EXPECT_EQ(st, 0);
    }
}

/* ---- job assignment ---------------------------------------------------- */
CHILD(no2b_sleeper) { Sleep(60000); return 0; }

TEST(assign_job)
{
    REQUIRE(UN(ZwAssignProcessToJobObject));
    HANDLE job = CreateJobObjectW(NULL, NULL); REQUIRE(job);
    PROCESS_INFORMATION pi;
    HANDLE hp = t_spawn_child("no2b_sleeper", "", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!hp) { t_skip("child spawn failed"); CloseHandle(job); return; }
    BOOL in = TRUE;
    IsProcessInJob(pi.hProcess, job, &in); EXPECT_EQ(in, 0);
    EXPECT_EQ(UN(ZwAssignProcessToJobObject)(job, pi.hProcess), 0);
    IsProcessInJob(pi.hProcess, job, &in); EXPECT_EQ(in, 1);
    NTSTATUS st = UN(ZwAssignProcessToJobObject)(job, pi.hProcess);
    EXPECT_EQ(st, 0);                      /* re-assigning to the job it is already in succeeds */
    EXPECT_EQ(UN(ZwAssignProcessToJobObject)(NULL, pi.hProcess), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwAssignProcessToJobObject)(job, NULL), ST_INVALID_HANDLE);
    EXPECT_EQ(UN(ZwAssignProcessToJobObject)(BADH, pi.hProcess), ST_INVALID_HANDLE);
    HANDLE ev = CreateEventW(NULL, 0, 0, NULL);
    EXPECT_EQ(UN(ZwAssignProcessToJobObject)(ev, pi.hProcess), ST_TYPE_MISMATCH);
    EXPECT_EQ(UN(ZwAssignProcessToJobObject)(job, ev), ST_TYPE_MISMATCH);
    CloseHandle(ev);
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
}

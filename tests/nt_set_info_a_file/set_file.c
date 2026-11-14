/* NtSetEaFile, NtSetQuotaInformationFile, NtSetVolumeInformationFile.
 *
 * Extended attributes are written to a throwaway file in the per-process scratch directory and
 * read back with NtQueryEaFile. The quota and volume setters would change system-wide volume
 * state on a valid volume handle, so only their argument validation is exercised, on handles
 * that can never accept the change (a regular file, a read-only handle, invalid handles).
 */
#include "t.h"

UDECL(NTSTATUS, NtSetEaFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryEaFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN));
UDECL(NTSTATUS, NtSetQuotaInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG));
UDECL(NTSTATUS, NtSetVolumeInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG));

#define S(x)            ((NTSTATUS)(x))
#define ST_BAD_CLASS    S(0xC0000003)
#define ST_BAD_LENGTH   S(0xC0000004)
#define ST_BAD_PARAM    S(0xC000000D)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_DENIED       S(0xC0000022)
#define ST_EAS_NOT_SUPP S(0xC000004F)
#define ST_INV_EA_NAME  S(0x80000013)
#define ST_EA_INCONS    S(0x80000014)
#define ST_INV_DEVREQ   S(0xC0000010)

typedef struct { ULONG next; UCHAR flags; UCHAR namelen; USHORT vallen; CHAR name[1]; } ea_info;

/* build one entry at p: name, NUL, value; returns bytes used (4-aligned when last == 0) */
static ULONG ea_put(BYTE *p, const char *name, const void *val, USHORT vlen, BOOL last)
{
    ea_info *e = (ea_info *)p; UCHAR nl = (UCHAR)strlen(name);
    ULONG raw = 8 + nl + 1 + vlen, total = (raw + 3) & ~3u;
    memset(p, 0, total);
    e->namelen = nl; e->vallen = vlen;
    memcpy(e->name, name, nl + 1);
    if (vlen) memcpy(p + 8 + nl + 1, val, vlen);
    e->next = last ? 0 : total;
    return last ? raw : total;
}

typedef struct { HANDLE h; char path[MAX_PATH]; } tfile;

static BOOL tfile_open(tfile *f, DWORD access)
{
    memset(f, 0, sizeof *f);
    t_tmpfile(f->path, sizeof f->path, "ea.dat");
    f->h = CreateFileA(f->path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    return f->h != INVALID_HANDLE_VALUE;
}

static void tfile_close(tfile *f)
{
    if (f->h && f->h != INVALID_HANDLE_VALUE) CloseHandle(f->h);
    DeleteFileA(f->path);
    memset(f, 0, sizeof *f);
}

TEST(set_file_alias_pairs)
{
    EXPECT_EQ(t_proc("NtSetEaFile"), t_proc("ZwSetEaFile"));
    EXPECT_EQ(t_proc("NtSetQuotaInformationFile"), t_proc("ZwSetQuotaInformationFile"));
    EXPECT_EQ(t_proc("NtSetVolumeInformationFile"), t_proc("ZwSetVolumeInformationFile"));
}

/* Reads all EAs; returns the count (0 when the file has none) or -1 on error. Names go to names[][16]. */
static int read_eas(HANDLE h, char names[][16], BYTE vals[][16], USHORT *vlens, int max)
{
    BYTE buf[1024]; IO_STATUS_BLOCK io; NTSTATUS st; int n = 0; ea_info *e;
    memset(buf, 0, sizeof buf);
    st = UN(NtQueryEaFile)(h, &io, buf, sizeof buf, FALSE, NULL, 0, NULL, TRUE);
    if (st == S(0xC0000052)) return 0;               /* STATUS_NO_EAS_ON_FILE */
    if (st < 0) return -1;
    e = (ea_info *)buf;
    for (;;) {
        if (n < max) {
            memcpy(names[n], e->name, e->namelen); names[n][e->namelen] = 0;
            vlens[n] = e->vallen;
            memcpy(vals[n], (BYTE *)e + 8 + e->namelen + 1, e->vallen < 16 ? e->vallen : 16);
        }
        n++;
        if (!e->next) break;
        e = (ea_info *)((BYTE *)e + e->next);
    }
    return n;
}

TEST(set_ea_roundtrip)
{
    tfile f; BYTE buf[256]; IO_STATUS_BLOCK io; ULONG used; NTSTATUS st;
    char names[4][16]; BYTE vals[4][16]; USHORT vl[4]; int n;
    REQUIRE(UN(NtSetEaFile)); REQUIRE(UN(NtQueryEaFile));
    CHECK(tfile_open(&f, GENERIC_READ | GENERIC_WRITE)); if (f.h == INVALID_HANDLE_VALUE) return;
    used = ea_put(buf, "SIAEA1", "hello", 5, FALSE);
    used += ea_put(buf + used, "siaea2", "xy", 2, TRUE);
    memset(&io, 0xCC, sizeof io);
    st = UN(NtSetEaFile)(f.h, &io, buf, used);
    if (st == ST_EAS_NOT_SUPP) { t_skip("scratch volume does not support extended attributes"); tfile_close(&f); return; }
    EXPECT_EQ(st, 0);
    EXPECT_EQ(io.Status, 0);
    n = read_eas(f.h, names, vals, vl, 4);
    EXPECT_EQ(n, 2);
    if (n == 2) {                                   /* names come back upper-cased */
        int a = !strcmp(names[0], "SIAEA1") ? 0 : 1, b = 1 - a;
        EXPECT_STR(names[a], "SIAEA1"); EXPECT_EQ(vl[a], 5); CHECK(memcmp(vals[a], "hello", 5) == 0);
        EXPECT_STR(names[b], "SIAEA2"); EXPECT_EQ(vl[b], 2); CHECK(memcmp(vals[b], "xy", 2) == 0);
    }
    /* overwrite one value, leave the other untouched */
    used = ea_put(buf, "SIAEA1", "bye!", 4, TRUE);
    EXPECT_EQ(UN(NtSetEaFile)(f.h, &io, buf, used), 0);
    n = read_eas(f.h, names, vals, vl, 4);
    EXPECT_EQ(n, 2);
    if (n == 2) {                                   /* the order of the entries is not specified */
        int a = !strcmp(names[0], "SIAEA1") ? 0 : 1, b = 1 - a;
        EXPECT_STR(names[a], "SIAEA1"); EXPECT_EQ(vl[a], 4); CHECK(memcmp(vals[a], "bye!", 4) == 0);
        EXPECT_STR(names[b], "SIAEA2"); EXPECT_EQ(vl[b], 2);
    }
    /* a zero-length value deletes the attribute */
    used = ea_put(buf, "SIAEA1", NULL, 0, TRUE);
    EXPECT_EQ(UN(NtSetEaFile)(f.h, &io, buf, used), 0);
    n = read_eas(f.h, names, vals, vl, 4);
    EXPECT_EQ(n, 1);
    if (n == 1) EXPECT_STR(names[0], "SIAEA2");
    tfile_close(&f);
}

TEST(set_ea_errors)
{
    tfile f, ro; BYTE buf[256]; IO_STATUS_BLOCK io; ULONG used; NTSTATUS st;
    REQUIRE(UN(NtSetEaFile));
    CHECK(tfile_open(&f, GENERIC_READ | GENERIC_WRITE)); if (f.h == INVALID_HANDLE_VALUE) return;
    used = ea_put(buf, "OK", "v", 1, TRUE);
    st = UN(NtSetEaFile)(f.h, &io, buf, used);
    if (st == ST_EAS_NOT_SUPP) { t_skip("scratch volume does not support extended attributes"); tfile_close(&f); return; }
    /* characters that cannot appear in an EA name */
    used = ea_put(buf, "BAD=NAME", "v", 1, TRUE);
    EXPECT_EQ(UN(NtSetEaFile)(f.h, &io, buf, used), ST_INV_EA_NAME);
    used = ea_put(buf, "A*B", "v", 1, TRUE);
    EXPECT_EQ(UN(NtSetEaFile)(f.h, &io, buf, used), ST_INV_EA_NAME);
    /* a list that is shorter than its own header is inconsistent */
    used = ea_put(buf, "OK", "value", 5, TRUE);
    st = UN(NtSetEaFile)(f.h, &io, buf, used - 3);
    t_note("NtSetEaFile(truncated list) = %08lx", (unsigned long)st);
    EXPECT_EQ(st, ST_EA_INCONS);
    EXPECT_EQ(UN(NtSetEaFile)((HANDLE)(ULONG_PTR)0xdeadbee4, &io, buf, used), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetEaFile)(NULL, &io, buf, used), ST_INV_HANDLE);
    /* a read-only handle has no FILE_WRITE_EA */
    memset(&ro, 0, sizeof ro);
    ro.h = CreateFileA(f.path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(ro.h != INVALID_HANDLE_VALUE);
    if (ro.h != INVALID_HANDLE_VALUE) {
        EXPECT_EQ(UN(NtSetEaFile)(ro.h, &io, buf, used), ST_DENIED);
        CloseHandle(ro.h);
    }
    tfile_close(&f);
}

TEST(set_quota_information_errors)
{
    tfile f; BYTE buf[64]; IO_STATUS_BLOCK io; NTSTATUS st;
    REQUIRE(UN(NtSetQuotaInformationFile));
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtSetQuotaInformationFile)((HANDLE)(ULONG_PTR)0xdeadbee4, &io, buf, sizeof buf), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetQuotaInformationFile)(NULL, &io, buf, sizeof buf), ST_INV_HANDLE);
    CHECK(tfile_open(&f, GENERIC_READ | GENERIC_WRITE)); if (f.h == INVALID_HANDLE_VALUE) return;
    /* quota is a volume property: a handle to an ordinary file is not a valid target */
    st = UN(NtSetQuotaInformationFile)(f.h, &io, buf, sizeof buf);
    t_note("NtSetQuotaInformationFile(regular file) = %08lx", (unsigned long)st);
    CHECK(st < 0);
    EXPECT_EQ(st, ST_DENIED);                       /* observed: a plain file handle carries no volume access */
    tfile_close(&f);
}

TEST(set_volume_information_errors)
{
    tfile f; HANDLE ro; BYTE buf[64]; IO_STATUS_BLOCK io; NTSTATUS st;
    REQUIRE(UN(NtSetVolumeInformationFile));
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtSetVolumeInformationFile)((HANDLE)(ULONG_PTR)0xdeadbee4, &io, buf, 8, 2), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtSetVolumeInformationFile)(NULL, &io, buf, 8, 2), ST_INV_HANDLE);
    CHECK(tfile_open(&f, GENERIC_READ | GENERIC_WRITE)); if (f.h == INVALID_HANDLE_VALUE) return;
    /* FileFsMaximumInformation and beyond are not information classes */
    EXPECT_EQ(UN(NtSetVolumeInformationFile)(f.h, &io, buf, 8, 0x7fff), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetVolumeInformationFile)(f.h, &io, buf, 8, 0), ST_BAD_CLASS);
    /* classes that are query-only for a caller */
    st = UN(NtSetVolumeInformationFile)(f.h, &io, buf, 8, 4 /* FileFsDeviceInformation */);
    EXPECT_EQ(st, ST_BAD_CLASS);
    /* FileFsLabelInformation on a handle that is not a volume is refused */
    st = UN(NtSetVolumeInformationFile)(f.h, &io, buf, 8, 2 /* FileFsLabelInformation */);
    EXPECT_EQ(st, ST_DENIED);
    /* a read-only handle cannot set volume information */
    ro = CreateFileA(f.path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(ro != INVALID_HANDLE_VALUE);
    if (ro != INVALID_HANDLE_VALUE) {
        st = UN(NtSetVolumeInformationFile)(ro, &io, buf, 8, 2);
        t_note("NtSetVolumeInformationFile(label, read-only handle) = %08lx", (unsigned long)st);
        EXPECT_EQ(st, ST_DENIED);
        CloseHandle(ro);
    }
    tfile_close(&f);
}

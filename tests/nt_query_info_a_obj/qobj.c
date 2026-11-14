/* Object-manager queries: NtQueryDirectoryObject, NtQuerySymbolicLinkObject, NtQuerySecurityObject,
 * NtQueryInformationAtom and NtQueryInformationJobObject. */
#include "t.h"

UDECL(NTSTATUS, NtOpenDirectoryObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtQueryDirectoryObject, (HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG));
UDECL(NTSTATUS, NtOpenSymbolicLinkObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateSymbolicLinkObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING));
UDECL(NTSTATUS, NtQuerySymbolicLinkObject, (HANDLE, PUNICODE_STRING, PULONG));
UDECL(NTSTATUS, NtQuerySecurityObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtAddAtom, (PWSTR, ULONG, USHORT *));
UDECL(NTSTATUS, NtDeleteAtom, (USHORT));
UDECL(NTSTATUS, NtQueryInformationAtom, (USHORT, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationJobObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));

#define S(x) ((NTSTATUS)(x))
#define DIRECTORY_QUERY 1
#define DIRECTORY_TRAVERSE 2
#define SYMBOLIC_LINK_QUERY 1
#define SYMBOLIC_LINK_ALL_ACCESS 0xF0001
#define ST_BUF_OVERFLOW S(0x80000005)
#define ST_NO_MORE_ENT  S(0x8000001A)
#define ST_INV_CLASS    S(0xC0000003)
#define ST_LEN_MISM     S(0xC0000004)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_INV_PARM     S(0xC000000D)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_DENIED       S(0xC0000022)
#define ST_TOO_SMALL    S(0xC0000023)
#define ST_NOT_FOUND    S(0xC0000034)

typedef struct { UNICODE_STRING Name, TypeName; } DIRENT;

static HANDLE open_dir(const WCHAR *path, ACCESS_MASK acc, NTSTATUS *st)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; HANDLE h = NULL;
    UN(RtlInitUnicodeString)(&us, path);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    *st = UN(NtOpenDirectoryObject)(&h, acc, &oa);
    return *st >= 0 ? h : NULL;
}

TEST(qobj_alias_pairs)
{
    static const char *n[] = { "QueryDirectoryObject", "QuerySymbolicLinkObject", "QuerySecurityObject",
        "QueryInformationAtom", "QueryInformationJobObject" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64]; sprintf(a, "Nt%s", n[i]); sprintf(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a);
        if (!pa) { t_note("%s not exported", a); continue; }
        CHECKF(pa == t_proc(b), "%s/%s address", a, b);
    }
}

/* ---- directory objects --------------------------------------------------- */

TEST(qobj_directory)
{
    HANDLE h; NTSTATUS s; BYTE buf[8192]; ULONG ctx, ret, total = 0, single = 0; int found = 0;
    REQUIRE(UN(NtOpenDirectoryObject)); REQUIRE(UN(NtQueryDirectoryObject)); REQUIRE(UN(NtClose)); REQUIRE(UN(RtlInitUnicodeString));
    h = open_dir(L"\\KernelObjects", DIRECTORY_QUERY, &s);
    EXPECT_EQ(s, 0);
    if (!h) return;
    /* bulk: one call returns every entry followed by a zeroed terminator entry */
    ctx = 0; ret = 0xcc; memset(buf, 0xcc, sizeof buf);
    s = UN(NtQueryDirectoryObject)(h, buf, sizeof buf, FALSE, TRUE, &ctx, &ret);
    EXPECT_EQ(s, 0);
    CHECK(ret > sizeof(DIRENT) && ret < sizeof buf);
    for (DIRENT *e = (DIRENT *)buf; e->Name.Length; e++) {
        total++;
        CHECK((BYTE *)e->Name.Buffer >= buf && (BYTE *)e->Name.Buffer < buf + sizeof buf);
        CHECK(e->TypeName.Length > 0);
        if (e->Name.Length == 36 && !_wcsnicmp(e->Name.Buffer, L"LowMemoryCondition", 18)) {
            found = 1;
            CHECK(e->TypeName.Length == 24 && !_wcsnicmp(e->TypeName.Buffer, L"SymbolicLink", 12));
        }
        if (total > 500) break;
    }
    CHECK(total >= 2);
    CHECKF(found, "LowMemoryCondition event present in \\KernelObjects (total %lu)", total);
    EXPECT_EQ(ctx, total);                       /* context is the index of the next entry */
    /* continue: nothing left */
    s = UN(NtQueryDirectoryObject)(h, buf, sizeof buf, FALSE, FALSE, &ctx, &ret);
    EXPECT_EQ(s, ST_NO_MORE_ENT);
    /* single entry at a time, restart on the first call */
    ctx = 0;
    for (int i = 0; i < 600; i++) {
        s = UN(NtQueryDirectoryObject)(h, buf, sizeof buf, TRUE, i == 0, &ctx, &ret);
        if (s == ST_NO_MORE_ENT) break;
        EXPECT_EQ(s, 0);
        if (s != 0) break;
        single++;
        CHECK(((DIRENT *)buf)->Name.Length > 0);
    }
    EXPECT_EQ(single, total);
    /* restart rewinds */
    s = UN(NtQueryDirectoryObject)(h, buf, sizeof buf, TRUE, TRUE, &ctx, &ret);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(ctx, 1);
    /* buffer too small for one entry */
    ctx = 0;
    s = UN(NtQueryDirectoryObject)(h, buf, 8, TRUE, TRUE, &ctx, &ret);
    t_note("tiny buffer = %08lx ret %lu", (unsigned long)s, ret);
    EXPECT_EQ(s, ST_TOO_SMALL);
    /* buffer too small for the whole set: STATUS_MORE_ENTRIES with partial data */
    ctx = 0;
    s = UN(NtQueryDirectoryObject)(h, buf, 2 * sizeof(DIRENT) + 100, FALSE, TRUE, &ctx, &ret);
    t_note("partial buffer = %08lx ctx %lu", (unsigned long)s, ctx);
    CHECK(s == 0 || s == S(0x105));
    UN(NtClose)(h);
    /* invalid / wrong-type handle */
    s = UN(NtQueryDirectoryObject)((HANDLE)(ULONG_PTR)0x7777, buf, sizeof buf, FALSE, TRUE, &ctx, &ret);
    EXPECT_EQ(s, ST_INV_HANDLE);
    { HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
      s = UN(NtQueryDirectoryObject)(ev, buf, sizeof buf, FALSE, TRUE, &ctx, &ret);
      EXPECT_EQ(s, ST_TYPE_MISM);
      CloseHandle(ev); }
    /* handle without DIRECTORY_QUERY */
    h = open_dir(L"\\KernelObjects", DIRECTORY_TRAVERSE, &s);
    if (h) {
        s = UN(NtQueryDirectoryObject)(h, buf, sizeof buf, FALSE, TRUE, &ctx, &ret);
        EXPECT_EQ(s, ST_DENIED);
        UN(NtClose)(h);
    }
    /* missing directory */
    h = open_dir(L"\\NoSuchDirectoryZz", DIRECTORY_QUERY, &s);
    EXPECT_EQ(s, ST_NOT_FOUND);
}

TEST(qobj_directory_root_types)
{
    HANDLE h; NTSTATUS s; BYTE buf[16384]; ULONG ctx = 0, ret; int dir = 0, type = 0, n = 0;
    REQUIRE(UN(NtOpenDirectoryObject)); REQUIRE(UN(NtQueryDirectoryObject)); REQUIRE(UN(NtClose)); REQUIRE(UN(RtlInitUnicodeString));
    h = open_dir(L"\\", DIRECTORY_QUERY, &s);
    EXPECT_EQ(s, 0);
    if (!h) return;
    s = UN(NtQueryDirectoryObject)(h, buf, sizeof buf, FALSE, TRUE, &ctx, &ret);
    CHECK(s == 0 || s == S(0x105));
    for (DIRENT *e = (DIRENT *)buf; e->Name.Length && n < 300; e++, n++) {
        if (e->Name.Length == 12 && !_wcsnicmp(e->Name.Buffer, L"Device", 6)) { dir++; CHECK(e->TypeName.Length == 18 && !_wcsnicmp(e->TypeName.Buffer, L"Directory", 9)); }
        if (e->Name.Length == 22 && !_wcsnicmp(e->Name.Buffer, L"ObjectTypes", 11)) type++;
    }
    EXPECT_EQ(dir, 1);
    EXPECT_EQ(type, 1);
    UN(NtClose)(h);
}

/* ---- symbolic links ------------------------------------------------------ */

TEST(qobj_symlink_created)
{
    HANDLE h = NULL; NTSTATUS s; UNICODE_STRING target, out; WCHAR buf[128]; ULONG ret; OBJECT_ATTRIBUTES oa;
    REQUIRE(UN(NtCreateSymbolicLinkObject)); REQUIRE(UN(NtQuerySymbolicLinkObject)); REQUIRE(UN(NtClose)); REQUIRE(UN(RtlInitUnicodeString));
    UN(RtlInitUnicodeString)(&target, L"\\??\\ntdllt_qobj_target\\leaf");
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);          /* unnamed link */
    s = UN(NtCreateSymbolicLinkObject)(&h, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target);
    EXPECT_EQ(s, 0);
    if (s != 0) return;
    /* exact-size buffer: ReturnedLength counts the terminator, UNICODE_STRING.Length does not */
    memset(buf, 0xcc, sizeof buf);
    out.Buffer = buf; out.Length = 0xffff; out.MaximumLength = target.Length + 2;
    ret = 0xcc;
    s = UN(NtQuerySymbolicLinkObject)(h, &out, &ret);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(out.Length, target.Length);
    EXPECT_EQ(ret, target.Length + 2);
    CHECK(!memcmp(buf, target.Buffer, target.Length));
    /* generous buffer, ReturnedLength optional */
    out.Buffer = buf; out.Length = 0; out.MaximumLength = sizeof buf;
    s = UN(NtQuerySymbolicLinkObject)(h, &out, NULL);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(out.Length, target.Length);
    /* one byte short */
    out.Buffer = buf; out.Length = 0; out.MaximumLength = target.Length + 1; ret = 0;
    s = UN(NtQuerySymbolicLinkObject)(h, &out, &ret);
    t_note("short symlink buffer = %08lx ret %lu", (unsigned long)s, ret);
    EXPECT_EQ(s, ST_TOO_SMALL);
    EXPECT_EQ(ret, target.Length + 2);
    UN(NtClose)(h);
    /* closed handle */
    out.Buffer = buf; out.Length = 0; out.MaximumLength = sizeof buf;
    s = UN(NtQuerySymbolicLinkObject)(h, &out, NULL);
    EXPECT_EQ(s, ST_INV_HANDLE);
}

TEST(qobj_symlink_access_and_type)
{
    HANDLE h = NULL, d, ev; NTSTATUS s; UNICODE_STRING target, out; WCHAR buf[128]; OBJECT_ATTRIBUTES oa;
    REQUIRE(UN(NtCreateSymbolicLinkObject)); REQUIRE(UN(NtQuerySymbolicLinkObject)); REQUIRE(UN(NtClose)); REQUIRE(UN(RtlInitUnicodeString));
    REQUIRE(UN(NtOpenDirectoryObject));
    UN(RtlInitUnicodeString)(&target, L"\\??\\ntdllt_qobj_t2");
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    s = UN(NtCreateSymbolicLinkObject)(&h, DELETE | SYNCHRONIZE, &oa, &target);    /* no SYMBOLIC_LINK_QUERY */
    EXPECT_EQ(s, 0);
    out.Buffer = buf; out.Length = 0; out.MaximumLength = sizeof buf;
    if (s == 0) {
        s = UN(NtQuerySymbolicLinkObject)(h, &out, NULL);
        EXPECT_EQ(s, ST_DENIED);
        UN(NtClose)(h);
    }
    d = open_dir(L"\\KernelObjects", DIRECTORY_QUERY, &s);
    if (d) { s = UN(NtQuerySymbolicLinkObject)(d, &out, NULL); EXPECT_EQ(s, ST_TYPE_MISM); UN(NtClose)(d); }
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    s = UN(NtQuerySymbolicLinkObject)(ev, &out, NULL); EXPECT_EQ(s, ST_TYPE_MISM);
    CloseHandle(ev);
    s = UN(NtQuerySymbolicLinkObject)((HANDLE)(ULONG_PTR)0x7777, &out, NULL); EXPECT_EQ(s, ST_INV_HANDLE);
}

TEST(qobj_symlink_dosdevice)
{
    HANDLE h = NULL; NTSTATUS s; UNICODE_STRING us, out; WCHAR buf[256]; ULONG ret = 0; OBJECT_ATTRIBUTES oa;
    REQUIRE(UN(NtOpenSymbolicLinkObject)); REQUIRE(UN(NtQuerySymbolicLinkObject)); REQUIRE(UN(NtClose)); REQUIRE(UN(RtlInitUnicodeString));
    UN(RtlInitUnicodeString)(&us, L"\\??\\C:");
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = UN(NtOpenSymbolicLinkObject)(&h, SYMBOLIC_LINK_QUERY, &oa);
    EXPECT_EQ(s, 0);
    if (s != 0) return;
    out.Buffer = buf; out.Length = 0; out.MaximumLength = sizeof buf;
    s = UN(NtQuerySymbolicLinkObject)(h, &out, &ret);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(ret, out.Length + 2);
    CHECK(out.Length > 16 && !_wcsnicmp(buf, L"\\Device\\", 8));
    UN(NtClose)(h);
    UN(RtlInitUnicodeString)(&us, L"\\??\\NUL");
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = UN(NtOpenSymbolicLinkObject)(&h, SYMBOLIC_LINK_QUERY, &oa);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        out.Buffer = buf; out.Length = 0; out.MaximumLength = sizeof buf;
        s = UN(NtQuerySymbolicLinkObject)(h, &out, &ret);
        EXPECT_EQ(s, 0);
        CHECK(out.Length == 24 && !_wcsnicmp(buf, L"\\Device\\Null", 12));
        UN(NtClose)(h);
    }
}

/* ---- security descriptors ----------------------------------------------- */

TEST(qobj_security_object)
{
    HANDLE ev, weak = NULL; NTSTATUS s; union { ULONGLONG a; BYTE b[1024]; } sd; ULONG need = 0xcc, need2;
    REQUIRE(UN(NtQuerySecurityObject)); REQUIRE(UN(NtClose));
    { WCHAR nm[64]; swprintf(nm, 64, L"Local\\ntdllt_qobj_sec_%lu", GetCurrentProcessId()); ev = CreateEventW(NULL, TRUE, FALSE, nm); }
    CHECK(ev != NULL);
    /* owner + group + dacl: self-relative descriptor (an unnamed object carries none, hence the named event) */
    memset(&sd, 0xcc, sizeof sd);
    s = UN(NtQuerySecurityObject)(ev, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &sd, sizeof sd, &need);
    EXPECT_EQ(s, 0);
    CHECK(need >= 20 && need <= sizeof sd);
    EXPECT_EQ(sd.b[0], 1);                              /* Revision */
    CHECK(*(USHORT *)(sd.b + 2) & 0x8000);              /* SE_SELF_RELATIVE */
    CHECK(*(USHORT *)(sd.b + 2) & 0x0004);              /* SE_DACL_PRESENT */
    CHECK(*(ULONG *)(sd.b + 4) != 0);                   /* owner offset */
    CHECK(*(ULONG *)(sd.b + 8) != 0);                   /* group offset */
    CHECK(*(ULONG *)(sd.b + 16) != 0);                  /* dacl offset */
    EXPECT_EQ(*(ULONG *)(sd.b + 12), 0);                /* no SACL requested */
    /* owner only is smaller */
    s = UN(NtQuerySecurityObject)(ev, OWNER_SECURITY_INFORMATION, &sd, sizeof sd, &need2);
    EXPECT_EQ(s, 0);
    CHECK(need2 < need);
    CHECK(*(ULONG *)(sd.b + 4) != 0 && *(ULONG *)(sd.b + 8) == 0 && *(ULONG *)(sd.b + 16) == 0);
    /* too small: reports the size needed */
    need2 = 0xcc;
    s = UN(NtQuerySecurityObject)(ev, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &sd, 8, &need2);
    EXPECT_EQ(s, ST_TOO_SMALL);
    EXPECT_EQ(need2, need);
    need2 = 0xcc;
    s = UN(NtQuerySecurityObject)(ev, DACL_SECURITY_INFORMATION, NULL, 0, &need2);
    EXPECT_EQ(s, ST_TOO_SMALL);
    CHECK(need2 >= 20);
    /* empty selection still produces a header-only descriptor */
    s = UN(NtQuerySecurityObject)(ev, 0, &sd, sizeof sd, &need2);
    t_note("info=0 -> %08lx need %lu", (unsigned long)s, need2);
    CHECK(s == 0 || s == ST_INV_PARM);
    /* SACL needs ACCESS_SYSTEM_SECURITY, not granted by an ordinary token */
    s = UN(NtQuerySecurityObject)(ev, SACL_SECURITY_INFORMATION, &sd, sizeof sd, &need2);
    t_note("SACL -> %08lx", (unsigned long)s);
    CHECK(s == ST_DENIED || s == S(0xC0000061) || s == 0);
    /* a handle without READ_CONTROL */
    CHECK(DuplicateHandle(GetCurrentProcess(), ev, GetCurrentProcess(), &weak, EVENT_MODIFY_STATE, FALSE, 0));
    if (weak) {
        s = UN(NtQuerySecurityObject)(weak, DACL_SECURITY_INFORMATION, &sd, sizeof sd, &need2);
        EXPECT_EQ(s, ST_DENIED);
        CloseHandle(weak);
    }
    /* bad handle / pseudo handle */
    s = UN(NtQuerySecurityObject)((HANDLE)(ULONG_PTR)0x7777, DACL_SECURITY_INFORMATION, &sd, sizeof sd, &need2);
    EXPECT_EQ(s, ST_INV_HANDLE);
    s = UN(NtQuerySecurityObject)((HANDLE)(LONG_PTR)-1, OWNER_SECURITY_INFORMATION, &sd, sizeof sd, &need2);
    EXPECT_EQ(s, 0);
    s = UN(NtQuerySecurityObject)((HANDLE)(LONG_PTR)-2, OWNER_SECURITY_INFORMATION, &sd, sizeof sd, &need2);
    EXPECT_EQ(s, 0);
    /* NULL length-needed pointer faults in the kernel, reported as a status */
    s = UN(NtQuerySecurityObject)(ev, DACL_SECURITY_INFORMATION, &sd, sizeof sd, NULL);
    EXPECT_EQ(s, S(0xC0000005));
    CloseHandle(ev);
}

/* ---- atoms ------------------------------------------------------------- */

typedef struct { USHORT UseCount, Flags, NameLength; WCHAR Name[1]; } ATOMBASIC;
typedef struct { ULONG Count; USHORT Atoms[1]; } ATOMTABLE;

TEST(qobj_atom)
{
    USHORT a = 0, b = 0, c = 0; NTSTATUS s; union { ULONGLONG al; BYTE b[512]; } buf; ULONG ret; ATOMBASIC *ab = (ATOMBASIC *)&buf;
    WCHAR name[] = L"ntdllt_qobj_atom_Zz";
    REQUIRE(UN(NtAddAtom)); REQUIRE(UN(NtDeleteAtom)); REQUIRE(UN(NtQueryInformationAtom));
    s = UN(NtAddAtom)(name, sizeof name - 2, &a);
    t_note("NtAddAtom = %08lx atom %04x; kernel32 GlobalAddAtomW %s", (unsigned long)s, a, "probe");
    if (s == ST_DENIED) {
        { USHORT bogus; NTSTATUS s2;
          s2 = UN(NtQueryInformationAtom)(0xC123, 0, &bogus, sizeof bogus, &ret); t_note("query atom C123 = %08lx", (unsigned long)s2);
          s2 = UN(NtQueryInformationAtom)(0x0001, 0, &bogus, sizeof bogus, &ret); t_note("query atom 1 = %08lx", (unsigned long)s2);
          s2 = UN(NtDeleteAtom)(0xC123); t_note("delete atom C123 = %08lx", (unsigned long)s2); }
        ATOM k = GlobalAddAtomW(L"ntdllt_qobj_probe");
        t_note("GlobalAddAtomW = %04x err %lu", k, GetLastError());
        if (k) GlobalDeleteAtom(k);
        t_skip("the global atom table is unreachable from this process (no window station); NtAddAtom = %08lx", (unsigned long)s);
        return;
    }
    EXPECT_EQ(s, 0);
    if (s != 0) return;
    CHECK(a >= 0xC000);
    /* AtomBasicInformation = 0 */
    memset(&buf, 0xcc, sizeof buf); ret = 0xcc;
    s = UN(NtQueryInformationAtom)(a, 0, &buf, sizeof buf, &ret);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(ab->UseCount, 1);
    EXPECT_EQ(ab->Flags, 0);
    EXPECT_EQ(ab->NameLength, sizeof name - 2);
    CHECK(!memcmp(ab->Name, name, sizeof name));        /* NUL terminated copy */
    EXPECT_EQ(ret, 6 + sizeof name);                    /* header + name + terminator */
    /* second add bumps the use count */
    s = UN(NtAddAtom)(name, sizeof name - 2, &b);
    EXPECT_EQ(s, 0); EXPECT_EQ(b, a);
    s = UN(NtQueryInformationAtom)(a, 0, &buf, sizeof buf, &ret);
    EXPECT_EQ(s, 0); EXPECT_EQ(ab->UseCount, 2);
    /* exact-size buffer */
    s = UN(NtQueryInformationAtom)(a, 0, &buf, 6 + sizeof name, &ret);
    EXPECT_EQ(s, 0);
    /* too short for the name */
    memset(&buf, 0xcc, sizeof buf); ret = 0;
    s = UN(NtQueryInformationAtom)(a, 0, &buf, 10, &ret);
    t_note("short atom buffer = %08lx ret %lu use %u len %u", (unsigned long)s, ret, ab->UseCount, ab->NameLength);
    CHECK(s == ST_BUF_OVERFLOW || s == ST_TOO_SMALL);
    s = UN(NtQueryInformationAtom)(a, 0, &buf, 4, &ret);
    EXPECT_EQ(s, ST_LEN_MISM);
    /* AtomTableInformation = 1 lists the atom */
    { ATOMTABLE *t = (ATOMTABLE *)buf.b; static BYTE big[8192]; ATOMTABLE *bt = (ATOMTABLE *)big; int seen = 0;
      memset(big, 0xcc, sizeof big);
      s = UN(NtQueryInformationAtom)(a, 1, big, sizeof big, &ret);
      EXPECT_EQ(s, 0);
      if (s == 0) {
          CHECK(bt->Count >= 1 && bt->Count < 3000);
          for (ULONG i = 0; i < bt->Count && 4 + 2 * i + 2 <= ret; i++) if (bt->Atoms[i] == a) seen = 1;
          CHECK(seen);
          EXPECT_EQ(ret, 4 + 2 * bt->Count);
      }
      (void)t; }
    /* bad class */
    s = UN(NtQueryInformationAtom)(a, 99, &buf, sizeof buf, &ret);
    EXPECT_EQ(s, ST_INV_CLASS);
    /* delete twice-added atom, query after the last reference */
    EXPECT_EQ(UN(NtDeleteAtom)(a), 0);
    s = UN(NtQueryInformationAtom)(a, 0, &buf, sizeof buf, &ret);
    EXPECT_EQ(s, 0); EXPECT_EQ(ab->UseCount, 1);
    EXPECT_EQ(UN(NtDeleteAtom)(a), 0);
    s = UN(NtQueryInformationAtom)(a, 0, &buf, sizeof buf, &ret);
    t_note("deleted atom = %08lx", (unsigned long)s);
    CHECK(s == ST_NOT_FOUND || s == S(0xC0000008));
    /* integer atoms and out-of-range values */
    s = UN(NtQueryInformationAtom)(0x0001, 0, &buf, sizeof buf, &ret);
    t_note("integer atom 1 = %08lx", (unsigned long)s);
    s = UN(NtQueryInformationAtom)(0, 0, &buf, sizeof buf, &ret);
    t_note("atom 0 = %08lx", (unsigned long)s);
    CHECK(s < 0);
    (void)c;
}

/* ---- job objects -------------------------------------------------------- */

TEST(qobj_job)
{
    HANDLE job, ev, weak = NULL; NTSTATUS s; ULONG ret; union { ULONGLONG a; BYTE b[512]; } buf;
    JOBOBJECT_BASIC_LIMIT_INFORMATION bl; JOBOBJECT_EXTENDED_LIMIT_INFORMATION el;
    REQUIRE(UN(NtQueryInformationJobObject));
    job = CreateJobObjectW(NULL, NULL);
    CHECK(job != NULL);
    if (!job) return;
    /* JobObjectBasicAccountingInformation = 1: empty job */
    memset(&buf, 0xcc, sizeof buf); ret = 0xcc;
    s = UN(NtQueryInformationJobObject)(job, 1, &buf, sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION), &ret);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(ret, sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
    { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION *ai = (void *)&buf;
      EXPECT_EQ(ai->TotalProcesses, 0); EXPECT_EQ(ai->ActiveProcesses, 0); EXPECT_EQ(ai->TotalTerminatedProcesses, 0);
      EXPECT_EQ(ai->TotalUserTime.QuadPart, 0); EXPECT_EQ(ai->TotalPageFaultCount, 0); }
    /* limits as set through kernel32 */
    memset(&el, 0, sizeof el);
    el.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PRIORITY_CLASS;
    el.BasicLimitInformation.ActiveProcessLimit = 7;
    el.BasicLimitInformation.PriorityClass = BELOW_NORMAL_PRIORITY_CLASS;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &el, sizeof el)) { t_skip("SetInformationJobObject failed %lu", GetLastError()); CloseHandle(job); return; }
    memset(&bl, 0xcc, sizeof bl); ret = 0xcc;
    s = UN(NtQueryInformationJobObject)(job, 2, &bl, sizeof bl, &ret);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(ret, sizeof bl);
    EXPECT_EQ(bl.LimitFlags, JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PRIORITY_CLASS);
    EXPECT_EQ(bl.ActiveProcessLimit, 7);
    EXPECT_EQ(bl.PriorityClass, 5);           /* native PROCESS_PRIORITY_CLASS_BELOW_NORMAL */
    memset(&el, 0xcc, sizeof el); ret = 0xcc;
    s = UN(NtQueryInformationJobObject)(job, 9, &el, sizeof el, &ret);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(ret, sizeof el);
    EXPECT_EQ(el.BasicLimitInformation.ActiveProcessLimit, 7);
    EXPECT_EQ(el.ProcessMemoryLimit, 0);
    /* process id list, empty */
    { struct { ULONG n, a; ULONG_PTR ids[4]; } pl; memset(&pl, 0xcc, sizeof pl);
      s = UN(NtQueryInformationJobObject)(job, 3, &pl, sizeof pl, &ret);
      EXPECT_EQ(s, 0);
      EXPECT_EQ(pl.n, 0); }
    /* length / class errors */
    s = UN(NtQueryInformationJobObject)(job, 2, &bl, sizeof bl - 4, &ret);
    EXPECT_EQ(s, ST_LEN_MISM);
    s = UN(NtQueryInformationJobObject)(job, 0x7777, &buf, sizeof buf, &ret);
    EXPECT_EQ(s, ST_INV_CLASS);
    s = UN(NtQueryInformationJobObject)(job, 0, &buf, sizeof buf, &ret);
    t_note("class 0 = %08lx", (unsigned long)s);
    CHECK(s == ST_INV_CLASS || s == ST_INV_PARM);
    /* handle checks */
    s = UN(NtQueryInformationJobObject)((HANDLE)(ULONG_PTR)0x7777, 2, &bl, sizeof bl, &ret);
    EXPECT_EQ(s, ST_INV_HANDLE);
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    s = UN(NtQueryInformationJobObject)(ev, 2, &bl, sizeof bl, &ret);
    EXPECT_EQ(s, ST_TYPE_MISM);
    CloseHandle(ev);
    CHECK(DuplicateHandle(GetCurrentProcess(), job, GetCurrentProcess(), &weak, JOB_OBJECT_SET_ATTRIBUTES, FALSE, 0));
    if (weak) {
        s = UN(NtQueryInformationJobObject)(weak, 2, &bl, sizeof bl, &ret);
        EXPECT_EQ(s, ST_DENIED);
        CloseHandle(weak);
    }
    /* NULL handle is a query on "the job of the calling process": not in a job here, or in one; observe */
    s = UN(NtQueryInformationJobObject)(NULL, 2, &bl, sizeof bl, &ret);
    t_note("NULL job handle = %08lx", (unsigned long)s);
    CloseHandle(job);
}

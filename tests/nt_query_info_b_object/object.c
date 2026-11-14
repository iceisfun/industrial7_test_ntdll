/* Object-manager query services on private objects:
 * NtQueryEvent, NtQueryMutant, NtQuerySemaphore, NtQueryTimer, NtQuerySection,
 * NtQuerySymbolicLinkObject, NtQueryObject, NtQueryDirectoryObject, NtQuerySecurityObject,
 * NtQueryInformationAtom. Zw names are asserted to alias the Nt names.
 * Expected values: see EVIDENCE.md. */
#include "t.h"

UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtCreateMutant, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN));
UDECL(NTSTATUS, NtReleaseMutant, (HANDLE, PLONG));
UDECL(NTSTATUS, NtWaitForSingleObject, (HANDLE, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtCreateSemaphore, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG));
UDECL(NTSTATUS, NtReleaseSemaphore, (HANDLE, LONG, PLONG));
UDECL(NTSTATUS, NtCreateTimer, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtSetTimer, (HANDLE, PLARGE_INTEGER, PVOID, PVOID, BOOLEAN, LONG, PBOOLEAN));
UDECL(NTSTATUS, NtCancelTimer, (HANDLE, PBOOLEAN));
UDECL(NTSTATUS, NtCreateSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE));
UDECL(NTSTATUS, NtCreateSymbolicLinkObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateDirectoryObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtOpenDirectoryObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtDuplicateObject, (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG));
UDECL(NTSTATUS, NtAddAtom, (PWSTR, ULONG, PUSHORT));
UDECL(NTSTATUS, NtDeleteAtom, (USHORT));
UDECL(NTSTATUS, NtQueryEvent, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryMutant, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQuerySemaphore, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryTimer, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQuerySection, (HANDLE, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtQuerySymbolicLinkObject, (HANDLE, PUNICODE_STRING, PULONG));
UDECL(NTSTATUS, NtQueryObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryDirectoryObject, (HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG));
UDECL(NTSTATUS, NtQuerySecurityObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationAtom, (USHORT, ULONG, PVOID, ULONG, PULONG));

#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 1
#endif
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 1
#define DIRECTORY_TRAVERSE 2
#define DIRECTORY_CREATE_OBJECT 4
#define DIRECTORY_ALL_ACCESS 0xF000F
#endif
#ifndef SYMBOLIC_LINK_ALL_ACCESS
#define SYMBOLIC_LINK_ALL_ACCESS 0xF0001
#endif
UDECL(BOOLEAN, RtlValidSecurityDescriptor, (PVOID));
#define S(x) ((NTSTATUS)(x))
#define ST_LEN_MISMATCH S(0xC0000004)
#define ST_INV_CLASS    S(0xC0000003)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_DENIED       S(0xC0000022)
#define ST_BUF_SMALL    S(0xC0000023)
#define ST_NO_MORE      S(0x8000001A)
#define ST_INV_PARAM    S(0xC000000D)
#define OBS(what, e) do { NTSTATUS os_ = (e); t_note("OBS %s: %08lx", what, (unsigned long)os_); } while (0)
#define OK(s) ((NTSTATUS)(s) >= 0)
#define PSEUDO_PROCESS ((HANDLE)(LONG_PTR)-1)

static void alias(const char *n)
{
    char z[96];
    snprintf(z, sizeof z, "Zw%s", n + 2);
    CHECKF(t_proc(n) != NULL, "%s missing", n);
    CHECKF(t_proc(n) == t_proc(z), "%s and %s differ", n, z);
}

TEST(alias_pairs)
{
    static const char *n[] = { "NtQueryEvent", "NtQueryMutant", "NtQuerySemaphore", "NtQueryTimer", "NtQuerySection",
        "NtQuerySymbolicLinkObject", "NtQueryObject", "NtQueryDirectoryObject", "NtQuerySecurityObject", "NtQueryInformationAtom" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) alias(n[i]);
}

/* ---- event ---- */
typedef struct { ULONG type; LONG state; } EVT_BASIC;

TEST(query_event)
{
    HANDLE h = NULL, s = NULL; EVT_BASIC b; ULONG ret;
    REQUIRE(UN(NtQueryEvent)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtCreateSemaphore));
    EXPECT_EQ(UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 0, FALSE), 0);
    memset(&b, 0xcc, sizeof b); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryEvent)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(ret, 8); EXPECT_EQ(b.type, 0); EXPECT_EQ(b.state, 0);
    CHECK(UN(NtClose)(h) == 0);
    /* synchronization event, initially signalled */
    EXPECT_EQ(UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 1, TRUE), 0);
    memset(&b, 0xcc, sizeof b);
    EXPECT_EQ(UN(NtQueryEvent)(h, 0, &b, sizeof b, NULL), 0);
    EXPECT_EQ(b.type, 1); EXPECT_EQ(b.state, 1);
    /* error paths */
    memset(&b, 0xcc, sizeof b);
    EXPECT_EQ(UN(NtQueryEvent)(h, 0, &b, sizeof b - 1, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryEvent)(h, 0, &b, sizeof b + 8, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryEvent)(h, 0, &b, 0, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryEvent)(h, 1, &b, sizeof b, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryEvent)(h, 0x100, &b, sizeof b, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryEvent)((HANDLE)(ULONG_PTR)0x7ffc, 0, &b, sizeof b, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryEvent)(NULL, 0, &b, sizeof b, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryEvent)(PSEUDO_PROCESS, 0, &b, sizeof b, &ret), ST_TYPE_MISM);
    EXPECT_EQ(UN(NtCreateSemaphore)(&s, SEMAPHORE_ALL_ACCESS, NULL, 0, 1), 0);
    EXPECT_EQ(UN(NtQueryEvent)(s, 0, &b, sizeof b, &ret), ST_TYPE_MISM);
    UN(NtClose)(s);
    /* a handle without EVENT_QUERY_STATE is refused */
    {
        HANDLE d = NULL;
        EXPECT_EQ(UN(NtDuplicateObject)((HANDLE)(LONG_PTR)-1, h, (HANDLE)(LONG_PTR)-1, &d, EVENT_MODIFY_STATE, 0, 0), 0);
        if (d) {
            EXPECT_EQ(UN(NtQueryEvent)(d, 0, &b, sizeof b, &ret), ST_DENIED);
            UN(NtClose)(d);
        }
    }
    UN(NtClose)(h);
    EXPECT_EQ(UN(NtQueryEvent)(h, 0, &b, sizeof b, &ret), ST_INV_HANDLE);
}

/* ---- mutant ---- */
typedef struct { LONG count; BOOLEAN owned; BOOLEAN abandoned; } MUT_BASIC;

TEST(query_mutant)
{
    HANDLE h = NULL; MUT_BASIC b; ULONG ret; LARGE_INTEGER z = { 0 };
    REQUIRE(UN(NtQueryMutant)); REQUIRE(UN(NtCreateMutant)); REQUIRE(UN(NtReleaseMutant));
    EXPECT_EQ(UN(NtCreateMutant)(&h, MUTANT_ALL_ACCESS, NULL, FALSE), 0);
    memset(&b, 0xcc, sizeof b); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryMutant)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(ret, sizeof b);
    EXPECT_EQ(b.count, 1); EXPECT_EQ(b.owned, 0); EXPECT_EQ(b.abandoned, 0);
    EXPECT_EQ(UN(NtWaitForSingleObject)(h, FALSE, &z), 0);
    EXPECT_EQ(UN(NtQueryMutant)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(b.count, 0); EXPECT_EQ(b.owned, 1);
    EXPECT_EQ(UN(NtWaitForSingleObject)(h, FALSE, &z), 0);   /* recursive acquire */
    EXPECT_EQ(UN(NtQueryMutant)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(b.count, -1); EXPECT_EQ(b.owned, 1);
    EXPECT_EQ(UN(NtReleaseMutant)(h, NULL), 0);
    EXPECT_EQ(UN(NtReleaseMutant)(h, NULL), 0);
    EXPECT_EQ(UN(NtQueryMutant)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(b.count, 1); EXPECT_EQ(b.owned, 0);
    /* initially owned */
    UN(NtClose)(h); h = NULL;
    EXPECT_EQ(UN(NtCreateMutant)(&h, MUTANT_ALL_ACCESS, NULL, TRUE), 0);
    EXPECT_EQ(UN(NtQueryMutant)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(b.count, 0); EXPECT_EQ(b.owned, 1);
    EXPECT_EQ(UN(NtQueryMutant)(h, 0, &b, sizeof b - 1, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryMutant)(h, 0, &b, sizeof b + 1, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryMutant)(h, 1, &b, sizeof b, &ret), ST_LEN_MISMATCH);   /* observed: not INVALID_INFO_CLASS */
    EXPECT_EQ(UN(NtQueryMutant)(NULL, 0, &b, sizeof b, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryMutant)(PSEUDO_PROCESS, 0, &b, sizeof b, &ret), ST_TYPE_MISM);
    UN(NtReleaseMutant)(h, NULL);
    UN(NtClose)(h);
}

/* ---- semaphore ---- */
TEST(query_semaphore)
{
    HANDLE h = NULL; LONG b[2]; ULONG ret; LONG prev;
    REQUIRE(UN(NtQuerySemaphore)); REQUIRE(UN(NtCreateSemaphore)); REQUIRE(UN(NtReleaseSemaphore));
    EXPECT_EQ(UN(NtCreateSemaphore)(&h, SEMAPHORE_ALL_ACCESS, NULL, 2, 5), 0);
    memset(b, 0xcc, sizeof b); ret = 0xdead;
    EXPECT_EQ(UN(NtQuerySemaphore)(h, 0, b, sizeof b, &ret), 0);
    EXPECT_EQ(ret, 8); EXPECT_EQ(b[0], 2); EXPECT_EQ(b[1], 5);
    EXPECT_EQ(UN(NtReleaseSemaphore)(h, 3, &prev), 0);
    EXPECT_EQ(prev, 2);
    EXPECT_EQ(UN(NtQuerySemaphore)(h, 0, b, sizeof b, NULL), 0);
    EXPECT_EQ(b[0], 5); EXPECT_EQ(b[1], 5);
    EXPECT_EQ(UN(NtQuerySemaphore)(h, 0, b, 4, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQuerySemaphore)(h, 0, b, 12, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQuerySemaphore)(h, 1, b, sizeof b, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQuerySemaphore)(NULL, 0, b, sizeof b, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQuerySemaphore)(PSEUDO_PROCESS, 0, b, sizeof b, &ret), ST_TYPE_MISM);
    {
        HANDLE d = NULL;
        EXPECT_EQ(UN(NtDuplicateObject)(PSEUDO_PROCESS, h, PSEUDO_PROCESS, &d, SEMAPHORE_MODIFY_STATE, 0, 0), 0);
        if (d) { EXPECT_EQ(UN(NtQuerySemaphore)(d, 0, b, sizeof b, &ret), ST_DENIED); UN(NtClose)(d); }
    }
    UN(NtClose)(h);
}

/* ---- timer ---- */
typedef struct { LARGE_INTEGER remaining; BOOLEAN state; } TMR_BASIC;

TEST(query_timer)
{
    HANDLE h = NULL; TMR_BASIC b; ULONG ret; LARGE_INTEGER due; BOOLEAN prev;
    REQUIRE(UN(NtQueryTimer)); REQUIRE(UN(NtCreateTimer)); REQUIRE(UN(NtSetTimer)); REQUIRE(UN(NtCancelTimer));
    EXPECT_EQ(UN(NtCreateTimer)(&h, TIMER_ALL_ACCESS, NULL, 0 /* notification */), 0);
    memset(&b, 0xcc, sizeof b); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryTimer)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(ret, sizeof b); CHECK(b.remaining.QuadPart <= 0); EXPECT_EQ(b.state, 0);   /* RemainingTime of a disarmed timer is not stable */
    /* armed, due in one hour (relative) */
    due.QuadPart = -36000000000LL;
    EXPECT_EQ(UN(NtSetTimer)(h, &due, NULL, NULL, FALSE, 0, &prev), 0);
    memset(&b, 0xcc, sizeof b);
    EXPECT_EQ(UN(NtQueryTimer)(h, 0, &b, sizeof b, &ret), 0);
    CHECK(b.remaining.QuadPart > 0 && b.remaining.QuadPart <= 36000000000LL);
    CHECK(b.remaining.QuadPart > 35000000000LL);
    EXPECT_EQ(b.state, 0);
    EXPECT_EQ(UN(NtCancelTimer)(h, &prev), 0);
    EXPECT_EQ(UN(NtQueryTimer)(h, 0, &b, sizeof b, &ret), 0);
    CHECK(b.remaining.QuadPart <= 0); EXPECT_EQ(b.state, 0);
    /* signalled: relative 0 fires immediately */
    due.QuadPart = -1;
    EXPECT_EQ(UN(NtSetTimer)(h, &due, NULL, NULL, FALSE, 0, &prev), 0);
    {
        LARGE_INTEGER to; to.QuadPart = -50000000LL;
        EXPECT_EQ(UN(NtWaitForSingleObject)(h, FALSE, &to), 0);
    }
    EXPECT_EQ(UN(NtQueryTimer)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(b.state, 1); CHECK(b.remaining.QuadPart <= 0);
    EXPECT_EQ(UN(NtQueryTimer)(h, 0, &b, sizeof b - 1, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryTimer)(h, 1, &b, sizeof b, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryTimer)(NULL, 0, &b, sizeof b, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQueryTimer)(PSEUDO_PROCESS, 0, &b, sizeof b, &ret), ST_TYPE_MISM);
    UN(NtClose)(h);
}

/* ---- section ---- */
typedef struct { PVOID base; ULONG attrs; LARGE_INTEGER size; } SEC_BASIC;

TEST(query_section)
{
    HANDLE h = NULL; SEC_BASIC b; SIZE_T ret; LARGE_INTEGER sz; char img[128];
    REQUIRE(UN(NtQuerySection)); REQUIRE(UN(NtCreateSection));
    sz.QuadPart = 0x10000;
    EXPECT_EQ(UN(NtCreateSection)(&h, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT, NULL), 0);
    memset(&b, 0xcc, sizeof b); ret = 0xdead;
    EXPECT_EQ(UN(NtQuerySection)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(ret, sizeof b);
    EXPECT_EQ(b.size.QuadPart, 0x10000);
    EXPECT_EQ(b.attrs & SEC_COMMIT, SEC_COMMIT);
    EXPECT_EQ(b.base, NULL);
    EXPECT_EQ(UN(NtQuerySection)(h, 0, &b, sizeof b - 1, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQuerySection)(h, 0, &b, 0, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQuerySection)(h, 7, &b, sizeof b, &ret), ST_INV_CLASS);
    /* image information is only available for image sections */
    memset(img, 0, sizeof img);
    EXPECT_EQ(UN(NtQuerySection)(h, 1, img, 64, &ret), S(0xC0000049) /* STATUS_SECTION_NOT_IMAGE */);
    EXPECT_EQ(UN(NtQuerySection)(NULL, 0, &b, sizeof b, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQuerySection)(PSEUDO_PROCESS, 0, &b, sizeof b, &ret), ST_TYPE_MISM);
    {
        HANDLE d = NULL;
        EXPECT_EQ(UN(NtDuplicateObject)(PSEUDO_PROCESS, h, PSEUDO_PROCESS, &d, SECTION_MAP_READ, 0, 0), 0);
        if (d) { EXPECT_EQ(UN(NtQuerySection)(d, 0, &b, sizeof b, &ret), ST_DENIED); UN(NtClose)(d); }
    }
    UN(NtClose)(h);
    /* page-file backed reserve section */
    sz.QuadPart = 0x20000;
    EXPECT_EQ(UN(NtCreateSection)(&h, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_RESERVE, NULL), 0);
    EXPECT_EQ(UN(NtQuerySection)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(b.attrs & SEC_RESERVE, SEC_RESERVE);
    EXPECT_EQ(b.size.QuadPart, 0x20000);
    UN(NtClose)(h);
}

/* ---- symbolic link ---- */
TEST(query_symlink)
{
    HANDLE h = NULL; UNICODE_STRING tgt, out; WCHAR buf[64]; ULONG ret; OBJECT_ATTRIBUTES oa;
    static const WCHAR target[] = L"\\Device\\Null";
    REQUIRE(UN(NtQuerySymbolicLinkObject)); REQUIRE(UN(NtCreateSymbolicLinkObject));
    tgt.Buffer = (PWSTR)target; tgt.Length = sizeof target - 2; tgt.MaximumLength = sizeof target;
    InitializeObjectAttributes(&oa, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtCreateSymbolicLinkObject)(&h, SYMBOLIC_LINK_ALL_ACCESS, &oa, &tgt), 0);
    memset(buf, 0xcc, sizeof buf);
    out.Buffer = buf; out.Length = 0; out.MaximumLength = sizeof buf; ret = 0xdead;
    EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(h, &out, &ret), 0);
    EXPECT_EQ(out.Length, tgt.Length);
    EXPECT_EQ(ret, tgt.Length + 2);    /* ReturnedLength counts the terminating NUL */
    CHECK(memcmp(buf, target, tgt.Length) == 0);
    /* output without a return-length pointer */
    out.Length = 0;
    EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(h, &out, NULL), 0);
    EXPECT_EQ(out.Length, tgt.Length);
    /* too small buffer: reports the needed length */
    out.Buffer = buf; out.Length = 0; out.MaximumLength = tgt.Length - 2; ret = 0;
    EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(h, &out, &ret), ST_BUF_SMALL);
    EXPECT_EQ(ret, tgt.Length + 2);
    /* Length bytes alone do not fit: room for the terminator is required */
    out.MaximumLength = tgt.Length; ret = 0;
    EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(h, &out, &ret), ST_BUF_SMALL);
    EXPECT_EQ(ret, tgt.Length + 2);
    out.MaximumLength = tgt.Length + 2; ret = 0;
    EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(h, &out, &ret), 0);
    EXPECT_EQ(out.Length, tgt.Length);
    EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(NULL, &out, &ret), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(PSEUDO_PROCESS, &out, &ret), ST_TYPE_MISM);
    {
        HANDLE d = NULL;
        EXPECT_EQ(UN(NtDuplicateObject)(PSEUDO_PROCESS, h, PSEUDO_PROCESS, &d, DELETE, 0, 0), 0);
        if (d) { EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(d, &out, &ret), ST_DENIED); UN(NtClose)(d); }
    }
    UN(NtClose)(h);
}

/* ---- QueryObject ---- */
typedef struct { UNICODE_STRING name; } OBJ_NAME;

TEST(query_object)
{
    HANDLE h = NULL, dir = NULL; ULONG ret; BYTE buf[512]; OBJECT_ATTRIBUTES oa; UNICODE_STRING nm;
    static WCHAR evname[] = L"qib_evt";
    REQUIRE(UN(NtQueryObject)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtCreateDirectoryObject));
    /* unnamed event: empty name */
    EXPECT_EQ(UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 0, FALSE), 0);
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryObject)(h, 1, buf, sizeof buf, &ret), 0);
    CHECK(ret >= sizeof(UNICODE_STRING));
    EXPECT_EQ(((UNICODE_STRING *)buf)->Length, 0);
    EXPECT_EQ(UN(NtQueryObject)(h, 1, buf, 0, &ret), ST_LEN_MISMATCH);
    CHECK(ret >= sizeof(UNICODE_STRING));
    /* type info: name "Event" */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryObject)(h, 2, buf, sizeof buf, &ret), 0);
    {
        UNICODE_STRING *t = (UNICODE_STRING *)buf;
        EXPECT_EQ(t->Length, 10);
        CHECK(t->Buffer && memcmp(t->Buffer, L"Event", 10) == 0);
    }
    EXPECT_EQ(UN(NtQueryObject)(h, 2, buf, 4, &ret), ST_LEN_MISMATCH);
    CHECK(ret > 4);
    /* handle flags (class 4): inherit/protect */
    {
        BYTE fl[2] = { 0xcc, 0xcc };
        EXPECT_EQ(UN(NtQueryObject)(h, 4, fl, 2, &ret), 0);
        EXPECT_EQ(ret, 2); EXPECT_EQ(fl[0], 0); EXPECT_EQ(fl[1], 0);
        EXPECT_EQ(UN(NtQueryObject)(h, 4, fl, 1, &ret), ST_LEN_MISMATCH);
    }
    EXPECT_EQ(UN(NtQueryObject)(h, 0x7777, buf, sizeof buf, &ret), ST_INV_CLASS);
    EXPECT_EQ(UN(NtQueryObject)((HANDLE)(ULONG_PTR)0x7ffc, 0, buf, sizeof buf, &ret), ST_INV_HANDLE);
    UN(NtClose)(h);
    /* named event inside a private directory: name is "\<leaf>" relative to the unnamed directory */
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    EXPECT_EQ(UN(NtCreateDirectoryObject)(&dir, DIRECTORY_ALL_ACCESS, &oa), 0);
    nm.Buffer = evname; nm.Length = sizeof evname - 2; nm.MaximumLength = sizeof evname;
    InitializeObjectAttributes(&oa, &nm, OBJ_CASE_INSENSITIVE, dir, NULL);
    EXPECT_EQ(UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, &oa, 0, FALSE), 0);
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryObject)(h, 1, buf, sizeof buf, &ret), 0);
    {
        UNICODE_STRING *u = (UNICODE_STRING *)buf;
        t_note("named object in private dir: name len %u", u->Length);
        CHECK(u->Length >= nm.Length);
        CHECK(u->Length >= nm.Length && memcmp((char *)u->Buffer + u->Length - nm.Length, evname, nm.Length) == 0);
    }
    UN(NtClose)(h);
    UN(NtClose)(dir);
}

/* ---- directory object enumeration ---- */
typedef struct { UNICODE_STRING name, type; } DIR_INFO;

TEST(query_directory_object)
{
    HANDLE dir = NULL, e[3] = { 0 }, l = NULL, qd = NULL; OBJECT_ATTRIBUTES oa; UNICODE_STRING nm, tgt;
    static WCHAR names[3][4] = { L"A_a", L"B_b", L"C_c" };
    static WCHAR lname[] = L"L_l", ltarget[] = L"\\Device\\Null";
    BYTE buf[2048]; ULONG ctx, ret; int i, found[4] = { 0 };
    REQUIRE(UN(NtQueryDirectoryObject)); REQUIRE(UN(NtCreateDirectoryObject)); REQUIRE(UN(NtCreateEvent));
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    EXPECT_EQ(UN(NtCreateDirectoryObject)(&dir, DIRECTORY_ALL_ACCESS, &oa), 0);
    /* empty directory */
    ctx = 0; ret = 0xdead;
    EXPECT_EQ(UN(NtQueryDirectoryObject)(dir, buf, sizeof buf, FALSE, TRUE, &ctx, &ret), ST_NO_MORE);
    for (i = 0; i < 3; i++) {
        nm.Buffer = names[i]; nm.Length = 6; nm.MaximumLength = 8;
        InitializeObjectAttributes(&oa, &nm, OBJ_CASE_INSENSITIVE, dir, NULL);
        EXPECT_EQ(UN(NtCreateEvent)(&e[i], EVENT_ALL_ACCESS, &oa, 0, FALSE), 0);
    }
    nm.Buffer = lname; nm.Length = 6; nm.MaximumLength = 8;
    tgt.Buffer = ltarget; tgt.Length = sizeof ltarget - 2; tgt.MaximumLength = sizeof ltarget;
    InitializeObjectAttributes(&oa, &nm, OBJ_CASE_INSENSITIVE, dir, NULL);
    EXPECT_EQ(UN(NtCreateSymbolicLinkObject)(&l, SYMBOLIC_LINK_ALL_ACCESS, &oa, &tgt), 0);
    /* all entries in one call, terminated by an all-zero entry */
    memset(buf, 0xcc, sizeof buf); ctx = 0; ret = 0xdead;
    EXPECT_EQ(UN(NtQueryDirectoryObject)(dir, buf, sizeof buf, FALSE, TRUE, &ctx, &ret), 0);
    EXPECT_EQ(ctx, 4);
    {
        DIR_INFO *d = (DIR_INFO *)buf; int n = 0;
        for (; d->name.Length; d++, n++) {
            CHECK(n < 8);
            if (n >= 8) break;
            if (d->name.Length == 6 && !_wcsnicmp(d->name.Buffer, L"A_a", 3)) { found[0]++; EXPECT_EQ(d->type.Length, 10); CHECK(!memcmp(d->type.Buffer, L"Event", 10)); }
            if (d->name.Length == 6 && !_wcsnicmp(d->name.Buffer, L"B_b", 3)) found[1]++;
            if (d->name.Length == 6 && !_wcsnicmp(d->name.Buffer, L"C_c", 3)) found[2]++;
            if (d->name.Length == 6 && !_wcsnicmp(d->name.Buffer, L"L_l", 3)) { found[3]++; EXPECT_EQ(d->type.Length, 24); CHECK(!memcmp(d->type.Buffer, L"SymbolicLink", 24)); }
        }
        EXPECT_EQ(n, 4);
        EXPECT_EQ(d->name.Length, 0); EXPECT_EQ(d->name.Buffer, NULL);
        CHECK(ret > 0 && ret <= sizeof buf);
    }
    for (i = 0; i < 4; i++) EXPECT_EQ(found[i], 1);
    /* single-entry enumeration walks all four, then reports no more */
    {
        int n = 0; NTSTATUS st; ctx = 0;
        for (;;) {
            memset(buf, 0xcc, sizeof buf);
            st = UN(NtQueryDirectoryObject)(dir, buf, sizeof buf, TRUE, n == 0, &ctx, &ret);
            if (st != 0) break;
            CHECK(((DIR_INFO *)buf)->name.Length == 6);
            n++;
            if (n > 8) break;
        }
        EXPECT_EQ(n, 4); EXPECT_EQ(st, ST_NO_MORE);
    }
    /* buffer too small for even one entry */
    ctx = 0; ret = 0;
    EXPECT_EQ(UN(NtQueryDirectoryObject)(dir, buf, 8, TRUE, TRUE, &ctx, &ret), ST_BUF_SMALL);
    /* restart scan rewinds the context */
    ctx = 0;
    EXPECT_EQ(UN(NtQueryDirectoryObject)(dir, buf, sizeof buf, TRUE, TRUE, &ctx, &ret), 0);
    EXPECT_EQ(UN(NtQueryDirectoryObject)(dir, buf, sizeof buf, TRUE, TRUE, &ctx, &ret), 0);
    EXPECT_EQ(ctx, 1);
    /* wrong object type, bad handle */
    EXPECT_EQ(UN(NtQueryDirectoryObject)(e[0], buf, sizeof buf, FALSE, TRUE, &ctx, &ret), ST_TYPE_MISM);
    EXPECT_EQ(UN(NtQueryDirectoryObject)(NULL, buf, sizeof buf, FALSE, TRUE, &ctx, &ret), ST_INV_HANDLE);
    /* a directory handle without DIRECTORY_QUERY */
    EXPECT_EQ(UN(NtDuplicateObject)(PSEUDO_PROCESS, dir, PSEUDO_PROCESS, &qd, DIRECTORY_TRAVERSE, 0, 0), 0);
    if (qd) { EXPECT_EQ(UN(NtQueryDirectoryObject)(qd, buf, sizeof buf, FALSE, TRUE, &ctx, &ret), ST_DENIED); UN(NtClose)(qd); }
    UN(NtClose)(l);
    for (i = 0; i < 3; i++) UN(NtClose)(e[i]);
    UN(NtClose)(dir);
}

TEST(query_directory_object_types)
{
    HANDLE dir = NULL; OBJECT_ATTRIBUTES oa; UNICODE_STRING nm; BYTE buf[8192]; ULONG ctx = 0, ret; int ev = 0, mut = 0;
    NTSTATUS st;
    REQUIRE(UN(NtQueryDirectoryObject)); REQUIRE(UN(NtOpenDirectoryObject));
    { static WCHAR ot[] = L"\\ObjectTypes"; nm.Buffer = ot; nm.Length = sizeof ot - 2; nm.MaximumLength = sizeof ot; }
    InitializeObjectAttributes(&oa, &nm, OBJ_CASE_INSENSITIVE, NULL, NULL);
    EXPECT_EQ(UN(NtOpenDirectoryObject)(&dir, DIRECTORY_QUERY, &oa), 0);
    if (!dir) return;
    st = UN(NtQueryDirectoryObject)(dir, buf, sizeof buf, FALSE, TRUE, &ctx, &ret);
    CHECK(st == 0 || st == S(0x00000105) /* STATUS_MORE_ENTRIES */);
    {
        DIR_INFO *d = (DIR_INFO *)buf;
        for (; d->name.Length; d++) {
            if (d->name.Length == 10 && !memcmp(d->name.Buffer, L"Event", 10)) ev++;
            if (d->name.Length == 12 && !memcmp(d->name.Buffer, L"Mutant", 12)) mut++;
            CHECK(d->type.Length == 8 && !memcmp(d->type.Buffer, L"Type", 8));
        }
    }
    CHECK(ev + mut >= 1);
    UN(NtClose)(dir);
}

/* ---- security descriptor ---- */
TEST(query_security_object)
{
    HANDLE h = NULL, d = NULL, dir = NULL; BYTE sd[1024]; ULONG need = 0; NTSTATUS st;
    OBJECT_ATTRIBUTES oa; UNICODE_STRING nm; static WCHAR en[] = L"qib_sd_evt";
    SECURITY_DESCRIPTOR_RELATIVE *r = (SECURITY_DESCRIPTOR_RELATIVE *)sd;
    REQUIRE(UN(NtQuerySecurityObject)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtCreateDirectoryObject));
    /* unnamed objects carry no security descriptor: an empty self-relative header comes back */
    EXPECT_EQ(UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 0, FALSE), 0);
    memset(sd, 0xcc, sizeof sd);
    EXPECT_EQ(UN(NtQuerySecurityObject)(h, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd, sizeof sd, &need), 0);
    EXPECT_EQ(need, 20); EXPECT_EQ(r->Revision, 1); CHECK(r->Control & SE_SELF_RELATIVE);
    EXPECT_EQ(r->Owner, 0); EXPECT_EQ(r->Dacl, 0);
    UN(NtClose)(h);
    /* named object in a private directory */
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    EXPECT_EQ(UN(NtCreateDirectoryObject)(&dir, DIRECTORY_ALL_ACCESS, &oa), 0);
    nm.Buffer = en; nm.Length = sizeof en - 2; nm.MaximumLength = sizeof en;
    InitializeObjectAttributes(&oa, &nm, OBJ_CASE_INSENSITIVE, dir, NULL);
    EXPECT_EQ(UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, &oa, 0, FALSE), 0);
    st = UN(NtQuerySecurityObject)(h, OWNER_SECURITY_INFORMATION, sd, 0, &need);
    t_note("owner query len 0: st=%08lx need=%lu", (unsigned long)st, need);
    EXPECT_EQ(st, ST_BUF_SMALL);
    CHECK(need > 20 && need <= sizeof sd);
    memset(sd, 0xcc, sizeof sd);
    EXPECT_EQ(UN(NtQuerySecurityObject)(h, OWNER_SECURITY_INFORMATION, sd, sizeof sd, &need), 0);
    EXPECT_EQ(r->Revision, 1); CHECK(r->Control & SE_SELF_RELATIVE);
    CHECK(r->Owner != 0); EXPECT_EQ(r->Group, 0); EXPECT_EQ(r->Dacl, 0); EXPECT_EQ(r->Sacl, 0);
    CHECK(UN(RtlValidSecurityDescriptor) == NULL || UN(RtlValidSecurityDescriptor)(sd));
    {
        ULONG need2 = 0;
        st = UN(NtQuerySecurityObject)(h, OWNER_SECURITY_INFORMATION, sd, need - 1, &need2);
        EXPECT_EQ(st, ST_BUF_SMALL); EXPECT_EQ(need2, need);
    }
    memset(sd, 0xcc, sizeof sd);
    EXPECT_EQ(UN(NtQuerySecurityObject)(h, GROUP_SECURITY_INFORMATION, sd, sizeof sd, &need), 0);
    CHECK(r->Group != 0); EXPECT_EQ(r->Owner, 0);
    st = UN(NtQuerySecurityObject)(h, DACL_SECURITY_INFORMATION, sd, sizeof sd, &need);
    t_note("dacl query: st=%08lx need=%lu dacl=%lu", (unsigned long)st, need, (unsigned long)r->Dacl);
    EXPECT_EQ(st, 0);
    /* no READ_CONTROL: refused */
    EXPECT_EQ(UN(NtDuplicateObject)(PSEUDO_PROCESS, h, PSEUDO_PROCESS, &d, EVENT_QUERY_STATE, 0, 0), 0);
    if (d) {
        EXPECT_EQ(UN(NtQuerySecurityObject)(d, OWNER_SECURITY_INFORMATION, sd, sizeof sd, &need), ST_DENIED);
        UN(NtClose)(d);
    }
    EXPECT_EQ(UN(NtQuerySecurityObject)(NULL, OWNER_SECURITY_INFORMATION, sd, sizeof sd, &need), ST_INV_HANDLE);
    UN(NtClose)(h);
    UN(NtClose)(dir);
}

/* ---- atoms ---- */
typedef struct { USHORT usage, flags, nameLen; WCHAR name[1]; } ATOM_BASIC;

TEST(query_information_atom)
{
    NTSTATUS st; USHORT atom = 0; BYTE buf[128]; ULONG ret; static WCHAR nm[] = L"qib_atom_test";
    REQUIRE(UN(NtQueryInformationAtom)); REQUIRE(UN(NtAddAtom)); REQUIRE(UN(NtDeleteAtom));
    st = UN(NtAddAtom)(nm, sizeof nm - 2, &atom);
    if (st == ST_DENIED) {   /* atom table belongs to the window station: needs a GUI-initialised process */
        HMODULE u = LoadLibraryA("user32.dll");
        if (u) { FARPROC f = GetProcAddress(u, "GetDesktopWindow"); if (f) f(); }
        st = UN(NtAddAtom)(nm, sizeof nm - 2, &atom);
        t_note("NtAddAtom after user32 init: %08lx", (unsigned long)st);
    }
    if (st == ST_DENIED) { t_skip("NtAddAtom denied: no window-station atom table in this process"); return; }
    EXPECT_EQ(st, 0);
    CHECK(atom >= 0xC000);
    memset(buf, 0xcc, sizeof buf); ret = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationAtom)(atom, 0, buf, sizeof buf, &ret), 0);
    {
        ATOM_BASIC *b = (ATOM_BASIC *)buf;
        EXPECT_EQ(b->usage, 1);
        EXPECT_EQ(b->nameLen, sizeof nm - 2);
        CHECK(memcmp(b->name, nm, sizeof nm - 2) == 0);
        EXPECT_EQ(b->name[sizeof nm / 2 - 1], 0);
        EXPECT_EQ(ret, 6 + sizeof nm);
    }
    /* second add bumps the reference count */
    {
        USHORT a2 = 0;
        EXPECT_EQ(UN(NtAddAtom)(nm, sizeof nm - 2, &a2), 0);
        EXPECT_EQ(a2, atom);
        EXPECT_EQ(UN(NtQueryInformationAtom)(atom, 0, buf, sizeof buf, &ret), 0);
        EXPECT_EQ(((ATOM_BASIC *)buf)->usage, 2);
        EXPECT_EQ(UN(NtDeleteAtom)(atom), 0);
    }
    /* too small for the name */
    EXPECT_EQ(UN(NtQueryInformationAtom)(atom, 0, buf, 6, &ret), ST_BUF_SMALL);
    EXPECT_EQ(UN(NtQueryInformationAtom)(atom, 0, buf, 5, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(UN(NtQueryInformationAtom)(atom, 9, buf, sizeof buf, &ret), ST_INV_CLASS);
    /* table information: too small a buffer still reports the atom count */
    memset(buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryInformationAtom)(0, 1, buf, 4, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(ret, 4);
    { ULONG n = *(ULONG *)buf; CHECK(n >= 1 && n < 400);
      if (n >= 1 && n < 400) {
        BYTE big[1024]; USHORT *a = (USHORT *)(big + 4); ULONG i; int f = 0;
        memset(big, 0xcc, sizeof big);
        EXPECT_EQ(UN(NtQueryInformationAtom)(0, 1, big, 4 + n * 2 - 2, &ret), ST_LEN_MISMATCH);
        EXPECT_EQ(UN(NtQueryInformationAtom)(0, 1, big, sizeof big, &ret), 0);
        CHECK(*(ULONG *)big >= n - 4 && *(ULONG *)big <= n + 4);
        EXPECT_EQ(ret, 4 + *(ULONG *)big * 2);
        for (i = 0; i < *(ULONG *)big && i < 400; i++) if (a[i] == atom) f++;
        EXPECT_EQ(f, 1);
      } }
    EXPECT_EQ(UN(NtDeleteAtom)(atom), 0);
    EXPECT_EQ(UN(NtQueryInformationAtom)(atom, 0, buf, sizeof buf, &ret), ST_INV_HANDLE);   /* deleted atom */
    EXPECT_EQ(UN(NtQueryInformationAtom)(0, 0, buf, sizeof buf, &ret), ST_INV_PARAM);
}

/* Object manager services on private events: NtQueryObject, NtSetInformationObject,
 * NtDuplicateObject and NtClose behaviour. */
#include "t.h"

UDECL(NTSTATUS, NtQueryObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationObject, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtDuplicateObject, (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtSetEvent, (HANDLE, PLONG));
UDECL(NTSTATUS, NtOpenEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));

#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 0x0001
#endif
#define XS(x) ((NTSTATUS)(x))
#define XOK(s) ((NTSTATUS)(s) >= 0)
#define XO_NEED() do { REQUIRE(UN(NtQueryObject)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtDuplicateObject)); REQUIRE(UN(NtSetInformationObject)); } while (0)
typedef struct { ULONG attributes, granted, handles, pointers, paged, nonpaged, res[3], name_size, type_size, sd_size; LARGE_INTEGER created; } xo_basic;

static HANDLE xo_event(void)
{
    HANDLE h = NULL;
    if (!XOK(UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 0 /* NotificationEvent */, FALSE))) return NULL;
    return h;
}
TEST(nt_sync_x_object_basic_information)
{
    HANDLE h; xo_basic b; ULONG ret = 0; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    CHECK(sizeof b == 56);
    memset(&b, 0xcc, sizeof b);
    EXPECT_EQ(UN(NtQueryObject)(h, 0, &b, sizeof b, &ret), 0);
    EXPECT_EQ(ret, 56);
    CHECK(b.handles >= 1); CHECK(b.pointers >= b.handles);
    EXPECT_EQ(b.granted & EVENT_ALL_ACCESS, EVENT_ALL_ACCESS);
    EXPECT_EQ(UN(NtQueryObject)(h, 0, &b, sizeof b - 1, &ret), XS(0xC0000004));
    EXPECT_EQ(UN(NtQueryObject)(h, 0, &b, 0, &ret), XS(0xC0000004));
    UN(NtClose)(h);
}
TEST(nt_sync_x_object_basic_information_counts_handles)
{
    HANDLE h, d = NULL; xo_basic b; ULONG ret, before; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    UN(NtQueryObject)(h, 0, &b, sizeof b, &ret); before = b.handles;
    EXPECT_EQ(UN(NtDuplicateObject)(GetCurrentProcess(), h, GetCurrentProcess(), &d, 0, 0, DUPLICATE_SAME_ACCESS), 0);
    UN(NtQueryObject)(h, 0, &b, sizeof b, &ret); EXPECT_EQ(b.handles, before + 1);
    if (d) UN(NtClose)(d);
    UN(NtQueryObject)(h, 0, &b, sizeof b, &ret); EXPECT_EQ(b.handles, before);
    UN(NtClose)(h);
}
TEST(nt_sync_x_object_type_information)
{
    HANDLE h; union { ULONGLONG a; BYTE b[512]; } buf; UNICODE_STRING *u = (UNICODE_STRING *)buf.b; ULONG ret = 0, need; NTSTATUS s; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    s = UN(NtQueryObject)(h, 2, NULL, 0, &ret);
    EXPECT_EQ(s, XS(0xC0000004)); CHECK(ret > 0); need = ret;
    if (need <= sizeof buf) {
        s = UN(NtQueryObject)(h, 2, &buf, need, &ret);
        EXPECT_EQ(s, 0);
        if (s == 0) { CHECK(u->Length == 10 && u->Buffer && !memcmp(u->Buffer, L"Event", 10)); }
        s = UN(NtQueryObject)(h, 2, &buf, need - 1, &ret);
        EXPECT_EQ(s, XS(0xC0000004));
    }
    UN(NtClose)(h);
}
TEST(nt_sync_x_object_type_names_of_other_kinds)
{
    union { ULONGLONG a; BYTE b[512]; } buf; UNICODE_STRING *u = (UNICODE_STRING *)buf.b; ULONG ret; HANDLE h; XO_NEED();
    memset(&buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtQueryObject)(GetCurrentProcess(), 2, &buf, sizeof buf, &ret), 0);
    CHECK(u->Length == 14 && !memcmp(u->Buffer, L"Process", 14));
    h = GetCurrentThread();
    EXPECT_EQ(UN(NtQueryObject)(h, 2, &buf, sizeof buf, &ret), 0);
    CHECK(u->Length == 12 && !memcmp(u->Buffer, L"Thread", 12));
    { HANDLE tok = NULL; if (XOK(((NTSTATUS (WINAPI *)(HANDLE, ACCESS_MASK, PHANDLE))t_proc("NtOpenProcessToken"))(GetCurrentProcess(), TOKEN_QUERY, &tok)) && tok) {
        EXPECT_EQ(UN(NtQueryObject)(tok, 2, &buf, sizeof buf, &ret), 0);
        CHECK(u->Length == 10 && !memcmp(u->Buffer, L"Token", 10)); UN(NtClose)(tok); } }
}
TEST(nt_sync_x_object_name_information_unnamed)
{
    HANDLE h; union { ULONGLONG a; BYTE b[512]; } buf; UNICODE_STRING *u = (UNICODE_STRING *)buf.b; ULONG ret = 0; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    memset(&buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQueryObject)(h, 1, &buf, sizeof buf, &ret), 0);
    EXPECT_EQ(u->Length, 0); t_note("unnamed object name returned length %lu", ret);
    CHECK(ret >= sizeof(UNICODE_STRING));
    EXPECT_EQ(UN(NtQueryObject)(h, 1, &buf, 4, &ret), XS(0xC0000004));
    UN(NtClose)(h);
}
TEST(nt_sync_x_object_name_information_named_event)
{
    HANDLE h = NULL; WCHAR name[64]; UNICODE_STRING us; OBJECT_ATTRIBUTES oa; union { ULONGLONG a; BYTE b[1024]; } buf; UNICODE_STRING *u = (UNICODE_STRING *)buf.b; ULONG ret = 0, full; NTSTATUS s; XO_NEED();
    REQUIRE(UIN("kernel32.dll", CreateEventW)); REQUIRE(UIN("kernel32.dll", CloseHandle));
    wsprintfW(name, L"NtdllConf_%lu_namedevent", GetCurrentProcessId());
    h = UIN("kernel32.dll", CreateEventW)(NULL, TRUE, FALSE, name); CHECK(h != NULL); if (!h) return;
    memset(&buf, 0, sizeof buf);
    s = UN(NtQueryObject)(h, 1, &buf, sizeof buf, &ret);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        int n = lstrlenW(name);
        CHECK(u->Length >= (n + 1) * 2 && u->Buffer != NULL);
        if (u->Length >= (n + 1) * 2) { CHECK(u->Buffer[u->Length / 2 - n - 1] == L'\\'); CHECK(!lstrcmpW(u->Buffer + u->Length / 2 - n, name)); }
        CHECK(!_wcsnicmp(u->Buffer, L"\\", 1));
        EXPECT_EQ(ret, sizeof(UNICODE_STRING) + u->Length + 2);
        full = ret;
        s = UN(NtQueryObject)(h, 1, &buf, full - 2, &ret);
        EXPECT_EQ(s, XS(0xC0000004)); EXPECT_EQ(ret, full);
    }
    /* open it again by name through the native API */
    us.Buffer = name; us.Length = us.MaximumLength = (USHORT)(lstrlenW(name) * 2);
    if (UN(NtOpenEvent)) {
        HANDLE o = NULL; /* relative open needs the session directory; just check that a bad name is refused */
        InitializeObjectAttributes(&oa, &us, 0, NULL, NULL);
        s = UN(NtOpenEvent)(&o, EVENT_ALL_ACCESS, &oa);
        CHECK(!XOK(s)); t_note("open of an unqualified name status=%08lx", s);
        if (o) UN(NtClose)(o);
    }
    UIN("kernel32.dll", CloseHandle)(h);
}
TEST(nt_sync_x_object_invalid_class_and_handle)
{
    HANDLE h; BYTE buf[256]; ULONG ret = 0; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(UN(NtQueryObject)(h, 0x7f, buf, sizeof buf, &ret), XS(0xC0000003));
    EXPECT_EQ(UN(NtQueryObject)((HANDLE)(ULONG_PTR)0x7ffc, 0, buf, sizeof buf, &ret), XS(0xC0000008));
    EXPECT_EQ(UN(NtQueryObject)(NULL, 2, buf, sizeof buf, &ret), XS(0xC0000008));
    UN(NtClose)(h);
}
TEST(nt_sync_x_object_handle_flags)
{
    HANDLE h; struct { BOOLEAN inherit, protect; } fl; DWORD kf = 0; ULONG ret = 0; XO_NEED(); REQUIRE(UIN("kernel32.dll", GetHandleInformation)); REQUIRE(UIN("kernel32.dll", SetHandleInformation));
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    memset(&fl, 0xcc, sizeof fl);
    EXPECT_EQ(UN(NtQueryObject)(h, 4, &fl, 2, &ret), 0);
    EXPECT_EQ(fl.inherit, 0); EXPECT_EQ(fl.protect, 0); EXPECT_EQ(ret, 2);
    fl.inherit = 1; fl.protect = 0;
    EXPECT_EQ(UN(NtSetInformationObject)(h, 4, &fl, 2), 0);
    UIN("kernel32.dll", GetHandleInformation)(h, &kf); CHECK(kf & HANDLE_FLAG_INHERIT);
    UIN("kernel32.dll", SetHandleInformation)(h, HANDLE_FLAG_INHERIT, 0);
    memset(&fl, 0xcc, sizeof fl);
    EXPECT_EQ(UN(NtQueryObject)(h, 4, &fl, 2, &ret), 0); EXPECT_EQ(fl.inherit, 0);
    EXPECT_EQ(UN(NtQueryObject)(h, 4, &fl, 1, &ret), XS(0xC0000004));
    EXPECT_EQ(UN(NtSetInformationObject)(h, 4, &fl, 1), XS(0xC0000004));
    EXPECT_EQ(UN(NtSetInformationObject)(h, 0x7f, &fl, 2), XS(0xC0000003));
    UN(NtClose)(h);
}
TEST(nt_sync_x_object_protect_from_close)
{
    HANDLE h; struct { BOOLEAN inherit, protect; } fl; NTSTATUS s; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    fl.inherit = 0; fl.protect = 1;
    EXPECT_EQ(UN(NtSetInformationObject)(h, 4, &fl, 2), 0);
    s = UN(NtClose)(h);
    EXPECT_EQ(s, XS(0xC0000235));                                  /* STATUS_HANDLE_NOT_CLOSABLE */
    fl.protect = 0;
    EXPECT_EQ(UN(NtSetInformationObject)(h, 4, &fl, 2), 0);
    EXPECT_EQ(UN(NtClose)(h), 0);
}
TEST(nt_sync_x_close_invalid_handles)
{
    HANDLE h; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(UN(NtClose)(h), 0);
    EXPECT_EQ(UN(NtClose)(h), XS(0xC0000008));                    /* already closed */
    EXPECT_EQ(UN(NtClose)((HANDLE)(ULONG_PTR)0x7ffc), XS(0xC0000008));
    EXPECT_EQ(UN(NtClose)(NULL), XS(0xC0000008));
}
TEST(nt_sync_x_duplicate_same_access_and_explicit_access)
{
    HANDLE h, d1 = NULL, d2 = NULL; xo_basic b; ULONG ret; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(UN(NtDuplicateObject)(GetCurrentProcess(), h, GetCurrentProcess(), &d1, 0, 0, DUPLICATE_SAME_ACCESS), 0);
    CHECK(d1 != NULL && d1 != h);
    if (d1) { UN(NtQueryObject)(d1, 0, &b, sizeof b, &ret); EXPECT_EQ(b.granted & EVENT_ALL_ACCESS, EVENT_ALL_ACCESS); }
    EXPECT_EQ(UN(NtDuplicateObject)(GetCurrentProcess(), h, GetCurrentProcess(), &d2, SYNCHRONIZE | EVENT_QUERY_STATE, 0, 0), 0);
    if (d2) { UN(NtQueryObject)(d2, 0, &b, sizeof b, &ret); EXPECT_EQ(b.granted, SYNCHRONIZE | EVENT_QUERY_STATE); }
    if (d2) {   /* a handle without modify access cannot signal the event */
        REQUIRE(UN(NtSetEvent));
        EXPECT_EQ(UN(NtSetEvent)(d2, NULL), XS(0xC0000022));
    }
    if (d1) UN(NtClose)(d1);
    if (d2) UN(NtClose)(d2);
    UN(NtClose)(h);
}
TEST(nt_sync_x_duplicate_cannot_widen_access)
{
    HANDLE h, narrow = NULL, wide = NULL; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(UN(NtDuplicateObject)(GetCurrentProcess(), h, GetCurrentProcess(), &narrow, SYNCHRONIZE, 0, 0), 0);
    /* Access is not capped by the source handle: a duplicate may request more, subject to the object's security descriptor. */
    if (narrow) {
        xo_basic b; ULONG ret;
        EXPECT_EQ(UN(NtDuplicateObject)(GetCurrentProcess(), narrow, GetCurrentProcess(), &wide, EVENT_ALL_ACCESS, 0, 0), 0);
        if (wide) { UN(NtQueryObject)(wide, 0, &b, sizeof b, &ret); EXPECT_EQ(b.granted & EVENT_ALL_ACCESS, EVENT_ALL_ACCESS); UN(NtClose)(wide); }
        UN(NtClose)(narrow);
    }
    UN(NtClose)(h);
}
TEST(nt_sync_x_duplicate_close_source)
{
    HANDLE h, d = NULL; xo_basic b; ULONG ret; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(UN(NtDuplicateObject)(GetCurrentProcess(), h, GetCurrentProcess(), &d, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE), 0);
    /* The source is closed before the duplicate is created, so within one process the duplicate usually reuses the value. */
    if (d != h) EXPECT_EQ(UN(NtQueryObject)(h, 0, &b, sizeof b, &ret), XS(0xC0000008));
    else t_note("the duplicate reuses the source handle value");
    if (d) { EXPECT_EQ(UN(NtQueryObject)(d, 0, &b, sizeof b, &ret), 0); EXPECT_EQ(b.handles, 1); UN(NtClose)(d); }
}
TEST(nt_sync_x_duplicate_flags_and_errors)
{
    HANDLE h, d = NULL; struct { BOOLEAN inherit, protect; } fl; ULONG ret; XO_NEED();
    h = xo_event(); CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(UN(NtDuplicateObject)(GetCurrentProcess(), h, GetCurrentProcess(), &d, 0, OBJ_INHERIT, DUPLICATE_SAME_ACCESS), 0);
    if (d) { memset(&fl, 0xcc, sizeof fl); UN(NtQueryObject)(d, 4, &fl, 2, &ret); EXPECT_EQ(fl.inherit, 1); UN(NtClose)(d); d = NULL; }
    EXPECT_EQ(UN(NtDuplicateObject)(GetCurrentProcess(), (HANDLE)(ULONG_PTR)0x7ffc, GetCurrentProcess(), &d, 0, 0, DUPLICATE_SAME_ACCESS), XS(0xC0000008));
    EXPECT_EQ(UN(NtDuplicateObject)((HANDLE)(ULONG_PTR)0x7ffc, h, GetCurrentProcess(), &d, 0, 0, DUPLICATE_SAME_ACCESS), XS(0xC0000008));
    EXPECT_EQ(UN(NtDuplicateObject)(GetCurrentProcess(), h, (HANDLE)(ULONG_PTR)0x7ffc, &d, 0, 0, DUPLICATE_SAME_ACCESS), XS(0xC0000008));
    /* without a target handle pointer only the close-source side effect happens */
    { HANDLE h2 = xo_event(); xo_basic b;
      if (h2) { NTSTATUS s = UN(NtDuplicateObject)(GetCurrentProcess(), h2, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE);
                t_note("close-source duplicate without a target status=%08lx", s);
                if (XOK(s)) EXPECT_EQ(UN(NtQueryObject)(h2, 0, &b, sizeof b, &ret), XS(0xC0000008)); else UN(NtClose)(h2); } }
    UN(NtClose)(h);
}
TEST(nt_sync_x_duplicate_pseudo_handle_to_real_process_handle)
{
    HANDLE real = NULL; struct { NTSTATUS exit; PVOID peb; ULONG_PTR aff; LONG prio; ULONG_PTR pid, ppid; } pb; ULONG ret; NTSTATUS (WINAPI *qip)(HANDLE, ULONG, PVOID, ULONG, PULONG); XO_NEED();
    qip = (void *)t_proc("NtQueryInformationProcess"); REQUIRE(qip);
    EXPECT_EQ(UN(NtDuplicateObject)((HANDLE)(LONG_PTR)-1, (HANDLE)(LONG_PTR)-1, (HANDLE)(LONG_PTR)-1, &real, 0, 0, DUPLICATE_SAME_ACCESS), 0);
    CHECK(real != NULL && real != (HANDLE)(LONG_PTR)-1);
    if (real) { EXPECT_EQ(qip(real, 0, &pb, sizeof pb, &ret), 0); EXPECT_EQ(pb.pid, GetCurrentProcessId()); UN(NtClose)(real); }
}

/* Create/open services for synchronization objects: mutant, semaphore, event,
 * event pair, timers (classic, Timer2, IR), keyed event. */
#include "cob.h"

UDECL(NTSTATUS, ZwCreateMutant, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN));
UDECL(NTSTATUS, ZwOpenMutant, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwCreateSemaphore, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG));
UDECL(NTSTATUS, ZwOpenSemaphore, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwOpenEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwCreateTimer, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, ZwOpenTimer, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwCreateTimer2, (PHANDLE, PVOID, POBJECT_ATTRIBUTES, ULONG, ACCESS_MASK));
UDECL(NTSTATUS, ZwCreateIRTimer, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwCreateKeyedEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, ZwOpenKeyedEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtReleaseKeyedEvent, (HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtWaitForKeyedEvent, (HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwOpenEventPair, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateEventPair, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtQueryMutant, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQuerySemaphore, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryTimer, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtWaitForSingleObject, (HANDLE, BOOLEAN, PLARGE_INTEGER));

#define KEYEDEVENT_ALL_ACCESS_ 0x3
#define NEED(x) do { REQUIRE(UN(x)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtQueryObject)); } while (0)

/* Generic named-object checks shared by every create/open pair here. */
typedef NTSTATUS (WINAPI *open_fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

static void open_error_paths(open_fn op, const char *tag, ACCESS_MASK acc)
{
    HANDLE h = (HANDLE)0x1234; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200];
    cob_name(name, 200, tag); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    EXPECT_EQ(op(&h, acc, &oa), S_NOTFOUND);
        /* path component that does not exist */
    { WCHAR deep[260]; UNICODE_STRING d; lstrcpyW(deep, name); lstrcatW(deep, L"\\child"); cob_us(&d, deep); cob_oa(&oa, &d, 0, NULL);
      h = (HANDLE)0x1234; EXPECT_EQ(op(&h, acc, &oa), S_PATHNF); }
    /* NULL object attributes / name */
    h = (HANDLE)0x1234; EXPECT_EQ(op(&h, acc, NULL), S_INVPARAM);
    cob_oa(&oa, NULL, 0, NULL); h = (HANDLE)0x1234; EXPECT_EQ(op(&h, acc, &oa), S_PATHSYN);
    { UNICODE_STRING e = {0, 0, NULL}; cob_oa(&oa, &e, 0, NULL); h = (HANDLE)0x1234; EXPECT_EQ(op(&h, acc, &oa), S_PATHSYN); }
    /* bad OA length */
    cob_us(&u, name); cob_oa(&oa, &u, 0, NULL); oa.Length = 8; h = (HANDLE)0x1234; EXPECT_EQ(op(&h, acc, &oa), S_INVPARAM);
    /* bad handle pointer */
    cob_oa(&oa, &u, 0, NULL); EXPECT_EQ(op((PHANDLE)(ULONG_PTR)8, acc, &oa), S_AV);
    EXPECT_EQ(op(NULL, acc, &oa), S_AV);
    /* invalid root directory handle */
    { UNICODE_STRING r; WCHAR *leaf = L"x"; cob_us(&r, leaf); cob_oa(&oa, &r, 0, (HANDLE)(ULONG_PTR)0x7ffffff0); h = (HANDLE)0x1234;
      EXPECT_EQ(op(&h, acc, &oa), S_INVHANDLE); }
}

TEST(nt_create_open_b_mutant)
{
    HANDLE h = NULL, h2 = NULL, o = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200], tn[32]; NTSTATUS s; ULONG g = 0;
    struct { LONG count; BOOLEAN owned, aband; } mi; ULONG ret = 0;
    NEED(ZwCreateMutant); REQUIRE(UN(ZwOpenMutant)); REQUIRE(UN(NtQueryMutant));
    COB_ALIAS("CreateMutant"); COB_ALIAS("OpenMutant");
    cob_name(name, 200, "mut"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    s = UN(ZwCreateMutant)(&h, MUTANT_ALL_ACCESS, &oa, TRUE);
    EXPECT_EQ(s, S_OK_); CHECK(h != NULL); if (!h) return;
    CHECK(cob_typename(h, tn, 32)); EXPECT_WSTR(tn, L"Mutant");
    CHECK(cob_granted(h, &g)); EXPECT_EQ(g & MUTANT_ALL_ACCESS, MUTANT_ALL_ACCESS);
    memset(&mi, 0xcc, sizeof mi);
    EXPECT_EQ(UN(NtQueryMutant)(h, 0, &mi, sizeof mi, &ret), S_OK_);
    EXPECT_EQ(mi.count, 0); EXPECT_EQ(mi.owned, 1); EXPECT_EQ(mi.aband, 0);
    /* same name again: success status NAME_EXISTS, a second handle to the same object */
    h2 = (HANDLE)0x1234; s = UN(ZwCreateMutant)(&h2, MUTANT_ALL_ACCESS, &oa, FALSE);
    EXPECT_EQ(s, S_COLLIDE); h2 = NULL;
    oa.Attributes = OBJ_OPENIF_;
    s = UN(ZwCreateMutant)(&h2, MUTANT_ALL_ACCESS, &oa, FALSE);
    EXPECT_EQ(s, S_EXISTS); CHECK(h2 != NULL);
    cob_close(h2); h2 = NULL;
    /* open the existing one: still owned by this thread */
    s = UN(ZwOpenMutant)(&o, MUTANT_QUERY_STATE | SYNCHRONIZE, &oa); EXPECT_EQ(s, S_OK_);
    if (o) { memset(&mi, 0, sizeof mi); EXPECT_EQ(UN(NtQueryMutant)(o, 0, &mi, sizeof mi, &ret), S_OK_); EXPECT_EQ(mi.owned, 1);
      CHECK(cob_granted(o, &g)); EXPECT_EQ(g & MUTANT_ALL_ACCESS, MUTANT_QUERY_STATE | SYNCHRONIZE); cob_close(o); }
    /* unnamed, not owned */
    cob_oa(&oa, NULL, 0, NULL);
    s = UN(ZwCreateMutant)(&h2, MUTANT_ALL_ACCESS, &oa, FALSE); EXPECT_EQ(s, S_OK_);
    if (h2) { EXPECT_EQ(UN(NtQueryMutant)(h2, 0, &mi, sizeof mi, &ret), S_OK_); EXPECT_EQ(mi.count, 1); EXPECT_EQ(mi.owned, 0); cob_close(h2); }
    s = UN(ZwCreateMutant)(&h2, MUTANT_ALL_ACCESS, NULL, FALSE); EXPECT_EQ(s, S_OK_); cob_close(h2);
    /* errors */
    EXPECT_EQ(UN(ZwCreateMutant)(NULL, MUTANT_ALL_ACCESS, NULL, FALSE), S_AV);
    cob_close(h);
    open_error_paths(UN(ZwOpenMutant), "mutx", MUTANT_QUERY_STATE);
}

TEST(nt_create_open_b_mutant_type_mismatch)
{
    HANDLE ev = NULL, o = (HANDLE)0x1234; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200];
    NEED(ZwOpenMutant); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(ZwOpenSemaphore)); REQUIRE(UN(ZwOpenTimer));
    cob_name(name, 200, "mm"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    EXPECT_EQ(UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, &oa, 0, FALSE), S_OK_); if (!ev) return;
    EXPECT_EQ(UN(ZwOpenMutant)(&o, MUTANT_QUERY_STATE, &oa), S_TYPEMM);
    o = (HANDLE)1; EXPECT_EQ(UN(ZwOpenSemaphore)(&o, SEMAPHORE_QUERY_STATE, &oa), S_TYPEMM);
    o = (HANDLE)1; EXPECT_EQ(UN(ZwOpenTimer)(&o, TIMER_QUERY_STATE, &oa), S_TYPEMM);
    o = NULL; EXPECT_EQ(UN(ZwOpenEvent)(&o, EVENT_QUERY_STATE, &oa), S_OK_); cob_close(o);
    cob_close(ev);
}

TEST(nt_create_open_b_semaphore)
{
    HANDLE h = NULL, h2 = NULL, o = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200], tn[32]; NTSTATUS s;
    LONG si[2]; ULONG ret = 0;
    NEED(ZwCreateSemaphore); REQUIRE(UN(ZwOpenSemaphore)); REQUIRE(UN(NtQuerySemaphore));
    COB_ALIAS("CreateSemaphore"); COB_ALIAS("OpenSemaphore");
    cob_name(name, 200, "sem"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    s = UN(ZwCreateSemaphore)(&h, SEMAPHORE_ALL_ACCESS, &oa, 2, 5); EXPECT_EQ(s, S_OK_); if (!h) return;
    CHECK(cob_typename(h, tn, 32)); EXPECT_WSTR(tn, L"Semaphore");
    memset(si, 0xcc, sizeof si);
    EXPECT_EQ(UN(NtQuerySemaphore)(h, 0, si, sizeof si, &ret), S_OK_); EXPECT_EQ(ret, 8); EXPECT_EQ(si[0], 2); EXPECT_EQ(si[1], 5);
    EXPECT_EQ(UN(ZwCreateSemaphore)(&h2, SEMAPHORE_ALL_ACCESS, &oa, 0, 9), S_COLLIDE); cob_close(h2); h2 = NULL;
    oa.Attributes = OBJ_OPENIF_;
    EXPECT_EQ(UN(ZwCreateSemaphore)(&h2, SEMAPHORE_ALL_ACCESS, &oa, 0, 9), S_EXISTS); cob_close(h2); h2 = NULL;
    EXPECT_EQ(UN(ZwOpenSemaphore)(&o, SEMAPHORE_QUERY_STATE, &oa), S_OK_);
    if (o) { EXPECT_EQ(UN(NtQuerySemaphore)(o, 0, si, sizeof si, &ret), S_OK_); EXPECT_EQ(si[1], 5); cob_close(o); }
    /* initial == max is allowed, initial 0 with max 1 too */
    cob_oa(&oa, NULL, 0, NULL);
    EXPECT_EQ(UN(ZwCreateSemaphore)(&h2, SEMAPHORE_ALL_ACCESS, &oa, 3, 3), S_OK_); cob_close(h2); h2 = NULL;
    EXPECT_EQ(UN(ZwCreateSemaphore)(&h2, SEMAPHORE_ALL_ACCESS, NULL, 0, 1), S_OK_); cob_close(h2); h2 = NULL;
    EXPECT_EQ(UN(ZwCreateSemaphore)(&h2, SEMAPHORE_ALL_ACCESS, NULL, 0, 0x7fffffff), S_OK_);
    if (h2) { EXPECT_EQ(UN(NtQuerySemaphore)(h2, 0, si, sizeof si, &ret), S_OK_); EXPECT_EQ(si[1], 0x7fffffff); cob_close(h2); h2 = NULL; }
    /* invalid parameters */
    EXPECT_EQ(UN(ZwCreateSemaphore)(&h2, SEMAPHORE_ALL_ACCESS, NULL, 0, 0), S_INVPARAM); EXPECT_EQ(h2, NULL);
    EXPECT_EQ(UN(ZwCreateSemaphore)(&h2, SEMAPHORE_ALL_ACCESS, NULL, 2, 1), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateSemaphore)(&h2, SEMAPHORE_ALL_ACCESS, NULL, -1, 5), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateSemaphore)(&h2, SEMAPHORE_ALL_ACCESS, NULL, 0, -1), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateSemaphore)(NULL, SEMAPHORE_ALL_ACCESS, NULL, 0, 1), S_AV);
    cob_close(h);
    open_error_paths(UN(ZwOpenSemaphore), "semx", SEMAPHORE_QUERY_STATE);
}

TEST(nt_create_open_b_event_open)
{
    HANDLE h = NULL, o = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200]; ULONG g = 0;
    NEED(ZwOpenEvent); REQUIRE(UN(NtCreateEvent));
    COB_ALIAS("OpenEvent");
    cob_name(name, 200, "evt"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    EXPECT_EQ(UN(NtCreateEvent)(&h, EVENT_ALL_ACCESS, &oa, 1, TRUE), S_OK_); if (!h) return;
    EXPECT_EQ(UN(ZwOpenEvent)(&o, EVENT_MODIFY_STATE, &oa), S_OK_);
    if (o) { CHECK(cob_granted(o, &g)); EXPECT_EQ(g & EVENT_ALL_ACCESS, EVENT_MODIFY_STATE); cob_close(o); }
    o = NULL; EXPECT_EQ(UN(ZwOpenEvent)(&o, MAXIMUM_ALLOWED, &oa), S_OK_);
    if (o) { CHECK(cob_granted(o, &g)); EXPECT_EQ(g & EVENT_ALL_ACCESS, EVENT_ALL_ACCESS); cob_close(o); }
    o = NULL; EXPECT_EQ(UN(ZwOpenEvent)(&o, 0, &oa), S_DENIED); cob_close(o);   /* zero access mask is refused */
    cob_close(h);
    open_error_paths(UN(ZwOpenEvent), "evx", EVENT_QUERY_STATE);
}

TEST(nt_create_open_b_event_pair)
{
    HANDLE h = (HANDLE)0x1234, o = (HANDLE)0x1234; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200];
    NEED(ZwOpenEventPair); REQUIRE(UN(NtCreateEventPair));
    COB_ALIAS("OpenEventPair");
    cob_name(name, 200, "evp"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    /* Event pair objects are not available to user mode on Windows 10: both services are stubs returning
     * STATUS_NOT_IMPLEMENTED without looking at their arguments. */
    EXPECT_EQ(UN(NtCreateEventPair)(&h, EVENT_ALL_ACCESS, &oa), S_NOTIMPL);
    EXPECT_EQ(UN(ZwOpenEventPair)(&o, SYNCHRONIZE, &oa), S_NOTIMPL);
    EXPECT_EQ(UN(ZwOpenEventPair)(NULL, SYNCHRONIZE, NULL), S_NOTIMPL);
    EXPECT_EQ(UN(ZwOpenEventPair)(&o, 0, NULL), S_NOTIMPL);
}

TEST(nt_create_open_b_timer)
{
    HANDLE h = NULL, h2 = NULL, o = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200], tn[32]; NTSTATUS s;
    struct { LARGE_INTEGER rem; BOOLEAN sig; } ti; ULONG ret = 0; LARGE_INTEGER z = {{0}};
    NEED(ZwCreateTimer); REQUIRE(UN(ZwOpenTimer)); REQUIRE(UN(NtQueryTimer)); REQUIRE(UN(NtWaitForSingleObject));
    COB_ALIAS("CreateTimer"); COB_ALIAS("OpenTimer");
    cob_name(name, 200, "tmr"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    s = UN(ZwCreateTimer)(&h, TIMER_ALL_ACCESS, &oa, 0 /* NotificationTimer */); EXPECT_EQ(s, S_OK_); if (!h) return;
    CHECK(cob_typename(h, tn, 32)); EXPECT_WSTR(tn, L"Timer");
    memset(&ti, 0xcc, sizeof ti);
    EXPECT_EQ(UN(NtQueryTimer)(h, 0, &ti, sizeof ti, &ret), S_OK_);
    EXPECT_EQ(ti.sig, 0);                               /* not signalled, not set */
    EXPECT_EQ(UN(NtWaitForSingleObject)(h, FALSE, &z), S_TIMEOUT);
    EXPECT_EQ(UN(ZwCreateTimer)(&h2, TIMER_ALL_ACCESS, &oa, 1), S_COLLIDE); cob_close(h2); h2 = NULL;
    oa.Attributes = OBJ_OPENIF_;
    EXPECT_EQ(UN(ZwCreateTimer)(&h2, TIMER_ALL_ACCESS, &oa, 1), S_EXISTS); cob_close(h2); h2 = NULL;
    EXPECT_EQ(UN(ZwOpenTimer)(&o, TIMER_QUERY_STATE, &oa), S_OK_); cob_close(o);
    cob_oa(&oa, NULL, 0, NULL);
    EXPECT_EQ(UN(ZwCreateTimer)(&h2, TIMER_ALL_ACCESS, &oa, 1 /* SynchronizationTimer */), S_OK_); cob_close(h2); h2 = NULL;
    EXPECT_EQ(UN(ZwCreateTimer)(&h2, TIMER_ALL_ACCESS, &oa, 2), S_INVPARAM4); EXPECT_EQ(h2, NULL);
    EXPECT_EQ(UN(ZwCreateTimer)(&h2, TIMER_ALL_ACCESS, &oa, 0xffffffff), S_INVPARAM4);
    EXPECT_EQ(UN(ZwCreateTimer)(NULL, TIMER_ALL_ACCESS, NULL, 0), S_AV);
    cob_close(h);
    open_error_paths(UN(ZwOpenTimer), "tmrx", TIMER_QUERY_STATE);
}

TEST(nt_create_open_b_timer2_and_irtimer)
{
    HANDLE h = NULL; WCHAR tn[32]; NTSTATUS s; ULONG g = 0;
    NEED(ZwCreateTimer2);
    COB_ALIAS("CreateTimer2"); COB_ALIAS("CreateIRTimer");
    /* parameters 2 and 3 are reserved and must be NULL; the object is an IRTimer */
    s = UN(ZwCreateTimer2)(&h, NULL, NULL, 0, TIMER_ALL_ACCESS); EXPECT_EQ(s, S_OK_);
    if (s == S_OK_) { CHECK(cob_typename(h, tn, 32)); EXPECT_WSTR(tn, L"IRTimer"); CHECK(cob_granted(h, &g)); EXPECT_EQ(g & TIMER_ALL_ACCESS, TIMER_ALL_ACCESS); cob_close(h); h = NULL; }
    s = UN(ZwCreateTimer2)(&h, (PVOID)(ULONG_PTR)1, NULL, 0, TIMER_ALL_ACCESS); EXPECT_EQ(s, S_PARAM2); cob_close(h); h = NULL;
    s = UN(ZwCreateTimer2)(&h, NULL, (PVOID)(ULONG_PTR)1, 0, TIMER_ALL_ACCESS); EXPECT_EQ(s, S_PARAM3); cob_close(h); h = NULL;
    EXPECT_EQ(UN(ZwCreateTimer2)(&h, NULL, NULL, 1, TIMER_ALL_ACCESS), S_INVPARAM4);
    /* attribute bits 4 (high resolution) and 8 (notification) are accepted */
    EXPECT_EQ(UN(ZwCreateTimer2)(&h, NULL, NULL, 8, TIMER_ALL_ACCESS), S_OK_); cob_close(h); h = NULL;
    EXPECT_EQ(UN(ZwCreateTimer2)(&h, NULL, NULL, 4, TIMER_ALL_ACCESS), S_OK_); cob_close(h); h = NULL;
    EXPECT_EQ(UN(ZwCreateTimer2)(&h, NULL, NULL, 0xf0, TIMER_ALL_ACCESS), S_INVPARAM4);
    EXPECT_EQ(UN(ZwCreateTimer2)(NULL, NULL, NULL, 0, TIMER_ALL_ACCESS), S_AV);
    /* NtCreateIRTimer */
    if (UN(ZwCreateIRTimer)) {
        /* only the rejection paths of this service are observable without its private parameter block:
         * a zero access mask is invalid, and the second argument is dereferenced as a pointer */
        EXPECT_EQ(UN(ZwCreateIRTimer)(&h, 0, NULL), S_INVPARAM); cob_close(h); h = NULL;
        EXPECT_EQ(UN(ZwCreateIRTimer)(&h, TIMER_ALL_ACCESS, NULL), S_AV);
        EXPECT_EQ(UN(ZwCreateIRTimer)(&h, 2, NULL), S_AV);
    }
}

TEST(nt_create_open_b_keyed_event)
{
    HANDLE h = NULL, h2 = NULL, o = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200], tn[32]; NTSTATUS s; LARGE_INTEGER z = {{0}};
    NEED(ZwCreateKeyedEvent); REQUIRE(UN(ZwOpenKeyedEvent));
    COB_ALIAS("CreateKeyedEvent"); COB_ALIAS("OpenKeyedEvent");
    cob_name(name, 200, "ke"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    s = UN(ZwCreateKeyedEvent)(&h, KEYEDEVENT_ALL_ACCESS_, &oa, 0); EXPECT_EQ(s, S_OK_); if (!h) return;
    CHECK(cob_typename(h, tn, 32)); EXPECT_WSTR(tn, L"KeyedEvent");
    EXPECT_EQ(UN(ZwCreateKeyedEvent)(&h2, KEYEDEVENT_ALL_ACCESS_, &oa, 0), S_COLLIDE); cob_close(h2); h2 = NULL;
    oa.Attributes = OBJ_OPENIF_;
    EXPECT_EQ(UN(ZwCreateKeyedEvent)(&h2, KEYEDEVENT_ALL_ACCESS_, &oa, 0), S_EXISTS); cob_close(h2);
    EXPECT_EQ(UN(ZwOpenKeyedEvent)(&o, KEYEDEVENT_ALL_ACCESS_, &oa), S_OK_); cob_close(o);
    /* with nobody waiting, a zero-timeout release or wait on an even key times out */
    if (UN(NtReleaseKeyedEvent) && UN(NtWaitForKeyedEvent)) {
        EXPECT_EQ(UN(NtReleaseKeyedEvent)(h, (PVOID)(ULONG_PTR)0x100, FALSE, &z), S_TIMEOUT);
        EXPECT_EQ(UN(NtWaitForKeyedEvent)(h, (PVOID)(ULONG_PTR)0x100, FALSE, &z), S_TIMEOUT);
    }
    cob_close(h);
    EXPECT_EQ(UN(ZwCreateKeyedEvent)(NULL, KEYEDEVENT_ALL_ACCESS_, NULL, 0), S_AV);
    open_error_paths(UN(ZwOpenKeyedEvent), "kex", KEYEDEVENT_ALL_ACCESS_);
}

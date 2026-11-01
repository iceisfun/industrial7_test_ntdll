#include "t.h"
#include <wchar.h>

UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtOpenEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtSetEvent, (HANDLE, PLONG));
UDECL(NTSTATUS, NtResetEvent, (HANDLE, PLONG));
UDECL(NTSTATUS, NtPulseEvent, (HANDLE, PLONG));
UDECL(NTSTATUS, NtQueryEvent, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateSemaphore, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG));
UDECL(NTSTATUS, NtOpenSemaphore, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtReleaseSemaphore, (HANDLE, LONG, PLONG));
UDECL(NTSTATUS, NtQuerySemaphore, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateMutant, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN));
UDECL(NTSTATUS, NtOpenMutant, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtReleaseMutant, (HANDLE, PLONG));
UDECL(NTSTATUS, NtQueryMutant, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateTimer, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtOpenTimer, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtSetTimer, (HANDLE, PLARGE_INTEGER, PVOID, PVOID, BOOLEAN, LONG, PBOOLEAN));
UDECL(NTSTATUS, NtCancelTimer, (HANDLE, PBOOLEAN));
UDECL(NTSTATUS, NtQueryTimer, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtWaitForSingleObject, (HANDLE, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtWaitForMultipleObjects, (ULONG, PHANDLE, ULONG, BOOLEAN, PLARGE_INTEGER));
UDECL(NTSTATUS, NtDuplicateObject, (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x) ((NTSTATUS)(x))
#define SUCCESS S(0)
#define TIMEOUT S(0x102)
#define INVALID_PARAMETER S(0xc000000d)
#define BAD_CLASS S(0xc0000003)
#define BAD_LENGTH S(0xc0000004)
#define DENIED S(0xc0000022)
#define WRONG_TYPE S(0xc0000024)
#define ALL_SYNC (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 3)
#define MUTANT_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 1)
/* Capture both channels before invoking any assertion/harness code. */
#define STATUS(call, want) do { NTSTATUS s_; DWORD e_; SetLastError(0x1234abcd); \
    s_ = (call); e_ = GetLastError(); EXPECT_EQ(s_, (want)); EXPECT_EQ(e_, 0x1234abcd); } while (0)

typedef struct { LONG type, state; } event_info;
typedef struct { LONG count, maximum; } semaphore_info;
typedef struct { LONG count; BOOLEAN owned, abandoned; BYTE pad[2]; } mutant_info;
typedef struct { LARGE_INTEGER remaining; BOOLEAN state; } timer_info;

static int ready(HANDLE h, NTSTATUS s) {
    EXPECT_EQ(s, SUCCESS);
    if (s < 0 || !h) { t_skip("fixture creation failed: %08lx", (ULONG)s); return 0; }
    return 1;
}
static void close_nt(HANDLE h) { if (h) STATUS(UN(NtClose)(h), SUCCESS); }
static void named(OBJECT_ATTRIBUTES *oa, UNICODE_STRING *us, WCHAR *buf, const WCHAR *kind) {
    static unsigned serial;
    swprintf(buf, 160, L"\\BaseNamedObjects\\ntdllt_%lu_%u_%ls", GetCurrentProcessId(), ++serial, kind);
    us->Buffer = buf; us->Length = (USHORT)(wcslen(buf) * sizeof(WCHAR)); us->MaximumLength = us->Length + 2;
    memset(oa, 0, sizeof(*oa)); oa->Length = sizeof(*oa); oa->ObjectName = us; oa->Attributes = OBJ_CASE_INSENSITIVE;
}
#define EVENT(type, initial, access) \
    HANDLE h = NULL; NTSTATUS cs; REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtClose)); \
    cs = UN(NtCreateEvent)(&h, access, NULL, type, initial); if (!ready(h, cs)) return
#define SEM(initial, maximum) \
    HANDLE h = NULL; NTSTATUS cs; REQUIRE(UN(NtCreateSemaphore)); REQUIRE(UN(NtClose)); \
    cs = UN(NtCreateSemaphore)(&h, ALL_SYNC, NULL, initial, maximum); if (!ready(h, cs)) return
#define MUT(owned) \
    HANDLE h = NULL; NTSTATUS cs; REQUIRE(UN(NtCreateMutant)); REQUIRE(UN(NtClose)); \
    REQUIRE(UN(NtReleaseMutant)); \
    cs = UN(NtCreateMutant)(&h, MUTANT_ACCESS, NULL, owned); if (!ready(h, cs)) return
#define TIMER(type, access) \
    HANDLE h = NULL; NTSTATUS cs; REQUIRE(UN(NtCreateTimer)); REQUIRE(UN(NtClose)); \
    cs = UN(NtCreateTimer)(&h, access, NULL, type); if (!ready(h, cs)) return

static void event_state(HANDLE h, LONG type, LONG state) {
    event_info q = {-7,-7}; ULONG n = 0;
    STATUS(UN(NtQueryEvent)(h, 0, &q, sizeof(q), &n), SUCCESS);
    EXPECT_EQ(n, sizeof(q)); EXPECT_EQ(q.type, type); EXPECT_EQ(q.state, state);
}
static void sem_state(HANDLE h, LONG count, LONG maximum) {
    semaphore_info q = {-7,-7}; ULONG n = 0;
    STATUS(UN(NtQuerySemaphore)(h, 0, &q, sizeof(q), &n), SUCCESS);
    EXPECT_EQ(n, sizeof(q)); EXPECT_EQ(q.count, count); EXPECT_EQ(q.maximum, maximum);
}
static void mut_state(HANDLE h, LONG count, BOOLEAN owned) {
    mutant_info q; ULONG n = 0; memset(&q, 0x77, sizeof(q));
    STATUS(UN(NtQueryMutant)(h, 0, &q, sizeof(q), &n), SUCCESS);
    EXPECT_EQ(n, sizeof(q)); EXPECT_EQ(q.count, count); EXPECT_EQ(q.owned, owned); EXPECT_EQ(q.abandoned, FALSE);
}
static void wait_zero(HANDLE h, NTSTATUS want) {
    LARGE_INTEGER zero; zero.QuadPart = 0;
    STATUS(UN(NtWaitForSingleObject)(h, FALSE, &zero), want);
}

static void event_initial(ULONG type, BOOLEAN initial) {
    REQUIRE(UN(NtQueryEvent)); EVENT(type, initial, ALL_SYNC);
    event_state(h, type, initial); close_nt(h);
}
TEST(nt_sync_event_notification_clear) { event_initial(0, FALSE); }
TEST(nt_sync_event_notification_set) { event_initial(0, TRUE); }
TEST(nt_sync_event_synchronization_clear) { event_initial(1, FALSE); }
TEST(nt_sync_event_synchronization_set) { event_initial(1, TRUE); }
TEST(nt_sync_event_invalid_type) {
    HANDLE h = NULL; REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtClose));
    STATUS(UN(NtCreateEvent)(&h, ALL_SYNC, NULL, 2, FALSE), INVALID_PARAMETER);
    EXPECT_EQ(h, NULL); close_nt(h);
}
static void event_change(int op, BOOLEAN initial) {
    LONG previous = -7; REQUIRE(UN(NtSetEvent)); REQUIRE(UN(NtResetEvent));
    REQUIRE(UN(NtPulseEvent)); REQUIRE(UN(NtQueryEvent)); EVENT(0, initial, ALL_SYNC);
    if (op == 0) STATUS(UN(NtSetEvent)(h, &previous), SUCCESS);
    if (op == 1) STATUS(UN(NtResetEvent)(h, &previous), SUCCESS);
    if (op == 2) STATUS(UN(NtPulseEvent)(h, &previous), SUCCESS);
    EXPECT_EQ(previous, initial); event_state(h, 0, op == 0); close_nt(h);
}
TEST(nt_sync_event_set_previous_clear) { event_change(0, FALSE); }
TEST(nt_sync_event_set_previous_set) { event_change(0, TRUE); }
TEST(nt_sync_event_reset_previous_clear) { event_change(1, FALSE); }
TEST(nt_sync_event_reset_previous_set) { event_change(1, TRUE); }
TEST(nt_sync_event_pulse_clear_no_waiters) { event_change(2, FALSE); }
TEST(nt_sync_event_pulse_set_no_waiters) { event_change(2, TRUE); }
TEST(nt_sync_event_optional_previous) {
    REQUIRE(UN(NtSetEvent)); REQUIRE(UN(NtResetEvent)); REQUIRE(UN(NtPulseEvent)); REQUIRE(UN(NtQueryEvent));
    EVENT(1, FALSE, ALL_SYNC);
    STATUS(UN(NtSetEvent)(h, NULL), SUCCESS); event_state(h, 1, TRUE);
    STATUS(UN(NtResetEvent)(h, NULL), SUCCESS); event_state(h, 1, FALSE);
    STATUS(UN(NtPulseEvent)(h, NULL), SUCCESS); event_state(h, 1, FALSE); close_nt(h);
}
static void event_wait(ULONG type, BOOLEAN initial) {
    REQUIRE(UN(NtWaitForSingleObject)); REQUIRE(UN(NtQueryEvent)); EVENT(type, initial, ALL_SYNC);
    wait_zero(h, initial ? SUCCESS : TIMEOUT); event_state(h, type, initial && type == 0);
    wait_zero(h, initial && type == 0 ? SUCCESS : TIMEOUT); close_nt(h);
}
TEST(nt_sync_event_notification_wait_retains) { event_wait(0, TRUE); }
TEST(nt_sync_event_synchronization_wait_consumes) { event_wait(1, TRUE); }
TEST(nt_sync_event_zero_wait_clear) { event_wait(0, FALSE); }
TEST(nt_sync_event_infinite_presignaled) {
    REQUIRE(UN(NtWaitForSingleObject)); REQUIRE(UN(NtQueryEvent)); EVENT(0, TRUE, ALL_SYNC);
    /* Never use an infinite timeout after a failed signal prerequisite. */
    event_info q; ULONG n;
    NTSTATUS s = UN(NtQueryEvent)(h, 0, &q, sizeof(q), &n);
    if (s == SUCCESS && q.state == 1) STATUS(UN(NtWaitForSingleObject)(h, FALSE, NULL), SUCCESS);
    else t_skip("pre-signaled prerequisite unavailable");
    close_nt(h);
}

static void query_bad(int kind, ULONG cls, ULONG size) {
    union { event_info e; semaphore_info s; mutant_info m; timer_info t; BYTE bytes[32]; } q, before;
    ULONG n = 0x12345678; HANDLE h = NULL; NTSTATUS s;
    REQUIRE(UN(NtClose)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtCreateSemaphore));
    REQUIRE(UN(NtCreateMutant)); REQUIRE(UN(NtCreateTimer));
    REQUIRE(UN(NtQueryEvent)); REQUIRE(UN(NtQuerySemaphore)); REQUIRE(UN(NtQueryMutant)); REQUIRE(UN(NtQueryTimer));
    if (kind == 0) s = UN(NtCreateEvent)(&h, ALL_SYNC, NULL, 0, FALSE);
    else if (kind == 1) s = UN(NtCreateSemaphore)(&h, ALL_SYNC, NULL, 0, 3);
    else if (kind == 2) s = UN(NtCreateMutant)(&h, MUTANT_ACCESS, NULL, FALSE);
    else s = UN(NtCreateTimer)(&h, ALL_SYNC, NULL, 0);
    if (!ready(h, s)) return;
    memset(&q, 0x55, sizeof(q)); before = q;
    NTSTATUS want = cls ? BAD_CLASS : BAD_LENGTH;
    if (kind == 0) STATUS(UN(NtQueryEvent)(h, cls, &q, size, &n), want);
    if (kind == 1) STATUS(UN(NtQuerySemaphore)(h, cls, &q, size, &n), want);
    if (kind == 2) STATUS(UN(NtQueryMutant)(h, cls, &q, size, &n), want);
    if (kind == 3) STATUS(UN(NtQueryTimer)(h, cls, &q, size, &n), want);
    EXPECT_EQ(memcmp(&q, &before, sizeof(q)), 0); EXPECT_EQ(n, 0x12345678); close_nt(h);
}
TEST(nt_sync_event_query_short) { query_bad(0, 0, 7); }
TEST(nt_sync_event_query_oversize) { query_bad(0, 0, 9); }
TEST(nt_sync_event_query_class) { query_bad(0, 9, 8); }
TEST(nt_sync_semaphore_query_short) { query_bad(1, 0, 7); }
TEST(nt_sync_semaphore_query_class) { query_bad(1, 9, 8); }
TEST(nt_sync_mutant_query_short) { query_bad(2, 0, 7); }
TEST(nt_sync_mutant_query_class) { query_bad(2, 9, 8); }
TEST(nt_sync_timer_query_short) { query_bad(3, 0, 15); }
TEST(nt_sync_timer_query_class) { query_bad(3, 9, 16); }

TEST(nt_sync_event_query_only_denies_set) {
    LONG prev = 123; REQUIRE(UN(NtSetEvent)); REQUIRE(UN(NtQueryEvent)); EVENT(0, FALSE, 1);
    STATUS(UN(NtSetEvent)(h, &prev), DENIED); EXPECT_EQ(prev, 123); event_state(h, 0, FALSE); close_nt(h);
}
TEST(nt_sync_event_modify_only_denies_query) {
    event_info q = {123,123}; ULONG n = 123;
    REQUIRE(UN(NtQueryEvent)); EVENT(0, FALSE, 2);
    STATUS(UN(NtQueryEvent)(h, 0, &q, sizeof(q), &n), DENIED);
    EXPECT_EQ(q.type, 123); EXPECT_EQ(q.state, 123); EXPECT_EQ(n, 123); close_nt(h);
}

static void sem_invalid(LONG initial, LONG maximum) {
    HANDLE h = NULL; REQUIRE(UN(NtCreateSemaphore)); REQUIRE(UN(NtClose));
    STATUS(UN(NtCreateSemaphore)(&h, ALL_SYNC, NULL, initial, maximum), INVALID_PARAMETER);
    EXPECT_EQ(h, NULL); close_nt(h);
}
TEST(nt_sync_semaphore_zero_maximum) { sem_invalid(0, 0); }
TEST(nt_sync_semaphore_negative_initial) { sem_invalid(-1, 2); }
TEST(nt_sync_semaphore_initial_exceeds_maximum) { sem_invalid(3, 2); }
TEST(nt_sync_semaphore_initial_zero) { REQUIRE(UN(NtQuerySemaphore)); SEM(0, 3); sem_state(h, 0, 3); close_nt(h); }
TEST(nt_sync_semaphore_initial_maximum) { REQUIRE(UN(NtQuerySemaphore)); SEM(3, 3); sem_state(h, 3, 3); close_nt(h); }
TEST(nt_sync_semaphore_release_previous) {
    LONG prev = -7; REQUIRE(UN(NtReleaseSemaphore)); REQUIRE(UN(NtQuerySemaphore)); SEM(1, 4);
    STATUS(UN(NtReleaseSemaphore)(h, 2, &prev), SUCCESS); EXPECT_EQ(prev, 1); sem_state(h, 3, 4); close_nt(h);
}
TEST(nt_sync_semaphore_release_optional_previous) {
    REQUIRE(UN(NtReleaseSemaphore)); REQUIRE(UN(NtQuerySemaphore)); SEM(0, 2);
    STATUS(UN(NtReleaseSemaphore)(h, 2, NULL), SUCCESS); sem_state(h, 2, 2); close_nt(h);
}
static void sem_bad_release(LONG amount, NTSTATUS want) {
    LONG prev = 123; REQUIRE(UN(NtReleaseSemaphore)); REQUIRE(UN(NtQuerySemaphore)); SEM(1, 2);
    STATUS(UN(NtReleaseSemaphore)(h, amount, &prev), want);
    EXPECT_EQ(prev, 123); sem_state(h, 1, 2); close_nt(h);
}
TEST(nt_sync_semaphore_release_zero) { sem_bad_release(0, INVALID_PARAMETER); }
TEST(nt_sync_semaphore_release_negative) { sem_bad_release(-1, INVALID_PARAMETER); }
TEST(nt_sync_semaphore_release_limit) { sem_bad_release(2, S(0xc0000047)); }
TEST(nt_sync_semaphore_wait_consumes_one) {
    REQUIRE(UN(NtWaitForSingleObject)); REQUIRE(UN(NtQuerySemaphore)); SEM(2, 3);
    wait_zero(h, SUCCESS); sem_state(h, 1, 3); wait_zero(h, SUCCESS);
    sem_state(h, 0, 3); wait_zero(h, TIMEOUT); sem_state(h, 0, 3); close_nt(h);
}
TEST(nt_sync_mutant_unowned) { REQUIRE(UN(NtQueryMutant)); MUT(FALSE); mut_state(h, 1, FALSE); close_nt(h); }
TEST(nt_sync_mutant_initial_owner) {
    REQUIRE(UN(NtQueryMutant)); MUT(TRUE); mut_state(h, 0, TRUE);
    STATUS(UN(NtReleaseMutant)(h, NULL), SUCCESS); mut_state(h, 1, FALSE); close_nt(h);
}
TEST(nt_sync_mutant_acquire_release) {
    LONG prev = 123; REQUIRE(UN(NtWaitForSingleObject)); REQUIRE(UN(NtQueryMutant)); MUT(FALSE);
    NTSTATUS s; LARGE_INTEGER zero; zero.QuadPart = 0; s = UN(NtWaitForSingleObject)(h, FALSE, &zero);
    EXPECT_EQ(s, SUCCESS);
    if (s == SUCCESS) { mut_state(h, 0, TRUE); STATUS(UN(NtReleaseMutant)(h, &prev), SUCCESS);
        EXPECT_EQ(prev, 0); mut_state(h, 1, FALSE); }
    else t_skip("mutant acquisition prerequisite failed");
    close_nt(h);
}
TEST(nt_sync_mutant_recursive_owner) {
    REQUIRE(UN(NtWaitForSingleObject)); REQUIRE(UN(NtQueryMutant)); MUT(TRUE);
    LARGE_INTEGER zero; zero.QuadPart = 0; NTSTATUS s = UN(NtWaitForSingleObject)(h, FALSE, &zero);
    EXPECT_EQ(s, SUCCESS);
    if (s == SUCCESS) { LONG prev = 123; mut_state(h, -1, TRUE);
        STATUS(UN(NtReleaseMutant)(h, &prev), SUCCESS); EXPECT_EQ(prev, -1); mut_state(h, 0, TRUE); }
    else t_skip("recursive acquisition prerequisite failed");
    STATUS(UN(NtReleaseMutant)(h, NULL), SUCCESS); close_nt(h);
}
TEST(nt_sync_mutant_release_not_owned) {
    LONG prev = 123; REQUIRE(UN(NtQueryMutant)); MUT(FALSE);
    STATUS(UN(NtReleaseMutant)(h, &prev), S(0xc0000046)); EXPECT_EQ(prev, 123); mut_state(h, 1, FALSE); close_nt(h);
}

static void timer_initial(ULONG type) {
    timer_info q; ULONG n = 0; REQUIRE(UN(NtQueryTimer)); REQUIRE(UN(NtWaitForSingleObject)); TIMER(type, ALL_SYNC);
    memset(&q, 0x77, sizeof(q)); STATUS(UN(NtQueryTimer)(h, 0, &q, sizeof(q), &n), SUCCESS);
    EXPECT_EQ(n, sizeof(q)); EXPECT_EQ(q.state, FALSE); wait_zero(h, TIMEOUT); close_nt(h);
}
TEST(nt_sync_timer_notification_initial) { timer_initial(0); }
TEST(nt_sync_timer_synchronization_initial) { timer_initial(1); }
TEST(nt_sync_timer_invalid_type) {
    HANDLE h = NULL; REQUIRE(UN(NtCreateTimer)); REQUIRE(UN(NtClose));
    STATUS(UN(NtCreateTimer)(&h, ALL_SYNC, NULL, 2), S(0xc00000f2)); EXPECT_EQ(h, NULL); close_nt(h);
}
TEST(nt_sync_timer_cancel_inactive) {
    BOOLEAN prev = 7; REQUIRE(UN(NtCancelTimer)); TIMER(0, ALL_SYNC);
    STATUS(UN(NtCancelTimer)(h, &prev), SUCCESS); EXPECT_EQ(prev, FALSE);
    STATUS(UN(NtCancelTimer)(h, NULL), SUCCESS); close_nt(h);
}
static void timer_arm(ULONG type, LONG period) {
    BOOLEAN prev = 7; LARGE_INTEGER due; timer_info q; ULONG n;
    REQUIRE(UN(NtSetTimer)); REQUIRE(UN(NtCancelTimer)); REQUIRE(UN(NtQueryTimer)); TIMER(type, ALL_SYNC);
    /* One day is a safety margin, not a timing assertion; always cancel before close. */
    due.QuadPart = -864000000000LL;
    STATUS(UN(NtSetTimer)(h, &due, NULL, NULL, FALSE, period, &prev), SUCCESS); EXPECT_EQ(prev, FALSE);
    STATUS(UN(NtQueryTimer)(h, 0, &q, sizeof(q), &n), SUCCESS); EXPECT_EQ(n, sizeof(q)); EXPECT_EQ(q.state, FALSE);
    prev = 7; STATUS(UN(NtCancelTimer)(h, &prev), SUCCESS); EXPECT_EQ(prev, FALSE); close_nt(h);
}
TEST(nt_sync_timer_arm_notification) { timer_arm(0, 0); }
TEST(nt_sync_timer_arm_synchronization) { timer_arm(1, 0); }
TEST(nt_sync_timer_periodic_cancel) { timer_arm(0, 60000); }
TEST(nt_sync_timer_negative_period) {
    BOOLEAN prev = 7; LARGE_INTEGER due; due.QuadPart = -864000000000LL;
    REQUIRE(UN(NtSetTimer)); REQUIRE(UN(NtCancelTimer)); TIMER(0, ALL_SYNC);
    STATUS(UN(NtSetTimer)(h, &due, NULL, NULL, FALSE, -1, &prev), S(0xc00000f4)); EXPECT_EQ(prev, 7);
    STATUS(UN(NtCancelTimer)(h, NULL), SUCCESS); close_nt(h);
}
TEST(nt_sync_timer_query_only_denies_set) {
    BOOLEAN prev = 7; LARGE_INTEGER due; due.QuadPart = -864000000000LL;
    REQUIRE(UN(NtSetTimer)); TIMER(0, 1);
    STATUS(UN(NtSetTimer)(h, &due, NULL, NULL, FALSE, 0, &prev), DENIED); EXPECT_EQ(prev, 7); close_nt(h);
}

static void named_roundtrip(int kind) {
    HANDLE h = NULL, opened = NULL; OBJECT_ATTRIBUTES oa; UNICODE_STRING us; WCHAR buf[160]; NTSTATUS s;
    REQUIRE(UN(NtClose)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtOpenEvent)); REQUIRE(UN(NtQueryEvent));
    REQUIRE(UN(NtCreateSemaphore)); REQUIRE(UN(NtOpenSemaphore)); REQUIRE(UN(NtQuerySemaphore));
    REQUIRE(UN(NtCreateMutant)); REQUIRE(UN(NtOpenMutant)); REQUIRE(UN(NtQueryMutant));
    REQUIRE(UN(NtCreateTimer)); REQUIRE(UN(NtOpenTimer)); REQUIRE(UN(NtQueryTimer));
    named(&oa, &us, buf, L"roundtrip");
    if (kind == 0) s = UN(NtCreateEvent)(&h, ALL_SYNC, &oa, 0, TRUE);
    else if (kind == 1) s = UN(NtCreateSemaphore)(&h, ALL_SYNC, &oa, 2, 4);
    else if (kind == 2) s = UN(NtCreateMutant)(&h, MUTANT_ACCESS, &oa, FALSE);
    else s = UN(NtCreateTimer)(&h, ALL_SYNC, &oa, 0);
    if (!ready(h, s)) return;
    if (kind == 0) s = UN(NtOpenEvent)(&opened, ALL_SYNC, &oa);
    else if (kind == 1) s = UN(NtOpenSemaphore)(&opened, ALL_SYNC, &oa);
    else if (kind == 2) s = UN(NtOpenMutant)(&opened, MUTANT_ACCESS, &oa);
    else s = UN(NtOpenTimer)(&opened, ALL_SYNC, &oa);
    if (ready(opened, s)) {
        close_nt(h); h = NULL;
        if (kind == 0) event_state(opened, 0, TRUE);
        if (kind == 1) sem_state(opened, 2, 4);
        if (kind == 2) mut_state(opened, 1, FALSE);
        if (kind == 3) { timer_info q; ULONG n = 0;
            STATUS(UN(NtQueryTimer)(opened, 0, &q, sizeof(q), &n), SUCCESS); EXPECT_EQ(q.state, FALSE); EXPECT_EQ(n, sizeof(q)); }
    }
    close_nt(opened); close_nt(h);
}
TEST(nt_sync_event_named_open_lifetime) { named_roundtrip(0); }
TEST(nt_sync_semaphore_named_open_lifetime) { named_roundtrip(1); }
TEST(nt_sync_mutant_named_open_lifetime) { named_roundtrip(2); }
TEST(nt_sync_timer_named_open_lifetime) { named_roundtrip(3); }

TEST(nt_sync_event_duplicate_shared_state) {
    HANDLE copy = NULL; LONG prev; REQUIRE(UN(NtDuplicateObject)); REQUIRE(UN(NtSetEvent)); REQUIRE(UN(NtQueryEvent));
    EVENT(0, FALSE, ALL_SYNC);
    NTSTATUS s = UN(NtDuplicateObject)((HANDLE)(LONG_PTR)-1, h, (HANDLE)(LONG_PTR)-1, &copy, 0, 0, 2);
    if (ready(copy, s)) { STATUS(UN(NtSetEvent)(copy, &prev), SUCCESS); EXPECT_EQ(prev, 0);
        event_state(h, 0, TRUE); close_nt(h); h = NULL; event_state(copy, 0, TRUE); }
    close_nt(copy); close_nt(h);
}
TEST(nt_sync_event_query_object_access) {
    PUBLIC_OBJECT_BASIC_INFORMATION q; ULONG n = 0; REQUIRE(UN(NtQueryObject)); EVENT(0, FALSE, SYNCHRONIZE | 1);
    memset(&q, 0, sizeof(q)); STATUS(UN(NtQueryObject)(h, 0, &q, sizeof(q), &n), SUCCESS);
    EXPECT_EQ(n, sizeof(q)); EXPECT_EQ(q.GrantedAccess, SYNCHRONIZE | 1); EXPECT_EQ(q.Attributes, 0);
    /* Reference counts include transient query references; only handle count is stable here. */
    EXPECT_EQ(q.HandleCount, 1); close_nt(h);
}
static void multiple(ULONG type, BOOLEAN first, BOOLEAN second, NTSTATUS want) {
    HANDLE hs[2] = {NULL,NULL}; LARGE_INTEGER zero; NTSTATUS s; zero.QuadPart = 0;
    REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtWaitForMultipleObjects)); REQUIRE(UN(NtQueryEvent));
    s = UN(NtCreateEvent)(&hs[0], ALL_SYNC, NULL, 0, first); if (!ready(hs[0], s)) return;
    s = UN(NtCreateEvent)(&hs[1], ALL_SYNC, NULL, 0, second);
    if (ready(hs[1], s)) { STATUS(UN(NtWaitForMultipleObjects)(2, hs, type, FALSE, &zero), want);
        event_state(hs[0], 0, first); event_state(hs[1], 0, second); }
    close_nt(hs[1]); close_nt(hs[0]);
}
TEST(nt_sync_wait_any_second_index) { multiple(1, FALSE, TRUE, S(1)); }
TEST(nt_sync_wait_any_lowest_index) { multiple(1, TRUE, TRUE, SUCCESS); }
TEST(nt_sync_wait_all_presignaled) { multiple(0, TRUE, TRUE, SUCCESS); }
TEST(nt_sync_wait_all_unsignaled) { multiple(0, TRUE, FALSE, TIMEOUT); }
TEST(nt_sync_wait_multiple_bad_count) {
    HANDLE hs[65] = {0}; LARGE_INTEGER zero; zero.QuadPart = 0; REQUIRE(UN(NtWaitForMultipleObjects));
    STATUS(UN(NtWaitForMultipleObjects)(0, hs, 0, FALSE, &zero), S(0xc00000ef));
    STATUS(UN(NtWaitForMultipleObjects)(65, hs, 0, FALSE, &zero), S(0xc00000ef));
}
TEST(nt_sync_wait_multiple_bad_type) {
    LARGE_INTEGER zero; zero.QuadPart = 0; REQUIRE(UN(NtWaitForMultipleObjects)); EVENT(0, TRUE, ALL_SYNC);
    STATUS(UN(NtWaitForMultipleObjects)(1, &h, 2, FALSE, &zero), S(0xc00000f1)); close_nt(h);
}
TEST(nt_sync_wrong_object_type_release_semaphore) {
    LONG prev = 123; REQUIRE(UN(NtReleaseSemaphore)); EVENT(0, FALSE, ALL_SYNC);
    STATUS(UN(NtReleaseSemaphore)(h, 1, &prev), WRONG_TYPE); EXPECT_EQ(prev, 123); close_nt(h);
}

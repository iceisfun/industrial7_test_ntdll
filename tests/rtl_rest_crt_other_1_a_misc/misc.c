/* Privileges, AVL trees, domain/culture/time helpers, barriers, API sets, context capture,
 * legacy timers, activation contexts and assorted small Rtl helpers. See EVIDENCE.md. */
#include "t.h"

#define S(x) ((NTSTATUS)(x))
#define K(name) UIN("kernel32.dll", name)

/* ------------------------------------------------------- RtlAdjustPrivilege */
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));
#define SE_SHUTDOWN 19
#define SE_TCB 7
TEST(adjust_privilege) {
    REQUIRE(UN(RtlAdjustPrivilege));
    BOOLEAN was = 0xEE, orig = 0xEE;
    /* SeShutdownPrivilege is held (disabled or enabled) by both a standard user and an administrator */
    NTSTATUS s = UN(RtlAdjustPrivilege)(SE_SHUTDOWN, FALSE, FALSE, &orig);
    if (s == S(0xC0000061)) { t_skip("SeShutdownPrivilege not held by this token"); return; }
    EXPECT_EQ(s, 0); EXPECT_EQ(orig == 0 || orig == 1, 1);
    /* now disabled */
    was = 0xEE; EXPECT_EQ(UN(RtlAdjustPrivilege)(SE_SHUTDOWN, TRUE, FALSE, &was), 0); EXPECT_EQ(was, 0);
    was = 0xEE; EXPECT_EQ(UN(RtlAdjustPrivilege)(SE_SHUTDOWN, TRUE, FALSE, &was), 0); EXPECT_EQ(was, 1);
    was = 0xEE; EXPECT_EQ(UN(RtlAdjustPrivilege)(SE_SHUTDOWN, FALSE, FALSE, &was), 0); EXPECT_EQ(was, 1);
    was = 0xEE; EXPECT_EQ(UN(RtlAdjustPrivilege)(SE_SHUTDOWN, FALSE, FALSE, &was), 0); EXPECT_EQ(was, 0);
    /* a privilege the token does not hold */
    was = 0xEE; s = UN(RtlAdjustPrivilege)(SE_TCB, TRUE, FALSE, &was);
    if (s == 0) { t_note("SeTcbPrivilege is held by this token"); UN(RtlAdjustPrivilege)(SE_TCB, FALSE, FALSE, &was); }
    else { EXPECT_EQ(s, S(0xC0000061)); EXPECT_EQ(was, 0xEE); }
    /* thread token requested but the thread is not impersonating */
    was = 0xEE; EXPECT_EQ(UN(RtlAdjustPrivilege)(SE_SHUTDOWN, TRUE, TRUE, &was), S(0xC000007C)); EXPECT_EQ(was, 0xEE);
    /* restore */
    UN(RtlAdjustPrivilege)(SE_SHUTDOWN, orig, FALSE, &was);
}

/* ------------------------------------------------------------- AVL trees */
typedef struct N { struct N *Left, *Right; ULONG_PTR Parent; int key; } N;
typedef struct { N *Root; } TREE;
UDECL(VOID, RtlAvlInsertNodeEx, (TREE *, N *, BOOLEAN, N *));
UDECL(VOID, RtlAvlRemoveNode, (TREE *, N *));
static N *par(N *n) { return (N *)(n->Parent & ~(ULONG_PTR)3); }
static int chk(N *n, N *parent, int *cnt, int *lo, int *hi, int *bad) {
    if (!n) return 0;
    if (par(n) != parent) (*bad)++;
    int l = chk(n->Left, n, cnt, lo, hi, bad), r = chk(n->Right, n, cnt, lo, hi, bad);
    if (n->Left && n->Left->key >= n->key) (*bad)++;
    if (n->Right && n->Right->key <= n->key) (*bad)++;
    int bal = (int)(n->Parent & 3); /* 0 balanced, 1 = left-high(-1), 2 = right-high(+1)... encoded as bits */
    int diff = r - l;
    if (diff < -1 || diff > 1) (*bad)++;
    (void)bal;
    (*cnt)++;
    return 1 + (l > r ? l : r);
}
static void avl_insert(TREE *t, N *n) {
    N *p = NULL; BOOLEAN right = 0, f = 0; N *c = t->Root;
    while (c) { p = c; if (n->key < c->key) { right = 0; c = c->Left; } else { right = 1; c = c->Right; } f = 1; }
    (void)f;
    UN(RtlAvlInsertNodeEx)(t, p, right, n);
}
static int avl_ok(TREE *t, int want_count) {
    int cnt = 0, lo = 0, hi = 0, bad = 0;
    if (t->Root && par(t->Root) != NULL) bad++;
    chk(t->Root, NULL, &cnt, &lo, &hi, &bad);
    return bad == 0 && cnt == want_count;
}
TEST(avl_insert_remove) {
    REQUIRE(UN(RtlAvlInsertNodeEx)); REQUIRE(UN(RtlAvlRemoveNode));
    enum { COUNT = 300 };
    static N nodes[COUNT]; TREE t = { NULL };
    memset(nodes, 0xCC, sizeof nodes);
    unsigned seed = 12345; int keys[COUNT];
    for (int i = 0; i < COUNT; i++) keys[i] = i;
    for (int i = COUNT - 1; i > 0; i--) { seed = seed * 1103515245u + 12345u; int j = (seed >> 8) % (i + 1); int x = keys[i]; keys[i] = keys[j]; keys[j] = x; }
    for (int i = 0; i < COUNT; i++) { nodes[i].key = keys[i]; avl_insert(&t, &nodes[i]); if (i < 40 || i % 25 == 0) CHECKF(avl_ok(&t, i + 1), "after insert %d", i); }
    EXPECT_EQ(avl_ok(&t, COUNT), 1);
    /* the first insert into an empty tree becomes the root with a NULL parent */
    TREE t2 = { NULL }; N one; memset(&one, 0xCC, sizeof one); one.key = 1;
    UN(RtlAvlInsertNodeEx)(&t2, NULL, 0, &one);
    EXPECT_EQ(t2.Root, &one); EXPECT_EQ(one.Left, NULL); EXPECT_EQ(one.Right, NULL); EXPECT_EQ(par(&one), NULL);
    UN(RtlAvlRemoveNode)(&t2, &one); EXPECT_EQ(t2.Root, NULL);
    /* ascending insertion forces rotations; the height stays logarithmic */
    TREE t3 = { NULL }; static N asc[128];
    for (int i = 0; i < 128; i++) { asc[i].key = i; avl_insert(&t3, &asc[i]); }
    EXPECT_EQ(avl_ok(&t3, 128), 1);
    { int cnt = 0, lo = 0, hi = 0, bad = 0; int h = chk(t3.Root, NULL, &cnt, &lo, &hi, &bad); EXPECT_EQ(h, 8); }
    for (int i = 0; i < 128; i += 2) { UN(RtlAvlRemoveNode)(&t3, &asc[i]); CHECKF(avl_ok(&t3, 128 - (i / 2 + 1)), "asc remove %d", i); }
    for (int i = 1; i < 128; i += 2) UN(RtlAvlRemoveNode)(&t3, &asc[i]);
    EXPECT_EQ(t3.Root, NULL);
    /* remove in a different order than insertion */
    int left = COUNT;
    for (int i = 0; i < COUNT; i += 3) { UN(RtlAvlRemoveNode)(&t, &nodes[(i * 7) % COUNT]); left--; nodes[(i * 7) % COUNT].key = -1; }
    /* some removals may have repeated indices when gcd(7,COUNT)!=1; recount from the tree */
    { int cnt = 0, lo = 0, hi = 0, bad = 0; chk(t.Root, NULL, &cnt, &lo, &hi, &bad); EXPECT_EQ(bad, 0); EXPECT_EQ(cnt, left); }
}

/* ------------------------------------------------- domain / culture / time */
UDECL(NTSTATUS, RtlCanonicalizeDomainName, (PUNICODE_STRING, PCUNICODE_STRING, BOOLEAN));
UDECL(BOOLEAN, RtlCultureNameToLCID, (PCUNICODE_STRING, PULONG));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
static void us(UNICODE_STRING *u, const WCHAR *w) { u->Buffer = (PWSTR)w; u->Length = (USHORT)(lstrlenW(w) * 2); u->MaximumLength = u->Length + 2; }

static void canon(const WCHAR *in, NTSTATUS want, const WCHAR *wantout, int line) {
    UNICODE_STRING i, o; NTSTATUS s; memset(&o, 0, sizeof o); us(&i, in);
    s = UN(RtlCanonicalizeDomainName)(&o, &i, FALSE);
    t_check(s == want, __FILE__, line, "canonicalize status", "got 0x%lx want 0x%lx", (unsigned long)s, (unsigned long)want);
    if (s == 0) {
        t_check(o.Buffer && o.Length == lstrlenW(wantout) * 2 && !memcmp(o.Buffer, wantout, o.Length), __FILE__, line, "canonicalize output", "unexpected string");
        if (UN(RtlFreeUnicodeString)) UN(RtlFreeUnicodeString)(&o);
    }
}
TEST(canonicalize_domain_name) {
    REQUIRE(UN(RtlCanonicalizeDomainName));
    canon(L"EXAMPLE.Com", 0, L"example.com", __LINE__);
    canon(L"host", 0, L"host", __LINE__);
    canon(L"Sub.Domain.NET", 0, L"sub.domain.net", __LINE__);
    canon(L"192.168.1.5", 0, L"192.168.1.5", __LINE__);
    canon(L"::1", 0, L"::1", __LINE__);
    canon(L"[::1]", 0, L"::1", __LINE__);
    /* an empty name is rejected */
    { UNICODE_STRING i, o; memset(&o, 0, sizeof o); us(&i, L"");
      NTSTATUS s = UN(RtlCanonicalizeDomainName)(&o, &i, FALSE); t_note("empty domain name: 0x%lx", (unsigned long)s); EXPECT_EQ(s, S(0xC0000716)); }
}
TEST(culture_name_to_lcid) {
    REQUIRE(UN(RtlCultureNameToLCID));
    struct { const WCHAR *n; ULONG l; } v[] = { { L"en-US", 0x409 }, { L"de-DE", 0x407 }, { L"ja-JP", 0x411 }, { L"fr-FR", 0x40c }, { L"EN-us", 0x409 } };
    for (int i = 0; i < 5; i++) {
        UNICODE_STRING n; ULONG l = 0xDEAD; us(&n, v[i].n);
        EXPECT_EQ(UN(RtlCultureNameToLCID)(&n, &l), TRUE); EXPECT_EQ(l, v[i].l);
    }
    UNICODE_STRING n; ULONG l = 0xDEAD;
    us(&n, L"zz-ZZ-nonsense"); EXPECT_EQ(UN(RtlCultureNameToLCID)(&n, &l), FALSE); EXPECT_EQ(l, 0xDEAD);
    us(&n, L""); EXPECT_EQ(UN(RtlCultureNameToLCID)(&n, &l), FALSE);
    EXPECT_EQ(UN(RtlCultureNameToLCID)(NULL, &l), FALSE);
    us(&n, L"en-US"); EXPECT_EQ(UN(RtlCultureNameToLCID)(&n, NULL), FALSE);
    /* name too long for the internal buffer (limit 0x56 bytes including terminator) */
    WCHAR big[64]; for (int i = 0; i < 63; i++) big[i] = L'a'; big[63] = 0;
    us(&n, big); EXPECT_EQ(UN(RtlCultureNameToLCID)(&n, &l), FALSE);
}

typedef struct { SHORT Year, Month, Day, Hour, Minute, Second, Milliseconds, Weekday; } TIME_FIELDS;
typedef TIME_FIELDS *PTIME_FIELDS;
UDECL(BOOLEAN, RtlCutoverTimeToSystemTime, (PTIME_FIELDS, PLARGE_INTEGER, PLARGE_INTEGER, BOOLEAN));
UDECL(BOOLEAN, RtlTimeFieldsToTime, (PTIME_FIELDS, PLARGE_INTEGER));
static LONGLONG tf(int y, int mo, int d, int h) {
    TIME_FIELDS f = { (SHORT)y, (SHORT)mo, (SHORT)d, (SHORT)h, 0, 0, 0, 0 }; LARGE_INTEGER t; t.QuadPart = 0;
    UN(RtlTimeFieldsToTime)(&f, &t); return t.QuadPart;
}
TEST(cutover_time_to_system_time) {
    REQUIRE(UN(RtlCutoverTimeToSystemTime)); REQUIRE(UN(RtlTimeFieldsToTime));
    LARGE_INTEGER cur, out; TIME_FIELDS c;
    /* relative form: Year 0, Month, Day = week of month (1..5, 5 = last), Weekday */
    cur.QuadPart = tf(2020, 1, 1, 0);
    memset(&c, 0, sizeof c); c.Month = 3; c.Day = 2; c.Hour = 2; c.Weekday = 0;
    out.QuadPart = 0; EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, FALSE), TRUE);
    EXPECT_EQ(out.QuadPart, tf(2020, 3, 8, 2));              /* second Sunday of March 2020 */
    c.Day = 1; out.QuadPart = 0; EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, FALSE), TRUE);
    EXPECT_EQ(out.QuadPart, tf(2020, 3, 1, 2));
    c.Month = 10; c.Day = 5; out.QuadPart = 0; EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, FALSE), TRUE);
    EXPECT_EQ(out.QuadPart, tf(2020, 10, 25, 2));            /* last Sunday of October 2020 */
    c.Month = 11; c.Day = 1; c.Weekday = 4;                  /* first Thursday of Nov 2020 = 5th */
    out.QuadPart = 0; EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, FALSE), TRUE);
    EXPECT_EQ(out.QuadPart, tf(2020, 11, 5, 2));
    /* month already passed in the current year: with ThisYear FALSE the next year is used */
    cur.QuadPart = tf(2020, 6, 1, 0);
    memset(&c, 0, sizeof c); c.Month = 3; c.Day = 2; c.Hour = 2; c.Weekday = 0;
    out.QuadPart = 0; EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, FALSE), TRUE);
    EXPECT_EQ(out.QuadPart, tf(2021, 3, 14, 2));
    out.QuadPart = 0; EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, TRUE), TRUE);
    EXPECT_EQ(out.QuadPart, tf(2020, 3, 8, 2));
    /* invalid week-of-month values */
    c.Day = 0; EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, TRUE), FALSE);
    c.Day = 6; EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, TRUE), FALSE);
    /* absolute form: nonzero Year is converted as is, and must not lie in the past unless ThisYear */
    memset(&c, 0, sizeof c); c.Year = 2021; c.Month = 5; c.Day = 6; c.Hour = 7;
    cur.QuadPart = tf(2020, 1, 1, 0); out.QuadPart = 0;
    EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, FALSE), TRUE); EXPECT_EQ(out.QuadPart, tf(2021, 5, 6, 7));
    cur.QuadPart = tf(2022, 1, 1, 0);
    EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, FALSE), FALSE);
    out.QuadPart = 0; EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, TRUE), TRUE); EXPECT_EQ(out.QuadPart, tf(2021, 5, 6, 7));
    c.Month = 13; EXPECT_EQ(UN(RtlCutoverTimeToSystemTime)(&c, &out, &cur, TRUE), FALSE);
}

/* ----------------------------------------------------------------- barriers */
typedef struct { __attribute__((aligned(8))) UCHAR b[48]; } BARRIER;
typedef struct { BARRIER *bar; ULONG flags; volatile LONG *trues; HANDLE start; int rounds; BOOLEAN (WINAPI *fn)(PVOID, ULONG); } BARG;
static DWORD WINAPI barrier_thread(LPVOID p) {
    BARG *a = p; WaitForSingleObject(a->start, 10000);
    for (int r = 0; r < a->rounds; r++) if (a->fn(a->bar, a->flags)) InterlockedIncrement(a->trues);
    return 0;
}
typedef BOOL (WINAPI *InitBar_t)(PVOID, LONG, LONG);
typedef BOOL (WINAPI *DelBar_t)(PVOID);
static void barrier_run(const char *name, BOOLEAN (WINAPI *fn)(PVOID, ULONG), ULONG flags) {
    InitBar_t ib = (InitBar_t)K(InitializeSynchronizationBarrier); DelBar_t db = (DelBar_t)K(DeleteSynchronizationBarrier);
    if (!ib || !db) { t_skip("kernel32 barrier initialization not available"); return; }
    BARRIER bar; memset(&bar, 0, sizeof bar);
    EXPECT_EQ(ib(&bar, 3, 0), TRUE);
    volatile LONG trues = 0; HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL);
    BARG a = { &bar, flags, &trues, start, 5, fn };
    HANDLE th[2]; for (int i = 0; i < 2; i++) th[i] = CreateThread(NULL, 0, barrier_thread, &a, 0, NULL);
    SetEvent(start);
    barrier_thread(&a);
    DWORD w = WaitForMultipleObjects(2, th, TRUE, 20000);
    EXPECT_EQ(w, WAIT_OBJECT_0);
    /* exactly one of the three participants is told it was last, in every round */
    EXPECT_EQ(trues, 5);
    if (w != WAIT_OBJECT_0) { t_note("%s: barrier workers did not finish", name); TerminateThread(th[0], 0); TerminateThread(th[1], 0); }
    CloseHandle(th[0]); CloseHandle(th[1]); CloseHandle(start);
    db(&bar);
}
TEST(barrier) { REQUIRE(t_proc("RtlBarrier")); barrier_run("RtlBarrier", (void *)t_proc("RtlBarrier"), 0); }
TEST(barrier_for_delete) { REQUIRE(t_proc("RtlBarrierForDelete")); barrier_run("RtlBarrierForDelete", (void *)t_proc("RtlBarrierForDelete"), 0); }
TEST(barrier_single_thread) {
    InitBar_t ib = (InitBar_t)K(InitializeSynchronizationBarrier); DelBar_t db = (DelBar_t)K(DeleteSynchronizationBarrier);
    REQUIRE(t_proc("RtlBarrier")); if (!ib || !db) { t_skip("kernel32 barrier initialization not available"); return; }
    BARRIER bar; memset(&bar, 0, sizeof bar);
    EXPECT_EQ(ib(&bar, 1, 0), TRUE);
    BOOLEAN (WINAPI *fn)(PVOID, ULONG) = (void *)t_proc("RtlBarrier");
    for (int i = 0; i < 4; i++) EXPECT_EQ(fn(&bar, 0), TRUE);
    db(&bar);
}
TEST(barrier_aliases) {
    EXPECT_EQ(t_proc("RtlBarrier") != NULL, 1);
    /* RtlBarrierForDelete is a distinct entry point (it forwards to the posix barrier with a flag) */
    if (t_proc("RtlBarrier") && t_proc("RtlBarrierForDelete")) EXPECT_NE(t_proc("RtlBarrier"), t_proc("RtlBarrierForDelete"));
}

/* ------------------------------------------------------------ API sets */
UDECL(NTSTATUS, ApiSetQueryApiSetPresence, (PCUNICODE_STRING, PBOOLEAN));
UDECL(NTSTATUS, ApiSetQueryApiSetPresenceEx, (PCUNICODE_STRING, PBOOLEAN, PBOOLEAN));
TEST(apiset_presence) {
    REQUIRE(UN(ApiSetQueryApiSetPresence)); REQUIRE(UN(ApiSetQueryApiSetPresenceEx));
    UNICODE_STRING n; BOOLEAN present = 0xEE, in_schema = 0xEE;
    us(&n, L"api-ms-win-core-synch-l1-1-0");
    NTSTATUS s = UN(ApiSetQueryApiSetPresence)(&n, &present); EXPECT_EQ(s, 0); EXPECT_EQ(present, 1);
    us(&n, L"api-ms-win-core-processthreads-l1-1-0");
    present = 0xEE; s = UN(ApiSetQueryApiSetPresence)(&n, &present); EXPECT_EQ(s, 0); EXPECT_EQ(present, 1);
    us(&n, L"api-ms-win-no-such-set-l9-9-9");
    present = 0xEE; s = UN(ApiSetQueryApiSetPresence)(&n, &present); EXPECT_EQ(s, 0); EXPECT_EQ(present, 0);
    us(&n, L"kernel32"); present = 0xEE; s = UN(ApiSetQueryApiSetPresence)(&n, &present); EXPECT_EQ(s, 0); EXPECT_EQ(present, 0);
    us(&n, L"api-ms-win-core-synch-l1-1-0"); present = 0xEE; in_schema = 0xEE;
    s = UN(ApiSetQueryApiSetPresenceEx)(&n, &in_schema, &present); EXPECT_EQ(s, 0); EXPECT_EQ(in_schema, 1); EXPECT_EQ(present, 1);
    us(&n, L"api-ms-win-no-such-set-l9-9-9"); present = 0xEE; in_schema = 0xEE;
    s = UN(ApiSetQueryApiSetPresenceEx)(&n, &in_schema, &present); EXPECT_EQ(s, 0); EXPECT_EQ(in_schema, 0); EXPECT_EQ(present, 0);
}

/* ------------------------------------------------------- RtlCaptureContext2 */
typedef void (WINAPI *CC2)(PCONTEXT);
TEST(capture_context2) {
    CC2 f = (CC2)t_proc("RtlCaptureContext2"); REQUIRE(f);
    __attribute__((aligned(16))) CONTEXT c; memset(&c, 0, sizeof c);
    volatile char marker; 
    f(&c);
    EXPECT_EQ(c.ContextFlags, 0x10000F);                    /* CONTEXT_AMD64|CONTROL|INTEGER|SEGMENTS|FLOATING_POINT */
    EXPECT_EQ(c.SegCs, 0x33); EXPECT_EQ(c.SegSs, 0x2B);
    EXPECT_EQ(c.MxCsr, 0x1F80);
    HMODULE self = NULL; GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)(ULONG_PTR)c.Rip, &self);
    EXPECT_EQ(self, GetModuleHandleW(NULL));                  /* Rip is the return address inside this image */
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    EXPECT_EQ(c.Rsp >= (ULONG_PTR)tib->StackLimit && c.Rsp < (ULONG_PTR)tib->StackBase, 1);
    EXPECT_EQ(c.Rsp < (ULONG_PTR)&marker + 0x1000, 1);
    /* a requested XSTATE flag without support is stripped; flag bits other than the xstate bit are rebuilt */
    memset(&c, 0, sizeof c); c.ContextFlags = 0x100001; f(&c);
    EXPECT_EQ((c.ContextFlags & 0x10000F), 0x10000F);
}

/* -------------------------------------------------------- memory streams */
TEST(memory_stream_stubs) {
    static const char *names[] = { "RtlCloneMemoryStream", "RtlCommitMemoryStream", "RtlCopyMemoryStreamTo", "RtlCopyOutOfProcessMemoryStreamTo",
        "RtlLockMemoryStreamRegion", "RtlQueryInterfaceMemoryStream", "RtlReadMemoryStream", "RtlReadOutOfProcessMemoryStream",
        "RtlRevertMemoryStream", "RtlSeekMemoryStream", "RtlSetMemoryStreamSize", "RtlStatMemoryStream", "RtlUnlockMemoryStreamRegion", "RtlWriteMemoryStream" };
    FARPROC base = t_proc("RtlCommitMemoryStream"); REQUIRE(base);
    /* the interface is not implemented: every method shares one E_NOTIMPL stub */
    for (int i = 0; i < 14; i++) { FARPROC p = t_proc(names[i]); if (p) EXPECT_EQ(p, base); else t_note("missing %s", names[i]); }
    LONG (WINAPI *f)(void *) = (void *)base;
    EXPECT_EQ(f(NULL), (LONG)0x80004001);
    FARPROC cl = t_proc("RtlCloneMemoryStream"); REQUIRE(cl);
    EXPECT_EQ(((LONG (WINAPI *)(void *, void **))cl)(NULL, NULL), (LONG)0x80004001);
}

/* -------------------------------------------------- process parameters */
typedef VOID *PV;
UDECL(PV, RtlDeNormalizeProcessParams, (PV));
TEST(denormalize_process_params) {
    REQUIRE(UN(RtlDeNormalizeProcessParams));
    EXPECT_EQ(UN(RtlDeNormalizeProcessParams)(NULL), NULL);
    static const int offs[] = { 0x40, 0x58, 0x68, 0x78, 0xB8, 0xC8, 0xD8, 0xE8, 0x418 };
    UCHAR *p = (UCHAR *)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); REQUIRE(p);
    memset(p, 0, 0x1000);
    *(ULONG *)(p + 8) = 1;                                    /* PROCESS_PARAMETERS_NORMALIZED */
    for (int i = 0; i < 9; i++) if (i != 4) *(ULONG_PTR *)(p + offs[i]) = (ULONG_PTR)p + 0x500 + i * 0x10;
    *(ULONG_PTR *)(p + offs[4]) = 0;                          /* NULL pointers stay NULL */
    EXPECT_EQ(UN(RtlDeNormalizeProcessParams)(p), p);
    for (int i = 0; i < 9; i++) EXPECT_EQ(*(ULONG_PTR *)(p + offs[i]), i == 4 ? 0 : (ULONG_PTR)(0x500 + i * 0x10));
    EXPECT_EQ(*(ULONG *)(p + 8), 0);
    /* already denormalized: nothing changes */
    EXPECT_EQ(UN(RtlDeNormalizeProcessParams)(p), p);
    EXPECT_EQ(*(ULONG_PTR *)(p + 0x40), 0x500);
    /* other flag bits are preserved */
    *(ULONG *)(p + 8) = 0x81; *(ULONG_PTR *)(p + 0x40) = (ULONG_PTR)p + 0x600;
    UN(RtlDeNormalizeProcessParams)(p); EXPECT_EQ(*(ULONG *)(p + 8), 0x80); EXPECT_EQ(*(ULONG_PTR *)(p + 0x40), 0x600);
    VirtualFree(p, 0, MEM_RELEASE);
}

/* ----------------------------------------------------------- hash tables */
typedef struct { PVOID a; } DHT;
UDECL(BOOLEAN, RtlCreateHashTable, (DHT **, ULONG, ULONG));
UDECL(VOID, RtlDeleteHashTable, (DHT *));
UDECL(BOOLEAN, RtlExpandHashTable, (DHT *));
UDECL(BOOLEAN, RtlContractHashTable, (DHT *));
TEST(hash_table_contract) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlDeleteHashTable)); REQUIRE(UN(RtlExpandHashTable)); REQUIRE(UN(RtlContractHashTable));
    DHT *t = NULL;
    EXPECT_EQ(UN(RtlCreateHashTable)(&t, 0, 0), TRUE); REQUIRE(t);
    /* a fresh table is at its minimum size */
    EXPECT_EQ(UN(RtlContractHashTable)(t), FALSE);
    EXPECT_EQ(UN(RtlExpandHashTable)(t), TRUE);
    EXPECT_EQ(UN(RtlContractHashTable)(t), TRUE);
    EXPECT_EQ(UN(RtlContractHashTable)(t), FALSE);
    for (int i = 0; i < 20; i++) EXPECT_EQ(UN(RtlExpandHashTable)(t), TRUE);
    for (int i = 0; i < 20; i++) EXPECT_EQ(UN(RtlContractHashTable)(t), TRUE);
    EXPECT_EQ(UN(RtlContractHashTable)(t), FALSE);
    UN(RtlDeleteHashTable)(t);
}

/* ------------------------------------------------------- debug info buffer */
UDECL(PVOID, RtlCommitDebugInfo, (PVOID, ULONG));
UDECL(VOID, RtlDeCommitDebugInfo, (PVOID, PVOID, ULONG));
TEST(debug_info_commit) {
    REQUIRE(UN(RtlCommitDebugInfo)); REQUIRE(UN(RtlDeCommitDebugInfo));
    UCHAR *b = (UCHAR *)VirtualAlloc(NULL, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); REQUIRE(b);
    memset(b, 0, 0x4000);
    *(ULONG_PTR *)(b + 0x48) = 0x100;   /* next free offset */
    *(ULONG_PTR *)(b + 0x50) = 0x1000;  /* end of committed area */
    *(ULONG_PTR *)(b + 0x58) = 0x4000;  /* end of reserved area */
    PVOID p = UN(RtlCommitDebugInfo)(b, 0x20); EXPECT_EQ(p, b + 0x100); EXPECT_EQ(*(ULONG_PTR *)(b + 0x48), 0x120);
    PVOID q = UN(RtlCommitDebugInfo)(b, 0x21); EXPECT_EQ(q, b + 0x120); EXPECT_EQ(*(ULONG_PTR *)(b + 0x48), 0x148);   /* rounded up to 8 */
    PVOID z = UN(RtlCommitDebugInfo)(b, 0); EXPECT_EQ(z, b + 0x148); EXPECT_EQ(*(ULONG_PTR *)(b + 0x48), 0x148);
    /* freeing something that is not the most recent allocation is ignored */
    UN(RtlDeCommitDebugInfo)(b, p, 0x20); EXPECT_EQ(*(ULONG_PTR *)(b + 0x48), 0x148);
    UN(RtlDeCommitDebugInfo)(b, q, 0x21); EXPECT_EQ(*(ULONG_PTR *)(b + 0x48), 0x120);
    UN(RtlDeCommitDebugInfo)(b, p, 0x20); EXPECT_EQ(*(ULONG_PTR *)(b + 0x48), 0x100);
    /* beyond the reserved limit */
    EXPECT_EQ(UN(RtlCommitDebugInfo)(b, 0x4000), NULL); EXPECT_EQ(*(ULONG_PTR *)(b + 0x48), 0x100);
    EXPECT_EQ(UN(RtlCommitDebugInfo)(b, 0xFFFFFFF9), NULL);
    EXPECT_EQ(UN(RtlCommitDebugInfo)(b, 0xFFFFFFFF), NULL);
    /* growing past the committed end commits more of the reservation */
    EXPECT_EQ(UN(RtlCommitDebugInfo)(b, 0x1000), (PVOID)(b + 0x100)); EXPECT_EQ(*(ULONG_PTR *)(b + 0x48), 0x1100);
    EXPECT_EQ(*(ULONG_PTR *)(b + 0x50) >= 0x1100, 1);
    VirtualFree(b, 0, MEM_RELEASE);
}

/* ------------------------------------------- work-on-behalf ticket clear */
UDECL(NTSTATUS, RtlClearThreadWorkOnBehalfTicket, (void));
TEST(clear_work_on_behalf_ticket) {
    REQUIRE(UN(RtlClearThreadWorkOnBehalfTicket));
    /* no ticket was ever set on this thread: nothing to clear */
    EXPECT_EQ(UN(RtlClearThreadWorkOnBehalfTicket)(), 0);
    EXPECT_EQ(UN(RtlClearThreadWorkOnBehalfTicket)(), 0);
}

/* ---------------------------------------------- trusted-installer owner */
UDECL(NTSTATUS, RtlAppxIsFileOwnedByTrustedInstaller, (HANDLE, PBOOLEAN));
TEST(appx_trusted_installer_owner) {
    REQUIRE(UN(RtlAppxIsFileOwnedByTrustedInstaller));
    typedef HANDLE (WINAPI *CF)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    CF cf = (CF)K(CreateFileW); REQUIRE(cf);
    WCHAR sys[MAX_PATH], p[MAX_PATH]; GetSystemDirectoryW(sys, MAX_PATH); lstrcpyW(p, sys); lstrcatW(p, L"\\kernel32.dll");
    HANDLE h = cf(p, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("cannot open system file with READ_CONTROL"); return; }
    BOOLEAN r = 0xEE; NTSTATUS s = UN(RtlAppxIsFileOwnedByTrustedInstaller)(h, &r);
    EXPECT_EQ(s, 0); EXPECT_EQ(r, 1);
    EXPECT_EQ(UN(RtlAppxIsFileOwnedByTrustedInstaller)(h, NULL), S(0xC000000D));
    CloseHandle(h);
    char tmp[MAX_PATH]; t_tmpfile(tmp, sizeof tmp, "own.tmp");
    HANDLE t = CreateFileA(tmp, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (t != INVALID_HANDLE_VALUE) { r = 0xEE; s = UN(RtlAppxIsFileOwnedByTrustedInstaller)(t, &r); EXPECT_EQ(s, 0); EXPECT_EQ(r, 0); CloseHandle(t); }
    r = 0xEE; EXPECT_EQ(UN(RtlAppxIsFileOwnedByTrustedInstaller)((HANDLE)(ULONG_PTR)0xFFFC, &r), S(0xC0000008)); EXPECT_EQ(r, 0xEE);
}

/* ------------------------------------------- inverted function table */
static int ift_find(const UCHAR *t, ULONG count, HMODULE m, ULONG *size_out) {
    for (ULONG i = 0; i < count; i++) {
        const UCHAR *e = t + 0x10 + i * 0x18;
        if (*(HMODULE *)(e + 8) == m) { *size_out = *(ULONG *)(e + 0x10); return 1; }
    }
    return 0;
}
TEST(inverted_function_table) {
    const UCHAR *t = (const UCHAR *)t_proc("KiUserInvertedFunctionTable");
    if (!t) { t_skip("KiUserInvertedFunctionTable not exported"); return; }
    ULONG count = *(const ULONG *)t, max = *(const ULONG *)(t + 4);
    EXPECT_EQ(count >= 2, 1);                 /* at least the executable and ntdll */
    EXPECT_EQ(count <= max, 1);
    HMODULE self = GetModuleHandleW(NULL), nt = GetModuleHandleW(L"ntdll.dll");
    ULONG sz = 0;
    for (int k = 0; k < 2; k++) {
        HMODULE m = k ? nt : self;
        if (!ift_find(t, count, m, &sz)) { CHECKF(0, "module %p missing from the inverted function table", m); continue; }
        const IMAGE_DOS_HEADER *dh = (const IMAGE_DOS_HEADER *)m;
        const IMAGE_NT_HEADERS64 *nh = (const IMAGE_NT_HEADERS64 *)((const UCHAR *)m + dh->e_lfanew);
        EXPECT_EQ(sz, nh->OptionalHeader.SizeOfImage);
        const UCHAR *e = NULL; for (ULONG i = 0; i < count; i++) if (*(HMODULE *)(t + 0x10 + i * 0x18 + 8) == m) e = t + 0x10 + i * 0x18;
        /* exception directory pointer and size agree with the PE header */
        const IMAGE_DATA_DIRECTORY *ed = &nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        EXPECT_EQ(*(const UCHAR **)e, (const UCHAR *)m + ed->VirtualAddress);
        EXPECT_EQ(*(const ULONG *)(e + 0x14), ed->Size);
    }
}

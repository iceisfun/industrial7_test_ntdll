/* RtlTraceDatabase* : the in-process stack-trace database used by the heap/handle tracers.
 *
 * Prototypes (as used by the public RTL_TRACE_* declarations):
 *   PRTL_TRACE_DATABASE RtlTraceDatabaseCreate(ULONG Buckets, SIZE_T MaximumSize, ULONG Flags, ULONG Tag,
 *                                              ULONG (*Hash)(ULONG Count, PVOID *Trace));
 *   BOOLEAN RtlTraceDatabaseAdd / Find (db, ULONG Count, PVOID *Trace, RTL_TRACE_BLOCK **Block)
 *   BOOLEAN RtlTraceDatabaseEnumerate(db, RTL_TRACE_ENUM *Enum, RTL_TRACE_BLOCK **Block)
 *   BOOLEAN RtlTraceDatabaseValidate(db), Destroy(db); void Lock(db), Unlock(db)
 * Header and block layouts below (magic values, field offsets) are the documented RTL_TRACE_DATABASE /
 * RTL_TRACE_BLOCK layout and were observed on Windows 10. A bucket count below 16 is never used: the
 * first Add then divides by (Buckets >> 4) and faults (observed, integer divide by zero).
 */
#include "t.h"

typedef struct {
    ULONG Magic;       /* 0xABCDAAAA */
    ULONG UserCount;   /* times this trace was added */
    ULONG Count;       /* frames in Trace */
    ULONG Pad;
    SIZE_T Size;       /* user-maintained */
    SIZE_T UserSize;
    PVOID UserContext;
    PVOID Next;
    PVOID *Trace;
} TBLOCK;
typedef struct { PVOID Database; ULONG Bucket; PVOID Block; } TENUM;
typedef struct { ULONG Magic; ULONG Flags; ULONG Tag; } TDB_HEAD;

typedef TDB_HEAD *(WINAPI *create_fn)(ULONG, SIZE_T, ULONG, ULONG, ULONG (WINAPI *)(ULONG, PVOID *));
typedef BOOLEAN (WINAPI *addfind_fn)(PVOID, ULONG, PVOID *, TBLOCK **);
typedef BOOLEAN (WINAPI *enum_fn)(PVOID, TENUM *, TBLOCK **);
typedef BOOLEAN (WINAPI *db1_fn)(PVOID);
typedef void (WINAPI *lock_fn)(PVOID);

static create_fn pCreate; static addfind_fn pAdd, pFind; static enum_fn pEnum;
static db1_fn pValidate, pDestroy; static lock_fn pLock, pUnlock;

static int resolve(void)
{
    pCreate = (create_fn)t_proc("RtlTraceDatabaseCreate");
    pAdd = (addfind_fn)t_proc("RtlTraceDatabaseAdd");
    pFind = (addfind_fn)t_proc("RtlTraceDatabaseFind");
    pEnum = (enum_fn)t_proc("RtlTraceDatabaseEnumerate");
    pValidate = (db1_fn)t_proc("RtlTraceDatabaseValidate");
    pDestroy = (db1_fn)t_proc("RtlTraceDatabaseDestroy");
    pLock = (lock_fn)t_proc("RtlTraceDatabaseLock");
    pUnlock = (lock_fn)t_proc("RtlTraceDatabaseUnlock");
    return pCreate && pAdd && pFind && pEnum && pValidate && pDestroy && pLock && pUnlock;
}
#define NEED() do { if (!resolve()) { t_skip("RtlTraceDatabase export missing"); return; } } while (0)

static volatile LONG g_hash_calls; static volatile ULONG g_hash_last_count;
static ULONG WINAPI const_hash(ULONG count, PVOID *trace)
{
    InterlockedIncrement(&g_hash_calls);
    g_hash_last_count = count;
    (void)trace;
    return 5; /* every trace lands in one bucket */
}

TEST(tracedb_create_destroy)
{
    NEED();
    TDB_HEAD *db = pCreate(16, 0x100000, 0x20, 0x55AA, NULL);
    CHECK(db != NULL);
    if (!db) return;
    EXPECT_EQ(db->Magic, 0xABCDCCCC);
    EXPECT_EQ(db->Flags, 0x21);          /* caller flags | 1 */
    EXPECT_EQ(db->Tag, 0x55AA);
    CHECK(pValidate(db));
    CHECK(pDestroy(db));
}

TEST(tracedb_create_bucket_limit)
{
    NEED();
    /* more than 0x100000 buckets is rejected up front, nothing is allocated */
    EXPECT_EQ((ULONG_PTR)pCreate(0x100001, 0x10000, 0, 0, NULL), 0);
    EXPECT_EQ((ULONG_PTR)pCreate(0xFFFFFFFF, 0x10000, 0, 0, NULL), 0);
}

TEST(tracedb_add_find_default_hash)
{
    NEED();
    TDB_HEAD *db = pCreate(64, 0x100000, 0, 1, NULL);
    CHECK(db != NULL);
    if (!db) return;
    PVOID t1[4] = { (PVOID)0x1000, (PVOID)0x2000, (PVOID)0x3000, (PVOID)0x4000 };
    PVOID t2[4] = { (PVOID)0x1000, (PVOID)0x2000, (PVOID)0x3000, (PVOID)0x4001 };
    PVOID t3[2] = { (PVOID)0x1000, (PVOID)0x2000 };
    TBLOCK *b = (TBLOCK *)(ULONG_PTR)0xdead, *b2 = NULL;

    /* not present yet: Find fails and nulls the output */
    CHECK(!pFind(db, 4, t1, &b));
    EXPECT_EQ((ULONG_PTR)b, 0);

    b = NULL;
    CHECK(pAdd(db, 4, t1, &b));
    CHECK(b != NULL);
    if (b) {
        EXPECT_EQ(b->Magic, 0xABCDAAAA);
        EXPECT_EQ(b->UserCount, 1);
        EXPECT_EQ(b->Count, 4);
        CHECK(b->Trace != NULL);
        if (b->Trace) CHECK(!memcmp(b->Trace, t1, sizeof t1));
        CHECK(b->Trace != t1);  /* the trace is copied into the database */
    }

    /* find returns the same block */
    CHECK(pFind(db, 4, t1, &b2));
    EXPECT_EQ((ULONG_PTR)b2, (ULONG_PTR)b);

    /* adding it again bumps UserCount and returns the same block */
    b2 = NULL;
    CHECK(pAdd(db, 4, t1, &b2));
    EXPECT_EQ((ULONG_PTR)b2, (ULONG_PTR)b);
    if (b) EXPECT_EQ(b->UserCount, 2);

    /* different content and different length are distinct entries */
    TBLOCK *bb2 = NULL, *bb3 = NULL;
    CHECK(pAdd(db, 4, t2, &bb2));
    CHECK(pAdd(db, 2, t3, &bb3));
    CHECK(bb2 && bb3 && bb2 != b && bb3 != b && bb2 != bb3);
    if (bb3) EXPECT_EQ(bb3->Count, 2);
    /* a prefix of an existing trace does not match it */
    TBLOCK *bf = NULL;
    CHECK(pFind(db, 2, t3, &bf));
    EXPECT_EQ((ULONG_PTR)bf, (ULONG_PTR)bb3);
    PVOID t4[3] = { (PVOID)0x1000, (PVOID)0x2000, (PVOID)0x3000 };
    bf = (TBLOCK *)(ULONG_PTR)1;
    CHECK(!pFind(db, 3, t4, &bf));
    EXPECT_EQ((ULONG_PTR)bf, 0);

    /* output pointer is optional */
    CHECK(pFind(db, 4, t1, NULL));
    CHECK(pAdd(db, 4, t1, NULL));
    if (b) EXPECT_EQ(b->UserCount, 3);
    CHECK(!pFind(db, 3, t4, NULL));

    CHECK(pValidate(db));
    CHECK(pDestroy(db));
}

TEST(tracedb_add_depth_limit)
{
    NEED();
    TDB_HEAD *db = pCreate(16, 0x100000, 0, 2, NULL);
    CHECK(db != NULL);
    if (!db) return;
    PVOID big[0x101]; for (int i = 0; i < 0x101; i++) big[i] = (PVOID)(ULONG_PTR)(0x10000 + i * 8);
    TBLOCK *b = (TBLOCK *)(ULONG_PTR)0xdead;
    /* 0x100 frames is the maximum depth; 0x101 is rejected without touching the output */
    CHECK(!pAdd(db, 0x101, big, &b));
    EXPECT_EQ((ULONG_PTR)b, 0xdead);
    b = NULL;
    CHECK(pAdd(db, 0x100, big, &b));
    CHECK(b != NULL);
    if (b) { EXPECT_EQ(b->Count, 0x100); CHECK(!memcmp(b->Trace, big, 0x100 * sizeof(PVOID))); }
    CHECK(pFind(db, 0x100, big, NULL));
    CHECK(pDestroy(db));
}

TEST(tracedb_custom_hash)
{
    NEED();
    TDB_HEAD *db = pCreate(16, 0x100000, 0, 3, const_hash);
    CHECK(db != NULL);
    if (!db) return;
    PVOID a[3] = { (PVOID)0x11, (PVOID)0x22, (PVOID)0x33 };
    PVOID b3[3] = { (PVOID)0x11, (PVOID)0x22, (PVOID)0x34 };
    TBLOCK *ba = NULL, *bb = NULL, *f = NULL;
    g_hash_calls = 0;
    CHECK(pAdd(db, 3, a, &ba));
    CHECK(g_hash_calls > 0);
    EXPECT_EQ(g_hash_last_count, 3);
    CHECK(pAdd(db, 3, b3, &bb));
    /* identical hash values must still be told apart by content (collision chain) */
    CHECK(ba && bb && ba != bb);
    CHECK(pFind(db, 3, a, &f));
    EXPECT_EQ((ULONG_PTR)f, (ULONG_PTR)ba);
    CHECK(pFind(db, 3, b3, &f));
    EXPECT_EQ((ULONG_PTR)f, (ULONG_PTR)bb);
    LONG before = g_hash_calls;
    PVOID miss[3] = { (PVOID)0x11, (PVOID)0x22, (PVOID)0x35 };
    CHECK(!pFind(db, 3, miss, &f));
    CHECK(g_hash_calls > before);
    EXPECT_EQ((ULONG_PTR)f, 0);
    CHECK(pDestroy(db));
}

TEST(tracedb_enumerate)
{
    NEED();
    TDB_HEAD *db = pCreate(32, 0x100000, 0, 4, NULL);
    CHECK(db != NULL);
    if (!db) return;
    TENUM e; TBLOCK *b = (TBLOCK *)(ULONG_PTR)7;

    /* empty database: nothing to enumerate */
    memset(&e, 0, sizeof e);
    CHECK(!pEnum(db, &e, &b));
    EXPECT_EQ((ULONG_PTR)b, 0);

    enum { N = 10 };
    TBLOCK *added[N];
    for (int i = 0; i < N; i++) {
        PVOID t[2] = { (PVOID)(ULONG_PTR)(0x7000 + i * 0x10), (PVOID)(ULONG_PTR)(0x8000 + i) };
        added[i] = NULL;
        CHECK(pAdd(db, 2, t, &added[i]));
    }
    int seen[N] = { 0 }, total = 0;
    memset(&e, 0, sizeof e);
    for (;;) {
        b = NULL;
        if (!pEnum(db, &e, &b)) break;
        CHECK(b != NULL);
        if (!b) break;
        EXPECT_EQ(b->Magic, 0xABCDAAAA);
        int hit = 0;
        for (int i = 0; i < N; i++) if (added[i] == b) { seen[i]++; hit = 1; }
        CHECK(hit);
        if (++total > N + 2) break;
    }
    EXPECT_EQ(total, N);
    for (int i = 0; i < N; i++) EXPECT_EQ(seen[i], 1);
    EXPECT_EQ((ULONG_PTR)b, 0);

    /* an enumeration state that belongs to another database is rejected */
    TDB_HEAD *db2 = pCreate(32, 0x100000, 0, 5, NULL);
    CHECK(db2 != NULL);
    if (db2) {
        b = (TBLOCK *)(ULONG_PTR)7;
        memset(&e, 0, sizeof e);
        CHECK(pEnum(db, &e, &b));   /* e now bound to db */
        CHECK(!pEnum(db2, &e, &b));
        CHECK(pDestroy(db2));
    }
    CHECK(pDestroy(db));
}

TEST(tracedb_find_counts_in_validate)
{
    NEED();
    TDB_HEAD *db = pCreate(16, 0x100000, 0, 6, NULL);
    CHECK(db != NULL);
    if (!db) return;
    for (int i = 0; i < 50; i++) {
        PVOID t[1] = { (PVOID)(ULONG_PTR)(0x9000 + i) };
        CHECK(pAdd(db, 1, t, NULL));
    }
    for (int i = 0; i < 50; i++) {
        PVOID t[1] = { (PVOID)(ULONG_PTR)(0x9000 + i) };
        TBLOCK *b = NULL;
        CHECK(pFind(db, 1, t, &b));
        CHECK(b && b->Count == 1 && b->Trace[0] == t[0]);
    }
    CHECK(pValidate(db));
    CHECK(pDestroy(db));
}

TEST(tracedb_many_traces_grow_segments)
{
    NEED();
    /* enough distinct traces that a single 64 KiB segment cannot hold them */
    TDB_HEAD *db = pCreate(256, 0x100000, 0, 7, NULL);
    CHECK(db != NULL);
    if (!db) return;
    int ok = 0;
    for (int i = 0; i < 2000; i++) {
        PVOID t[8]; for (int j = 0; j < 8; j++) t[j] = (PVOID)(ULONG_PTR)(i * 100 + j + 1);
        TBLOCK *b = NULL;
        if (pAdd(db, 8, t, &b) && b) ok++; else break;
    }
    EXPECT_EQ(ok, 2000);
    for (int i = 0; i < 2000; i += 97) {
        PVOID t[8]; for (int j = 0; j < 8; j++) t[j] = (PVOID)(ULONG_PTR)(i * 100 + j + 1);
        CHECK(pFind(db, 8, t, NULL));
    }
    TENUM e; TBLOCK *b; int total = 0; memset(&e, 0, sizeof e);
    while (pEnum(db, &e, &b) && total < 3000) total++;
    EXPECT_EQ(total, 2000);
    CHECK(pValidate(db));
    CHECK(pDestroy(db));
}

/* ---- Lock / Unlock ---- */
typedef struct { PVOID db; HANDLE got; volatile LONG phase; } lockctx;
static DWORD WINAPI locker(LPVOID p)
{
    lockctx *c = (lockctx *)p;
    InterlockedExchange(&c->phase, 1);
    pLock(c->db);
    InterlockedExchange(&c->phase, 2);
    SetEvent(c->got);
    pUnlock(c->db);
    return 0;
}

TEST(tracedb_lock_unlock)
{
    NEED();
    TDB_HEAD *db = pCreate(16, 0x100000, 0, 8, NULL);
    CHECK(db != NULL);
    if (!db) return;
    lockctx c = { db, CreateEventW(NULL, TRUE, FALSE, NULL), 0 };
    CHECK(c.got != NULL);
    pLock(db);
    pLock(db);                              /* recursive for the owning thread */
    HANDLE th = CreateThread(NULL, 0, locker, &c, 0, NULL);
    CHECK(th != NULL);
    /* the other thread must stay blocked while we hold the lock */
    DWORD w = WaitForSingleObject(c.got, 300);
    EXPECT_EQ(w, WAIT_TIMEOUT);
    EXPECT_EQ(c.phase, 1);
    /* operations by the owner still work (they re-enter the lock) */
    PVOID t[1] = { (PVOID)0x1234 };
    CHECK(pAdd(db, 1, t, NULL));
    pUnlock(db);
    w = WaitForSingleObject(c.got, 300);
    EXPECT_EQ(w, WAIT_TIMEOUT);             /* one level still held */
    pUnlock(db);
    w = WaitForSingleObject(c.got, 5000);
    EXPECT_EQ(w, WAIT_OBJECT_0);
    EXPECT_EQ(c.phase, 2);
    if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
    if (c.got) CloseHandle(c.got);
    CHECK(pDestroy(db));
}

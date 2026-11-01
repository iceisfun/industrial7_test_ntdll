/* Interlocked singly linked lists (SLIST): LIFO order, depth, flush, list push and
   concurrent push/pop. Entries and headers must be 16-byte aligned on x64. */
#include "t.h"

UDECL(void, RtlInitializeSListHead, (PSLIST_HEADER));
UDECL(PSLIST_ENTRY, RtlInterlockedPushEntrySList, (PSLIST_HEADER, PSLIST_ENTRY));
UDECL(PSLIST_ENTRY, RtlInterlockedPopEntrySList, (PSLIST_HEADER));
UDECL(PSLIST_ENTRY, RtlInterlockedFlushSList, (PSLIST_HEADER));
UDECL(USHORT, RtlQueryDepthSList, (PSLIST_HEADER));
UDECL(PSLIST_ENTRY, RtlFirstEntrySList, (const SLIST_HEADER *));
UDECL(PSLIST_ENTRY, RtlInterlockedPushListSList, (PSLIST_HEADER, PSLIST_ENTRY, PSLIST_ENTRY, ULONG));
UDECL(PSLIST_ENTRY, RtlInterlockedPushListSListEx, (PSLIST_HEADER, PSLIST_ENTRY, PSLIST_ENTRY, ULONG));

typedef struct { SLIST_ENTRY link; ULONG value; } SITEM;
typedef struct { _Alignas(16) SLIST_HEADER head; } SHEAD;
typedef struct { _Alignas(16) SITEM it; } SENTRY;
_Static_assert(_Alignof(SLIST_ENTRY) == 16 && sizeof(SLIST_HEADER) == 16, "x64 SLIST layout");

#define SL_REQUIRE() do { REQUIRE(UN(RtlInitializeSListHead)); REQUIRE(UN(RtlInterlockedPushEntrySList)); \
    REQUIRE(UN(RtlInterlockedPopEntrySList)); REQUIRE(UN(RtlQueryDepthSList)); } while (0)

TEST(rtl_slist_empty_head) {
    SL_REQUIRE();
    SHEAD h; memset(&h, 0xcc, sizeof(h));
    UN(RtlInitializeSListHead)(&h.head);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), 0);
    CHECK(UN(RtlInterlockedPopEntrySList)(&h.head) == NULL);
    if (UN(RtlFirstEntrySList)) CHECK(UN(RtlFirstEntrySList)(&h.head) == NULL);
    if (UN(RtlInterlockedFlushSList)) CHECK(UN(RtlInterlockedFlushSList)(&h.head) == NULL);
}

TEST(rtl_slist_push_returns_previous_first) {
    SL_REQUIRE();
    SHEAD h; SENTRY e[3]; PSLIST_ENTRY r;
    UN(RtlInitializeSListHead)(&h.head);
    r = UN(RtlInterlockedPushEntrySList)(&h.head, &e[0].it.link); CHECK(r == NULL);
    r = UN(RtlInterlockedPushEntrySList)(&h.head, &e[1].it.link); CHECK(r == &e[0].it.link);
    r = UN(RtlInterlockedPushEntrySList)(&h.head, &e[2].it.link); CHECK(r == &e[1].it.link);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), 3);
    if (UN(RtlFirstEntrySList)) CHECK(UN(RtlFirstEntrySList)(&h.head) == &e[2].it.link);
    UN(RtlInterlockedPopEntrySList)(&h.head); UN(RtlInterlockedPopEntrySList)(&h.head); UN(RtlInterlockedPopEntrySList)(&h.head);
}

TEST(rtl_slist_pop_is_lifo) {
    SL_REQUIRE();
    SHEAD h; SENTRY e[10]; unsigned i; PSLIST_ENTRY p;
    UN(RtlInitializeSListHead)(&h.head);
    for (i = 0; i < 10; ++i) { e[i].it.value = i; UN(RtlInterlockedPushEntrySList)(&h.head, &e[i].it.link); }
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), 10);
    for (i = 10; i-- > 0; ) {
        p = UN(RtlInterlockedPopEntrySList)(&h.head);
        CHECK(p == &e[i].it.link);
        EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), i);
    }
    CHECK(UN(RtlInterlockedPopEntrySList)(&h.head) == NULL);
}

TEST(rtl_slist_depth_tracks_push_and_pop) {
    SL_REQUIRE();
    SHEAD h; SENTRY e[5]; unsigned i;
    UN(RtlInitializeSListHead)(&h.head);
    for (i = 0; i < 5; ++i) { UN(RtlInterlockedPushEntrySList)(&h.head, &e[i].it.link); EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), i + 1); }
    for (i = 5; i > 0; --i) { UN(RtlInterlockedPopEntrySList)(&h.head); EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), i - 1); }
}

TEST(rtl_slist_flush_returns_chain_newest_first) {
    SL_REQUIRE(); REQUIRE(UN(RtlInterlockedFlushSList));
    SHEAD h; SENTRY e[6]; unsigned i; PSLIST_ENTRY p;
    UN(RtlInitializeSListHead)(&h.head);
    for (i = 0; i < 6; ++i) UN(RtlInterlockedPushEntrySList)(&h.head, &e[i].it.link);
    p = UN(RtlInterlockedFlushSList)(&h.head);
    for (i = 6; i-- > 0; ) { CHECK(p == &e[i].it.link); if (!p) break; p = p->Next; }
    CHECK(p == NULL);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), 0);
    CHECK(UN(RtlInterlockedPopEntrySList)(&h.head) == NULL);
    /* The list is reusable after a flush. */
    CHECK(UN(RtlInterlockedPushEntrySList)(&h.head, &e[0].it.link) == NULL);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), 1);
    UN(RtlInterlockedPopEntrySList)(&h.head);
}

TEST(rtl_slist_push_list_splices_chain) {
    SL_REQUIRE(); REQUIRE(UN(RtlInterlockedPushListSListEx));
    SHEAD h; SENTRY e[6]; unsigned i; PSLIST_ENTRY p, prev;
    UN(RtlInitializeSListHead)(&h.head);
    UN(RtlInterlockedPushEntrySList)(&h.head, &e[0].it.link);
    /* Chain e[3] -> e[2] -> e[1]; first is e[3], last is e[1]. */
    e[3].it.link.Next = &e[2].it.link; e[2].it.link.Next = &e[1].it.link; e[1].it.link.Next = NULL;
    prev = UN(RtlInterlockedPushListSListEx)(&h.head, &e[3].it.link, &e[1].it.link, 3);
    CHECK(prev == &e[0].it.link);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), 4);
    for (i = 3; i >= 1; --i) { p = UN(RtlInterlockedPopEntrySList)(&h.head); CHECK(p == &e[i].it.link); }
    p = UN(RtlInterlockedPopEntrySList)(&h.head); CHECK(p == &e[0].it.link);
    CHECK(UN(RtlInterlockedPopEntrySList)(&h.head) == NULL);
}

TEST(rtl_slist_push_list_into_empty_head) {
    SL_REQUIRE(); REQUIRE(UN(RtlInterlockedPushListSListEx));
    SHEAD h; SENTRY e[2];
    UN(RtlInitializeSListHead)(&h.head);
    e[1].it.link.Next = &e[0].it.link; e[0].it.link.Next = NULL;
    CHECK(UN(RtlInterlockedPushListSListEx)(&h.head, &e[1].it.link, &e[0].it.link, 2) == NULL);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), 2);
    CHECK(UN(RtlInterlockedPopEntrySList)(&h.head) == &e[1].it.link);
    CHECK(UN(RtlInterlockedPopEntrySList)(&h.head) == &e[0].it.link);
}

TEST(rtl_slist_push_list_legacy_entry_point) {
    SL_REQUIRE(); REQUIRE(UN(RtlInterlockedPushListSList));
    SHEAD h; SENTRY e[2];
    UN(RtlInitializeSListHead)(&h.head);
    e[1].it.link.Next = &e[0].it.link; e[0].it.link.Next = NULL;
    CHECK(UN(RtlInterlockedPushListSList)(&h.head, &e[1].it.link, &e[0].it.link, 2) == NULL);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), 2);
    UN(RtlInterlockedPopEntrySList)(&h.head); UN(RtlInterlockedPopEntrySList)(&h.head);
}

TEST(rtl_slist_reinitialize_discards_contents) {
    SL_REQUIRE();
    SHEAD h; SENTRY e[3]; unsigned i;
    UN(RtlInitializeSListHead)(&h.head);
    for (i = 0; i < 3; ++i) UN(RtlInterlockedPushEntrySList)(&h.head, &e[i].it.link);
    UN(RtlInitializeSListHead)(&h.head);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), 0);
    CHECK(UN(RtlInterlockedPopEntrySList)(&h.head) == NULL);
}

TEST(rtl_slist_many_entries_depth) {
    SL_REQUIRE();
    enum { N = 1000 };
    SHEAD h; SENTRY *e = (SENTRY *)VirtualAlloc(NULL, N * sizeof(SENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    unsigned i; CHECK(e != NULL); if (!e) return;
    UN(RtlInitializeSListHead)(&h.head);
    for (i = 0; i < N; ++i) UN(RtlInterlockedPushEntrySList)(&h.head, &e[i].it.link);
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), N);
    for (i = N; i-- > 0; ) if (UN(RtlInterlockedPopEntrySList)(&h.head) != &e[i].it.link) { CHECK(0); break; }
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h.head), 0);
    VirtualFree(e, 0, MEM_RELEASE);
}

/* ---- concurrency: each thread moves its own entries through a shared list ---- */
enum { SL_THREADS = 4, SL_PER = 2000 };
typedef struct { SHEAD *head; SENTRY *entries; volatile LONG moved; } SLWORK;
static DWORD WINAPI sl_worker(void *arg)
{
    SLWORK *w = arg; unsigned i, got = 0;
    for (i = 0; i < SL_PER; ++i) UN(RtlInterlockedPushEntrySList)(&w->head->head, &w->entries[i].it.link);
    while (got < SL_PER) {
        PSLIST_ENTRY p = UN(RtlInterlockedPopEntrySList)(&w->head->head);
        if (p) ++got;
    }
    w->moved = (LONG)got;
    return 0;
}

TEST(rtl_slist_concurrent_push_pop_conserves_entries) {
    SL_REQUIRE();
    SHEAD *h = (SHEAD *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SENTRY *pool = (SENTRY *)VirtualAlloc(NULL, (size_t)SL_THREADS * SL_PER * sizeof(SENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SLWORK w[SL_THREADS]; HANDLE th[SL_THREADS]; unsigned i; DWORD r;
    CHECK(h && pool); if (!h || !pool) goto out;
    UN(RtlInitializeSListHead)(&h->head);
    for (i = 0; i < SL_THREADS; ++i) {
        w[i].head = h; w[i].entries = pool + (size_t)i * SL_PER; w[i].moved = 0;
        th[i] = CreateThread(NULL, 0, sl_worker, &w[i], 0, NULL);
        CHECK(th[i] != NULL);
    }
    for (i = 0; i < SL_THREADS; ++i) if (th[i]) {
        r = WaitForSingleObject(th[i], 60000);
        CHECKF(r == WAIT_OBJECT_0, "worker %u did not finish", i);
        if (r == WAIT_OBJECT_0) { EXPECT_EQ(w[i].moved, SL_PER); CloseHandle(th[i]); }
    }
    EXPECT_EQ(UN(RtlQueryDepthSList)(&h->head), 0);
    CHECK(UN(RtlInterlockedPopEntrySList)(&h->head) == NULL);
out:
    if (h) VirtualFree(h, 0, MEM_RELEASE);
    if (pool) VirtualFree(pool, 0, MEM_RELEASE);
}

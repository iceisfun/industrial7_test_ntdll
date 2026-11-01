#include "t.h"

UDECL(void *, RtlCreateHeap, (ULONG, void *, SIZE_T, SIZE_T, void *, void *));
UDECL(void *, RtlDestroyHeap, (void *));
UDECL(void *, RtlAllocateHeap, (void *, ULONG, SIZE_T));
UDECL(void *, RtlReAllocateHeap, (void *, ULONG, void *, SIZE_T));
UDECL(BOOLEAN, RtlFreeHeap, (void *, ULONG, void *));
UDECL(SIZE_T, RtlSizeHeap, (void *, ULONG, const void *));
UDECL(BOOLEAN, RtlValidateHeap, (void *, ULONG, const void *));
UDECL(ULONG, RtlGetProcessHeaps, (ULONG, void **));
UDECL(NTSTATUS, RtlWalkHeap, (void *, void *));

/* Each helper resolves cleanup before acquiring any resource. */
#define HEAP_REQUIRE() do { REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); \
    REQUIRE(UN(RtlAllocateHeap)); REQUIRE(UN(RtlFreeHeap)); } while (0)

static void allocation_case(SIZE_T n, ULONG flags)
{
    void *h; BYTE *p; SIZE_T i; int ok = 1;
    HEAP_REQUIRE(); REQUIRE(UN(RtlSizeHeap)); REQUIRE(UN(RtlValidateHeap));
    h = UN(RtlCreateHeap)(HEAP_GROWABLE,NULL,0,0,NULL,NULL);
    CHECK(h != NULL); if (!h) return;
    p = UN(RtlAllocateHeap)(h,flags,n);
    CHECK(p != NULL);
    if (p) {
        EXPECT_EQ((ULONG_PTR)p % MEMORY_ALLOCATION_ALIGNMENT,0);
        EXPECT_EQ(UN(RtlSizeHeap)(h,0,p),n);
        CHECK(UN(RtlValidateHeap)(h,0,p));
        if (flags & HEAP_ZERO_MEMORY) {
            for (i = 0; i < n; ++i) if (p[i]) ok = 0;
            CHECK(ok);
        }
        for (i = 0; i < n; ++i) p[i] = (BYTE)(i * 17 + 3);
        for (i = 0; i < n; ++i) if (p[i] != (BYTE)(i * 17 + 3)) ok = 0;
        CHECK(ok);
        CHECK(UN(RtlFreeHeap)(h,0,p));
    }
    CHECK(UN(RtlValidateHeap)(h,0,NULL));
    EXPECT_EQ(UN(RtlDestroyHeap)(h),NULL);
}
#define ALLOC(name,n,f) TEST(rtl_heap_alloc_##name) { allocation_case(n,f); }
ALLOC(zero_size,0,0)
ALLOC(one,1,0)
ALLOC(fifteen,15,0)
ALLOC(sixteen,16,0)
ALLOC(seventeen,17,0)
ALLOC(page_minus_one,4095,0)
ALLOC(page,4096,0)
ALLOC(page_plus_one,4097,0)
ALLOC(large,262144,0)
ALLOC(zero_one,1,HEAP_ZERO_MEMORY)
ALLOC(zero_seventeen,17,HEAP_ZERO_MEMORY)
ALLOC(zero_page,4096,HEAP_ZERO_MEMORY)
ALLOC(zero_large,262144,HEAP_ZERO_MEMORY)
ALLOC(no_serialize,63,HEAP_NO_SERIALIZE)
ALLOC(no_serialize_zero,127,HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY)

static void reallocation_case(SIZE_T before, SIZE_T after, ULONG flags)
{
    void *h; BYTE *p, *q; SIZE_T i; int ok = 1;
    HEAP_REQUIRE(); REQUIRE(UN(RtlReAllocateHeap)); REQUIRE(UN(RtlSizeHeap));
    h = UN(RtlCreateHeap)(HEAP_GROWABLE,NULL,0,0,NULL,NULL);
    CHECK(h != NULL); if (!h) return;
    p = UN(RtlAllocateHeap)(h,0,before);
    CHECK(p != NULL);
    if (p) {
        for (i = 0; i < before; ++i) p[i] = (BYTE)(i * 29 + 1);
        q = UN(RtlReAllocateHeap)(h,flags,p,after);
        /* In-place growth may fail; its failure must leave p intact. */
        if (!(flags & HEAP_REALLOC_IN_PLACE_ONLY)) CHECK(q != NULL);
        if (q) {
            if (flags & HEAP_REALLOC_IN_PLACE_ONLY) EXPECT_EQ(q,p);
            EXPECT_EQ(UN(RtlSizeHeap)(h,0,q),after);
            for (i = 0; i < before && i < after; ++i)
                if (q[i] != (BYTE)(i * 29 + 1)) ok = 0;
            CHECK(ok);
            if (flags & HEAP_ZERO_MEMORY) {
                for (i = before; i < after; ++i) if (q[i]) ok = 0;
                CHECK(ok);
            }
            p = q;
        } else {
            EXPECT_EQ(UN(RtlSizeHeap)(h,0,p),before);
            for (i = 0; i < before; ++i) if (p[i] != (BYTE)(i * 29 + 1)) ok = 0;
            CHECK(ok);
            t_note("in-place resize %llu -> %llu unavailable",(unsigned long long)before,(unsigned long long)after);
        }
        CHECK(UN(RtlFreeHeap)(h,0,p));
    }
    EXPECT_EQ(UN(RtlDestroyHeap)(h),NULL);
}
#define REALLOC(name,b,a,f) TEST(rtl_heap_realloc_##name) { reallocation_case(b,a,f); }
REALLOC(same,63,63,0)
REALLOC(grow_small,1,127,0)
REALLOC(grow_page,127,4097,0)
REALLOC(grow_large,4096,262144,0)
REALLOC(shrink_small,127,1,0)
REALLOC(shrink_page,8192,4095,0)
REALLOC(shrink_large,262144,17,0)
REALLOC(zero_grow_small,17,129,HEAP_ZERO_MEMORY)
REALLOC(zero_grow_page,63,8193,HEAP_ZERO_MEMORY)
REALLOC(zero_shrink,129,17,HEAP_ZERO_MEMORY)
REALLOC(inplace_same,63,63,HEAP_REALLOC_IN_PLACE_ONLY)
REALLOC(inplace_shrink,8192,17,HEAP_REALLOC_IN_PLACE_ONLY)
REALLOC(inplace_grow,17,65536,HEAP_REALLOC_IN_PLACE_ONLY)
REALLOC(inplace_zero_grow,17,4096,HEAP_REALLOC_IN_PLACE_ONLY | HEAP_ZERO_MEMORY)
REALLOC(no_serialize,63,1024,HEAP_NO_SERIALIZE)

static void create_case(SIZE_T reserve, SIZE_T commit, ULONG flags)
{
    void *h; BYTE *p;
    HEAP_REQUIRE(); REQUIRE(UN(RtlValidateHeap));
    h = UN(RtlCreateHeap)(HEAP_GROWABLE | flags,NULL,reserve,commit,NULL,NULL);
    CHECK(h != NULL); if (!h) return;
    CHECK(UN(RtlValidateHeap)(h,0,NULL));
    p = UN(RtlAllocateHeap)(h,HEAP_ZERO_MEMORY,32);
    CHECK(p != NULL);
    if (p) { EXPECT_EQ(p[0],0); EXPECT_EQ(p[31],0); CHECK(UN(RtlFreeHeap)(h,0,p)); }
    EXPECT_EQ(UN(RtlDestroyHeap)(h),NULL);
}
TEST(rtl_heap_create_defaults) { create_case(0,0,0); }
TEST(rtl_heap_create_reserve) { create_case(65536,0,0); }
TEST(rtl_heap_create_commit) { create_case(0,4096,0); }
TEST(rtl_heap_create_both) { create_case(131072,8192,0); }
TEST(rtl_heap_create_rounding) { create_case(65537,4097,0); }
TEST(rtl_heap_create_no_serialize) { create_case(0,0,HEAP_NO_SERIALIZE); }

TEST(rtl_heap_free_null)
{
    void *h;
    HEAP_REQUIRE();
    h = UN(RtlCreateHeap)(HEAP_GROWABLE,NULL,0,0,NULL,NULL);
    CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(UN(RtlFreeHeap)(h,0,NULL),TRUE);
    EXPECT_EQ(UN(RtlDestroyHeap)(h),NULL);
}

TEST(rtl_heap_process_heaps_query)
{
    REQUIRE(UN(RtlGetProcessHeaps));
    CHECK(UN(RtlGetProcessHeaps)(0,NULL) > 0);
}

TEST(rtl_heap_process_heaps_capacity_zero)
{
    void *slot = (void *)(ULONG_PTR)0x1234;
    REQUIRE(UN(RtlGetProcessHeaps));
    CHECK(UN(RtlGetProcessHeaps)(0,&slot) > 0);
    EXPECT_EQ(slot,(void *)(ULONG_PTR)0x1234);
}

TEST(rtl_heap_process_heaps_contains_private)
{
    void *h, *heaps[1025]; ULONG n, i; int found = 0;
    HEAP_REQUIRE(); REQUIRE(UN(RtlGetProcessHeaps));
    h = UN(RtlCreateHeap)(HEAP_GROWABLE,NULL,0,0,NULL,NULL);
    CHECK(h != NULL); if (!h) return;
    heaps[1024] = (void *)(ULONG_PTR)0x1234;
    n = UN(RtlGetProcessHeaps)(1024,heaps);
    CHECK(n > 0); EXPECT_EQ(heaps[1024],(void *)(ULONG_PTR)0x1234);
    if (n <= 1024) {
        for (i = 0; i < n; ++i) if (heaps[i] == h) found = 1;
        CHECK(found);
    } else t_note("heap inventory exceeds bounded buffer: %lu",n);
    EXPECT_EQ(UN(RtlDestroyHeap)(h),NULL);
}

static void walk_case(int allocated)
{
    void *h, *p = NULL; unsigned i; NTSTATUS status = 0; int found = 0;
    union { ULONGLONG alignment; BYTE bytes[128]; } entry;
    HEAP_REQUIRE(); REQUIRE(UN(RtlWalkHeap));
    h = UN(RtlCreateHeap)(HEAP_GROWABLE,NULL,0,0,NULL,NULL);
    CHECK(h != NULL); if (!h) return;
    if (allocated) {
        p = UN(RtlAllocateHeap)(h,0,137); CHECK(p != NULL);
        if (!p) { UN(RtlDestroyHeap)(h); return; }
    }
    memset(&entry,0,sizeof entry);
    /* Only this thread touches this heap; never mutate it during enumeration. */
    for (i = 0; i < 4096; ++i) {
        void *address; SIZE_T size;
        status = UN(RtlWalkHeap)(h,&entry);
        if (status != 0) break;
        memcpy(&address,entry.bytes,sizeof address);
        memcpy(&size,entry.bytes + sizeof(void *),sizeof size);
        if (p && address == p) { found = 1; EXPECT_EQ(size,137); }
    }
    CHECK(i < 4096);
    EXPECT_EQ((ULONG)status,0x8000001a);
    if (allocated) CHECK(found);
    if (p) CHECK(UN(RtlFreeHeap)(h,0,p));
    EXPECT_EQ(UN(RtlDestroyHeap)(h),NULL);
}
TEST(rtl_heap_walk_empty) { walk_case(0); }
TEST(rtl_heap_walk_live_block) { walk_case(1); }

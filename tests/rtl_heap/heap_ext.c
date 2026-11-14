/* Heap information classes, failure modes, exceptions and block-layout invariants. */
#include "t.h"

UDECL(void *, RtlCreateHeap, (ULONG, void *, SIZE_T, SIZE_T, void *, void *));
UDECL(void *, RtlDestroyHeap, (void *));
UDECL(void *, RtlAllocateHeap, (void *, ULONG, SIZE_T));
UDECL(void *, RtlReAllocateHeap, (void *, ULONG, void *, SIZE_T));
UDECL(BOOLEAN, RtlFreeHeap, (void *, ULONG, void *));
UDECL(SIZE_T, RtlSizeHeap, (void *, ULONG, const void *));
UDECL(BOOLEAN, RtlValidateHeap, (void *, ULONG, const void *));
UDECL(BOOLEAN, RtlValidateProcessHeaps, (void));
UDECL(NTSTATUS, RtlQueryHeapInformation, (void *, int, void *, SIZE_T, SIZE_T *));
UDECL(NTSTATUS, RtlSetHeapInformation, (void *, int, void *, SIZE_T));
UDECL(SIZE_T, RtlCompactHeap, (void *, ULONG));
UDECL(ULONG, RtlGetNtGlobalFlags, (void));
UDECL(void *, RtlProcessHeap, (void));

#define HX_BUF_SMALL ((NTSTATUS)0xc0000023)
#define HX_NO_MEMORY ((NTSTATUS)0xc0000017)

static void *hx_new(ULONG flags)
{
    return UN(RtlCreateHeap) ? UN(RtlCreateHeap)(flags | HEAP_GROWABLE, NULL, 0, 0, NULL, NULL) : NULL;
}

TEST(rtl_heap_ext_query_compat_information) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlQueryHeapInformation));
    void *h = hx_new(0); ULONG v = 0xdeadbeef; SIZE_T ret = 0xdead; NTSTATUS s;
    CHECK(h != NULL); if (!h) return;
    s = UN(RtlQueryHeapInformation)(h, 0 /* HeapCompatibilityInformation */, &v, sizeof(v), &ret);
    EXPECT_EQ(s, 0);
    if (!s) { EXPECT_EQ(ret, 4); CHECK(v == 0 || v == 1 || v == 2); t_note("compat info of new heap = %lu", v); }
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_query_buffer_protocol) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlQueryHeapInformation));
    void *h = hx_new(0); ULONG v[2]; SIZE_T ret = 0; NTSTATUS s;
    CHECK(h != NULL); if (!h) return;
    memset(v, 0x5a, sizeof(v));
    s = UN(RtlQueryHeapInformation)(h, 0, v, 2, &ret);
    EXPECT_EQ(s, HX_BUF_SMALL); EXPECT_EQ(ret, 4);
    EXPECT_EQ(v[0], 0x5a5a5a5a);
    ret = 0; s = UN(RtlQueryHeapInformation)(h, 0, NULL, 0, &ret);
    EXPECT_EQ(s, HX_BUF_SMALL); EXPECT_EQ(ret, 4);
    /* Return-length pointer is optional once the buffer is large enough. */
    s = UN(RtlQueryHeapInformation)(h, 0, v, sizeof(ULONG), NULL);
    EXPECT_EQ(s, 0);
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_query_unknown_class) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlQueryHeapInformation));
    void *h = hx_new(0); ULONG v[16]; SIZE_T ret = 0; NTSTATUS s;
    CHECK(h != NULL); if (!h) return;
    s = UN(RtlQueryHeapInformation)(h, 0x7777, v, sizeof(v), &ret);
    CHECK(s != 0 && (s & 0xc0000000) == 0xc0000000);
    t_note("unknown heap information class status = 0x%08lx", (ULONG)s);
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_enable_low_fragmentation) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlQueryHeapInformation));
    REQUIRE(UN(RtlSetHeapInformation)); REQUIRE(UN(RtlAllocateHeap)); REQUIRE(UN(RtlFreeHeap));
    void *h = hx_new(0); ULONG mode = 2, v = 0; SIZE_T ret = 0; NTSTATUS s; void *p;
    CHECK(h != NULL); if (!h) return;
    s = UN(RtlSetHeapInformation)(h, 0, &mode, sizeof(mode));
    t_note("enable LFH status = 0x%08lx", (ULONG)s);
    if (s == 0) {
        s = UN(RtlQueryHeapInformation)(h, 0, &v, sizeof(v), &ret);
        EXPECT_EQ(s, 0); EXPECT_EQ(v, 2);
        p = UN(RtlAllocateHeap)(h, 0, 48); CHECK(p != NULL);
        if (p) CHECK(UN(RtlFreeHeap)(h, 0, p));
    }
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_set_information_invalid) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlSetHeapInformation));
    void *h = hx_new(0); ULONG v = 1; NTSTATUS s;
    CHECK(h != NULL); if (!h) return;
    s = UN(RtlSetHeapInformation)(h, 0x7777, &v, sizeof(v));
    EXPECT_EQ(s, 0);                                               /* unknown classes are ignored */
    /* HeapCompatibilityInformation needs a ULONG. */
    s = UN(RtlSetHeapInformation)(h, 0, &v, 1);
    EXPECT_EQ(s, (NTSTATUS)0xC0000023);
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_validate_process_heaps) {
    REQUIRE(UN(RtlValidateProcessHeaps)); REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap));
    REQUIRE(UN(RtlAllocateHeap)); REQUIRE(UN(RtlFreeHeap));
    void *h = hx_new(0), *p; CHECK(h != NULL); if (!h) return;
    p = UN(RtlAllocateHeap)(h, 0, 100); CHECK(p != NULL);
    CHECK(UN(RtlValidateProcessHeaps)());
    if (p) UN(RtlFreeHeap)(h, 0, p);
    CHECK(UN(RtlValidateProcessHeaps)());
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_compact_heap) {
    REQUIRE(UN(RtlCompactHeap)); REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap));
    REQUIRE(UN(RtlAllocateHeap)); REQUIRE(UN(RtlFreeHeap));
    void *h = hx_new(0), *p[8]; unsigned i; SIZE_T r; CHECK(h != NULL); if (!h) return;
    for (i = 0; i < 8; ++i) { p[i] = UN(RtlAllocateHeap)(h, 0, 1000 + i); CHECK(p[i] != NULL); }
    for (i = 0; i < 8; i += 2) if (p[i]) UN(RtlFreeHeap)(h, 0, p[i]);
    r = UN(RtlCompactHeap)(h, 0);
    t_note("RtlCompactHeap returned %llu", (unsigned long long)r);
    CHECK(UN(RtlValidateHeap)(h, 0, NULL));
    for (i = 1; i < 8; i += 2) if (p[i]) { EXPECT_EQ(UN(RtlSizeHeap)(h, 0, p[i]), 1000 + i); UN(RtlFreeHeap)(h, 0, p[i]); }
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_global_flags_stable) {
    REQUIRE(UN(RtlGetNtGlobalFlags));
    ULONG a = UN(RtlGetNtGlobalFlags)(), b = UN(RtlGetNtGlobalFlags)();
    EXPECT_EQ(a, b);
    t_note("NtGlobalFlag = 0x%08lx", a);
}

TEST(rtl_heap_ext_huge_allocation_fails) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlAllocateHeap));
    void *h = hx_new(0); CHECK(h != NULL); if (!h) return;
    SET_ERR(0);
    EXPECT_EQ(UN(RtlAllocateHeap)(h, 0, (SIZE_T)1 << 62), 0);
    EXPECT_EQ(UN(RtlAllocateHeap)(h, 0, (SIZE_T)-1), 0);
    EXPECT_EQ(UN(RtlAllocateHeap)(h, 0, (SIZE_T)-64), 0);
    CHECK(UN(RtlValidateHeap)(h, 0, NULL));
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_fixed_heap_exhaustion) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlAllocateHeap)); REQUIRE(UN(RtlFreeHeap));
    /* A non-growable heap with a fixed reserve cannot satisfy an allocation larger than the reserve. */
    void *h = UN(RtlCreateHeap)(HEAP_NO_SERIALIZE, NULL, 0x10000, 0x1000, NULL, NULL);
    void *p, *q; CHECK(h != NULL); if (!h) return;
    p = UN(RtlAllocateHeap)(h, 0, 0x2000); CHECK(p != NULL);
    q = UN(RtlAllocateHeap)(h, 0, 0x20000); EXPECT_EQ(q, 0);
    if (p) CHECK(UN(RtlFreeHeap)(h, 0, p));
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_zero_size_allocation) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlAllocateHeap));
    REQUIRE(UN(RtlFreeHeap)); REQUIRE(UN(RtlSizeHeap));
    void *h = hx_new(0), *p; CHECK(h != NULL); if (!h) return;
    p = UN(RtlAllocateHeap)(h, 0, 0); CHECK(p != NULL);
    if (p) { EXPECT_EQ(UN(RtlSizeHeap)(h, 0, p), 0); CHECK(UN(RtlFreeHeap)(h, 0, p)); }
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_blocks_do_not_overlap) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlAllocateHeap));
    REQUIRE(UN(RtlFreeHeap)); REQUIRE(UN(RtlSizeHeap));
    enum { N = 64 };
    void *h = hx_new(0); BYTE *p[N]; unsigned i, j; int bad = 0;
    CHECK(h != NULL); if (!h) return;
    for (i = 0; i < N; ++i) {
        p[i] = UN(RtlAllocateHeap)(h, 0, 1 + i * 13);
        CHECK(p[i] != NULL); if (!p[i]) goto out;
        memset(p[i], (int)(i + 1), 1 + i * 13);
    }
    for (i = 0; i < N; ++i) for (j = 0; j < 1 + i * 13; ++j) if (p[i][j] != (BYTE)(i + 1)) bad++;
    CHECK(bad == 0);
    for (i = 0; i < N; ++i) {
        EXPECT_EQ((ULONG_PTR)p[i] % 16, 0);
        EXPECT_EQ(UN(RtlSizeHeap)(h, 0, p[i]), 1 + i * 13);
    }
    CHECK(UN(RtlValidateHeap)(h, 0, NULL));
out:
    for (i = 0; i < N; ++i) if (p[i]) UN(RtlFreeHeap)(h, 0, p[i]);
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_free_then_reuse_same_size) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlAllocateHeap)); REQUIRE(UN(RtlFreeHeap));
    void *h = hx_new(HEAP_NO_SERIALIZE), *p, *q; CHECK(h != NULL); if (!h) return;
    p = UN(RtlAllocateHeap)(h, 0, 4096); CHECK(p != NULL);
    if (p) CHECK(UN(RtlFreeHeap)(h, 0, p));
    q = UN(RtlAllocateHeap)(h, 0, 4096); CHECK(q != NULL);
    if (q) CHECK(UN(RtlFreeHeap)(h, 0, q));
    CHECK(UN(RtlValidateHeap)(h, 0, NULL));
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_realloc_failure_keeps_block) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlAllocateHeap));
    REQUIRE(UN(RtlReAllocateHeap)); REQUIRE(UN(RtlFreeHeap)); REQUIRE(UN(RtlSizeHeap));
    void *h = hx_new(0); BYTE *p; unsigned i; int bad = 0; CHECK(h != NULL); if (!h) return;
    p = UN(RtlAllocateHeap)(h, 0, 64); CHECK(p != NULL);
    if (p) {
        for (i = 0; i < 64; ++i) p[i] = (BYTE)(i ^ 0x3c);
        EXPECT_EQ(UN(RtlReAllocateHeap)(h, 0, p, (SIZE_T)1 << 62), 0);
        EXPECT_EQ(UN(RtlSizeHeap)(h, 0, p), 64);
        for (i = 0; i < 64; ++i) if (p[i] != (BYTE)(i ^ 0x3c)) bad++;
        CHECK(bad == 0);
        CHECK(UN(RtlFreeHeap)(h, 0, p));
    }
    UN(RtlDestroyHeap)(h);
}

TEST(rtl_heap_ext_realloc_preserves_prefix) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlAllocateHeap));
    REQUIRE(UN(RtlReAllocateHeap)); REQUIRE(UN(RtlFreeHeap)); REQUIRE(UN(RtlSizeHeap));
    static const SIZE_T sizes[] = {1, 15, 16, 17, 100, 1000, 5000, 70000, 3, 70001};
    void *h = hx_new(0); BYTE *p, *q; unsigned i, k; SIZE_T cur, keep; int bad = 0;
    CHECK(h != NULL); if (!h) return;
    cur = sizes[0]; p = UN(RtlAllocateHeap)(h, 0, cur); CHECK(p != NULL); if (!p) goto out;
    p[0] = 0x42;
    for (i = 1; i < sizeof(sizes)/sizeof(*sizes); ++i) {
        keep = sizes[i] < cur ? sizes[i] : cur;
        for (k = 0; k < keep; ++k) p[k] = (BYTE)(k * 7 + 1);
        q = UN(RtlReAllocateHeap)(h, 0, p, sizes[i]);
        CHECK(q != NULL); if (!q) goto out;
        p = q; cur = sizes[i];
        EXPECT_EQ(UN(RtlSizeHeap)(h, 0, p), cur);
        for (k = 0; k < keep; ++k) if (p[k] != (BYTE)(k * 7 + 1)) bad++;
    }
    CHECK(bad == 0);
out:
    if (p) UN(RtlFreeHeap)(h, 0, p);
    UN(RtlDestroyHeap)(h);
}

/* HEAP_GENERATE_EXCEPTIONS: failure raises STATUS_NO_MEMORY instead of returning NULL.
   Run in a child so an unexpected fault cannot take the whole area down. */
static LONG WINAPI hx_filter(EXCEPTION_POINTERS *ep)
{
    ExitProcess(ep->ExceptionRecord->ExceptionCode == (DWORD)HX_NO_MEMORY ? 0x31 : 0x32);
    return EXCEPTION_EXECUTE_HANDLER;
}
CHILD(rtl_heap_ext_exception_child) {
    void *h; void *p;
    if (!UN(RtlCreateHeap) || !UN(RtlAllocateHeap)) return 0x30;
    h = UN(RtlCreateHeap)(HEAP_GROWABLE | HEAP_GENERATE_EXCEPTIONS, NULL, 0, 0, NULL, NULL);
    if (!h) return 0x33;
    SetUnhandledExceptionFilter(hx_filter);
    p = UN(RtlAllocateHeap)(h, 0, (SIZE_T)1 << 62);
    return p ? 0x34 : 0x35;
}
CHILD(rtl_heap_ext_exception_flag_child) {
    void *h; void *p;
    if (!UN(RtlCreateHeap) || !UN(RtlAllocateHeap)) return 0x30;
    h = UN(RtlCreateHeap)(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    if (!h) return 0x33;
    SetUnhandledExceptionFilter(hx_filter);
    p = UN(RtlAllocateHeap)(h, HEAP_GENERATE_EXCEPTIONS, (SIZE_T)1 << 62);
    return p ? 0x34 : 0x35;
}
TEST(rtl_heap_ext_generate_exceptions_on_heap) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlAllocateHeap));
    EXPECT_EQ(t_run_child("rtl_heap_ext_exception_child", NULL, 30000), 0x31);
}
TEST(rtl_heap_ext_generate_exceptions_on_call) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlAllocateHeap));
    EXPECT_EQ(t_run_child("rtl_heap_ext_exception_flag_child", NULL, 30000), 0x31);
}

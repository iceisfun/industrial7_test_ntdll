/* RtlQuery* and RtlSetAllBitsEx: shared-data readers, time, S-list, bitmap, thread/process mode queries. */
#include "t.h"

UDECL(BOOLEAN, RtlQueryPerformanceCounter, (PLARGE_INTEGER));
UDECL(BOOLEAN, RtlQueryPerformanceFrequency, (PLARGE_INTEGER));
UDECL(BOOLEAN, RtlQueryUnbiasedInterruptTime, (PULONGLONG));
UDECL(USHORT, RtlQueryDepthSList, (PSLIST_HEADER));
UDECL(NTSTATUS, RtlQueryElevationFlags, (PULONG));
UDECL(ULONG, RtlQueryValidationRunlevel, (PVOID));
UDECL(ULONGLONG, RtlQueryFeatureConfigurationChangeStamp, (void));
UDECL(NTSTATUS, RtlQueryThreadProfiling, (HANDLE, PBOOLEAN));
UDECL(CHAR, RtlQueryProcessPlaceholderCompatibilityMode, (void));
UDECL(CHAR, RtlQueryThreadPlaceholderCompatibilityMode, (void));
UDECL(NTSTATUS, RtlQueryTimeZoneInformation, (PVOID));
UDECL(NTSTATUS, RtlQueryDynamicTimeZoneInformation, (PVOID));
UDECL(VOID, RtlSetAllBitsEx, (PVOID));
UDECL(PSLIST_ENTRY, RtlInterlockedPushEntrySList, (PSLIST_HEADER, PSLIST_ENTRY));
UDECL(PSLIST_ENTRY, RtlInterlockedPopEntrySList, (PSLIST_HEADER));
UDECL(VOID, RtlInitializeSListHead, (PSLIST_HEADER));
UDECL(HRESULT, RtlQueryInterfaceMemoryStream, (PVOID, PVOID, PVOID, PVOID));

#define KUSER ((volatile BYTE *)0x7ffe0000)
#define ST_INVALID_HANDLE ((NTSTATUS)0xC0000008)

TEST(qs_perf_frequency) {
    REQUIRE(UN(RtlQueryPerformanceFrequency));
    LARGE_INTEGER f = {{0}}, k = {{0}};
    BOOLEAN r = UN(RtlQueryPerformanceFrequency)(&f);
    EXPECT_EQ(r, 1);
    EXPECT_NE(f.QuadPart, 0);
    /* the frequency is published in the shared data page (QpcFrequency) */
    EXPECT_EQ((ULONGLONG)f.QuadPart, *(volatile ULONGLONG *)(KUSER + 0x300));
    CHECK(QueryPerformanceFrequency(&k));
    EXPECT_EQ(f.QuadPart, k.QuadPart);
    /* stable across calls */
    LARGE_INTEGER f2 = {{0}}; UN(RtlQueryPerformanceFrequency)(&f2);
    EXPECT_EQ(f2.QuadPart, f.QuadPart);
}

TEST(qs_perf_counter) {
    REQUIRE(UN(RtlQueryPerformanceCounter)); REQUIRE(UN(RtlQueryPerformanceFrequency));
    LARGE_INTEGER a = {{0}}, b = {{0}}, k1 = {{0}}, k2 = {{0}}, f = {{0}};
    UN(RtlQueryPerformanceFrequency)(&f);
    QueryPerformanceCounter(&k1);
    EXPECT_EQ(UN(RtlQueryPerformanceCounter)(&a), 1);
    Sleep(50);
    EXPECT_EQ(UN(RtlQueryPerformanceCounter)(&b), 1);
    QueryPerformanceCounter(&k2);
    CHECK(a.QuadPart > 0);
    CHECK(b.QuadPart >= a.QuadPart);
    /* same time base as kernel32 QueryPerformanceCounter */
    CHECK(a.QuadPart >= k1.QuadPart - f.QuadPart / 100 && a.QuadPart <= k2.QuadPart);
    CHECK(b.QuadPart <= k2.QuadPart + f.QuadPart / 100);
    LONGLONG dt_ms = (b.QuadPart - a.QuadPart) * 1000 / f.QuadPart;
    CHECKF(dt_ms >= 40 && dt_ms < 2000, "Sleep(50) measured %lld ms", dt_ms);
}

TEST(qs_unbiased_interrupt_time) {
    REQUIRE(UN(RtlQueryUnbiasedInterruptTime));
    ULONGLONG a = 0, b = 0, k = 0;
    SET_ERR(0);
    EXPECT_EQ(UN(RtlQueryUnbiasedInterruptTime)(&a), 1);
    CHECK(a > 0);
    Sleep(60);
    EXPECT_EQ(UN(RtlQueryUnbiasedInterruptTime)(&b), 1);
    CHECK(b > a);
    CHECKF(b - a >= 400000 && b - a < 20000000, "delta %llu (100ns)", b - a);
    typedef BOOL (WINAPI *QUIT)(PULONGLONG);
    QUIT q = (QUIT)t_proc_in("kernel32.dll", "QueryUnbiasedInterruptTime");
    if (q) { CHECK(q(&k)); CHECK(k >= b && k - b < 10000000); }
    /* NULL: returns FALSE and sets last error ERROR_INVALID_PARAMETER */
    SET_ERR(0);
    EXPECT_EQ(UN(RtlQueryUnbiasedInterruptTime)(NULL), 0);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(qs_depth_slist) {
    REQUIRE(UN(RtlQueryDepthSList)); REQUIRE(UN(RtlInitializeSListHead));
    REQUIRE(UN(RtlInterlockedPushEntrySList)); REQUIRE(UN(RtlInterlockedPopEntrySList));
    SLIST_HEADER *h = (SLIST_HEADER *)_aligned_malloc(sizeof(SLIST_HEADER), 16);
    SLIST_ENTRY *e = (SLIST_ENTRY *)_aligned_malloc(sizeof(SLIST_ENTRY) * 3, 16);
    if (!h || !e) { t_skip("alloc failed"); return; }
    UN(RtlInitializeSListHead)(h);
    EXPECT_EQ(UN(RtlQueryDepthSList)(h), 0);
    for (int i = 0; i < 3; i++) {
        UN(RtlInterlockedPushEntrySList)(h, (PSLIST_ENTRY)((char *)e + i * sizeof(SLIST_ENTRY)));
        EXPECT_EQ(UN(RtlQueryDepthSList)(h), i + 1);
    }
    for (int i = 3; i > 0; i--) {
        CHECK(UN(RtlInterlockedPopEntrySList)(h) != NULL);
        EXPECT_EQ(UN(RtlQueryDepthSList)(h), i - 1);
    }
    CHECK(UN(RtlInterlockedPopEntrySList)(h) == NULL);
    EXPECT_EQ(UN(RtlQueryDepthSList)(h), 0);
    /* agrees with the kernel32 forwarder */
    typedef USHORT (WINAPI *QDS)(PSLIST_HEADER);
    QDS k = (QDS)t_proc_in("kernel32.dll", "QueryDepthSList");
    if (k) { UN(RtlInterlockedPushEntrySList)(h, e); EXPECT_EQ(k(h), 1); UN(RtlInterlockedPopEntrySList)(h); }
    _aligned_free(h); _aligned_free(e);
}

TEST(qs_elevation_flags) {
    REQUIRE(UN(RtlQueryElevationFlags));
    ULONG f = 0xdeadbeef;
    EXPECT_EQ(UN(RtlQueryElevationFlags)(&f), 0);
    /* shared-data SharedDataFlags (0x2f0): bit1 ElevationEnabled, bit2 VirtEnabled, bit3 InstallerDetectEnabled */
    ULONG sd = *(volatile ULONG *)(KUSER + 0x2f0);
    ULONG want = ((sd & 2) ? 1 : 0) | ((sd & 4) ? 2 : 0) | ((sd & 8) ? 4 : 0);
    EXPECT_EQ(f, want);
    CHECK((f & ~7UL) == 0);
    /* output replaced wholesale on repeat */
    ULONG g = 0xffffffff; UN(RtlQueryElevationFlags)(&g); EXPECT_EQ(g, f);
}

TEST(qs_validation_runlevel) {
    REQUIRE(UN(RtlQueryValidationRunlevel));
    ULONG sd = *(volatile ULONG *)(KUSER + 0x258);
    /* with no key argument the runlevel is exactly the shared-data value */
    EXPECT_EQ(UN(RtlQueryValidationRunlevel)(NULL), sd);
    EXPECT_EQ(UN(RtlQueryValidationRunlevel)(NULL), sd);
}

TEST(qs_feature_change_stamp) {
    REQUIRE(UN(RtlQueryFeatureConfigurationChangeStamp));
    ULONGLONG a = UN(RtlQueryFeatureConfigurationChangeStamp)();
    EXPECT_EQ(a, *(volatile ULONGLONG *)(KUSER + 0x710));
    ULONGLONG b = UN(RtlQueryFeatureConfigurationChangeStamp)();
    CHECK(b >= a);
}

TEST(qs_thread_profiling) {
    REQUIRE(UN(RtlQueryThreadProfiling));
    BOOLEAN en = 0x7f;
    NTSTATUS s = UN(RtlQueryThreadProfiling)(GetCurrentThread(), &en);
    t_note("RtlQueryThreadProfiling(current) = 0x%08lx enabled=%d", (unsigned long)s, en);
    EXPECT_EQ(s, 0);
    if (s == 0) EXPECT_EQ(en, 0);
    en = 0x7f;
    s = UN(RtlQueryThreadProfiling)((HANDLE)(ULONG_PTR)0x7ffffff0, &en);
    EXPECT_EQ(s, ST_INVALID_HANDLE);
}

TEST(qs_placeholder_modes) {
    REQUIRE(UN(RtlQueryProcessPlaceholderCompatibilityMode)); REQUIRE(UN(RtlQueryThreadPlaceholderCompatibilityMode));
    CHAR p = UN(RtlQueryProcessPlaceholderCompatibilityMode)();
    CHAR t = UN(RtlQueryThreadPlaceholderCompatibilityMode)();
    BYTE *teb = (BYTE *)NtCurrentTeb();
    BYTE *peb = *(BYTE **)(teb + 0x60);
    EXPECT_EQ((BYTE)p, peb[0x7b0]);
    EXPECT_EQ((BYTE)t, teb[0x280]);
    /* an ordinary process and thread use the application default mode */
    EXPECT_EQ(p, 0);
    EXPECT_EQ(t, 0);
}

/* The kernel32 wrappers resolve display names through MUI and may fix up the transition dates,
 * so only the numeric biases are compared against kernel32. */
static void tz_bias_compare(const TIME_ZONE_INFORMATION *a, const TIME_ZONE_INFORMATION *b) {
    EXPECT_EQ(a->Bias, b->Bias);
    EXPECT_EQ(a->StandardBias, b->StandardBias);
    EXPECT_EQ(a->DaylightBias, b->DaylightBias);
}
static void tz_compare(const TIME_ZONE_INFORMATION *a, const TIME_ZONE_INFORMATION *b) {
    tz_bias_compare(a, b);
    CHECK(!memcmp(&a->StandardDate, &b->StandardDate, sizeof(SYSTEMTIME)));
    CHECK(!memcmp(&a->DaylightDate, &b->DaylightDate, sizeof(SYSTEMTIME)));
    CHECK(!memcmp(a->StandardName, b->StandardName, sizeof a->StandardName));
    CHECK(!memcmp(a->DaylightName, b->DaylightName, sizeof a->DaylightName));
}

TEST(qs_time_zone_information) {
    REQUIRE(UN(RtlQueryTimeZoneInformation));
    DWORD (WINAPI *gtz)(LPTIME_ZONE_INFORMATION) = (void *)t_proc_in("kernel32.dll", "GetTimeZoneInformation");
    if (!gtz) { t_skip("GetTimeZoneInformation missing"); return; }
    TIME_ZONE_INFORMATION r, k;
    memset(&r, 0xcc, sizeof r); memset(&k, 0, sizeof k);
    NTSTATUS s = UN(RtlQueryTimeZoneInformation)(&r);
    EXPECT_EQ(s, 0);
    DWORD id = gtz(&k);
    CHECK(id != TIME_ZONE_ID_INVALID);
    if (s != 0) return;
    tz_bias_compare(&r, &k);
    /* names are NUL terminated within the buffer */
    CHECK(wcsnlen(r.StandardName, 32) < 32);
    CHECK(wcsnlen(r.DaylightName, 32) < 32);
}

TEST(qs_dynamic_time_zone_information) {
    REQUIRE(UN(RtlQueryDynamicTimeZoneInformation));
    DYNAMIC_TIME_ZONE_INFORMATION r, k;
    memset(&r, 0xcc, sizeof r); memset(&k, 0, sizeof k);
    NTSTATUS s = UN(RtlQueryDynamicTimeZoneInformation)(&r);
    EXPECT_EQ(s, 0);
    typedef DWORD (WINAPI *GDTZ)(PDYNAMIC_TIME_ZONE_INFORMATION);
    GDTZ g = (GDTZ)t_proc_in("kernel32.dll", "GetDynamicTimeZoneInformation");
    if (!g) { t_skip("GetDynamicTimeZoneInformation missing"); return; }
    CHECK(g(&k) != TIME_ZONE_ID_INVALID);
    if (s != 0) return;
    tz_bias_compare((TIME_ZONE_INFORMATION *)&r, (TIME_ZONE_INFORMATION *)&k);
    CHECK(!memcmp(r.TimeZoneKeyName, k.TimeZoneKeyName, sizeof r.TimeZoneKeyName));
    CHECK(wcsnlen(r.TimeZoneKeyName, 128) < 128);
    EXPECT_EQ(r.DynamicDaylightTimeDisabled, k.DynamicDaylightTimeDisabled);
    /* the plain query returns the same leading TIME_ZONE_INFORMATION */
    TIME_ZONE_INFORMATION p; memset(&p, 0, sizeof p);
    if (UN(RtlQueryTimeZoneInformation)(&p) == 0) tz_compare((TIME_ZONE_INFORMATION *)&r, &p);
}

typedef struct { ULONG64 Size; ULONG64 *Buf; } BMEX;

TEST(qs_set_all_bits_ex) {
    REQUIRE(UN(RtlSetAllBitsEx));
    ULONG64 store[8];
    /* 70 bits => ceil(70/32)=3 ULONGs are written, the 4th is untouched (bits past the size in the last ULONG are set) */
    for (int off = 0; off < 2; off++) {   /* off=1: buffer misaligned to 4 mod 8 */
        memset(store, 0, sizeof store);
        ULONG *base = (ULONG *)store + off;
        BMEX bm = { 70, (ULONG64 *)base };
        UN(RtlSetAllBitsEx)(&bm);
        for (int i = 0; i < 3; i++) EXPECT_EQ(base[i], 0xffffffffUL);
        EXPECT_EQ(base[3], 0);
        EXPECT_EQ(bm.Size, 70);
        if (off == 0) EXPECT_EQ(((ULONG *)store)[-0 + 3], 0);
    }
    /* exact multiples of 32 */
    memset(store, 0, sizeof store);
    { BMEX bm = { 64, store }; UN(RtlSetAllBitsEx)(&bm); EXPECT_EQ(store[0], ~0ULL); EXPECT_EQ(store[1], 0); }
    memset(store, 0, sizeof store);
    { BMEX bm = { 32, store }; UN(RtlSetAllBitsEx)(&bm); EXPECT_EQ(((ULONG *)store)[0], 0xffffffffUL); EXPECT_EQ(((ULONG *)store)[1], 0); }
    memset(store, 0, sizeof store);
    { BMEX bm = { 1, store }; UN(RtlSetAllBitsEx)(&bm); EXPECT_EQ(((ULONG *)store)[0], 0xffffffffUL); EXPECT_EQ(((ULONG *)store)[1], 0); }
    /* zero-size bitmap writes nothing */
    memset(store, 0, sizeof store);
    { BMEX bm = { 0, store }; UN(RtlSetAllBitsEx)(&bm); EXPECT_EQ(store[0], 0); }
    /* already-set and mixed content is overwritten */
    memset(store, 0x5a, sizeof store);
    { BMEX bm = { 128, store }; UN(RtlSetAllBitsEx)(&bm); EXPECT_EQ(store[0], ~0ULL); EXPECT_EQ(store[1], ~0ULL); EXPECT_EQ(store[2], 0x5a5a5a5a5a5a5a5aULL); }
}

TEST(qs_interface_memory_stream_stub) {
    REQUIRE(UN(RtlQueryInterfaceMemoryStream));
    EXPECT_EQ(UN(RtlQueryInterfaceMemoryStream)(NULL, NULL, NULL, NULL), (HRESULT)0x80004001);
    char dummy[64] = {0};
    EXPECT_EQ(UN(RtlQueryInterfaceMemoryStream)(dummy, dummy, dummy, dummy), (HRESULT)0x80004001);
    /* all memory-stream entry points share one stub */
    static const char *const same[] = { "RtlCloneMemoryStream", "RtlCommitMemoryStream", "RtlReadMemoryStream",
        "RtlWriteMemoryStream", "RtlSeekMemoryStream", "RtlStatMemoryStream", "RtlRevertMemoryStream" };
    FARPROC q = t_proc("RtlQueryInterfaceMemoryStream");
    for (unsigned i = 0; i < sizeof same / sizeof *same; i++) { FARPROC o = t_proc(same[i]); if (o) CHECKF(o == q, "%s", same[i]); }
}

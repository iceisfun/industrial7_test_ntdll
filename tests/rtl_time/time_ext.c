/* System time, performance counter, timer resolution, time zone and version queries. */
#include "t.h"

typedef struct { SHORT Year, Month, Day, Hour, Minute, Second, Milliseconds, Weekday; } xtm_fields;
typedef struct { LONG Bias; WCHAR StandardName[32]; xtm_fields StandardStart; LONG StandardBias; WCHAR DaylightName[32]; xtm_fields DaylightStart; LONG DaylightBias; } xtm_tz;
UDECL(NTSTATUS, NtQuerySystemTime, (PLARGE_INTEGER));
UDECL(NTSTATUS, NtQueryPerformanceCounter, (PLARGE_INTEGER, PLARGE_INTEGER));
UDECL(NTSTATUS, NtQueryTimerResolution, (PULONG, PULONG, PULONG));
UDECL(NTSTATUS, NtSetTimerResolution, (ULONG, BOOLEAN, PULONG));
UDECL(BOOLEAN, RtlQueryPerformanceCounter, (PLARGE_INTEGER));
UDECL(BOOLEAN, RtlQueryPerformanceFrequency, (PLARGE_INTEGER));
UDECL(VOID, RtlTimeToElapsedTimeFields, (PLARGE_INTEGER, xtm_fields *));
UDECL(NTSTATUS, RtlQueryTimeZoneInformation, (xtm_tz *));
UDECL(NTSTATUS, RtlGetVersion, (PVOID));
UDECL(BOOLEAN, RtlGetNtProductType, (PULONG));
UDECL(ULONG, RtlGetCurrentProcessorNumber, (void));
UDECL(ULONGLONG, RtlGetSystemTimePrecise, (void));
UDECL(BOOLEAN, RtlQueryUnbiasedInterruptTime, (PULONGLONG));

#define XS(x) ((NTSTATUS)(x))
#define XOK(s) ((NTSTATUS)(s) >= 0)
#define XT_1601_TO_2020 132223104000000000LL   /* 2020-01-01 in 100 ns units since 1601 */

TEST(rtl_time_x_query_system_time_matches_kernel32)
{
    LARGE_INTEGER n; FILETIME f; LONGLONG k; REQUIRE(UN(NtQuerySystemTime)); REQUIRE(UIN("kernel32.dll", GetSystemTimeAsFileTime));
    n.QuadPart = 0;
    EXPECT_EQ(UN(NtQuerySystemTime)(&n), 0);
    UIN("kernel32.dll", GetSystemTimeAsFileTime)(&f);
    k = ((LONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime;
    CHECK(n.QuadPart > XT_1601_TO_2020);
    CHECK(k >= n.QuadPart && k - n.QuadPart < 50000000);      /* within five seconds */
}
TEST(rtl_time_x_query_system_time_monotonic_tick)
{
    LARGE_INTEGER a, b; REQUIRE(UN(NtQuerySystemTime)); REQUIRE(UIN("kernel32.dll", Sleep));
    UN(NtQuerySystemTime)(&a);
    UIN("kernel32.dll", Sleep)(60);
    UN(NtQuerySystemTime)(&b);
    CHECK(b.QuadPart > a.QuadPart);
    CHECK(b.QuadPart - a.QuadPart >= 400000);                  /* at least ~40 ms */
    CHECK(b.QuadPart - a.QuadPart < 50000000);                 /* and not seconds */
}
TEST(rtl_time_x_performance_counter_and_frequency)
{
    LARGE_INTEGER c1, c2, fq, kf; REQUIRE(UN(NtQueryPerformanceCounter)); REQUIRE(UIN("kernel32.dll", QueryPerformanceFrequency));
    fq.QuadPart = 0; c1.QuadPart = 0;
    EXPECT_EQ(UN(NtQueryPerformanceCounter)(&c1, &fq), 0);
    CHECK(fq.QuadPart >= 1000000);                              /* at least 1 MHz on any supported machine */
    UIN("kernel32.dll", QueryPerformanceFrequency)(&kf);
    EXPECT_EQ(fq.QuadPart, kf.QuadPart);
    EXPECT_EQ(UN(NtQueryPerformanceCounter)(&c2, NULL), 0);    /* frequency is optional */
    CHECK(c2.QuadPart >= c1.QuadPart);
    CHECK(c1.QuadPart > 0);
}
TEST(rtl_time_x_performance_counter_advances)
{
    LARGE_INTEGER a, b, fq; double ms; REQUIRE(UN(NtQueryPerformanceCounter)); REQUIRE(UIN("kernel32.dll", Sleep));
    UN(NtQueryPerformanceCounter)(&a, &fq);
    UIN("kernel32.dll", Sleep)(50);
    UN(NtQueryPerformanceCounter)(&b, NULL);
    ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)fq.QuadPart;
    CHECK(ms >= 40.0 && ms < 2000.0);
}
TEST(rtl_time_x_rtl_performance_counter)
{
    LARGE_INTEGER a, b, fq, nf; BOOLEAN r; REQUIRE(UN(RtlQueryPerformanceCounter)); REQUIRE(UN(RtlQueryPerformanceFrequency)); REQUIRE(UN(NtQueryPerformanceCounter));
    a.QuadPart = 0; fq.QuadPart = 0;
    r = UN(RtlQueryPerformanceCounter)(&a); EXPECT_EQ(r, TRUE);
    r = UN(RtlQueryPerformanceFrequency)(&fq); EXPECT_EQ(r, TRUE);
    UN(NtQueryPerformanceCounter)(&b, &nf);
    EXPECT_EQ(fq.QuadPart, nf.QuadPart);
    CHECK(a.QuadPart > 0 && b.QuadPart >= a.QuadPart);
}
TEST(rtl_time_x_timer_resolution_ordering)
{
    ULONG mn = 0, mx = 0, cur = 0; REQUIRE(UN(NtQueryTimerResolution));
    EXPECT_EQ(UN(NtQueryTimerResolution)(&mn, &mx, &cur), 0);
    CHECK(mn > 0 && mx > 0 && cur > 0);
    CHECK(mx <= cur && cur <= mn);                              /* finest <= current <= coarsest */
    CHECK(mn <= 200000);                                        /* coarsest resolution is 20 ms or better */
    t_note("timer resolution min=%lu max=%lu current=%lu (100 ns units)", mn, mx, cur);
}
TEST(rtl_time_x_set_timer_resolution_request_and_release)
{
    ULONG mn = 0, mx = 0, cur = 0, set = 0, after = 0; NTSTATUS s; REQUIRE(UN(NtQueryTimerResolution)); REQUIRE(UN(NtSetTimerResolution));
    UN(NtQueryTimerResolution)(&mn, &mx, &cur);
    s = UN(NtSetTimerResolution)(mn, TRUE, &set);               /* asking for the coarsest value is always legal */
    EXPECT_EQ(s, 0);
    if (s == 0) {
        CHECK(set >= mx && set <= mn);
        EXPECT_EQ(UN(NtSetTimerResolution)(mn, FALSE, &after), 0);   /* release our request */
        CHECK(after >= mx && after <= mn);
    }
    s = UN(NtSetTimerResolution)(mn, FALSE, &after);                 /* nothing left to release */
    EXPECT_EQ(s, XS(0xC0000245));
}
TEST(rtl_time_x_set_timer_resolution_clamps_request)
{
    ULONG mn = 0, mx = 0, cur = 0, set = 0, after = 0; NTSTATUS s; REQUIRE(UN(NtQueryTimerResolution)); REQUIRE(UN(NtSetTimerResolution));
    UN(NtQueryTimerResolution)(&mn, &mx, &cur);
    s = UN(NtSetTimerResolution)(1, TRUE, &set);                /* finer than possible: clamped to the finest */
    t_note("request of 1 status=%08lx resulting=%lu finest=%lu", s, set, mx);
    if (XOK(s)) { CHECK(set >= mx); UN(NtSetTimerResolution)(1, FALSE, &after); }
}
TEST(rtl_time_x_elapsed_time_fields)
{
    LARGE_INTEGER t; xtm_fields f; REQUIRE(UN(RtlTimeToElapsedTimeFields));
    t.QuadPart = (((3LL * 24 + 4) * 60 + 5) * 60 + 6) * 10000000LL + 7 * 10000LL;   /* 3 d 04:05:06.007 */
    memset(&f, 0x55, sizeof f);
    UN(RtlTimeToElapsedTimeFields)(&t, &f);
    EXPECT_EQ(f.Day, 3); EXPECT_EQ(f.Hour, 4); EXPECT_EQ(f.Minute, 5); EXPECT_EQ(f.Second, 6); EXPECT_EQ(f.Milliseconds, 7);
    t_note("year=%d month=%d weekday=%d", f.Year, f.Month, f.Weekday);
    t.QuadPart = 0;
    UN(RtlTimeToElapsedTimeFields)(&t, &f);
    EXPECT_EQ(f.Day, 0); EXPECT_EQ(f.Hour, 0); EXPECT_EQ(f.Minute, 0); EXPECT_EQ(f.Second, 0); EXPECT_EQ(f.Milliseconds, 0);
    t.QuadPart = 10000000LL - 1;                                 /* just under a second: milliseconds truncate */
    UN(RtlTimeToElapsedTimeFields)(&t, &f);
    EXPECT_EQ(f.Second, 0); EXPECT_EQ(f.Milliseconds, 999);
    t.QuadPart = 24LL * 3600 * 10000000LL * 400;                 /* longer than a year still reports days */
    UN(RtlTimeToElapsedTimeFields)(&t, &f);
    t_note("400 days -> year=%d month=%d day=%d", f.Year, f.Month, f.Day);
}
TEST(rtl_time_x_query_time_zone_information)
{
    xtm_tz tz; TIME_ZONE_INFORMATION k; DWORD kr; NTSTATUS s; REQUIRE(UN(RtlQueryTimeZoneInformation)); REQUIRE(UIN("kernel32.dll", GetTimeZoneInformation));
    CHECK(sizeof tz == 172);
    memset(&tz, 0xcc, sizeof tz);
    s = UN(RtlQueryTimeZoneInformation)(&tz);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        CHECK(tz.Bias > -1440 && tz.Bias < 1440);
        CHECK(tz.StandardName[31] == 0 || tz.StandardName[0] != 0xcccc);
        CHECK(tz.StandardBias > -1440 && tz.StandardBias < 1440);
        CHECK(tz.DaylightBias > -1440 && tz.DaylightBias < 1440);
        kr = UIN("kernel32.dll", GetTimeZoneInformation)(&k);
        /* The names are not compared: the Win32 call returns a localized display name, the Rtl call the registry value. */
        if (kr != TIME_ZONE_ID_INVALID) { EXPECT_EQ(tz.Bias, k.Bias); EXPECT_EQ(tz.StandardBias, k.StandardBias); EXPECT_EQ(tz.DaylightBias, k.DaylightBias); }
    }
}
TEST(rtl_time_x_get_version)
{
    struct { ULONG size, major, minor, build, platform; WCHAR csd[128]; } v; NTSTATUS s; REQUIRE(UN(RtlGetVersion));
    memset(&v, 0, sizeof v); v.size = sizeof v;
    CHECK(sizeof v == 276);
    s = UN(RtlGetVersion)(&v);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(v.major, 10); EXPECT_EQ(v.minor, 0); CHECK(v.build >= 10240); EXPECT_EQ(v.platform, 2);
        t_note("version %lu.%lu.%lu", v.major, v.minor, v.build);
    }
    /* RtlGetVersion is documented to always return STATUS_SUCCESS; it does not validate the structure size. */
    memset(&v, 0, sizeof v); v.size = 20;
    EXPECT_EQ(UN(RtlGetVersion)(&v), 0);
    memset(&v, 0, sizeof v); v.size = 0;
    EXPECT_EQ(UN(RtlGetVersion)(&v), 0);
}
TEST(rtl_time_x_get_version_extended)
{
    struct { ULONG size, major, minor, build, platform; WCHAR csd[128]; USHORT spmaj, spmin, suite; BYTE product, reserved; } v; NTSTATUS s; REQUIRE(UN(RtlGetVersion));
    CHECK(sizeof v == 284);
    memset(&v, 0, sizeof v); v.size = sizeof v;
    s = UN(RtlGetVersion)(&v);
    EXPECT_EQ(s, 0);
    if (s == 0) { EXPECT_EQ(v.major, 10); CHECK(v.product >= 1 && v.product <= 3); t_note("service pack %u.%u suite=%04x product=%u", v.spmaj, v.spmin, v.suite, v.product); }
}
TEST(rtl_time_x_product_type_and_processor_number)
{
    ULONG type = 0; ULONG cpu; REQUIRE(UN(RtlGetNtProductType));
    EXPECT_EQ(UN(RtlGetNtProductType)(&type), TRUE);
    CHECK(type >= 1 && type <= 3);
    REQUIRE(UN(RtlGetCurrentProcessorNumber));
    cpu = UN(RtlGetCurrentProcessorNumber)();
    CHECK(cpu < 64);
}
TEST(rtl_time_x_precise_time_and_unbiased_interrupt)
{
    ULONGLONG t1, a = 0, b = 0; LARGE_INTEGER n; REQUIRE(UN(RtlGetSystemTimePrecise)); REQUIRE(UN(NtQuerySystemTime));
    t1 = UN(RtlGetSystemTimePrecise)();
    UN(NtQuerySystemTime)(&n);
    CHECK((LONGLONG)t1 > XT_1601_TO_2020);
    CHECK(n.QuadPart + 50000000 > (LONGLONG)t1 && (LONGLONG)t1 + 50000000 > n.QuadPart);
    if (UN(RtlQueryUnbiasedInterruptTime)) {
        EXPECT_EQ(UN(RtlQueryUnbiasedInterruptTime)(&a), TRUE);
        EXPECT_EQ(UN(RtlQueryUnbiasedInterruptTime)(&b), TRUE);
        CHECK(a > 0 && b >= a);
    }
}

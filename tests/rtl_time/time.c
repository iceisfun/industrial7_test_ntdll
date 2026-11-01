#include "t.h"

typedef struct rtl_time_fields {
    SHORT Year, Month, Day, Hour, Minute, Second, Milliseconds, Weekday;
} rtl_time_fields;
UDECL(BOOLEAN, RtlTimeFieldsToTime, (const rtl_time_fields *, PLARGE_INTEGER));
UDECL(void, RtlTimeToTimeFields, (const LARGE_INTEGER *, rtl_time_fields *));
UDECL(void, RtlSecondsSince1970ToTime, (ULONG, PLARGE_INTEGER));
UDECL(void, RtlSecondsSince1980ToTime, (ULONG, PLARGE_INTEGER));
UDECL(BOOLEAN, RtlTimeToSecondsSince1970, (const LARGE_INTEGER *, PULONG));
UDECL(BOOLEAN, RtlTimeToSecondsSince1980, (const LARGE_INTEGER *, PULONG));
UDECL(NTSTATUS, RtlSystemTimeToLocalTime, (const LARGE_INTEGER *, PLARGE_INTEGER));
UDECL(NTSTATUS, RtlLocalTimeToSystemTime, (const LARGE_INTEGER *, PLARGE_INTEGER));

static void calendar(SHORT year, SHORT month, SHORT day, SHORT hour,
                     SHORT minute, SHORT second, SHORT ms, SHORT weekday,
                     LONGLONG exact)
{
    rtl_time_fields in = {year, month, day, hour, minute, second, ms, -1}, out;
    LARGE_INTEGER t; BOOLEAN ok;
    REQUIRE(UN(RtlTimeFieldsToTime)); REQUIRE(UN(RtlTimeToTimeFields));
    t.QuadPart = -1;
    ok = UN(RtlTimeFieldsToTime)(&in, &t);
    EXPECT_EQ(ok, TRUE);
    if (!ok) return;
    if (exact >= 0) EXPECT_EQ(t.QuadPart, exact);
    memset(&out, 0x5a, sizeof(out));
    UN(RtlTimeToTimeFields)(&t, &out);
    EXPECT_EQ(out.Year, year); EXPECT_EQ(out.Month, month); EXPECT_EQ(out.Day, day);
    EXPECT_EQ(out.Hour, hour); EXPECT_EQ(out.Minute, minute); EXPECT_EQ(out.Second, second);
    EXPECT_EQ(out.Milliseconds, ms); EXPECT_EQ(out.Weekday, weekday);
}
#define DATE(name, y, m, d, weekday, exact) \
    TEST(rtl_time_calendar_##name) { calendar(y, m, d, 0, 0, 0, 0, weekday, exact); }
DATE(epoch1601, 1601, 1, 1, 1, 0)
DATE(second_day, 1601, 1, 2, 2, 864000000000LL)
DATE(first_leap, 1604, 2, 29, 0, 997056000000000LL)
DATE(century1700, 1700, 3, 1, 1, 31292352000000000LL)
DATE(century1900, 1900, 3, 1, 4, 94405824000000000LL)
DATE(epoch1970, 1970, 1, 1, 4, 116444736000000000LL)
/* Later dates round-trip without assuming a machine's leap-second table. */
DATE(epoch1980, 1980, 1, 1, 2, -1)
DATE(leap2000, 2000, 2, 29, 2, -1)
DATE(leap2024, 2024, 2, 29, 4, -1)
DATE(century2100, 2100, 3, 1, 1, -1)
DATE(century2400, 2400, 2, 29, 2, -1)
DATE(year_end, 1999, 12, 31, 5, -1)
DATE(year_start, 2000, 1, 1, 6, -1)
DATE(april_end, 2024, 4, 30, 2, -1)
DATE(may_start, 2024, 5, 1, 3, -1)
TEST(rtl_time_calendar_last_millisecond)
{
    calendar(1601, 1, 1, 23, 59, 59, 999, 1, 863999990000LL);
}
TEST(rtl_time_calendar_components)
{
    calendar(1601, 1, 1, 12, 34, 56, 789, 1, 452967890000LL);
}

static void invalid(SHORT year, SHORT month, SHORT day, SHORT hour,
                    SHORT minute, SHORT second, SHORT ms)
{
    rtl_time_fields in = {year, month, day, hour, minute, second, ms, 0};
    LARGE_INTEGER t; BOOLEAN ok;
    REQUIRE(UN(RtlTimeFieldsToTime));
    t.QuadPart = 0x123456789abcdefLL;
    ok = UN(RtlTimeFieldsToTime)(&in, &t);
    EXPECT_EQ(ok, FALSE);
    EXPECT_EQ(t.QuadPart, 0x123456789abcdefLL);
}
#define INVALID(name, y, mo, d, h, mi, s, ms) \
    TEST(rtl_time_invalid_##name) { invalid(y, mo, d, h, mi, s, ms); }
INVALID(before_epoch, 1600, 1, 1, 0, 0, 0, 0)
INVALID(year_zero, 0, 1, 1, 0, 0, 0, 0)
INVALID(negative_year, -1, 1, 1, 0, 0, 0, 0)
INVALID(month_zero, 2000, 0, 1, 0, 0, 0, 0)
INVALID(month_thirteen, 2000, 13, 1, 0, 0, 0, 0)
INVALID(month_negative, 2000, -1, 1, 0, 0, 0, 0)
INVALID(day_zero, 2000, 1, 0, 0, 0, 0, 0)
INVALID(day_negative, 2000, 1, -1, 0, 0, 0, 0)
INVALID(day_thirtytwo, 2000, 1, 32, 0, 0, 0, 0)
INVALID(april_thirtyone, 2000, 4, 31, 0, 0, 0, 0)
INVALID(february_thirty, 2000, 2, 30, 0, 0, 0, 0)
INVALID(nonleap, 2023, 2, 29, 0, 0, 0, 0)
INVALID(century1900, 1900, 2, 29, 0, 0, 0, 0)
INVALID(century2100, 2100, 2, 29, 0, 0, 0, 0)
INVALID(hour24, 2000, 1, 1, 24, 0, 0, 0)
INVALID(hour_negative, 2000, 1, 1, -1, 0, 0, 0)
INVALID(minute60, 2000, 1, 1, 0, 60, 0, 0)
INVALID(minute_negative, 2000, 1, 1, 0, -1, 0, 0)
INVALID(second61, 2000, 1, 1, 0, 0, 61, 0)
INVALID(second_negative, 2000, 1, 1, 0, 0, -1, 0)
INVALID(millisecond1000, 2000, 1, 1, 0, 0, 0, 1000)
INVALID(millisecond_negative, 2000, 1, 1, 0, 0, 0, -1)

TEST(rtl_time_weekday_input_ignored)
{
    rtl_time_fields in = {1601, 1, 1, 0, 0, 0, 0, 12345}; LARGE_INTEGER t;
    REQUIRE(UN(RtlTimeFieldsToTime));
    t.QuadPart = -1;
    EXPECT_EQ(UN(RtlTimeFieldsToTime)(&in, &t), TRUE);
    EXPECT_EQ(t.QuadPart, 0);
}

static void seconds(BOOL since1980, ULONG value)
{
    LARGE_INTEGER t; ULONG out = 0xdeadbeef;
    LONGLONG epoch = since1980 ? 119600064000000000LL : 116444736000000000LL;
    REQUIRE(UN(RtlSecondsSince1970ToTime)); REQUIRE(UN(RtlSecondsSince1980ToTime));
    REQUIRE(UN(RtlTimeToSecondsSince1970)); REQUIRE(UN(RtlTimeToSecondsSince1980));
    if (since1980) UN(RtlSecondsSince1980ToTime)(value, &t);
    else UN(RtlSecondsSince1970ToTime)(value, &t);
    EXPECT_EQ(t.QuadPart, epoch + (ULONGLONG)value * 10000000);
    if (since1980) EXPECT_EQ(UN(RtlTimeToSecondsSince1980)(&t, &out), TRUE);
    else EXPECT_EQ(UN(RtlTimeToSecondsSince1970)(&t, &out), TRUE);
    EXPECT_EQ(out, value);
}
#define SECONDS(name, value) \
    TEST(rtl_time_seconds1970_##name) { seconds(FALSE, value); } \
    TEST(rtl_time_seconds1980_##name) { seconds(TRUE, value); }
SECONDS(zero, 0)
SECONDS(one, 1)
SECONDS(minute, 60)
SECONDS(hour, 3600)
SECONDS(day, 86400)
SECONDS(year365, 31536000)
SECONDS(signed_max, 0x7fffffff)
SECONDS(highbit, 0x80000000)
SECONDS(max_minus_one, 0xfffffffe)
SECONDS(maximum, 0xffffffff)

static void boundary(BOOL since1980, LONGLONG offset, BOOLEAN expected, ULONG value)
{
    LARGE_INTEGER t; ULONG out = 0xdeadbeef; BOOLEAN ok;
    REQUIRE(UN(RtlTimeToSecondsSince1970)); REQUIRE(UN(RtlTimeToSecondsSince1980));
    t.QuadPart = (since1980 ? 119600064000000000LL : 116444736000000000LL) + offset;
    ok = since1980 ? UN(RtlTimeToSecondsSince1980)(&t, &out) : UN(RtlTimeToSecondsSince1970)(&t, &out);
    EXPECT_EQ(ok, expected); EXPECT_EQ(out, expected ? value : 0xdeadbeef);
}
#define BOUNDARY(name, offset, expected, value) \
    TEST(rtl_time_boundary1970_##name) { boundary(FALSE, offset, expected, value); } \
    TEST(rtl_time_boundary1980_##name) { boundary(TRUE, offset, expected, value); }
BOUNDARY(before_epoch_tick, -1, FALSE, 0)
BOUNDARY(before_epoch_second, -10000000, FALSE, 0)
BOUNDARY(first_tick, 1, TRUE, 0)
BOUNDARY(fraction, 9999999, TRUE, 0)
BOUNDARY(second_tick, 10000001, TRUE, 1)
BOUNDARY(max_fraction, 42949672959999999LL, TRUE, 0xffffffff)
BOUNDARY(overflow, 42949672960000000LL, FALSE, 0)

TEST(rtl_time_submillisecond_truncation)
{
    LARGE_INTEGER t; rtl_time_fields out;
    REQUIRE(UN(RtlTimeToTimeFields));
    t.QuadPart = 9999;
    UN(RtlTimeToTimeFields)(&t, &out);
    EXPECT_EQ(out.Year, 1601); EXPECT_EQ(out.Month, 1); EXPECT_EQ(out.Day, 1);
    EXPECT_EQ(out.Hour, 0); EXPECT_EQ(out.Minute, 0); EXPECT_EQ(out.Second, 0);
    EXPECT_EQ(out.Milliseconds, 0); EXPECT_EQ(out.Weekday, 1);
    t.QuadPart = 10000;
    UN(RtlTimeToTimeFields)(&t, &out);
    EXPECT_EQ(out.Milliseconds, 1);
}

TEST(rtl_time_local_timezone_observation)
{
    LARGE_INTEGER utc, local, back; NTSTATUS a, b;
    REQUIRE(UN(RtlSystemTimeToLocalTime)); REQUIRE(UN(RtlLocalTimeToSystemTime));
    utc.QuadPart = 116444736000000000LL; local.QuadPart = back.QuadPart = 0;
    a = UN(RtlSystemTimeToLocalTime)(&utc, &local);
    t_note("system-to-local status=%08lx", (ULONG)a);
    if (a < 0) return;
    b = UN(RtlLocalTimeToSystemTime)(&local, &back);
    t_note("local-to-system status=%08lx offset_ticks=%lld roundtrip=%lld; timezone/configuration observation only",
           (ULONG)b, local.QuadPart - utc.QuadPart, back.QuadPart);
}

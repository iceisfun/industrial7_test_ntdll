/* WinSqm* user-mode telemetry (SQM) exports in ntdll.
 *
 * On Windows 10 22H2 every export in this file is a trivial stub; the stubs fall into four
 * behavioural groups, each of which is a single shared code body (the exports in a group
 * resolve to one address):
 *   - void/no-op group    : returns without touching any argument (callee pops nothing; x64)
 *   - zero group          : returns 0 (FALSE / ERROR_SUCCESS) in the full return register
 *   - one group           : returns 1 (TRUE) in eax
 *   - invalid-handle group: WinSqmStartSession / ForPartner return (HANDLE)-1
 * WinSqmGetInstrumentationProperty is separate: it zeroes its two optional output slots.
 *
 * All calls pass pointer arguments that point at sentinel-filled buffers; the tests assert
 * that the buffers are untouched (the stubs never dereference or write arguments), that NULL
 * and garbage arguments are accepted, and the constant return values.
 */
#include "t.h"

typedef ULONGLONG (WINAPI *sqm6_fn)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

static const char *const g_void[] = {
    "WinSqmAddToAverageDWORD", "WinSqmAddToStream", "WinSqmAddToStreamEx", "WinSqmEndSession",
    "WinSqmIncrementDWORD", "WinSqmSetDWORD", "WinSqmSetDWORD64", "WinSqmSetIfMaxDWORD",
    "WinSqmSetIfMinDWORD", "WinSqmSetString" };
static const char *const g_zero[] = {
    "WinSqmCheckEscalationAddToStreamEx", "WinSqmCheckEscalationSetDWORD",
    "WinSqmCheckEscalationSetDWORD64", "WinSqmCheckEscalationSetString", "WinSqmEventEnabled",
    "WinSqmEventWrite", "WinSqmGetEscalationRuleStatus", "WinSqmIsOptedIn", "WinSqmIsOptedInEx",
    "WinSqmStartSqmOptinListener" };
static const char *const g_one[] = {
    "WinSqmCommonDatapointDelete", "WinSqmCommonDatapointSetDWORD", "WinSqmCommonDatapointSetDWORD64",
    "WinSqmCommonDatapointSetStreamEx", "WinSqmCommonDatapointSetString", "WinSqmIsSessionDisabled",
    "WinSqmSetEscalationInfo" };
static const char *const g_inv[] = { "WinSqmStartSession", "WinSqmStartSessionForPartner" };
#define N(a) (sizeof(a) / sizeof((a)[0]))

static void same_body(const char *const *names, size_t n)
{
    FARPROC first = t_proc(names[0]);
    for (size_t i = 0; i < n; i++) {
        FARPROC p = t_proc(names[i]);
        CHECKF(p != NULL, "%s missing", names[i]);
        CHECKF(p == first, "%s differs from %s", names[i], names[0]);
    }
}

TEST(sqm_group_bodies_shared)
{
    FARPROC v = t_proc(g_void[0]), z = t_proc(g_zero[0]), o = t_proc(g_one[0]), i = t_proc(g_inv[0]);
    REQUIRE(v); REQUIRE(z); REQUIRE(o); REQUIRE(i);
    same_body(g_void, N(g_void));
    same_body(g_zero, N(g_zero));
    same_body(g_one, N(g_one));
    same_body(g_inv, N(g_inv));
    CHECK(v != z && v != o && v != i && z != o && z != i && o != i);
}

TEST(sqm_void_group_noop)
{
    for (size_t k = 0; k < N(g_void); k++) {
        sqm6_fn f = (sqm6_fn)t_proc(g_void[k]);
        REQUIRE(f);
        BYTE buf[32]; DWORD dw = 0x11223344; WCHAR str[8] = L"abc";
        memset(buf, 0xA5, sizeof buf);
        f(0, 0, 0, 0, 0, 0);                                   /* all NULL / zero */
        f((ULONG_PTR)buf, (ULONG_PTR)&dw, 7, (ULONG_PTR)str, 1, 0xFFFFFFFF);
        f((ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1); /* never dereferenced */
        BYTE want[32]; memset(want, 0xA5, sizeof want);
        CHECKF(!memcmp(buf, want, sizeof buf), "%s modified buffer", g_void[k]);
        CHECKF(dw == 0x11223344, "%s modified dword", g_void[k]);
        CHECKF(!lstrcmpW(str, L"abc"), "%s modified string", g_void[k]);
    }
}

TEST(sqm_zero_group_returns_zero)
{
    for (size_t k = 0; k < N(g_zero); k++) {
        sqm6_fn f = (sqm6_fn)t_proc(g_zero[k]);
        REQUIRE(f);
        BYTE buf[16]; memset(buf, 0x5A, sizeof buf);
        ULONGLONG r0 = f(0, 0, 0, 0, 0, 0);
        ULONGLONG r1 = f((ULONG_PTR)buf, 1, 2, 3, 4, 5);
        ULONGLONG r2 = f((ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1);
        CHECKF(r0 == 0, "%s(NULLs) = %llx", g_zero[k], r0);
        CHECKF(r1 == 0, "%s(args) = %llx", g_zero[k], r1);
        CHECKF(r2 == 0, "%s(-1s) = %llx", g_zero[k], r2);
        BYTE want[16]; memset(want, 0x5A, sizeof want);
        CHECKF(!memcmp(buf, want, sizeof buf), "%s modified buffer", g_zero[k]);
    }
}

TEST(sqm_one_group_returns_one)
{
    for (size_t k = 0; k < N(g_one); k++) {
        sqm6_fn f = (sqm6_fn)t_proc(g_one[k]);
        REQUIRE(f);
        BYTE buf[16]; memset(buf, 0x3C, sizeof buf);
        DWORD r0 = (DWORD)f(0, 0, 0, 0, 0, 0);
        DWORD r1 = (DWORD)f((ULONG_PTR)buf, 1, 2, 3, 4, 5);
        DWORD r2 = (DWORD)f((ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1, (ULONG_PTR)-1);
        CHECKF(r0 == 1, "%s(NULLs) = %lx", g_one[k], r0);
        CHECKF(r1 == 1, "%s(args) = %lx", g_one[k], r1);
        CHECKF(r2 == 1, "%s(-1s) = %lx", g_one[k], r2);
        BYTE want[16]; memset(want, 0x3C, sizeof want);
        CHECKF(!memcmp(buf, want, sizeof buf), "%s modified buffer", g_one[k]);
    }
}

TEST(sqm_start_session_invalid_handle)
{
    for (size_t k = 0; k < N(g_inv); k++) {
        sqm6_fn f = (sqm6_fn)t_proc(g_inv[k]);
        REQUIRE(f);
        GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } };
        ULONGLONG r0 = f(0, 0, 0, 0, 0, 0);
        ULONGLONG r1 = f((ULONG_PTR)&g, 0, 1, 0, 0, 0);
        CHECKF(r0 == (ULONGLONG)-1, "%s() = %llx", g_inv[k], r0);
        CHECKF(r1 == (ULONGLONG)-1, "%s(guid) = %llx", g_inv[k], r1);
        CHECK(g.Data1 == 1 && g.Data2 == 2 && g.Data3 == 3);
    }
}

TEST(sqm_get_instrumentation_property)
{
    UDECL(ULONG, WinSqmGetInstrumentationProperty, (ULONG_PTR, ULONG_PTR, USHORT *, ULONG *));
    REQUIRE(UN(WinSqmGetInstrumentationProperty));
    USHORT us = 0xCCCC; ULONG ul = 0xCCCCCCCC;
    ULONG r = UN(WinSqmGetInstrumentationProperty)(0, 0, &us, &ul);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(us, 0);
    EXPECT_EQ(ul, 0);
    /* only the USHORT slot */
    us = 0xCCCC; ul = 0xCCCCCCCC;
    UN(WinSqmGetInstrumentationProperty)(1, 2, &us, NULL);
    EXPECT_EQ(us, 0);
    EXPECT_EQ(ul, 0xCCCCCCCC);
    /* only the ULONG slot */
    us = 0xCCCC; ul = 0xCCCCCCCC;
    UN(WinSqmGetInstrumentationProperty)(1, 2, NULL, &ul);
    EXPECT_EQ(us, 0xCCCC);
    EXPECT_EQ(ul, 0);
    /* neither */
    r = UN(WinSqmGetInstrumentationProperty)(3, 4, NULL, NULL);
    EXPECT_EQ(r, 0);
    /* no relation to the first two arguments: a non-zero property id yields the same result */
    us = 0xCCCC; ul = 0xCCCCCCCC;
    UN(WinSqmGetInstrumentationProperty)((ULONG_PTR)-1, (ULONG_PTR)-1, &us, &ul);
    EXPECT_EQ(us, 0);
    EXPECT_EQ(ul, 0);
}

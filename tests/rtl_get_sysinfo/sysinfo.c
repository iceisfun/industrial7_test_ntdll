#include "t.h"
#include <stdlib.h>

UDECL(PVOID, RtlGetCurrentPeb, (void));
UDECL(NTSTATUS, RtlGetVersion, (PVOID));
UDECL(VOID, RtlGetNtVersionNumbers, (ULONG *, ULONG *, ULONG *));
UDECL(BOOLEAN, RtlGetNtProductType, (ULONG *));
UDECL(ULONG, RtlGetSuiteMask, (void));
UDECL(PWSTR, RtlGetNtSystemRoot, (void));
UDECL(ULONG, RtlGetNtGlobalFlags, (void));
UDECL(BOOLEAN, RtlGetProductInfo, (ULONG, ULONG, ULONG, ULONG, ULONG *));
UDECL(ULONG, RtlGetCurrentServiceSessionId, (void));
UDECL(ULONG, RtlGetActiveConsoleId, (void));
UDECL(ULONGLONG, RtlGetConsoleSessionForegroundProcessId, (void));
UDECL(LONGLONG, RtlGetSystemTimeAndBias, (LONGLONG *, LONGLONG *, LONGLONG *));
UDECL(LONGLONG, RtlGetSystemTimePrecise, (void));
UDECL(LONGLONG, RtlGetInterruptTimePrecise, (ULONGLONG *));
UDECL(NTSTATUS, RtlGetMultiTimePrecise, (ULONGLONG *, ULONG, ULONG *));
UDECL(ULONG, RtlGetCurrentProcessorNumber, (void));
UDECL(VOID, RtlGetCurrentProcessorNumberEx, (PROCESSOR_NUMBER *));
UDECL(ULONGLONG, RtlGetEnabledExtendedFeatures, (ULONGLONG));
UDECL(NTSTATUS, RtlGetExtendedContextLength, (ULONG, ULONG *));
UDECL(NTSTATUS, RtlGetExtendedContextLength2, (ULONG, ULONG *, ULONGLONG));
UDECL(ULONGLONG, RtlGetExtendedFeaturesMask, (PVOID));
UDECL(ULONG, RtlGetLongestNtPathLength, (void));
UDECL(NTSTATUS, RtlGetSessionProperties, (ULONG, ULONG *));
UDECL(VOID, RtlGetDeviceFamilyInfoEnum, (ULONGLONG *, ULONG *, ULONG *));
UDECL(NTSTATUS, RtlGetNativeSystemInformation, (ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQuerySystemInformation, (ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, ZwQuerySystemInformation, (ULONG, PVOID, ULONG, PULONG));

#define SUD ((volatile const unsigned char *)0x7ffe0000)
#define SUD32(off) (*(volatile const ULONG *)(SUD + (off)))
#define SUD64(off) (*(volatile const ULONGLONG *)(SUD + (off)))

typedef struct {
    ULONG Size, Major, Minor, Build, Platform;
    WCHAR Csd[128];
    USHORT SpMajor, SpMinor, Suite;
    UCHAR ProductType, Reserved;
    ULONG Extra[2];
} OSVI;

static LONGLONG ft_now(void) { FILETIME f; GetSystemTimeAsFileTime(&f); return ((LONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }
static LONGLONG ft_precise(void) { FILETIME f; UIN("kernel32.dll", GetSystemTimePreciseAsFileTime)(&f); return ((LONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }

TEST(get_current_peb) {
    REQUIRE(UN(RtlGetCurrentPeb));
    PVOID p = UN(RtlGetCurrentPeb)();
    CHECK(p != NULL);
    EXPECT_EQ(p, NtCurrentTeb()->ProcessEnvironmentBlock);
    EXPECT_EQ(p, UN(RtlGetCurrentPeb)());
}

TEST(get_version_struct) {
    REQUIRE(UN(RtlGetVersion)); REQUIRE(UN(RtlGetNtVersionNumbers)); REQUIRE(UN(RtlGetNtProductType)); REQUIRE(UN(RtlGetSuiteMask));
    OSVI v; memset(&v, 0xCC, sizeof v); v.Size = 0x11c;
    EXPECT_EQ(UN(RtlGetVersion)(&v), 0);
    EXPECT_EQ(v.Major, 10); EXPECT_EQ(v.Minor, 0); EXPECT_EQ(v.Platform, 2);
    CHECK(v.Build >= 19041);
    ULONG maj = 0, min = 0, bld = 0;
    UN(RtlGetNtVersionNumbers)(&maj, &min, &bld);
    EXPECT_EQ(maj, v.Major); EXPECT_EQ(min, v.Minor);
    EXPECT_EQ(bld, v.Build | 0xF0000000);
    UN(RtlGetNtVersionNumbers)(NULL, NULL, NULL);          /* all-NULL is allowed */
    ULONG only = 0xdead; UN(RtlGetNtVersionNumbers)(NULL, &only, NULL); EXPECT_EQ(only, v.Minor);
    /* the OS version fields mirror the PEB */
    BYTE *peb = (BYTE *)NtCurrentTeb()->ProcessEnvironmentBlock;
    EXPECT_EQ(*(ULONG *)(peb + 0x118), v.Major); EXPECT_EQ(*(ULONG *)(peb + 0x11c), v.Minor);
    EXPECT_EQ(*(USHORT *)(peb + 0x120), v.Build); EXPECT_EQ(*(ULONG *)(peb + 0x124), v.Platform);
    EXPECT_EQ(v.ProductType, SUD32(0x264) & 0xff);
    CHECK(v.ProductType >= 1 && v.ProductType <= 3);
    EXPECT_EQ(v.Suite, (UN(RtlGetSuiteMask)() & 0xffef & 0xffff) | 0x100);
    /* ProductType via the dedicated API */
    ULONG pt = 0; EXPECT_EQ(UN(RtlGetNtProductType)(&pt), TRUE);
    EXPECT_EQ(pt, v.ProductType); EXPECT_EQ(pt, SUD32(0x264));
    /* PEB CSD version string is copied */
    memset(&v, 0, sizeof v); v.Size = 0x11c; UN(RtlGetVersion)(&v);
    CHECK(wcslen(v.Csd) < 128);
}

TEST(get_version_small_size) {
    REQUIRE(UN(RtlGetVersion));
    OSVI v; memset(&v, 0xCC, sizeof v); v.Size = 0x114;   /* OSVERSIONINFOW */
    EXPECT_EQ(UN(RtlGetVersion)(&v), 0);
    EXPECT_EQ(v.Major, 10);
    /* the extended fields are not written for the basic structure */
    EXPECT_EQ(v.SpMajor, 0xCCCC); EXPECT_EQ(v.ProductType, 0xCC);
    memset(&v, 0xCC, sizeof v); v.Size = 0x124;           /* with the extra suite dword */
    EXPECT_EQ(UN(RtlGetVersion)(&v), 0);
    CHECK(v.Suite != 0xCCCC);
}

TEST(get_suite_mask_and_system_root) {
    REQUIRE(UN(RtlGetSuiteMask)); REQUIRE(UN(RtlGetNtSystemRoot)); REQUIRE(UN(RtlGetNtGlobalFlags));
    EXPECT_EQ(UN(RtlGetSuiteMask)(), SUD32(0x2d0));
    PWSTR root = UN(RtlGetNtSystemRoot)();
    CHECK(root != NULL);
    EXPECT_EQ((BYTE *)root, (BYTE *)(SUD + 0x30));
    WCHAR win[MAX_PATH];
    UINT n = UIN("kernel32.dll", GetSystemWindowsDirectoryW)(win, MAX_PATH);
    CHECK(n > 3);
    CHECK(lstrcmpiW(root, win) == 0);
    EXPECT_EQ(UN(RtlGetNtGlobalFlags)(), *(ULONG *)((BYTE *)NtCurrentTeb()->ProcessEnvironmentBlock + 0xbc));
}

TEST(get_product_info) {
    REQUIRE(UN(RtlGetProductInfo));
    ULONG info = 0xdeadbeef;
    BOOLEAN ok = UN(RtlGetProductInfo)(10, 0, 0, 0, &info);
    EXPECT_EQ(ok, TRUE);
    CHECK(info != 0xdeadbeef);
    ULONG k32 = 0xdeadbeef;
    BOOL kok = UIN("kernel32.dll", GetProductInfo)(10, 0, 0, 0, &k32);
    EXPECT_EQ(kok, TRUE);
    EXPECT_EQ(info, k32);
    /* newer requested versions still resolve to the installed edition */
    info = 0xdeadbeef;
    EXPECT_EQ(UN(RtlGetProductInfo)(11, 0, 0, 0, &info), TRUE); EXPECT_EQ(info, k32);
    /* versions older than 6.0 are rejected and the output is zeroed */
    info = 0xdeadbeef;
    EXPECT_EQ(UN(RtlGetProductInfo)(5, 1, 0, 0, &info), FALSE);
    EXPECT_EQ(info, 0);
    info = 0xdeadbeef;
    EXPECT_EQ(UN(RtlGetProductInfo)(5, 2, 2, 0, &info), FALSE);
    EXPECT_EQ(info, 0);
    info = 0xdeadbeef;
    EXPECT_EQ(UN(RtlGetProductInfo)(6, 0, 0, 0, &info), TRUE); CHECK(info != 0xdeadbeef);
    /* NULL output */
    EXPECT_EQ(UN(RtlGetProductInfo)(10, 0, 0, 0, NULL), FALSE);
}

TEST(get_session_ids) {
    REQUIRE(UN(RtlGetCurrentServiceSessionId)); REQUIRE(UN(RtlGetActiveConsoleId)); REQUIRE(UN(RtlGetConsoleSessionForegroundProcessId));
    EXPECT_EQ(UN(RtlGetCurrentServiceSessionId)(), 0);
    DWORD con = UIN("kernel32.dll", WTSGetActiveConsoleSessionId)();
    EXPECT_EQ(UN(RtlGetActiveConsoleId)(), con);
    EXPECT_EQ(UN(RtlGetActiveConsoleId)(), SUD32(0x2d8));
    int same = 0;
    for (int i = 0; i < 20 && !same; i++) { ULONGLONG a = UN(RtlGetConsoleSessionForegroundProcessId)(); same = a == SUD64(0x338) && (a >> 32) == 0; }
    CHECK(same);
}

TEST(get_session_properties) {
    REQUIRE(UN(RtlGetSessionProperties));
    ULONG v = 0xdead;
    EXPECT_EQ(UN(RtlGetSessionProperties)(0, NULL), (NTSTATUS)0xC000000D);
    EXPECT_EQ(UN(RtlGetSessionProperties)(0xFFFFFFFF, &v), (NTSTATUS)0xC000000D);
    EXPECT_EQ(v, 0xdead);
    /* the service session id of this process matches property id 0 (the classic session) */
    v = 0xdead; EXPECT_EQ(UN(RtlGetSessionProperties)(0, &v), 0); CHECK(v == 0 || v == 1);
    ULONG w = 0xdead; EXPECT_EQ(UN(RtlGetSessionProperties)(0x7fffffff, &w), 0); EXPECT_EQ(w, 0);
    t_note("RtlGetSessionProperties(0) = %lu", v);
}

TEST(get_system_time_and_bias) {
    REQUIRE(UN(RtlGetSystemTimeAndBias));
    LONGLONG bias = 0x1111, st = 0x2222, en = 0x3333;
    LONGLONG t0 = ft_now();
    LONGLONG t = UN(RtlGetSystemTimeAndBias)(&bias, &st, &en);
    LONGLONG t1 = ft_now();
    CHECK(t >= t0 && t <= t1);
    /* bias is in 100ns units and within +-24h */
    CHECK(bias > -(LONGLONG)24 * 3600 * 10000000 && bias < (LONGLONG)24 * 3600 * 10000000);
    TIME_ZONE_INFORMATION tz; DWORD r = GetTimeZoneInformation(&tz);
    if (r != TIME_ZONE_ID_INVALID) {
        LONGLONG b = (LONGLONG)(tz.Bias + (r == TIME_ZONE_ID_DAYLIGHT ? tz.DaylightBias : tz.StandardBias)) * 60 * 10000000;
        EXPECT_EQ(bias, b);
    }
    CHECK(st != 0x2222 && en != 0x3333);
    /* optional outputs may be NULL */
    LONGLONG b2 = 0;
    LONGLONG t2 = UN(RtlGetSystemTimeAndBias)(&b2, NULL, NULL);
    CHECK(t2 >= t); EXPECT_EQ(b2, bias);
}

TEST(get_system_time_precise) {
    REQUIRE(UN(RtlGetSystemTimePrecise));
    LONGLONG a = ft_precise(); LONGLONG r = UN(RtlGetSystemTimePrecise)(); LONGLONG b = ft_precise();
    CHECK(r >= a - 10000 && r <= b + 10000);
    LONGLONG c = ft_now();
    CHECK(r > c - 10000000 && r < c + 10000000);
    LONGLONG prev = r; int mono = 1;
    for (int i = 0; i < 1000; i++) { LONGLONG x = UN(RtlGetSystemTimePrecise)(); if (x < prev) mono = 0; prev = x; }
    CHECK(mono);
}

TEST(get_interrupt_time_precise) {
    REQUIRE(UN(RtlGetInterruptTimePrecise));
    ULONGLONG q1 = 0, q2 = 0;
    LONGLONG i1 = UN(RtlGetInterruptTimePrecise)(&q1);
    Sleep(60);
    LONGLONG i2 = UN(RtlGetInterruptTimePrecise)(&q2);
    CHECK(q1 != 0 && q2 > q1);
    CHECK(i1 > 0 && i2 > i1);
    LONGLONG d = i2 - i1;
    CHECK(d >= 50 * 10000 && d < 5000 * 10000);
    LARGE_INTEGER f; QueryPerformanceFrequency(&f);
    LONGLONG dq = (LONGLONG)((q2 - q1) * 10000000.0 / (double)f.QuadPart);
    CHECK(dq > d - 30 * 10000 && dq < d + 30 * 10000);
    /* interrupt time is close to the coarse shared-data value */
    ULONGLONG coarse = SUD64(0x08);
    CHECK((ULONGLONG)i2 >= coarse - 10 * 10000 && (ULONGLONG)i2 <= coarse + 2000 * 10000ull);
}

TEST(get_multi_time_precise) {
    REQUIRE(UN(RtlGetMultiTimePrecise));
    ULONGLONG out[3]; ULONG got = 0xdead;
    memset(out, 0, sizeof out);
    EXPECT_EQ(UN(RtlGetMultiTimePrecise)(out, 0, &got), 0); EXPECT_EQ(got, 0);
    LARGE_INTEGER q0; QueryPerformanceCounter(&q0);
    got = 0xdead; EXPECT_EQ(UN(RtlGetMultiTimePrecise)(out, 1, &got), 0); EXPECT_EQ(got, 1);
    LARGE_INTEGER q1; QueryPerformanceCounter(&q1);
    CHECK(out[0] >= (ULONGLONG)q0.QuadPart && out[0] <= (ULONGLONG)q1.QuadPart);
    memset(out, 0, sizeof out); got = 0xdead;
    LONGLONG a = ft_precise();
    EXPECT_EQ(UN(RtlGetMultiTimePrecise)(out, 5, &got), 0); EXPECT_EQ(got, 5);
    LONGLONG b = ft_precise();
    CHECK(out[0] != 0); CHECK((LONGLONG)out[2] >= a - 10000 && (LONGLONG)out[2] <= b + 10000);
    got = 0xdead; EXPECT_EQ(UN(RtlGetMultiTimePrecise)(out, 4, &got), 0); EXPECT_EQ(got, 4);
    /* hypervisor time is optional: only the requested bits can be reported */
    got = 0xdead; EXPECT_EQ(UN(RtlGetMultiTimePrecise)(out, 2, &got), 0); CHECK((got & ~2u) == 0);
}

TEST(get_current_processor_number) {
    REQUIRE(UN(RtlGetCurrentProcessorNumber)); REQUIRE(UN(RtlGetCurrentProcessorNumberEx));
    PROCESSOR_NUMBER pn; memset(&pn, 0xCC, sizeof pn);
    UN(RtlGetCurrentProcessorNumberEx)(&pn);
    WORD groups = GetActiveProcessorGroupCount();
    CHECK(pn.Group < groups);
    CHECK(pn.Number < GetActiveProcessorCount(pn.Group));
    ULONG n = UN(RtlGetCurrentProcessorNumber)();
    CHECK(n < 64 || n < GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    if (groups != 1) { t_skip("multiple processor groups: pinning test needs a single group"); return; }
    DWORD_PTR old = SetThreadAffinityMask(GetCurrentThread(), 1);
    if (!old) { t_skip("SetThreadAffinityMask failed"); return; }
    Sleep(1);
    PROCESSOR_NUMBER p2; UN(RtlGetCurrentProcessorNumberEx)(&p2);
    EXPECT_EQ(p2.Number, 0); EXPECT_EQ(p2.Group, 0);
    EXPECT_EQ(UN(RtlGetCurrentProcessorNumber)(), 0);
    SetThreadAffinityMask(GetCurrentThread(), old);
}

TEST(get_enabled_extended_features) {
    REQUIRE(UN(RtlGetEnabledExtendedFeatures));
    ULONGLONG all = UN(RtlGetEnabledExtendedFeatures)(~0ull);
    EXPECT_EQ(UN(RtlGetEnabledExtendedFeatures)(0), 0);
    CHECK((all & 3) == 3);                          /* x87 + SSE are always enabled on x64 */
    EXPECT_EQ(UN(RtlGetEnabledExtendedFeatures)(1), 1);
    EXPECT_EQ(UN(RtlGetEnabledExtendedFeatures)(0xfull), all & 0xfull);
    EXPECT_EQ(UN(RtlGetEnabledExtendedFeatures)(0x8000000000000000ull), 0);
    ULONG64 (WINAPI *k)(ULONG64) = (void *)UIN("kernel32.dll", GetEnabledXStateFeatures);
    if (k) EXPECT_EQ(k(~0ull), all);
}

TEST(get_extended_context_length) {
    REQUIRE(UN(RtlGetExtendedContextLength)); REQUIRE(UN(RtlGetExtendedContextLength2)); REQUIRE(UN(RtlGetEnabledExtendedFeatures));
    ULONG len = 0xdead;
    EXPECT_EQ(UN(RtlGetExtendedContextLength)(CONTEXT_FULL, &len), 0);
    CHECK(len >= sizeof(CONTEXT) + 0x18);
    ULONG plain = len;
    ULONG len2 = 0xdead;
    EXPECT_EQ(UN(RtlGetExtendedContextLength2)(CONTEXT_FULL, &len2, 0), 0);
    EXPECT_EQ(len2, plain);                      /* without XSTATE the mask is irrelevant */
    ULONG x = 0xdead;
    NTSTATUS s = UN(RtlGetExtendedContextLength)(CONTEXT_FULL | CONTEXT_XSTATE, &x);
    EXPECT_EQ(s, 0);
    CHECK(x > plain);
    ULONG x2 = 0xdead;
    EXPECT_EQ(UN(RtlGetExtendedContextLength2)(CONTEXT_FULL | CONTEXT_XSTATE, &x2, UN(RtlGetEnabledExtendedFeatures)(~0ull)), 0);
    EXPECT_EQ(x2, x);
    ULONG x3 = 0xdead;
    EXPECT_EQ(UN(RtlGetExtendedContextLength2)(CONTEXT_FULL | CONTEXT_XSTATE, &x3, 3), 0);
    CHECK(x3 <= x2 && x3 > plain);
    /* the mask is the same as kernel32's InitializeContext length query */
    DWORD need = 0;
    BOOL (WINAPI *ic)(PVOID, DWORD, PCONTEXT *, PDWORD) = (void *)UIN("kernel32.dll", InitializeContext);
    if (ic) { ic(NULL, CONTEXT_FULL | CONTEXT_XSTATE, NULL, &need); EXPECT_EQ(need, x); }
    /* invalid flags */
    ULONG bad = 0xdead;
    EXPECT_EQ(UN(RtlGetExtendedContextLength)(0xdeadbeef, &bad), (NTSTATUS)0xC000000D);
    EXPECT_EQ(bad, 0xdead);
    EXPECT_EQ(UN(RtlGetExtendedContextLength2)(0xdeadbeef, &bad, 0), (NTSTATUS)0xC000000D);
    EXPECT_EQ(bad, 0xdead);
}

TEST(get_longest_nt_path_length) {
    REQUIRE(UN(RtlGetLongestNtPathLength));
    EXPECT_EQ(UN(RtlGetLongestNtPathLength)(), 0x10d);
}

TEST(get_device_family_info) {
    REQUIRE(UN(RtlGetDeviceFamilyInfoEnum));
    ULONGLONG ver = 0xdead; ULONG fam = 0xdead, form = 0xdead;
    UN(RtlGetDeviceFamilyInfoEnum)(&ver, &fam, &form);
    OSVI v; memset(&v, 0, sizeof v); v.Size = 0x11c; UN(RtlGetVersion)(&v);
    EXPECT_EQ((ver >> 48) & 0xffff, v.Major); EXPECT_EQ((ver >> 32) & 0xffff, v.Minor);
    EXPECT_EQ((ver >> 16) & 0xffff, v.Build);
    CHECK(fam != 0xdead && form != 0xdead);
    t_note("DeviceFamily=%lu FormFactor=%lu ver=0x%llx", fam, form, ver);
    /* each output is optional */
    ULONG fam2 = 0xdead; UN(RtlGetDeviceFamilyInfoEnum)(NULL, &fam2, NULL); EXPECT_EQ(fam2, fam);
    ULONGLONG ver2 = 0xdead; UN(RtlGetDeviceFamilyInfoEnum)(&ver2, NULL, NULL); EXPECT_EQ(ver2, ver);
    UN(RtlGetDeviceFamilyInfoEnum)(NULL, NULL, NULL);
}

TEST(get_native_system_information) {
    REQUIRE(UN(RtlGetNativeSystemInformation)); REQUIRE(UN(NtQuerySystemInformation));
    EXPECT_EQ((void *)t_proc("RtlGetNativeSystemInformation"), (void *)t_proc("NtQuerySystemInformation"));
    EXPECT_EQ((void *)t_proc("ZwQuerySystemInformation"), (void *)t_proc("NtQuerySystemInformation"));
    struct { ULONG a, timer, page; BYTE rest[0x34]; } sbi; memset(&sbi, 0, sizeof sbi); ULONG rl = 0;
    EXPECT_EQ(UN(RtlGetNativeSystemInformation)(0, &sbi, sizeof sbi, &rl), 0);
    EXPECT_EQ(rl, sizeof sbi);
    SYSTEM_INFO si; GetNativeSystemInfo(&si);
    CHECK(sbi.page == si.dwPageSize); CHECK(sbi.timer != 0);
    EXPECT_EQ(UN(RtlGetNativeSystemInformation)(0, &sbi, 4, &rl), (NTSTATUS)0xC0000004);
    EXPECT_EQ(UN(RtlGetNativeSystemInformation)(0xfffff, &sbi, sizeof sbi, &rl), (NTSTATUS)0xC0000003);
}

TEST(get_extended_features_mask) {
    REQUIRE(UN(RtlGetExtendedFeaturesMask)); REQUIRE(UN(RtlGetEnabledExtendedFeatures));
    BOOL (WINAPI *ic)(PVOID, DWORD, PCONTEXT *, PDWORD) = (void *)UIN("kernel32.dll", InitializeContext);
    BOOL (WINAPI *setm)(PCONTEXT, DWORD64) = (void *)UIN("kernel32.dll", SetXStateFeaturesMask);
    REQUIRE(ic); REQUIRE(setm);
    ULONGLONG enabled = UN(RtlGetEnabledExtendedFeatures)(~0ull);
    if (!(enabled & 4)) { t_skip("AVX state is not enabled on this processor"); return; }
    DWORD need = 0;
    ic(NULL, CONTEXT_FULL | CONTEXT_XSTATE, NULL, &need);
    BYTE *mem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need);
    PCONTEXT ctx = NULL;
    CHECK(ic(mem, CONTEXT_FULL | CONTEXT_XSTATE, &ctx, &need));
    if (!ctx) { HeapFree(GetProcessHeap(), 0, mem); return; }
    PVOID ex = (BYTE *)ctx + sizeof(CONTEXT);         /* CONTEXT_EX directly follows the legacy context */
    EXPECT_EQ(UN(RtlGetExtendedFeaturesMask)(ex), 0);
    CHECK(setm(ctx, 4));
    EXPECT_EQ(UN(RtlGetExtendedFeaturesMask)(ex), 4);
    CHECK(setm(ctx, 7));
    EXPECT_EQ(UN(RtlGetExtendedFeaturesMask)(ex), 4);   /* x87 and SSE bits are masked off */
    CHECK(setm(ctx, 0));
    EXPECT_EQ(UN(RtlGetExtendedFeaturesMask)(ex), 0);
    HeapFree(GetProcessHeap(), 0, mem);
}

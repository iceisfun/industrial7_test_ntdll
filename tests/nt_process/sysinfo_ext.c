/* Information-class protocols of NtQuerySystemInformation and NtQueryInformationProcess:
 * fixed sizes, length mismatches, invalid classes and sanity of the returned values. */
#include "t.h"

UDECL(NTSTATUS, NtQuerySystemInformation, (ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQuerySystemTime, (PLARGE_INTEGER));

#define XS(x) ((NTSTATUS)(x))
#define XOK(s) ((NTSTATUS)(s) >= 0)
#define XQ_NEED() do { REQUIRE(UN(NtQuerySystemInformation)); } while (0)

typedef struct { ULONG reserved, timer_res, page_size, phys_pages, lowest_page, highest_page, granularity; ULONG_PTR min_addr, max_addr, affinity; CCHAR cpus; } xq_basic;

TEST(nt_process_x_sysinfo_basic_information)
{
    union { ULONGLONG a; BYTE b[128]; } buf; ULONG ret = 0; xq_basic *bi = (xq_basic *)buf.b; SYSTEM_INFO si; XQ_NEED(); REQUIRE(UIN("kernel32.dll", GetNativeSystemInfo));
    memset(&buf, 0xcc, sizeof buf);
    EXPECT_EQ(UN(NtQuerySystemInformation)(0, &buf, 64, &ret), 0);
    EXPECT_EQ(ret, 64);
    UIN("kernel32.dll", GetNativeSystemInfo)(&si);
    EXPECT_EQ(bi->page_size, 4096); EXPECT_EQ(bi->granularity, 65536);
    EXPECT_EQ(bi->min_addr, 0x10000); EXPECT_EQ(bi->max_addr, 0x7FFFFFFEFFFF);
    CHECK((BYTE)bi->cpus >= 1);                                  /* the field is a signed char: only compare when it cannot wrap */
    if (si.dwNumberOfProcessors < 128) EXPECT_EQ((BYTE)bi->cpus, si.dwNumberOfProcessors);
    CHECK(bi->phys_pages > 1000); CHECK(bi->lowest_page <= bi->highest_page);
    CHECK(bi->timer_res >= 10000 && bi->timer_res <= 200000);
    CHECK(bi->affinity != 0);
}
TEST(nt_process_x_sysinfo_length_mismatch_leaves_buffer)
{
    union { ULONGLONG a; BYTE b[128]; } buf; ULONG ret = 0; NTSTATUS s; XQ_NEED();
    memset(&buf, 0xcc, sizeof buf);
    s = UN(NtQuerySystemInformation)(0, &buf, 63, &ret);
    EXPECT_EQ(s, XS(0xC0000004)); EXPECT_EQ(ret, 64);
    for (int i = 0; i < 64; i++) if (buf.b[i] != 0xcc) { CHECK(0 && "buffer written on length mismatch"); break; }
    s = UN(NtQuerySystemInformation)(0, &buf, 0, &ret);
    EXPECT_EQ(s, XS(0xC0000004)); EXPECT_EQ(ret, 64);
    s = UN(NtQuerySystemInformation)(0, &buf, 128, &ret);        /* SystemBasicInformation requires an exact size */
    EXPECT_EQ(s, XS(0xC0000004)); EXPECT_EQ(ret, 64);
    s = UN(NtQuerySystemInformation)(0, &buf, 64, &ret);
    EXPECT_EQ(s, 0); EXPECT_EQ(ret, 64);
}
TEST(nt_process_x_sysinfo_invalid_class)
{
    BYTE buf[64]; ULONG ret = 0x1234; XQ_NEED();
    EXPECT_EQ(UN(NtQuerySystemInformation)(0x7fff, buf, sizeof buf, &ret), XS(0xC0000003));
    EXPECT_EQ(UN(NtQuerySystemInformation)(0xffff, buf, sizeof buf, &ret), XS(0xC0000003));
    EXPECT_EQ(UN(NtQuerySystemInformation)(0x1000, buf, sizeof buf, &ret), XS(0xC0000003));
}
TEST(nt_process_x_sysinfo_return_length_optional)
{
    union { ULONGLONG a; BYTE b[128]; } buf; XQ_NEED();
    EXPECT_EQ(UN(NtQuerySystemInformation)(0, &buf, 64, NULL), 0);
    EXPECT_EQ(UN(NtQuerySystemInformation)(0, &buf, 8, NULL), XS(0xC0000004));
}
TEST(nt_process_x_sysinfo_processor_information)
{
    struct { USHORT arch, level, revision, max_procs; ULONG feature_bits; } pi; ULONG ret = 0; SYSTEM_INFO si; XQ_NEED(); REQUIRE(UIN("kernel32.dll", GetNativeSystemInfo));
    memset(&pi, 0xcc, sizeof pi);
    CHECK(sizeof pi == 12);
    EXPECT_EQ(UN(NtQuerySystemInformation)(1, &pi, 12, &ret), 0);
    EXPECT_EQ(ret, 12); EXPECT_EQ(pi.arch, 9);                    /* PROCESSOR_ARCHITECTURE_AMD64 */
    UIN("kernel32.dll", GetNativeSystemInfo)(&si);
    EXPECT_EQ(pi.level, si.wProcessorLevel); EXPECT_EQ(pi.revision, si.wProcessorRevision);
    EXPECT_EQ(UN(NtQuerySystemInformation)(1, &pi, 11, &ret), XS(0xC0000004));
}
TEST(nt_process_x_sysinfo_time_of_day)
{
    struct { LARGE_INTEGER boot, now, bias; ULONG zone, pad; ULONGLONG boot_bias, sleep_bias; } t; ULONG ret = 0; LARGE_INTEGER n; NTSTATUS s; XQ_NEED(); REQUIRE(UN(NtQuerySystemTime));
    CHECK(sizeof t == 48);
    memset(&t, 0, sizeof t);
    s = UN(NtQuerySystemInformation)(3, &t, sizeof t, &ret);
    EXPECT_EQ(s, 0); EXPECT_EQ(ret, 48);
    UN(NtQuerySystemTime)(&n);
    CHECK(t.boot.QuadPart > 0 && t.boot.QuadPart < t.now.QuadPart);
    CHECK(t.now.QuadPart <= n.QuadPart && n.QuadPart - t.now.QuadPart < 100000000);
    CHECK(t.bias.QuadPart > -24LL * 36000000000 && t.bias.QuadPart < 24LL * 36000000000);
    /* The time-of-day structure has grown between Windows versions; a truncated copy is accepted. */
    s = UN(NtQuerySystemInformation)(3, &t, 47, &ret);
    EXPECT_EQ(s, 0); EXPECT_EQ(ret, 47);
}
TEST(nt_process_x_sysinfo_processor_performance_per_cpu)
{
    ULONG ret = 0; BYTE *buf; ULONG n; NTSTATUS s; XQ_NEED(); REQUIRE(UIN("kernel32.dll", GetNativeSystemInfo)); REQUIRE(UIN("kernel32.dll", VirtualAlloc));
    { SYSTEM_INFO si; UIN("kernel32.dll", GetNativeSystemInfo)(&si); n = si.dwNumberOfProcessors; }
    if (n < 1 || n > 64) { t_skip("processor count %lu is outside a single group", n); return; }
    buf = (BYTE *)UIN("kernel32.dll", VirtualAlloc)(NULL, 64 * 80, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { t_skip("alloc"); return; }
    s = UN(NtQuerySystemInformation)(8, buf, n * 48 - 1, &ret);
    EXPECT_EQ(s, XS(0xC0000004));
    t_note("short processor-performance request returned length %lu", ret);
    s = UN(NtQuerySystemInformation)(8, buf, n * 48, &ret);
    EXPECT_EQ(s, 0); EXPECT_EQ(ret, n * 48);
    if (s == 0) { ULONGLONG idle = *(ULONGLONG *)buf, kernel = *(ULONGLONG *)(buf + 8), user = *(ULONGLONG *)(buf + 16); CHECK(kernel > 0 || user > 0 || idle > 0); CHECK(idle <= kernel + user + idle); }
    UIN("kernel32.dll", VirtualFree)(buf, 0, MEM_RELEASE);
}
TEST(nt_process_x_sysinfo_process_list_size_protocol)
{
    ULONG need = 0, ret = 0; BYTE *buf = NULL; NTSTATUS s; int found_self = 0, idle = 0; ULONG off = 0; XQ_NEED(); REQUIRE(UIN("kernel32.dll", VirtualAlloc)); REQUIRE(UIN("kernel32.dll", GetCurrentProcessId));
    s = UN(NtQuerySystemInformation)(5, NULL, 0, &need);
    EXPECT_EQ(s, XS(0xC0000004)); CHECK(need >= 512);
    for (int attempt = 0; attempt < 8; attempt++) {
        ULONG size = need + 65536 * (attempt + 1);
        buf = (BYTE *)UIN("kernel32.dll", VirtualAlloc)(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) break;
        s = UN(NtQuerySystemInformation)(5, buf, size, &ret);
        if (s == 0) break;
        UIN("kernel32.dll", VirtualFree)(buf, 0, MEM_RELEASE); buf = NULL;
        if (s != XS(0xC0000004)) break;
        need = ret;
    }
    CHECK(buf != NULL && s == 0);
    if (buf && s == 0) {
        DWORD me = UIN("kernel32.dll", GetCurrentProcessId)();
        for (;;) {
            ULONG next = *(ULONG *)(buf + off); ULONG_PTR pid = *(ULONG_PTR *)(buf + off + 80);
            USHORT nlen = *(USHORT *)(buf + off + 56); WCHAR *nm = *(WCHAR **)(buf + off + 64);
            if (pid == me) { found_self = 1; CHECK(nlen > 0 && nm != NULL); CHECK(*(ULONG *)(buf + off + 4) >= 1); }
            if (pid == 0) { idle = 1; CHECK(*(ULONG *)(buf + off + 4) >= 1); }
            if (!next) break;
            off += next;
            if (off >= ret) { CHECK(0 && "entry beyond returned length"); break; }
        }
        EXPECT_EQ(found_self, 1); EXPECT_EQ(idle, 1);
    }
    if (buf) UIN("kernel32.dll", VirtualFree)(buf, 0, MEM_RELEASE);
}
TEST(nt_process_x_sysinfo_kernel_debugger_and_range_start)
{
    BYTE dbg[2] = {0xcc, 0xcc}; ULONG_PTR range = 0; ULONG ret = 0; NTSTATUS s; XQ_NEED();
    s = UN(NtQuerySystemInformation)(35, dbg, 2, &ret);
    EXPECT_EQ(s, 0); EXPECT_EQ(ret, 2); CHECK(dbg[0] <= 1 && dbg[1] <= 1);
    EXPECT_EQ(UN(NtQuerySystemInformation)(35, dbg, 1, &ret), XS(0xC0000004));
    s = UN(NtQuerySystemInformation)(50, &range, sizeof range, &ret);
    EXPECT_EQ(s, 0); EXPECT_EQ(ret, 8); CHECK(range >= 0xFFFF000000000000ULL);
    t_note("system range start=%016llx", (unsigned long long)range);
}

/* ---- process information ---------------------------------------------------- */
#define XP_NEED() do { REQUIRE(UN(NtQueryInformationProcess)); } while (0)
TEST(nt_process_x_procinfo_basic_information)
{
    struct { NTSTATUS exit; PVOID peb; ULONG_PTR affinity; LONG prio; ULONG_PTR pid, ppid; } bi; ULONG ret = 0; XP_NEED();
    CHECK(sizeof bi == 48);
    memset(&bi, 0xcc, sizeof bi);
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 0, &bi, 48, &ret), 0);
    EXPECT_EQ(ret, 48);
    EXPECT_EQ(bi.exit, 259);                                     /* STATUS_PENDING: still running */
    EXPECT_EQ(bi.pid, GetCurrentProcessId());
    EXPECT_EQ(bi.peb, NtCurrentTeb()->ProcessEnvironmentBlock);
    CHECK(bi.affinity != 0); CHECK(bi.prio >= 4 && bi.prio <= 24);
    CHECK(bi.ppid != 0 && bi.ppid != bi.pid);
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 0, &bi, 47, &ret), XS(0xC0000004));
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 0, &bi, 0, &ret), XS(0xC0000004));
}
typedef struct { ULONG cls; ULONG size; const char *name; } xp_fixed;
static const xp_fixed xp_fixed_classes[] = {
    { 2, 48, "IoCounters" }, { 4, 32, "Times" }, { 7, 8, "DebugPort" }, { 12, 4, "DefaultHardErrorMode" }, { 18, 2, "PriorityClass" },
    { 20, 4, "HandleCount" }, { 22, 4, "PriorityBoost" }, { 24, 4, "SessionInformation" }, { 26, 8, "Wow64Information" },
    { 29, 4, "BreakOnTermination" }, { 31, 4, "DebugFlags" }, { 36, 4, "Cookie" },
};
TEST(nt_process_x_procinfo_fixed_size_classes)
{
    XP_NEED();
    for (size_t i = 0; i < sizeof xp_fixed_classes / sizeof xp_fixed_classes[0]; i++) {
        union { ULONGLONG a; BYTE b[128]; } buf; ULONG ret = 0; NTSTATUS s; const xp_fixed *c = &xp_fixed_classes[i];
        memset(&buf, 0xcc, sizeof buf);
        s = UN(NtQueryInformationProcess)(GetCurrentProcess(), c->cls, &buf, c->size, &ret);
        CHECKF(s == 0, "%s status=%08lx", c->name, s);
        if (s == 0) CHECKF(ret == c->size, "%s length=%lu", c->name, ret);
        s = UN(NtQueryInformationProcess)(GetCurrentProcess(), c->cls, &buf, c->size - 1, &ret);
        CHECKF(s == XS(0xC0000004), "%s short status=%08lx", c->name, s);
    }
}
TEST(nt_process_x_procinfo_known_values)
{
    ULONG v = 0xcc; ULONGLONG q[4]; ULONG ret; ULONG pc = 0; ULONG_PTR dbgport = 1, wow = 1; XP_NEED();
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 20, &v, 4, &ret), 0); CHECK(v >= 3);        /* at least std handles / process / thread */
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 7, &dbgport, 8, &ret), 0); EXPECT_EQ(dbgport, 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 26, &wow, 8, &ret), 0); EXPECT_EQ(wow, 0);  /* native 64-bit process */
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 31, &v, 4, &ret), 0); EXPECT_EQ(v, 1);      /* debugger inheritance not suppressed */
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 29, &v, 4, &ret), 0); EXPECT_EQ(v, 0);
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 36, &v, 4, &ret), 0); CHECK(v != 0);
    /* ProcessPriorityClass: PROCESS_PRIORITY_CLASS { BOOLEAN Foreground; UCHAR PriorityClass; }, buffer must be 4-byte aligned */
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 18, &pc, 2, &ret), 0); CHECK(((pc >> 8) & 0xff) >= 1 && ((pc >> 8) & 0xff) <= 5);
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 4, q, 32, &ret), 0);
    CHECK(q[0] > 132223104000000000ULL);                          /* creation time after 2020 */
    CHECK(q[1] == 0);                                             /* exit time of a live process */
}
TEST(nt_process_x_procinfo_image_file_name)
{
    union { ULONGLONG a; BYTE b[1024]; } buf; ULONG ret = 0, first; NTSTATUS s; UNICODE_STRING *u = (UNICODE_STRING *)buf.b; XP_NEED();
    s = UN(NtQueryInformationProcess)(GetCurrentProcess(), 27, NULL, 0, &ret);
    EXPECT_EQ(s, XS(0xC0000004)); CHECK(ret > sizeof(UNICODE_STRING)); first = ret;
    s = UN(NtQueryInformationProcess)(GetCurrentProcess(), 27, &buf, first - 1, &ret);
    EXPECT_EQ(s, XS(0xC0000004));
    if (first <= sizeof buf) {
        s = UN(NtQueryInformationProcess)(GetCurrentProcess(), 27, &buf, first, &ret);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            const char *self = t_self_path(); WCHAR tail[260]; int n = 0; const char *base = strrchr(self, '\\'); base = base ? base + 1 : self;
            while (base[n] && n < 259) { tail[n] = (WCHAR)base[n]; n++; } tail[n] = 0;
            CHECK(u->Length >= n * 2 && u->Buffer != NULL);
            CHECK((BYTE *)u->Buffer >= buf.b && (BYTE *)u->Buffer < buf.b + first);   /* string stored inside the caller's buffer */
            if (u->Length >= n * 2) CHECK(!_wcsnicmp(u->Buffer + u->Length / 2 - n, tail, n));
            CHECK(u->Buffer[0] == L'\\');                         /* NT path form: \Device\HarddiskVolumeN\... */
        }
    }
}
TEST(nt_process_x_procinfo_invalid_class_and_handle)
{
    BYTE buf[256]; ULONG ret = 0; HANDLE sync; XP_NEED();
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 0xff, buf, sizeof buf, &ret), XS(0xC0000003));
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 0x7fffffff, buf, sizeof buf, &ret), XS(0xC0000003));
    EXPECT_EQ(UN(NtQueryInformationProcess)((HANDLE)(ULONG_PTR)0x7ffc, 0, buf, 48, &ret), XS(0xC0000008));
    EXPECT_EQ(UN(NtQueryInformationProcess)(NULL, 0, buf, 48, &ret), XS(0xC0000008));
    REQUIRE(UIN("kernel32.dll", OpenProcess)); REQUIRE(UIN("kernel32.dll", CloseHandle));
    sync = UIN("kernel32.dll", OpenProcess)(SYNCHRONIZE, FALSE, GetCurrentProcessId());
    if (sync) { EXPECT_EQ(UN(NtQueryInformationProcess)(sync, 0, buf, 48, &ret), XS(0xC0000022)); UIN("kernel32.dll", CloseHandle)(sync); }
}
TEST(nt_process_x_procinfo_limited_access_handle)
{
    BYTE buf[128]; ULONG ret = 0; HANDLE lim; NTSTATUS s; XP_NEED(); REQUIRE(UIN("kernel32.dll", OpenProcess)); REQUIRE(UIN("kernel32.dll", CloseHandle));
    lim = UIN("kernel32.dll", OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    CHECK(lim != NULL); if (!lim) return;
    s = UN(NtQueryInformationProcess)(lim, 0, buf, 48, &ret); EXPECT_EQ(s, 0);        /* basic information needs only limited access */
    s = UN(NtQueryInformationProcess)(lim, 27, buf, sizeof buf, &ret); CHECK(s == 0 || s == XS(0xC0000004) || s == XS(0xC0000022));
    t_note("image name through a limited handle status=%08lx", s);
    s = UN(NtQueryInformationProcess)(lim, 20, buf, 4, &ret); t_note("handle count through a limited handle status=%08lx", s);
    UIN("kernel32.dll", CloseHandle)(lim);
}

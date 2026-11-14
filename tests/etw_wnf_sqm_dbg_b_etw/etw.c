/* ETW user-mode helpers, NtTraceControl/NtTraceEvent, WNF state update and the RtlWnf* helpers.
 *
 * NtTraceControl(FunctionCode, InBuffer, InSize, OutBuffer, OutSize, ReturnLength)
 * NtTraceEvent(TraceHandle, Flags, FieldSize, Fields)
 * NtUpdateWnfStateData(StateName*, Buffer, Length, TypeId*, ExplicitScope, MatchingChangeStamp, CheckStamp)
 * EtwUnregisterTraceGuids(RegHandle) -> Win32 error     EtwRegisterTraceGuidsW is used only to obtain a handle
 * EtwTraceMessageVa(LoggerFlags, MessageFlags, Guid*, MessageNumber, va_list) -> Win32 error
 * EtwWriteUMSecurityEvent(Guid*, USHORT, ULONG, ULONGLONG) -> Win32 error
 * EtwpGetCpuSpeed(ULONG *Mhz) -> NTSTATUS       EtwpCreateEtwThread(Start, Param) -> thread HANDLE or 0
 * RtlWnfCompareChangeStamp(a, b) -> -1/0/1      RtlWnfDllUnloadCallback(HMODULE, ...) -> NTSTATUS
 * NtCreate/Query/DeleteWnfStateName are used only as fixtures for the WNF update tests.
 *
 * Status codes: STATUS_INVALID_PARAMETER c000000d, STATUS_INVALID_DEVICE_REQUEST c0000010,
 * STATUS_ACCESS_VIOLATION c0000005, STATUS_UNSUCCESSFUL c0000001, STATUS_OBJECT_NAME_NOT_FOUND c0000034,
 * STATUS_INVALID_BUFFER_SIZE c0000206, STATUS_DLL_NOT_FOUND c0000135, STATUS_ACCESS_DENIED c0000022.
 */
#include "t.h"

UDECL(NTSTATUS, NtTraceControl, (ULONG, PVOID, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtTraceEvent, (HANDLE, ULONG, ULONG, PVOID));
UDECL(NTSTATUS, NtUpdateWnfStateData, (const ULONGLONG *, const void *, ULONG, const void *, const void *, ULONG, ULONG));
UDECL(NTSTATUS, NtCreateWnfStateName, (ULONGLONG *, ULONG, ULONG, ULONG, const void *, ULONG, PVOID));
UDECL(NTSTATUS, NtDeleteWnfStateName, (const ULONGLONG *));
UDECL(NTSTATUS, NtQueryWnfStateData, (const ULONGLONG *, const void *, const void *, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PVOID, ULONG));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PVOID, BOOLEAN, PVOID, BOOLEAN));
UDECL(ULONG, EtwUnregisterTraceGuids, (ULONGLONG));
UDECL(ULONG, EtwRegisterTraceGuidsW, (PVOID, PVOID, const GUID *, ULONG, PVOID, const WCHAR *, const WCHAR *, ULONGLONG *));
UDECL(ULONG, EtwWriteUMSecurityEvent, (const GUID *, USHORT, ULONG, ULONGLONG));
UDECL(ULONG, EtwTraceMessageVa, (ULONGLONG, ULONG, const GUID *, USHORT, PVOID));
UDECL(NTSTATUS, EtwpGetCpuSpeed, (ULONG *));
UDECL(HANDLE, EtwpCreateEtwThread, (PVOID, PVOID));
UDECL(LONG, RtlWnfCompareChangeStamp, (ULONG, ULONG));
UDECL(NTSTATUS, RtlWnfDllUnloadCallback, (HMODULE, PVOID, PVOID, PVOID));

#define ST_INVALID_PARAMETER   ((NTSTATUS)0xC000000D)
#define ST_INVALID_DEVICE_REQ  ((NTSTATUS)0xC0000010)
#define ST_UNSUCCESSFUL        ((NTSTATUS)0xC0000001)
#define ST_NAME_NOT_FOUND      ((NTSTATUS)0xC0000034)
#define ST_BUFFER_SIZE         ((NTSTATUS)0xC0000206)
#define ST_DLL_NOT_FOUND       ((NTSTATUS)0xC0000135)
#define ST_DENIED              ((NTSTATUS)0xC0000022)
#define ST_ACCESS_VIOLATION    ((NTSTATUS)0xC0000005)

/* ---- NtTraceControl / NtTraceEvent ---- */

TEST(trace_alias_pairs)
{
    CHECK(t_proc("NtTraceControl") && t_proc("NtTraceControl") == t_proc("ZwTraceControl"));
    CHECK(t_proc("NtTraceEvent") && t_proc("NtTraceEvent") == t_proc("ZwTraceEvent"));
    CHECK(t_proc("NtUpdateWnfStateData") && t_proc("NtUpdateWnfStateData") == t_proc("ZwUpdateWnfStateData"));
}

static int denied(NTSTATUS s, const char *what)
{
    if (s == ST_DENIED) { t_skip("%s: STATUS_ACCESS_DENIED for this account (needs trace privilege)", what); return 1; }
    return 0;
}

TEST(trace_control_codes)
{
    REQUIRE(UN(NtTraceControl));
    BYTE in[64], out[64];
    ULONG rl;
    NTSTATUS s;

    /* function codes that are not implemented */
    static const ULONG unimpl[] = { 0x00, 0x2c, 0x2d, 0x2e, 0x2f };
    for (size_t i = 0; i < sizeof unimpl / sizeof *unimpl; i++) {
        memset(in, 0, sizeof in); rl = 0xdeadbeef;
        s = UN(NtTraceControl)(unimpl[i], in, sizeof in, out, sizeof out, &rl);
        if (denied(s, "NtTraceControl unimplemented code")) return;
        CHECKF(s == ST_INVALID_DEVICE_REQ, "code %lx -> %08lx", unimpl[i], (ULONG)s);
        EXPECT_EQ(rl, 0xdeadbeef);
    }
    /* an out-of-range function code */
    s = UN(NtTraceControl)(0xFFF, NULL, 0, NULL, 0, NULL);
    if (denied(s, "NtTraceControl 0xfff")) return;
    EXPECT_EQ((ULONG)s, (ULONG)ST_INVALID_PARAMETER);
    s = UN(NtTraceControl)(0xFFFFFFFF, in, sizeof in, out, sizeof out, &rl);
    if (denied(s, "NtTraceControl -1")) return;
    EXPECT_EQ((ULONG)s, (ULONG)ST_INVALID_DEVICE_REQ);

    /* session control codes 1..7 take a WNODE_HEADER/EVENT_TRACE_PROPERTIES sized input: 64 zero bytes is not */
    for (ULONG c = 1; c <= 7; c++) {
        memset(in, 0, sizeof in); rl = 0xdeadbeef;
        s = UN(NtTraceControl)(c, in, sizeof in, out, sizeof out, &rl);
        if (denied(s, "NtTraceControl session code")) return;
        CHECKF(s == ST_BUFFER_SIZE, "code %lu -> %08lx", c, (ULONG)s);
    }
}

TEST(trace_control_query_codes)
{
    REQUIRE(UN(NtTraceControl));
    /* observed-only: these function codes succeed with a 64-byte zero input and report a fixed output length */
    struct { ULONG code, len; } q[] = { { 0x27, 8 }, { 0x2a, 4 }, { 0x2b, 4 } };
    for (int i = 0; i < 3; i++) {
        BYTE in[64], out[64]; ULONG rl = 0xdeadbeef;
        memset(in, 0, sizeof in); memset(out, 0, sizeof out);
        NTSTATUS s = UN(NtTraceControl)(q[i].code, in, sizeof in, out, sizeof out, &rl);
        if (denied(s, "NtTraceControl query code")) return;
        CHECKF(s == 0, "code %lx -> %08lx", q[i].code, (ULONG)s);
        CHECKF(rl == q[i].len, "code %lx rl=%lu want %lu", q[i].code, rl, q[i].len);
    }
}

TEST(trace_event_invalid)
{
    REQUIRE(UN(NtTraceEvent));
    BYTE data[0x40]; memset(data, 0, sizeof data);
    static const struct { HANDLE h; ULONG flags, size; int data; } c[] = {
        { NULL, 0, 0, 0 }, { (HANDLE)8, 1, 0, 0 }, { NULL, 2, 0x1c, 1 }, { NULL, 0x20, 0x1c, 1 }, { NULL, 0x40, 0x1c, 1 } };
    for (size_t i = 0; i < sizeof c / sizeof *c; i++) {
        NTSTATUS s = UN(NtTraceEvent)(c[i].h, c[i].flags, c[i].size, c[i].data ? data : NULL);
        if (denied(s, "NtTraceEvent")) return;
        CHECKF(s == ST_INVALID_PARAMETER, "case %zu -> %08lx", i, (ULONG)s);
    }
}

/* ---- Etw* ---- */

static ULONG WINAPI reg_cb(ULONG a, PVOID b, PVOID c) { (void)a; (void)b; (void)c; return 0; }

TEST(etw_unregister_trace_guids)
{
    REQUIRE(UN(EtwUnregisterTraceGuids)); REQUIRE(UN(EtwRegisterTraceGuidsW));
    EXPECT_EQ(UN(EtwUnregisterTraceGuids)(0), ERROR_INVALID_HANDLE);
    EXPECT_EQ(UN(EtwUnregisterTraceGuids)(0x1234), ERROR_INVALID_HANDLE);
    EXPECT_EQ(UN(EtwUnregisterTraceGuids)((ULONGLONG)-1), ERROR_INVALID_HANDLE);

    GUID ctl = { 0x6f1d3b52, 0x44c1, 0x4a77, { 0x91, 0x0e, 0x5a, 0x03, 0x0c, 0x77, 0x11, 0x42 } };
    ULONGLONG h = 0;
    ULONG r = UN(EtwRegisterTraceGuidsW)(reg_cb, NULL, &ctl, 0, NULL, NULL, NULL, &h);
    EXPECT_EQ(r, ERROR_SUCCESS);
    CHECK(h != 0);
    if (r != ERROR_SUCCESS) return;
    SetLastError(0x1234);
    EXPECT_EQ(UN(EtwUnregisterTraceGuids)(h), ERROR_SUCCESS);
    /* the handle is gone: a second unregister fails */
    EXPECT_EQ(UN(EtwUnregisterTraceGuids)(h), ERROR_INVALID_HANDLE);

    /* two live registrations get distinct handles and unregister independently */
    ULONGLONG h1 = 0, h2 = 0;
    CHECK(UN(EtwRegisterTraceGuidsW)(reg_cb, NULL, &ctl, 0, NULL, NULL, NULL, &h1) == 0);
    CHECK(UN(EtwRegisterTraceGuidsW)(reg_cb, NULL, &ctl, 0, NULL, NULL, NULL, &h2) == 0);
    CHECK(h1 != 0 && h2 != 0 && h1 != h2);
    EXPECT_EQ(UN(EtwUnregisterTraceGuids)(h1), ERROR_SUCCESS);
    EXPECT_EQ(UN(EtwUnregisterTraceGuids)(h1), ERROR_INVALID_HANDLE);
    EXPECT_EQ(UN(EtwUnregisterTraceGuids)(h2), ERROR_SUCCESS);
}

TEST(etw_trace_message_va_invalid_logger)
{
    REQUIRE(UN(EtwTraceMessageVa));
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } };
    struct { PVOID p; SIZE_T n; } va[2] = { { 0, 0 }, { 0, 0 } };   /* empty (terminated) argument list */
    ULONG r = UN(EtwTraceMessageVa)(0, 0, &g, 1, va);
    EXPECT_EQ(r, ERROR_INVALID_HANDLE);
    r = UN(EtwTraceMessageVa)(0x1234, 2, &g, 7, va);
    EXPECT_EQ(r, ERROR_INVALID_HANDLE);
}

TEST(etw_write_um_security_event)
{
    REQUIRE(UN(EtwWriteUMSecurityEvent));
    EXPECT_EQ(UN(EtwWriteUMSecurityEvent)(NULL, 0, 0, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(EtwWriteUMSecurityEvent)(NULL, 5, 7, 0x1000), ERROR_INVALID_PARAMETER);
    /* only the security auditing component may write: everyone else is refused by the kernel */
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } };
    ULONG r = UN(EtwWriteUMSecurityEvent)(&g, 0, 0, 0);
    EXPECT_EQ(r, ERROR_ACCESS_DENIED);
}

TEST(etw_cpu_speed)
{
    REQUIRE(UN(EtwpGetCpuSpeed));
    ULONG mhz = 0xdeadbeef;
    NTSTATUS s = UN(EtwpGetCpuSpeed)(&mhz);
    if (s == (NTSTATUS)0xC0000034) { t_skip("no ~MHz value for CPU 0 in the registry on this machine"); return; }
    EXPECT_EQ((ULONG)s, 0);
    CHECKF(mhz > 0 && mhz < 100000, "mhz=%lu", mhz);

    /* it reports the ~MHz value of HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0 */
    HMODULE adv = LoadLibraryA("advapi32.dll");
    LONG (WINAPI *pRegGet)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD) =
        adv ? (void *)GetProcAddress(adv, "RegGetValueA") : NULL;
    if (!pRegGet) { t_skip("RegGetValueA not available"); return; }
    DWORD v = 0, cb = sizeof v, type = 0;
    LONG e = pRegGet(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "~MHz",
                     RRF_RT_REG_DWORD, &type, &v, &cb);
    if (e != ERROR_SUCCESS) { t_skip("cannot read ~MHz from the registry (error %ld)", e); return; }
    EXPECT_EQ(mhz, v);
}

static volatile LONG g_thr_ran; static HANDLE g_thr_evt; static ULONG_PTR g_thr_param;
static DWORD WINAPI thr_proc(LPVOID p)
{
    g_thr_param = (ULONG_PTR)p;
    InterlockedIncrement(&g_thr_ran);
    SetEvent(g_thr_evt);
    return 77;
}

TEST(etw_create_etw_thread)
{
    REQUIRE(UN(EtwpCreateEtwThread));
    g_thr_ran = 0; g_thr_param = 0;
    g_thr_evt = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(g_thr_evt != NULL);
    HANDLE th = UN(EtwpCreateEtwThread)((PVOID)thr_proc, (PVOID)0x5150);
    CHECK(th != NULL);
    if (th) {
        /* the thread is created suspended and resumed before return: it runs on its own */
        EXPECT_EQ(WaitForSingleObject(g_thr_evt, 10000), WAIT_OBJECT_0);
        EXPECT_EQ(g_thr_ran, 1);
        EXPECT_EQ(g_thr_param, 0x5150);
        EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
        DWORD code = 0;
        CHECK(GetExitCodeThread(th, &code));
        EXPECT_EQ(code, 77);
        CHECK(GetThreadId(th) != 0);
        CHECK(GetThreadId(th) != GetCurrentThreadId());
        CloseHandle(th);
    }
    CloseHandle(g_thr_evt);
}

/* ---- WNF ---- */

TEST(wnf_compare_change_stamp)
{
    REQUIRE(UN(RtlWnfCompareChangeStamp));
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(0, 0), 0);
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(5, 5), 0);
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(0xFFFFFFFF, 0xFFFFFFFF), 0);
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(1, 2), -1);
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(2, 1), 1);
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(0, 1), -1);
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(1, 0), 1);
    /* unsigned comparison, no wraparound handling */
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(0x7FFFFFFF, 0x80000000), -1);
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(0x80000000, 0x7FFFFFFF), 1);
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(0xFFFFFFFF, 0), 1);
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(0, 0xFFFFFFFF), -1);
    EXPECT_EQ(UN(RtlWnfCompareChangeStamp)(0xFFFFFFFE, 0xFFFFFFFF), -1);
}

static const char *const g_unload_candidates[] = { "msimg32.dll", "winmm.dll", "version.dll", "winspool.drv", "wsock32.dll" };

TEST(wnf_dll_unload_callback)
{
    REQUIRE(UN(RtlWnfDllUnloadCallback));
    /* handles that are not loaded modules */
    EXPECT_EQ((ULONG)UN(RtlWnfDllUnloadCallback)(NULL, 0, 0, 0), (ULONG)ST_DLL_NOT_FOUND);
    EXPECT_EQ((ULONG)UN(RtlWnfDllUnloadCallback)((HMODULE)0x10000, 0, 0, 0), (ULONG)ST_DLL_NOT_FOUND);
    EXPECT_EQ((ULONG)UN(RtlWnfDllUnloadCallback)((HMODULE)(ULONG_PTR)-1, 0, 0, 0), (ULONG)ST_DLL_NOT_FOUND);

    const char *name = NULL;
    for (size_t i = 0; i < sizeof g_unload_candidates / sizeof *g_unload_candidates; i++)
        if (!GetModuleHandleA(g_unload_candidates[i])) { name = g_unload_candidates[i]; break; }
    if (!name) { t_skip("no candidate module is free of earlier loads in this process"); return; }

    /* one reference: the callback drops it exactly like FreeLibrary and the module goes away */
    HMODULE m = LoadLibraryA(name);
    if (!m) { t_skip("cannot load %s", name); return; }
    CHECK(GetModuleHandleA(name) == m);
    NTSTATUS s = UN(RtlWnfDllUnloadCallback)(m, 0, 0, 0);
    EXPECT_EQ((ULONG)s, 0);
    CHECK(GetModuleHandleA(name) == NULL);
    /* the stale handle is no longer a loaded module */
    EXPECT_EQ((ULONG)UN(RtlWnfDllUnloadCallback)(m, 0, 0, 0), (ULONG)ST_DLL_NOT_FOUND);

    /* two references: one callback leaves it loaded, a second FreeLibrary unloads it */
    m = LoadLibraryA(name);
    HMODULE m2 = LoadLibraryA(name);
    CHECK(m && m2 == m);
    if (m) {
        EXPECT_EQ((ULONG)UN(RtlWnfDllUnloadCallback)(m, 0, 0, 0), 0);
        CHECK(GetModuleHandleA(name) == m);
        CHECK(FreeLibrary(m));
        CHECK(GetModuleHandleA(name) == NULL);
    }
}

static int make_name(ULONGLONG *sn)
{
    BYTE sd[64];
    if (!UN(NtCreateWnfStateName) || !UN(NtDeleteWnfStateName) || !UN(NtQueryWnfStateData) ||
        !UN(RtlCreateSecurityDescriptor) || !UN(RtlSetDaclSecurityDescriptor)) return 0;
    UN(RtlCreateSecurityDescriptor)(sd, 1);
    UN(RtlSetDaclSecurityDescriptor)(sd, TRUE, NULL, FALSE);     /* NULL DACL: everyone */
    *sn = 0;
    /* temporary lifetime (3), user scope (2), maximum state size 0x1000 */
    NTSTATUS s = UN(NtCreateWnfStateName)(sn, 3, 2, 0, NULL, 0x1000, sd);
    return s == 0 && *sn != 0;
}

static NTSTATUS wnf_query(ULONGLONG *sn, ULONG *stamp, void *buf, ULONG *len)
{
    return UN(NtQueryWnfStateData)(sn, NULL, NULL, stamp, buf, len);
}

TEST(wnf_update_state_data)
{
    REQUIRE(UN(NtUpdateWnfStateData));
    ULONGLONG sn;
    if (!make_name(&sn)) { t_skip("cannot create a temporary WNF state name on this machine"); return; }
    BYTE data[0x1000], got[0x1000];
    ULONG stamp = 0xdead, len = sizeof got;
    NTSTATUS s;

    /* fresh name: no data, change stamp 0 */
    s = wnf_query(&sn, &stamp, got, &len);
    EXPECT_EQ((ULONG)s, 0); EXPECT_EQ(stamp, 0); EXPECT_EQ(len, 0);

    memcpy(data, "\x11\x22\x33\x44\x55", 5);
    s = UN(NtUpdateWnfStateData)(&sn, data, 5, NULL, NULL, 0, 0);
    EXPECT_EQ((ULONG)s, 0);
    memset(got, 0xEE, sizeof got); len = sizeof got; stamp = 0xdead;
    s = wnf_query(&sn, &stamp, got, &len);
    EXPECT_EQ((ULONG)s, 0); EXPECT_EQ(stamp, 1); EXPECT_EQ(len, 5);
    CHECK(!memcmp(got, data, 5));

    /* conditional update: stamp must match when CheckStamp is non-zero */
    s = UN(NtUpdateWnfStateData)(&sn, data, 3, NULL, NULL, 5, 1);
    EXPECT_EQ((ULONG)s, (ULONG)ST_UNSUCCESSFUL);
    len = sizeof got; s = wnf_query(&sn, &stamp, got, &len);
    EXPECT_EQ(stamp, 1); EXPECT_EQ(len, 5);                      /* unchanged */
    s = UN(NtUpdateWnfStateData)(&sn, data, 3, NULL, NULL, 1, 1);
    EXPECT_EQ((ULONG)s, 0);
    len = sizeof got; s = wnf_query(&sn, &stamp, got, &len);
    EXPECT_EQ(stamp, 2); EXPECT_EQ(len, 3);
    /* CheckStamp 0 ignores MatchingChangeStamp */
    s = UN(NtUpdateWnfStateData)(&sn, data, 4, NULL, NULL, 99, 0);
    EXPECT_EQ((ULONG)s, 0);
    len = sizeof got; wnf_query(&sn, &stamp, got, &len);
    EXPECT_EQ(stamp, 3); EXPECT_EQ(len, 4);

    /* zero-length update with a NULL buffer clears the data and still bumps the stamp */
    s = UN(NtUpdateWnfStateData)(&sn, NULL, 0, NULL, NULL, 0, 0);
    EXPECT_EQ((ULONG)s, 0);
    len = sizeof got; wnf_query(&sn, &stamp, got, &len);
    EXPECT_EQ(stamp, 4); EXPECT_EQ(len, 0);

    /* size limits: the creation maximum is 0x1000 */
    memset(data, 0x6B, sizeof data);
    s = UN(NtUpdateWnfStateData)(&sn, data, 0x1000, NULL, NULL, 0, 0);
    EXPECT_EQ((ULONG)s, 0);
    len = sizeof got; memset(got, 0, sizeof got); s = wnf_query(&sn, &stamp, got, &len);
    EXPECT_EQ(len, 0x1000); EXPECT_EQ(stamp, 5);
    CHECK(!memcmp(got, data, 0x1000));
    BYTE *big = (BYTE *)calloc(0x2001, 1);
    CHECK(big != NULL);
    if (big) {
        s = UN(NtUpdateWnfStateData)(&sn, big, 0x1001, NULL, NULL, 0, 0);
        EXPECT_EQ((ULONG)s, (ULONG)ST_INVALID_PARAMETER);
        s = UN(NtUpdateWnfStateData)(&sn, big, 0x2000, NULL, NULL, 0, 0);
        EXPECT_EQ((ULONG)s, (ULONG)ST_INVALID_PARAMETER);
        free(big);
    }
    len = sizeof got; wnf_query(&sn, &stamp, got, &len);
    EXPECT_EQ(stamp, 5);                                         /* rejected updates do not bump it */

    /* non-zero length with a NULL buffer faults in the kernel's probe and is reported, not raised */
    s = UN(NtUpdateWnfStateData)(&sn, NULL, 4, NULL, NULL, 0, 0);
    EXPECT_EQ((ULONG)s, (ULONG)ST_ACCESS_VIOLATION);
    /* NULL state name */
    s = UN(NtUpdateWnfStateData)(NULL, data, 4, NULL, NULL, 0, 0);
    EXPECT_EQ((ULONG)s, (ULONG)ST_ACCESS_VIOLATION);

    UN(NtDeleteWnfStateName)(&sn);
    /* deleted name */
    s = UN(NtUpdateWnfStateData)(&sn, data, 4, NULL, NULL, 0, 0);
    EXPECT_EQ((ULONG)s, (ULONG)ST_NAME_NOT_FOUND);
}

TEST(wnf_update_bogus_name)
{
    REQUIRE(UN(NtUpdateWnfStateData));
    BYTE data[4] = { 1, 2, 3, 4 };
    /* a value that does not decode to a valid state-name (wrong version/lifetime/scope bits) */
    ULONGLONG bogus = 0x0123456789ABCDEFULL;
    NTSTATUS s = UN(NtUpdateWnfStateData)(&bogus, data, 4, NULL, NULL, 0, 0);
    EXPECT_EQ((ULONG)s, (ULONG)ST_INVALID_PARAMETER);
    ULONGLONG zero = 0;
    s = UN(NtUpdateWnfStateData)(&zero, data, 4, NULL, NULL, 0, 0);
    EXPECT_EQ((ULONG)s, (ULONG)ST_INVALID_PARAMETER);
}

/* Rarely-used native services: validation behaviour of calls that cannot be driven to success from an
 * ordinary process (enclave termination, UMS yield, activity references, driver unload, partition unit
 * replacement, WNF subscription, VDM control) and the window-procedure helpers.
 * Expected values: see EVIDENCE.md. */
#include "t.h"

#define S(x) ((NTSTATUS)(x))
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_INV_PARAM    S(0xC000000D)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_PRIV_NOT_HELD S(0xC0000061)
#define BOGUS ((HANDLE)(ULONG_PTR)0x7ffffff4)
#define ST_DENIED S(0xC0000022)
#define ST_NOT_IMPL S(0xC0000002)
#define NT_CUR_PROC ((HANDLE)(LONG_PTR)-1)

UDECL(NTSTATUS, NtRegisterProtocolAddressInformation, (HANDLE, PVOID, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtTerminateEnclave, (PVOID, BOOLEAN));
UDECL(NTSTATUS, NtTranslateFilePath, (PVOID, ULONG, PVOID, PULONG));
UDECL(NTSTATUS, NtUmsThreadYield, (PVOID));
UDECL(NTSTATUS, NtUnloadDriver, (PUNICODE_STRING));
UDECL(NTSTATUS, NtVdmControl, (ULONG, PVOID));
UDECL(NTSTATUS, NtAcquireCrossVmMutant, (HANDLE, PLARGE_INTEGER));
UDECL(NTSTATUS, NtAcquireProcessActivityReference, (PHANDLE, HANDLE, ULONG));
UDECL(NTSTATUS, NtReplacePartitionUnit, (PUNICODE_STRING, PUNICODE_STRING, ULONG));
UDECL(NTSTATUS, NtRevertContainerImpersonation, (void));
UDECL(NTSTATUS, NtSubscribeWnfStateChange, (PVOID, ULONG, ULONG, PULONGLONG));
UDECL(NTSTATUS, NtUnsubscribeWnfStateChange, (PVOID));
UDECL(NTSTATUS, NtSerializeBoot, (void));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));
typedef LRESULT (WINAPI *wndproc_pfn)(HWND, UINT, WPARAM, LPARAM);

#define EXPECT_ST(call, want) do { NTSTATUS st_ = (call); t_check(st_ == (NTSTATUS)(want), __FILE__, __LINE__, #call " == " #want, "got 0x%lx want 0x%lx", (unsigned long)st_, (unsigned long)(NTSTATUS)(want)); } while (0)
#define NOTE(call) do { NTSTATUS st_ = (call); t_note(#call " -> 0x%lx", (unsigned long)st_); } while (0)

TEST(vdm_control)
{
    REQUIRE(UN(NtVdmControl));
    BYTE data[64] = {0};
    /* no VDM on a 64-bit process: every service fails before looking at its arguments */
    EXPECT_ST(UN(NtVdmControl)(0, data), ST_NOT_IMPL);
    EXPECT_ST(UN(NtVdmControl)(1, NULL), ST_NOT_IMPL);
    EXPECT_ST(UN(NtVdmControl)(0xFFFF, data), ST_NOT_IMPL);
}

TEST(enclave_ums_activity)
{
    REQUIRE(UN(NtTerminateEnclave)); REQUIRE(UN(NtUmsThreadYield));
    BYTE *p = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    REQUIRE(p);
    EXPECT_ST(UN(NtTerminateEnclave)(p, FALSE), S(0xC0000018));    /* STATUS_CONFLICTING_ADDRESSES: not an enclave */
    EXPECT_ST(UN(NtTerminateEnclave)(NULL, FALSE), S(0xC00000A0)); /* STATUS_MEMORY_NOT_ALLOCATED */
    VirtualFree(p, 0, MEM_RELEASE);
    EXPECT_ST(UN(NtUmsThreadYield)(NULL), S(0xC00000BB));          /* STATUS_NOT_SUPPORTED: not a UMS thread */
    EXPECT_ST(UN(NtUmsThreadYield)(p), S(0xC00000BB));
    if (UN(NtAcquireProcessActivityReference)) {
        HANDLE h = (HANDLE)0x1234;
        EXPECT_ST(UN(NtAcquireProcessActivityReference)(&h, NT_CUR_PROC, 0), ST_DENIED);   /* caller check, observed */
        EXPECT_ST(UN(NtAcquireProcessActivityReference)(&h, BOGUS, 0), ST_DENIED);
        if (h && h != (HANDLE)0x1234) UN(NtClose)(h);
    }
    if (UN(NtAcquireCrossVmMutant)) EXPECT_ST(UN(NtAcquireCrossVmMutant)(BOGUS, NULL), ST_TYPE_MISM);   /* observed */
    if (UN(NtRevertContainerImpersonation)) EXPECT_ST(UN(NtRevertContainerImpersonation)(), S(0xC0000001)); /* STATUS_UNSUCCESSFUL: not impersonating */
    CHECK(t_proc("NtTerminateEnclave") == t_proc("ZwTerminateEnclave"));
    CHECK(t_proc("NtUmsThreadYield") == t_proc("ZwUmsThreadYield"));
    CHECK(t_proc("NtAcquireProcessActivityReference") == t_proc("ZwAcquireProcessActivityReference"));
    CHECK(t_proc("NtAcquireCrossVmMutant") == t_proc("ZwAcquireCrossVmMutant"));
    CHECK(t_proc("NtRevertContainerImpersonation") == t_proc("ZwRevertContainerImpersonation"));
}

TEST(driver_partition_protocol)
{
    REQUIRE(UN(NtUnloadDriver)); REQUIRE(UN(RtlInitUnicodeString)); REQUIRE(UN(RtlAdjustPrivilege));
    UNICODE_STRING nm; UN(RtlInitUnicodeString)(&nm, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NtOther2aNoSuchDriver");
    BOOLEAN old; UN(RtlAdjustPrivilege)(10 /*SeLoadDriverPrivilege*/, FALSE, FALSE, &old);
    EXPECT_ST(UN(NtUnloadDriver)(&nm), ST_PRIV_NOT_HELD);
    NTSTATUS pst = UN(RtlAdjustPrivilege)(10, TRUE, FALSE, &old);
    if (pst == 0) {
        EXPECT_ST(UN(NtUnloadDriver)(&nm), S(0xC0000034));   /* STATUS_OBJECT_NAME_NOT_FOUND: no such service key */
        UN(RtlAdjustPrivilege)(10, FALSE, FALSE, &old);
    } else {
        EXPECT_ST(pst, ST_PRIV_NOT_HELD);
        t_note("SeLoadDriverPrivilege cannot be enabled (0x%lx): service-key lookup path not exercised", (unsigned long)pst);
    }
    if (UN(NtReplacePartitionUnit)) {
        UNICODE_STRING a, b; UN(RtlInitUnicodeString)(&a, L"\\NoSuch\\A"); UN(RtlInitUnicodeString)(&b, L"\\NoSuch\\B");
        EXPECT_ST(UN(NtReplacePartitionUnit)(&a, &b, 0), ST_PRIV_NOT_HELD);
    }
    if (UN(NtRegisterProtocolAddressInformation)) {
        BYTE info[16] = {0};
        EXPECT_ST(UN(NtRegisterProtocolAddressInformation)(BOGUS, info, sizeof info, info, 0), ST_INV_HANDLE);
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        EXPECT_ST(UN(NtRegisterProtocolAddressInformation)(ev, info, sizeof info, info, 0), ST_TYPE_MISM);
        CloseHandle(ev);
    }
    if (UN(NtTranslateFilePath)) {
        ULONG len = 0; BYTE in[64] = {0}, out[256];
        EXPECT_ST(UN(NtTranslateFilePath)(NULL, 0, NULL, &len), ST_NOT_IMPL);
        len = sizeof out;
        EXPECT_ST(UN(NtTranslateFilePath)(in, 2, out, &len), ST_NOT_IMPL);
    }
    if (UN(NtSerializeBoot)) EXPECT_ST(UN(NtSerializeBoot)(), ST_PRIV_NOT_HELD);
    CHECK(t_proc("NtUnloadDriver") == t_proc("ZwUnloadDriver"));
    CHECK(t_proc("NtReplacePartitionUnit") == t_proc("ZwReplacePartitionUnit"));
    CHECK(t_proc("NtTranslateFilePath") == t_proc("ZwTranslateFilePath"));
    CHECK(t_proc("NtSerializeBoot") == t_proc("ZwSerializeBoot"));
    CHECK(t_proc("NtRegisterProtocolAddressInformation") == t_proc("ZwRegisterProtocolAddressInformation"));
    CHECK(t_proc("NtVdmControl") == t_proc("ZwVdmControl"));
}

TEST(wnf_subscribe)
{
    REQUIRE(UN(NtSubscribeWnfStateChange)); REQUIRE(UN(NtUnsubscribeWnfStateChange));
    ULONGLONG name = 0x0D83063EA3BE0075ULL;   /* arbitrary state name; subscribing does not require it to exist */
    ULONGLONG sub1 = 0x1111, sub2 = 0x2222;
    EXPECT_ST(UN(NtSubscribeWnfStateChange)(&name, 0, 1, &sub1), 0);
    EXPECT_ST(UN(NtSubscribeWnfStateChange)(&name, 0, 0, &sub2), 0);
    t_note("subscription ids 0x%llx 0x%llx", sub1, sub2);
    CHECK(sub1 != 0x1111);
    CHECK(sub2 != 0x2222);
    EXPECT_ST(UN(NtSubscribeWnfStateChange)(NULL, 0, 1, &sub1), S(0xC0000005));
    EXPECT_ST(UN(NtUnsubscribeWnfStateChange)(NULL), S(0xC0000005));
    EXPECT_ST(UN(NtUnsubscribeWnfStateChange)(&name), 0);
    /* one call removed every subscription of this process for the name */
    EXPECT_ST(UN(NtUnsubscribeWnfStateChange)(&name), S(0xC0000034));   /* STATUS_OBJECT_NAME_NOT_FOUND */
    CHECK(t_proc("NtSubscribeWnfStateChange") == t_proc("ZwSubscribeWnfStateChange"));
    CHECK(t_proc("NtUnsubscribeWnfStateChange") == t_proc("ZwUnsubscribeWnfStateChange"));
}

TEST(ntdll_window_procs)
{
    wndproc_pfn defa = (wndproc_pfn)t_proc("NtdllDefWindowProc_A"), defw = (wndproc_pfn)t_proc("NtdllDefWindowProc_W");
    wndproc_pfn dlga = (wndproc_pfn)t_proc("NtdllDialogWndProc_A"), dlgw = (wndproc_pfn)t_proc("NtdllDialogWndProc_W");
    REQUIRE(defa); REQUIRE(defw);
    HWND h = CreateWindowExW(0, L"STATIC", L"conf", WS_POPUP, 0, 0, 10, 10, HWND_MESSAGE, NULL, GetModuleHandleW(NULL), NULL);
    if (!h) { t_skip("cannot create a message window (GetLastError %lu)", GetLastError()); return; }
    WCHAR buf[32] = {0}; char ab[32] = {0};
    EXPECT_EQ(defw(h, WM_SETTEXT, 0, (LPARAM)L"hello"), 1);
    EXPECT_EQ(defw(h, WM_GETTEXTLENGTH, 0, 0), 5);
    EXPECT_EQ(defw(h, WM_GETTEXT, 32, (LPARAM)buf), 5); EXPECT_WSTR(buf, L"hello");
    EXPECT_EQ(defa(h, WM_GETTEXT, 32, (LPARAM)ab), 5); EXPECT_STR(ab, "hello");
    EXPECT_EQ(defa(h, WM_SETTEXT, 0, (LPARAM)"ansi!"), 1);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(defw(h, WM_GETTEXT, 32, (LPARAM)buf), 5); EXPECT_WSTR(buf, L"ansi!");
    EXPECT_EQ(defw(h, WM_GETTEXT, 3, (LPARAM)buf), 2); EXPECT_WSTR(buf, L"an");   /* truncated to the buffer */
    EXPECT_EQ(defw(h, WM_NULL, 0, 0), 0);
    EXPECT_EQ(defw(h, WM_NCHITTEST, 0, MAKELPARAM(1, 1)), HTCLIENT);
    if (dlgw) EXPECT_EQ(dlgw(h, WM_NULL, 0, 0), 0);
    if (dlga) EXPECT_EQ(dlga(h, WM_NULL, 0, 0), 0);
    DestroyWindow(h);
}

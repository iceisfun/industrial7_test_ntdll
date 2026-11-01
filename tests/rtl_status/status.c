#include "t.h"

UDECL(ULONG, RtlNtStatusToDosErrorNoTeb, (NTSTATUS));
UDECL(NTSTATUS, RtlGetLastNtStatus, (void));
UDECL(ULONG, RtlGetLastWin32Error, (void));
UDECL(void, RtlSetLastWin32Error, (ULONG));
UDECL(void, RtlRestoreLastWin32Error, (ULONG));
UDECL(void, RtlSetLastWin32ErrorAndNtStatusFromNtStatus, (NTSTATUS));

#define REQUIRE_STATE() do { \
    REQUIRE(U(RtlNtStatusToDosError)); \
    REQUIRE(UN(RtlNtStatusToDosErrorNoTeb)); \
    REQUIRE(UN(RtlGetLastNtStatus)); \
    REQUIRE(UN(RtlGetLastWin32Error)); \
    REQUIRE(UN(RtlSetLastWin32Error)); \
    REQUIRE(UN(RtlRestoreLastWin32Error)); \
    REQUIRE(UN(RtlSetLastWin32ErrorAndNtStatusFromNtStatus)); \
} while (0)

static void restore_state(NTSTATUS status, ULONG error)
{
    U(RtlNtStatusToDosError)(status);
    UN(RtlRestoreLastWin32Error)(error);
}

static void mapping_case(ULONG status, ULONG error)
{
    NTSTATUS saved_status, n1, n2, n3;
    ULONG saved_error, r1, r2, e1, e2, e3;
    REQUIRE_STATE();
    saved_status = UN(RtlGetLastNtStatus)();
    saved_error = UN(RtlGetLastWin32Error)();
    U(RtlNtStatusToDosError)((NTSTATUS)0xc0000008);
    UN(RtlSetLastWin32Error)(0x12345678);
    r1 = UN(RtlNtStatusToDosErrorNoTeb)((NTSTATUS)status);
    n1 = UN(RtlGetLastNtStatus)(); e1 = UN(RtlGetLastWin32Error)();
    r2 = U(RtlNtStatusToDosError)((NTSTATUS)status);
    n2 = UN(RtlGetLastNtStatus)(); e2 = UN(RtlGetLastWin32Error)();
    UN(RtlSetLastWin32ErrorAndNtStatusFromNtStatus)((NTSTATUS)status);
    n3 = UN(RtlGetLastNtStatus)(); e3 = UN(RtlGetLastWin32Error)();
    restore_state(saved_status, saved_error);
    EXPECT_EQ(r1, error); EXPECT_EQ(r2, error);
    EXPECT_EQ((ULONG)n1, 0xc0000008); EXPECT_EQ(e1, 0x12345678);
    EXPECT_EQ((ULONG)n2, status); EXPECT_EQ(e2, 0x12345678);
    EXPECT_EQ((ULONG)n3, status); EXPECT_EQ(e3, error);
}

#define MAP(name,s,e) TEST(rtl_status_map_##name) { mapping_case(s,e); }
MAP(success,0,0)
MAP(pending,0x103,997)
MAP(timeout,0x102,1460)
MAP(unsuccessful,0xc0000001,31)
MAP(not_implemented,0xc0000002,1)
MAP(access_violation,0xc0000005,998)
MAP(invalid_handle,0xc0000008,6)
MAP(invalid_parameter,0xc000000d,87)
MAP(no_such_file,0xc000000f,2)
MAP(no_memory,0xc0000017,8)
MAP(access_denied,0xc0000022,5)
MAP(buffer_too_small,0xc0000023,122)
MAP(name_not_found,0xc0000034,2)
MAP(name_collision,0xc0000035,183)
MAP(path_not_found,0xc000003a,3)
MAP(sharing_violation,0xc0000043,32)
MAP(lock_conflict,0xc0000054,33)
MAP(privilege_not_held,0xc0000061,1314)
MAP(wrong_password,0xc000006a,86)
MAP(invalid_image,0xc000007b,193)
MAP(insufficient_resources,0xc000009a,1450)
MAP(file_is_directory,0xc00000ba,5)
MAP(cancelled,0xc0000120,995)
MAP(not_found,0xc0000225,1168)
MAP(buffer_overflow,0x80000005,234)
MAP(no_more_files,0x80000006,18)
MAP(customer_success,0x20001234,0x20001234)
MAP(customer_info,0x60001234,0x60001234)
MAP(customer_warning,0xa0001234,0xa0001234)
MAP(customer_error,0xe0001234,0xe0001234)
MAP(customer_precedes_facility,0xe0070005,0xe0070005)
MAP(win32_warning,0x80070005,5)
MAP(win32_error,0xc0070057,87)
MAP(win32_zero,0xc0070000,0)
MAP(win32_max,0x8007ffff,65535)
MAP(nt_bit_access_denied,0xd0000022,5)
MAP(nt_bit_invalid_handle,0xd0000008,6)
MAP(c001_fallback,0xc0011234,0x1234)
MAP(unmapped,0xc0ffffff,317)
MAP(unmapped_nt_bit,0xd0ffffff,317)
MAP(info_facility_not_extracted,0x4007ffff,317)
MAP(other_facility_not_extracted,0xc0080057,317)

static void setter_case(ULONG value, int restore)
{
    NTSTATUS saved_status, after, again;
    ULONG saved_error, got, repeated, win32;
    REQUIRE_STATE();
    saved_status = UN(RtlGetLastNtStatus)();
    saved_error = UN(RtlGetLastWin32Error)();
    U(RtlNtStatusToDosError)((NTSTATUS)0xc0000022);
    if (restore) UN(RtlRestoreLastWin32Error)(value);
    else UN(RtlSetLastWin32Error)(value);
    got = UN(RtlGetLastWin32Error)(); after = UN(RtlGetLastNtStatus)();
    win32 = GetLastError();
    if (restore) UN(RtlRestoreLastWin32Error)(value);
    else UN(RtlSetLastWin32Error)(value);
    repeated = UN(RtlGetLastWin32Error)(); again = UN(RtlGetLastNtStatus)();
    restore_state(saved_status, saved_error);
    EXPECT_EQ(got,value); EXPECT_EQ(win32,value); EXPECT_EQ(repeated,value);
    EXPECT_EQ((ULONG)after,0xc0000022); EXPECT_EQ((ULONG)again,0xc0000022);
}
#define SETTER(name,v,r) TEST(rtl_status_##name) { setter_case(v,r); }
SETTER(set_zero,0,0)
SETTER(set_pending,997,0)
SETTER(set_high_bit,0x80000001,0)
SETTER(set_all_bits,0xffffffff,0)
SETTER(restore_zero,0,1)
SETTER(restore_pending,997,1)
SETTER(restore_high_bit,0x80000001,1)
SETTER(restore_all_bits,0xffffffff,1)

struct thread_result { ULONG error, status, error_after, status_after; };
static DWORD WINAPI status_worker(void *arg)
{
    struct thread_result *r = arg;
    NTSTATUS s = UN(RtlGetLastNtStatus)();
    ULONG e = UN(RtlGetLastWin32Error)();
    UN(RtlSetLastWin32ErrorAndNtStatusFromNtStatus)((NTSTATUS)0xc0000008);
    r->error = UN(RtlGetLastWin32Error)(); r->status = (ULONG)UN(RtlGetLastNtStatus)();
    UN(RtlRestoreLastWin32Error)(0x87654321);
    r->error_after = UN(RtlGetLastWin32Error)();
    r->status_after = (ULONG)UN(RtlGetLastNtStatus)();
    restore_state(s,e);
    return 0;
}
CHILD(rtl_status_thread)
{
    struct thread_result r = {0};
    HANDLE thread;
    ULONG error, status;
    if (!U(RtlNtStatusToDosError) || !UN(RtlGetLastNtStatus) ||
        !UN(RtlGetLastWin32Error) || !UN(RtlRestoreLastWin32Error) ||
        !UN(RtlSetLastWin32ErrorAndNtStatusFromNtStatus)) return 77;
    UN(RtlSetLastWin32ErrorAndNtStatusFromNtStatus)((NTSTATUS)0xc0000022);
    thread = CreateThread(NULL,0,status_worker,&r,0,NULL);
    if (!thread) return 1;
    if (WaitForSingleObject(thread,10000) != WAIT_OBJECT_0) return 2;
    CloseHandle(thread);
    error = UN(RtlGetLastWin32Error)(); status = (ULONG)UN(RtlGetLastNtStatus)();
    return !(error == 5 && status == 0xc0000022 && r.error == 6 &&
             r.status == 0xc0000008 && r.error_after == 0x87654321 &&
             r.status_after == 0xc0000008);
}
TEST(rtl_status_thread_isolation)
{
    DWORD code;
    NTSTATUS saved_status;
    ULONG saved_error;
    REQUIRE_STATE();
    saved_status = UN(RtlGetLastNtStatus)();
    saved_error = UN(RtlGetLastWin32Error)();
    code = t_run_child("rtl_status_thread",NULL,15000);
    restore_state(saved_status,saved_error);
    if (code == 77) { t_skip("child missing state exports"); return; }
    EXPECT_EQ(code,0);
}

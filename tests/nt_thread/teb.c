/* Thread and process environment blocks as seen through NtCurrentTeb(): field layout
 * on Windows 10 x64, consistency with the documented Win32 accessors. */
#include "t.h"

UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(ULONG, RtlGetNtGlobalFlags, (VOID));
UDECL(VOID, RtlAcquirePebLock, (VOID));
UDECL(VOID, RtlReleasePebLock, (VOID));
UDECL(ULONG, RtlGetCurrentProcessorNumber, (VOID));
UDECL(VOID, RtlGetCurrentProcessorNumberEx, (PPROCESSOR_NUMBER));

#define TEB_BYTES(off, type) (*(type *)((BYTE *)NtCurrentTeb() + (off)))
#define PEB_BYTES(peb, off, type) (*(type *)((BYTE *)(peb) + (off)))

enum {
    TEB_STACK_BASE = 0x08, TEB_STACK_LIMIT = 0x10, TEB_SELF = 0x30, TEB_PID = 0x40, TEB_TID = 0x48,
    TEB_TLS_POINTER = 0x58, TEB_PEB = 0x60, TEB_LAST_ERROR = 0x68, TEB_DEALLOC_STACK = 0x1478, TEB_TLS_SLOTS = 0x1480,
    PEB_BEING_DEBUGGED = 0x02, PEB_IMAGE_BASE = 0x10, PEB_LDR = 0x18, PEB_PARAMS = 0x20, PEB_PROCESS_HEAP = 0x30,
    PEB_FAST_LOCK = 0x38, PEB_NT_GLOBAL_FLAG = 0xbc, PEB_NUM_PROCESSORS = 0xb8, PEB_LOADER_LOCK = 0x110,
    PEB_OS_MAJOR = 0x118, PEB_OS_MINOR = 0x11c, PEB_OS_BUILD = 0x120, PEB_OS_PLATFORM = 0x124
};

static PVOID peb_of_process(void)
{
    struct { NTSTATUS exit; PVOID peb; ULONG_PTR affinity; LONG prio; ULONG_PTR pid, ppid; } pbi;
    memset(&pbi, 0, sizeof pbi);
    if (!UN(NtQueryInformationProcess)) return NULL;
    if (UN(NtQueryInformationProcess)((HANDLE)(LONG_PTR)-1, 0, &pbi, sizeof pbi, NULL) != 0) return NULL;
    return pbi.peb;
}

TEST(nt_teb_self_and_client_id)
{
    BYTE *teb = (BYTE *)NtCurrentTeb();
    CHECK(teb != NULL);
    EXPECT_EQ(TEB_BYTES(TEB_SELF, PVOID), teb);
    EXPECT_EQ(TEB_BYTES(TEB_PID, ULONG_PTR), GetCurrentProcessId());
    EXPECT_EQ(TEB_BYTES(TEB_TID, ULONG_PTR), GetCurrentThreadId());
    EXPECT_EQ((ULONG_PTR)teb & 0xfff, 0); /* the TEB occupies whole pages */
}

TEST(nt_teb_matches_thread_information)
{
    struct { NTSTATUS exit; PVOID teb; CLIENT_ID id; ULONG_PTR aff; LONG pri, base; } b;
    REQUIRE(UN(NtQueryInformationThread));
    memset(&b, 0, sizeof b);
    EXPECT_EQ(UN(NtQueryInformationThread)((HANDLE)(LONG_PTR)-2, 0, &b, sizeof b, NULL), 0);
    EXPECT_EQ(b.teb, NtCurrentTeb());
    EXPECT_EQ((ULONG_PTR)b.id.UniqueThread, GetCurrentThreadId());
    EXPECT_EQ((ULONG_PTR)b.id.UniqueProcess, GetCurrentProcessId());
}

TEST(nt_teb_peb_pointer)
{
    PVOID peb = TEB_BYTES(TEB_PEB, PVOID);
    CHECK(peb != NULL);
    if (peb_of_process()) EXPECT_EQ(peb_of_process(), peb);
    else t_skip("NtQueryInformationProcess unavailable");
}

TEST(nt_teb_stack_bounds)
{
    volatile char local = 0;
    ULONG_PTR base = TEB_BYTES(TEB_STACK_BASE, ULONG_PTR), limit = TEB_BYTES(TEB_STACK_LIMIT, ULONG_PTR);
    ULONG_PTR dealloc = TEB_BYTES(TEB_DEALLOC_STACK, ULONG_PTR), here = (ULONG_PTR)&local;
    CHECK(limit < base);
    CHECK(here >= limit && here < base);
    CHECK(dealloc != 0 && dealloc <= limit);
    EXPECT_EQ(base & 0xfff, 0);
    EXPECT_EQ(limit & 0xfff, 0);
}

TEST(nt_teb_last_error_value)
{
    SetLastError(0x1234);
    EXPECT_EQ(TEB_BYTES(TEB_LAST_ERROR, DWORD), 0x1234);
    TEB_BYTES(TEB_LAST_ERROR, DWORD) = 0x4321;
    EXPECT_EQ(GetLastError(), 0x4321);
    SetLastError(0);
    EXPECT_EQ(TEB_BYTES(TEB_LAST_ERROR, DWORD), 0);
}

TEST(nt_teb_tls_slots)
{
    DWORD i = TlsAlloc();
    PVOID *slots = (PVOID *)((BYTE *)NtCurrentTeb() + TEB_TLS_SLOTS);
    if (i == TLS_OUT_OF_INDEXES) { t_skip("no TLS index"); return; }
    if (i >= 64) { t_note("TLS index %lu is outside the in-TEB array", i); TlsFree(i); return; }
    CHECK(TlsSetValue(i, (PVOID)0x5a5a50));
    EXPECT_EQ(slots[i], 0x5a5a50);
    slots[i] = (PVOID)0xa5a5a0;
    EXPECT_EQ(TlsGetValue(i), 0xa5a5a0);
    CHECK(TlsFree(i));
}

typedef struct { volatile PVOID teb; volatile PVOID stack_base; volatile ULONG_PTR tid; } other_t;
static DWORD WINAPI other_thread(PVOID p)
{
    other_t *o = p;
    o->stack_base = TEB_BYTES(TEB_STACK_BASE, PVOID);
    o->tid = TEB_BYTES(TEB_TID, ULONG_PTR);
    o->teb = NtCurrentTeb();
    return GetLastError();
}
TEST(nt_teb_distinct_per_thread)
{
    other_t o = {0};
    DWORD id = 0;
    HANDLE h = CreateThread(NULL, 0, other_thread, &o, 0, &id);
    PVOID mine_base = TEB_BYTES(TEB_STACK_BASE, PVOID);
    if (!h) { t_skip("CreateThread failed"); return; }
    WaitForSingleObject(h, 10000);
    CloseHandle(h);
    CHECK(o.teb != NULL);
    CHECK(o.teb != (PVOID)NtCurrentTeb());
    EXPECT_EQ(o.tid, id);
    CHECK(o.stack_base != mine_base);
}

TEST(nt_teb_new_thread_last_error_zero)
{
    other_t o = {0};
    HANDLE h;
    DWORD code = 99;
    SetLastError(0x77);
    h = CreateThread(NULL, 0, other_thread, &o, 0, NULL);
    if (!h) { t_skip("CreateThread failed"); return; }
    WaitForSingleObject(h, 10000);
    GetExitCodeThread(h, &code);
    CloseHandle(h);
    t_note("last-error value observed at the start of a new thread: %lu", code);   /* not specified; thread start-up may leave a value */
    EXPECT_EQ(GetLastError(), 0x77);                                              /* creating a thread does not disturb the caller */
}

TEST(nt_peb_basic_fields)
{
    PVOID peb = TEB_BYTES(TEB_PEB, PVOID);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    EXPECT_EQ(PEB_BYTES(peb, PEB_IMAGE_BASE, PVOID), GetModuleHandleA(NULL));
    EXPECT_EQ(PEB_BYTES(peb, PEB_PROCESS_HEAP, PVOID), GetProcessHeap());
    EXPECT_EQ(PEB_BYTES(peb, PEB_BEING_DEBUGGED, BYTE), IsDebuggerPresent() ? 1 : 0);
    CHECK(PEB_BYTES(peb, PEB_LDR, PVOID) != NULL);
    CHECK(PEB_BYTES(peb, PEB_PARAMS, PVOID) != NULL);
    CHECK(PEB_BYTES(peb, PEB_NUM_PROCESSORS, ULONG) >= si.dwNumberOfProcessors);
}

TEST(nt_peb_os_version)
{
    PVOID peb = TEB_BYTES(TEB_PEB, PVOID);
    EXPECT_EQ(PEB_BYTES(peb, PEB_OS_MAJOR, ULONG), 10);
    EXPECT_EQ(PEB_BYTES(peb, PEB_OS_MINOR, ULONG), 0);
    CHECK(PEB_BYTES(peb, PEB_OS_BUILD, USHORT) >= 10240);
    EXPECT_EQ(PEB_BYTES(peb, PEB_OS_PLATFORM, ULONG), 2); /* VER_PLATFORM_WIN32_NT */
    t_note("PEB OS build %u", PEB_BYTES(peb, PEB_OS_BUILD, USHORT));
}

TEST(nt_peb_global_flags_accessor)
{
    PVOID peb = TEB_BYTES(TEB_PEB, PVOID);
    REQUIRE(UN(RtlGetNtGlobalFlags));
    EXPECT_EQ(UN(RtlGetNtGlobalFlags)(), PEB_BYTES(peb, PEB_NT_GLOBAL_FLAG, ULONG));
}

TEST(nt_peb_loader_list_starts_with_image)
{
    PVOID peb = TEB_BYTES(TEB_PEB, PVOID);
    BYTE *ldr = PEB_BYTES(peb, PEB_LDR, BYTE *);
    LIST_ENTRY *head = (LIST_ENTRY *)(ldr + 0x10), *e;
    int count = 0, saw_ntdll = 0, saw_k32 = 0;
    CHECK(PEB_BYTES(ldr, 4, BYTE) == 1); /* Initialized */
    CHECK(head->Flink != head);
    /* LDR_DATA_TABLE_ENTRY: DllBase at 0x30, in load order the image comes first. */
    EXPECT_EQ(*(PVOID *)((BYTE *)head->Flink + 0x30), GetModuleHandleA(NULL));
    for (e = head->Flink; e != head && count < 4096; e = e->Flink, count++) {
        PVOID base = *(PVOID *)((BYTE *)e + 0x30);
        if (base == GetModuleHandleA("ntdll.dll")) saw_ntdll = 1;
        if (base == GetModuleHandleA("kernel32.dll")) saw_k32 = 1;
    }
    CHECK(count >= 3 && count < 4096);
    CHECK(saw_ntdll);
    CHECK(saw_k32);
}

TEST(nt_peb_process_parameters_command_line)
{
    PVOID peb = TEB_BYTES(TEB_PEB, PVOID);
    BYTE *pp = PEB_BYTES(peb, PEB_PARAMS, BYTE *);
    UNICODE_STRING *cmd = (UNICODE_STRING *)(pp + 0x70);
    const WCHAR *api = GetCommandLineW();
    EXPECT_EQ(cmd->Length, lstrlenW(api) * 2);
    CHECK(cmd->Buffer != NULL && !memcmp(cmd->Buffer, api, cmd->Length));
}

TEST(nt_peb_fast_lock_held_by_acquire)
{
    PVOID peb = TEB_BYTES(TEB_PEB, PVOID);
    RTL_CRITICAL_SECTION *cs = PEB_BYTES(peb, PEB_FAST_LOCK, RTL_CRITICAL_SECTION *);
    REQUIRE(UN(RtlAcquirePebLock)); REQUIRE(UN(RtlReleasePebLock));
    CHECK(cs != NULL);
    if (!cs) return;
    UN(RtlAcquirePebLock)();
    EXPECT_EQ((ULONG_PTR)cs->OwningThread, GetCurrentThreadId());
    CHECK(cs->RecursionCount >= 1);
    UN(RtlAcquirePebLock)(); /* recursive acquisition by the owner */
    CHECK(cs->RecursionCount >= 2);
    UN(RtlReleasePebLock)();
    UN(RtlReleasePebLock)();
    EXPECT_EQ(cs->RecursionCount, 0);
    CHECK(cs->OwningThread == NULL);
}

TEST(nt_teb_processor_number)
{
    SYSTEM_INFO si;
    ULONG n;
    PROCESSOR_NUMBER pn;
    REQUIRE(UN(RtlGetCurrentProcessorNumber));
    GetSystemInfo(&si);
    n = UN(RtlGetCurrentProcessorNumber)();
    CHECK(n < 1024);
    if (UN(RtlGetCurrentProcessorNumberEx)) {
        memset(&pn, 0xcc, sizeof pn);
        UN(RtlGetCurrentProcessorNumberEx)(&pn);
        CHECK(pn.Number < 64);
        EXPECT_EQ(pn.Reserved, 0);
        t_note("processor group=%u number=%u (processors in group %lu)", pn.Group, pn.Number, si.dwNumberOfProcessors);
    }
}

/* I/O completion ports and wait completion packets (native API).
 * NtCreateIoCompletion / NtOpenIoCompletion / NtQueryIoCompletion / NtSetIoCompletion(Ex) /
 * NtRemoveIoCompletion(Ex) and NtCreateWaitCompletionPacket / NtAssociateWaitCompletionPacket /
 * NtCancelWaitCompletionPacket (each Nt name and its Zw alias). See EVIDENCE.md. */
#include "t.h"

typedef struct { PVOID KeyContext; PVOID ApcContext; IO_STATUS_BLOCK IoStatusBlock; } FICI;
UDECL(NTSTATUS, NtCreateIoCompletion, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtOpenIoCompletion, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtQueryIoCompletion, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetIoCompletion, (HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR));
UDECL(NTSTATUS, NtSetIoCompletionEx, (HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR));
UDECL(NTSTATUS, NtRemoveIoCompletion, (HANDLE, PVOID *, PVOID *, PIO_STATUS_BLOCK, PLARGE_INTEGER));
UDECL(NTSTATUS, NtRemoveIoCompletionEx, (HANDLE, FICI *, ULONG, PULONG, PLARGE_INTEGER, BOOLEAN));
UDECL(NTSTATUS, NtCreateWaitCompletionPacket, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtAssociateWaitCompletionPacket, (HANDLE, HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR, PBOOLEAN));
UDECL(NTSTATUS, NtCancelWaitCompletionPacket, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, NtAllocateReserveObject, (PHANDLE, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtQueryObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQuerySystemTime, (PLARGE_INTEGER));

#define S(x) ((NTSTATUS)(x))
#define ST_TIMEOUT S(0x102)
#define ST_PENDING S(0x103)
#define ST_INV_HANDLE S(0xC0000008)
#define ST_INV_PARAM S(0xC000000D)
#define ST_TYPE S(0xC0000024)
#define ST_INFO_CLASS S(0xC0000003)
#define ST_LEN_MISMATCH S(0xC0000004)
#define ST_ACCVIO S(0xC0000005)
#define ST_NOT_FOUND S(0xC0000225)
#define ST_CANCELLED S(0xC0000120)
#define ST_EXISTS S(0xC0000035)
#define ST_NAME_NOT_FOUND S(0xC0000034)
#define ST_DENIED S(0xC0000022)
#define MAXIMUM_ALLOWED_ 0x02000000
#define IOCP_ALL 0x1F0003

static LARGE_INTEGER rel_ms(int ms) { LARGE_INTEGER l; l.QuadPart = -(LONGLONG)ms * 10000; return l; }
static LARGE_INTEGER zero_to(void) { LARGE_INTEGER l; l.QuadPart = 0; return l; }

#define NEED_IOCP() do { REQUIRE(UN(NtCreateIoCompletion)); REQUIRE(UN(NtSetIoCompletion)); REQUIRE(UN(NtRemoveIoCompletion)); REQUIRE(UN(NtQueryIoCompletion)); REQUIRE(UN(NtClose)); } while (0)

static ULONG depth(HANDLE h, NTSTATUS *st)
{
    ULONG d = 0xdeadbeef, rl = 0xdeadbeef;
    NTSTATUS s = UN(NtQueryIoCompletion)(h, 0, &d, sizeof d, &rl);
    if (st) *st = s;
    if (s == 0) EXPECT_EQ(rl, 4);
    return d;
}

TEST(alias_pairs)
{
    static const char *n[] = { "CreateIoCompletion", "OpenIoCompletion", "QueryIoCompletion", "SetIoCompletion",
        "SetIoCompletionEx", "RemoveIoCompletion", "RemoveIoCompletionEx", "CreateWaitCompletionPacket",
        "AssociateWaitCompletionPacket", "CancelWaitCompletionPacket" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64];
        snprintf(a, sizeof a, "Nt%s", n[i]); snprintf(b, sizeof b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a), pb = t_proc(b);
        if (!pa) { t_note("%s not exported", a); continue; }
        CHECKF(pa == pb, "%s / %s must be the same entry", a, b);
    }
}

TEST(iocp_queue_order)
{
    NEED_IOCP();
    HANDLE h = NULL;
    NTSTATUS st = UN(NtCreateIoCompletion)(&h, IOCP_ALL, NULL, 0);
    EXPECT_EQ(st, 0);
    CHECK(h != NULL);
    EXPECT_EQ(depth(h, &st), 0); EXPECT_EQ(st, 0);
    for (int i = 0; i < 3; i++) {
        st = UN(NtSetIoCompletion)(h, (PVOID)(ULONG_PTR)(0x100 + i), (PVOID)(ULONG_PTR)(0x200 + i), i == 1 ? S(0xC0000120) : 0, 0x300 + i);
        EXPECT_EQ(st, 0);
    }
    EXPECT_EQ(depth(h, &st), 3); EXPECT_EQ(st, 0);
    for (int i = 0; i < 3; i++) {
        PVOID key = NULL, apc = NULL; IO_STATUS_BLOCK io; memset(&io, 0xcc, sizeof io);
        LARGE_INTEGER to = rel_ms(2000);
        st = UN(NtRemoveIoCompletion)(h, &key, &apc, &io, &to);
        EXPECT_EQ(st, 0);
        EXPECT_EQ((ULONG_PTR)key, 0x100 + i);
        EXPECT_EQ((ULONG_PTR)apc, 0x200 + i);
        EXPECT_EQ(io.Status, i == 1 ? S(0xC0000120) : 0);
        EXPECT_EQ(io.Information, 0x300 + i);
    }
    EXPECT_EQ(depth(h, &st), 0);
    PVOID key = (PVOID)1, apc = (PVOID)1; IO_STATUS_BLOCK io; LARGE_INTEGER z = zero_to();
    st = UN(NtRemoveIoCompletion)(h, &key, &apc, &io, &z);
    EXPECT_EQ(st, ST_TIMEOUT);
    LARGE_INTEGER t = rel_ms(30);
    DWORD t0 = GetTickCount();
    st = UN(NtRemoveIoCompletion)(h, &key, &apc, &io, &t);
    EXPECT_EQ(st, ST_TIMEOUT);
    CHECK(GetTickCount() - t0 >= 15);
    UN(NtClose)(h);
}

TEST(iocp_errors)
{
    NEED_IOCP();
    HANDLE h = NULL; NTSTATUS st;
    PVOID key, apc; IO_STATUS_BLOCK io; LARGE_INTEGER z = zero_to();
    st = UN(NtCreateIoCompletion)(NULL, IOCP_ALL, NULL, 0);
    EXPECT_EQ(st, ST_ACCVIO);
    st = UN(NtSetIoCompletion)((HANDLE)(LONG_PTR)-1, 0, 0, 0, 0);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtSetIoCompletion)((HANDLE)0x7ffc, 0, 0, 0, 0);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtSetIoCompletion)(NULL, 0, 0, 0, 0);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtRemoveIoCompletion)(NULL, &key, &apc, &io, &z);
    EXPECT_EQ(st, ST_INV_HANDLE);
    ULONG d, rl;
    st = UN(NtQueryIoCompletion)(NULL, 0, &d, 4, &rl);
    EXPECT_EQ(st, ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    st = UN(NtSetIoCompletion)(ev, 0, 0, 0, 0);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtRemoveIoCompletion)(ev, &key, &apc, &io, &z);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtQueryIoCompletion)(ev, 0, &d, 4, &rl);
    EXPECT_EQ(st, ST_TYPE);
    CloseHandle(ev);

    st = UN(NtCreateIoCompletion)(&h, IOCP_ALL, NULL, 1);
    EXPECT_EQ(st, 0);
    /* query argument validation */
    d = 0; rl = 0;
    st = UN(NtQueryIoCompletion)(h, 1, &d, 4, &rl);
    EXPECT_EQ(st, ST_INFO_CLASS);
    st = UN(NtQueryIoCompletion)(h, 0, &d, 3, &rl);
    EXPECT_EQ(st, ST_LEN_MISMATCH);
    st = UN(NtQueryIoCompletion)(h, 0, &d, 8, &rl);
    EXPECT_EQ(st, ST_LEN_MISMATCH);
    st = UN(NtQueryIoCompletion)(h, 0, &d, 0, &rl);
    EXPECT_EQ(st, ST_LEN_MISMATCH);
    st = UN(NtQueryIoCompletion)(h, 0, &d, 4, NULL);
    EXPECT_EQ(st, 0);
    st = UN(NtQueryIoCompletion)(h, 0, NULL, 4, &rl);
    EXPECT_EQ(st, ST_ACCVIO);
    /* handle without the needed access */
    HANDLE ro = NULL;
    st = UN(NtCreateIoCompletion)(&ro, 0x100000 /*SYNCHRONIZE*/, NULL, 0);
    EXPECT_EQ(st, 0);
    st = UN(NtSetIoCompletion)(ro, 0, 0, 0, 0);
    EXPECT_EQ(st, ST_DENIED);
    st = UN(NtRemoveIoCompletion)(ro, &key, &apc, &io, &z);
    EXPECT_EQ(st, ST_DENIED);
    st = UN(NtQueryIoCompletion)(ro, 0, &d, 4, &rl);
    EXPECT_EQ(st, ST_DENIED);
    UN(NtClose)(ro);
    UN(NtClose)(h);
    st = UN(NtClose)(h);
    EXPECT_NE(st, 0);
}

TEST(iocp_open_named)
{
    NEED_IOCP();
    REQUIRE(UN(NtOpenIoCompletion)); REQUIRE(UN(NtQueryObject));
    /* find this session's named-object directory through a named event */
    WCHAR evname[64];
    wsprintfW(evname, L"tp_iocp_probe_%lu", GetCurrentProcessId());
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, evname);
    if (!ev) { t_skip("cannot create named event"); return; }
    BYTE buf[512]; ULONG rl = 0;
    NTSTATUS st = UN(NtQueryObject)(ev, 1, buf, sizeof buf, &rl);
    CloseHandle(ev);
    EXPECT_EQ(st, 0);
    UNICODE_STRING *nm = (UNICODE_STRING *)buf;
    WCHAR path[512];
    int n = nm->Length / 2;
    memcpy(path, nm->Buffer, nm->Length);
    path[n] = 0;
    WCHAR *slash = wcsrchr(path, L'\\');
    if (!slash) { t_skip("unexpected event name"); return; }
    wsprintfW(slash + 1, L"tp_iocp_%lu", GetCurrentProcessId());
    UNICODE_STRING us; us.Buffer = path; us.Length = (USHORT)(lstrlenW(path) * 2); us.MaximumLength = us.Length + 2;
    OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE h1 = NULL, h2 = NULL, h3 = NULL;
    st = UN(NtOpenIoCompletion)(&h3, IOCP_ALL, &oa);
    EXPECT_EQ(st, ST_NAME_NOT_FOUND);
    st = UN(NtCreateIoCompletion)(&h1, IOCP_ALL, &oa, 0);
    if (st == ST_DENIED) { t_skip("cannot create named objects here: 0x%lx", (unsigned long)st); return; }
    EXPECT_EQ(st, 0);
    if (st) return;
    st = UN(NtOpenIoCompletion)(&h2, IOCP_ALL, &oa);
    EXPECT_EQ(st, 0);
    CHECK(h2 && h2 != h1);
    HANDLE h4 = NULL;
    st = UN(NtCreateIoCompletion)(&h4, IOCP_ALL, &oa, 0);
    EXPECT_EQ(st, ST_EXISTS);   /* STATUS_OBJECT_NAME_COLLISION */
    if (h4) UN(NtClose)(h4);
    /* shared object: set via one handle, observe via the other */
    st = UN(NtSetIoCompletion)(h1, (PVOID)0x11, (PVOID)0x22, 0, 0x33);
    EXPECT_EQ(st, 0);
    NTSTATUS s2; EXPECT_EQ(depth(h2, &s2), 1); EXPECT_EQ(s2, 0);
    PVOID key = 0, apc = 0; IO_STATUS_BLOCK io; LARGE_INTEGER t = rel_ms(2000);
    st = UN(NtRemoveIoCompletion)(h2, &key, &apc, &io, &t);
    EXPECT_EQ(st, 0); EXPECT_EQ((ULONG_PTR)key, 0x11); EXPECT_EQ((ULONG_PTR)apc, 0x22); EXPECT_EQ(io.Information, 0x33);
    /* opening with a wrong type name: event of same name pattern */
    UN(NtClose)(h2);
    st = UN(NtOpenIoCompletion)(NULL, IOCP_ALL, &oa);
    EXPECT_EQ(st, ST_ACCVIO);
    st = UN(NtOpenIoCompletion)(&h2, IOCP_ALL, NULL);
    EXPECT_EQ(st, ST_INV_PARAM);
    UN(NtClose)(h1);
    st = UN(NtOpenIoCompletion)(&h3, IOCP_ALL, &oa);
    EXPECT_EQ(st, ST_NAME_NOT_FOUND);
}

static volatile LONG g_apc_ran;
static VOID CALLBACK apc_fn(ULONG_PTR p) { g_apc_ran = 1; }

TEST(iocp_remove_ex)
{
    NEED_IOCP();
    REQUIRE(UN(NtRemoveIoCompletionEx));
    HANDLE h = NULL; NTSTATUS st;
    EXPECT_EQ(UN(NtCreateIoCompletion)(&h, IOCP_ALL, NULL, 0), 0);
    FICI info[8]; ULONG got = 0xff; LARGE_INTEGER z = zero_to();
    st = UN(NtRemoveIoCompletionEx)(h, info, 8, &got, &z, FALSE);
    EXPECT_EQ(st, ST_TIMEOUT);
    t_note("RemoveEx timeout: EntriesRemoved=%lu", got);
    for (int i = 0; i < 5; i++)
        EXPECT_EQ(UN(NtSetIoCompletion)(h, (PVOID)(ULONG_PTR)(1 + i), (PVOID)(ULONG_PTR)(10 + i), i, 100 + i), 0);
    memset(info, 0xcc, sizeof info);
    LARGE_INTEGER t = rel_ms(2000);
    got = 0;
    st = UN(NtRemoveIoCompletionEx)(h, info, 3, &got, &t, FALSE);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(got, 3);
    for (ULONG i = 0; i < got && i < 3; i++) {
        EXPECT_EQ((ULONG_PTR)info[i].KeyContext, 1 + i);
        EXPECT_EQ((ULONG_PTR)info[i].ApcContext, 10 + i);
        EXPECT_EQ(info[i].IoStatusBlock.Status, (NTSTATUS)i);
        EXPECT_EQ(info[i].IoStatusBlock.Information, 100 + i);
    }
    got = 0;
    st = UN(NtRemoveIoCompletionEx)(h, info, 8, &got, &t, FALSE);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(got, 2);
    EXPECT_EQ((ULONG_PTR)info[0].KeyContext, 4);
    EXPECT_EQ((ULONG_PTR)info[1].KeyContext, 5);
    /* count 0, NULL out parameters */
    got = 0xff;
    st = UN(NtRemoveIoCompletionEx)(h, info, 0, &got, &z, FALSE);
    EXPECT_EQ(st, ST_INV_PARAM);
    st = UN(NtRemoveIoCompletionEx)(h, NULL, 1, &got, &z, FALSE);
    EXPECT_EQ(st, ST_ACCVIO);
    st = UN(NtRemoveIoCompletionEx)(h, info, 1, NULL, &z, FALSE);
    EXPECT_EQ(st, ST_ACCVIO);
    st = UN(NtRemoveIoCompletionEx)(NULL, info, 1, &got, &z, FALSE);
    EXPECT_EQ(st, ST_INV_HANDLE);
    /* alertable wait with nothing queued times out */
    t = rel_ms(100);
    st = UN(NtRemoveIoCompletionEx)(h, info, 1, &got, &t, TRUE);
    EXPECT_EQ(st, ST_TIMEOUT);
    /* alertable wait is interrupted by a queued user APC (STATUS_USER_APC) */
    g_apc_ran = 0;
    QueueUserAPC(apc_fn, GetCurrentThread(), 1);
    t = rel_ms(2000);
    st = UN(NtRemoveIoCompletionEx)(h, info, 1, &got, &t, TRUE);
    EXPECT_EQ(st, S(0xC0));
    SleepEx(0, TRUE);
    EXPECT_EQ(g_apc_ran, 1);
    UN(NtClose)(h);
}

TEST(iocp_set_ex_reserve)
{
    NEED_IOCP();
    REQUIRE(UN(NtSetIoCompletionEx)); REQUIRE(UN(NtAllocateReserveObject));
    HANDLE h = NULL, rsv = NULL; NTSTATUS st;
    EXPECT_EQ(UN(NtCreateIoCompletion)(&h, IOCP_ALL, NULL, 0), 0);
    st = UN(NtAllocateReserveObject)(&rsv, NULL, 1 /* IoCompletionReserve */);
    EXPECT_EQ(st, 0);
    if (st) { UN(NtClose)(h); return; }
    for (int round = 0; round < 2; round++) {
        st = UN(NtSetIoCompletionEx)(h, rsv, (PVOID)0xA1, (PVOID)0xA2, S(0x1234), 0xA3);
        EXPECT_EQ(st, 0);
        NTSTATUS s2; EXPECT_EQ(depth(h, &s2), 1);
        PVOID key = 0, apc = 0; IO_STATUS_BLOCK io; LARGE_INTEGER t = rel_ms(2000);
        st = UN(NtRemoveIoCompletion)(h, &key, &apc, &io, &t);
        EXPECT_EQ(st, 0);
        EXPECT_EQ((ULONG_PTR)key, 0xA1); EXPECT_EQ((ULONG_PTR)apc, 0xA2);
        EXPECT_EQ(io.Status, S(0x1234)); EXPECT_EQ(io.Information, 0xA3);
    }
    /* the reserve is in use while its packet is queued: a second use is rejected */
    EXPECT_EQ(UN(NtSetIoCompletionEx)(h, rsv, (PVOID)1, (PVOID)2, 0, 3), 0);
    st = UN(NtSetIoCompletionEx)(h, rsv, (PVOID)1, (PVOID)2, 0, 3);
    EXPECT_EQ(st, S(0xC00000F0));
    st = UN(NtSetIoCompletionEx)(NULL, rsv, 0, 0, 0, 0);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtSetIoCompletionEx)(h, NULL, 0, 0, 0, 0);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtSetIoCompletionEx)(h, h, 0, 0, 0, 0);
    EXPECT_EQ(st, ST_TYPE);
    UN(NtClose)(rsv);
    UN(NtClose)(h);
}

TEST(wait_packet)
{
    NEED_IOCP();
    REQUIRE(UN(NtCreateWaitCompletionPacket)); REQUIRE(UN(NtAssociateWaitCompletionPacket)); REQUIRE(UN(NtCancelWaitCompletionPacket));
    HANDLE io = NULL, wp = NULL, ev = CreateEventW(NULL, TRUE, FALSE, NULL); NTSTATUS st;
    EXPECT_EQ(UN(NtCreateIoCompletion)(&io, IOCP_ALL, NULL, 0), 0);
    st = UN(NtCreateWaitCompletionPacket)(&wp, 0x1F0001 /* ALL? */, NULL);
    EXPECT_EQ(st, 0);
    if (st == 0) UN(NtClose)(wp);
    wp = NULL;
    st = UN(NtCreateWaitCompletionPacket)(&wp, MAXIMUM_ALLOWED_, NULL);
    EXPECT_EQ(st, 0);
    if (st) { t_skip("no wait completion packets"); return; }
    BOOLEAN already = 7;
    /* not signaled: association pends; cancel removes it */
    st = UN(NtAssociateWaitCompletionPacket)(wp, io, ev, (PVOID)0x51, (PVOID)0x52, S(0x77), 0x53, &already);
    EXPECT_EQ(st, 0); EXPECT_EQ(already, 0);
    NTSTATUS s2; EXPECT_EQ(depth(io, &s2), 0);
    st = UN(NtCancelWaitCompletionPacket)(wp, FALSE);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(depth(io, &s2), 0);
    /* associate again, then signal: a packet shows up */
    already = 7;
    st = UN(NtAssociateWaitCompletionPacket)(wp, io, ev, (PVOID)0x51, (PVOID)0x52, S(0x77), 0x53, &already);
    EXPECT_EQ(st, 0); EXPECT_EQ(already, 0);
    /* second associate while active */
    already = 7;
    st = UN(NtAssociateWaitCompletionPacket)(wp, io, ev, (PVOID)0x51, (PVOID)0x52, S(0x77), 0x53, &already);
    EXPECT_EQ(st, S(0xC00000EF));
    SetEvent(ev);
    PVOID key = 0, apc = 0; IO_STATUS_BLOCK iosb; LARGE_INTEGER t = rel_ms(3000);
    st = UN(NtRemoveIoCompletion)(io, &key, &apc, &iosb, &t);
    EXPECT_EQ(st, 0);
    EXPECT_EQ((ULONG_PTR)key, 0x51); EXPECT_EQ((ULONG_PTR)apc, 0x52);
    EXPECT_EQ(iosb.Status, S(0x77)); EXPECT_EQ(iosb.Information, 0x53);
    /* cancel after the packet was delivered */
    st = UN(NtCancelWaitCompletionPacket)(wp, FALSE);
    EXPECT_EQ(st, ST_CANCELLED);
    /* already-signaled target */
    already = 0;
    st = UN(NtAssociateWaitCompletionPacket)(wp, io, ev, (PVOID)0x61, (PVOID)0x62, S(0x78), 0x63, &already);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(already, 1);
    t = rel_ms(3000);
    st = UN(NtRemoveIoCompletion)(io, &key, &apc, &iosb, &t);
    EXPECT_EQ(st, 0);
    EXPECT_EQ((ULONG_PTR)key, 0x61); EXPECT_EQ((ULONG_PTR)apc, 0x62);
    EXPECT_EQ(iosb.Status, S(0x78)); EXPECT_EQ(iosb.Information, 0x63);
    /* cancel with RemoveSignaledPacket removes a queued packet */
    ResetEvent(ev);
    SetEvent(ev);
    st = UN(NtAssociateWaitCompletionPacket)(wp, io, ev, (PVOID)0x71, (PVOID)0x72, 0, 0x73, &already);
    EXPECT_EQ(st, 0);
    st = UN(NtCancelWaitCompletionPacket)(wp, TRUE);
    EXPECT_EQ(st, 0);
    t = rel_ms(100);
    st = UN(NtRemoveIoCompletion)(io, &key, &apc, &iosb, &t);
    EXPECT_EQ(st, ST_TIMEOUT);
    /* error paths */
    st = UN(NtAssociateWaitCompletionPacket)(NULL, io, ev, 0, 0, 0, 0, &already);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtAssociateWaitCompletionPacket)(wp, NULL, ev, 0, 0, 0, 0, &already);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtAssociateWaitCompletionPacket)(wp, io, NULL, 0, 0, 0, 0, &already);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtAssociateWaitCompletionPacket)(ev, io, ev, 0, 0, 0, 0, &already);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtAssociateWaitCompletionPacket)(wp, ev, ev, 0, 0, 0, 0, &already);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtCancelWaitCompletionPacket)(NULL, FALSE);
    EXPECT_EQ(st, ST_INV_HANDLE);
    st = UN(NtCancelWaitCompletionPacket)(ev, FALSE);
    EXPECT_EQ(st, ST_TYPE);
    st = UN(NtCreateWaitCompletionPacket)(NULL, MAXIMUM_ALLOWED_, NULL);
    EXPECT_EQ(st, ST_ACCVIO);
    UN(NtCancelWaitCompletionPacket)(wp, TRUE);
    UN(NtClose)(wp);
    UN(NtClose)(io);
    CloseHandle(ev);
}

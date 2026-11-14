/* RtlWow64* machine/CPU-area/thread helpers and the Rtlp context converters, exercised in a native
 * 64-bit process. See EVIDENCE.md for the source of every expectation. */
#include "t.h"

#define ST_SUCCESS  ((NTSTATUS)0)
#define ST_INV_HANDLE ((NTSTATUS)0xC0000008)
#define ST_INV_PARAM  ((NTSTATUS)0xC000000D)
#define ST_TYPE_MISM  ((NTSTATUS)0xC0000024)
#define ST_NOT_IMPL   ((NTSTATUS)0xC0000002)
#define ST_UNSUCC     ((NTSTATUS)0xC0000001)
#define ST_LEN_MISM   ((NTSTATUS)0xC0000004)
#define NT_CUR_PROC   ((HANDLE)(LONG_PTR)-1)
#define NT_CUR_THREAD ((HANDLE)(LONG_PTR)-2)

UDECL(USHORT, RtlWow64GetCurrentMachine, (void));
UDECL(NTSTATUS, RtlWow64GetProcessMachines, (HANDLE, USHORT *, USHORT *));
UDECL(NTSTATUS, RtlWow64IsWowGuestMachineSupported, (USHORT, BOOLEAN *));
UDECL(USHORT, RtlWow64GetEquivalentMachineCHPE, (USHORT));
UDECL(NTSTATUS, RtlWow64GetCpuAreaInfo, (ULONG64, USHORT, ULONG64 *));
UDECL(NTSTATUS, RtlWow64GetSharedInfoProcess, (HANDLE, BYTE *));
UDECL(NTSTATUS, RtlWow64GetThreadContext, (HANDLE, PVOID));
UDECL(NTSTATUS, RtlWow64SetThreadContext, (HANDLE, PVOID));
UDECL(NTSTATUS, RtlWow64GetThreadSelectorEntry, (HANDLE, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, RtlWow64SuspendThread, (HANDLE, PULONG));
UDECL(NTSTATUS, RtlWow64SuspendProcess, (HANDLE));
UDECL(NTSTATUS, RtlWow64CallFunction64, (void));
UDECL(NTSTATUS, RtlWow64EnableFsRedirection, (BOOLEAN));
UDECL(NTSTATUS, RtlWow64EnableFsRedirectionEx, (PVOID, PVOID *));
UDECL(NTSTATUS, NtResumeProcess, (HANDLE));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtResumeThread, (HANDLE, PULONG));

TEST(machine_queries)
{
    REQUIRE(UN(RtlWow64GetCurrentMachine)); REQUIRE(UN(RtlWow64GetEquivalentMachineCHPE));
    REQUIRE(UN(RtlWow64GetProcessMachines)); REQUIRE(UN(RtlWow64IsWowGuestMachineSupported));
    EXPECT_EQ(UN(RtlWow64GetCurrentMachine)(), 0x8664);
    EXPECT_EQ(UN(RtlWow64GetEquivalentMachineCHPE)(0x3a64), 0x14c);
    EXPECT_EQ(UN(RtlWow64GetEquivalentMachineCHPE)(0x8664), 0x8664);
    EXPECT_EQ(UN(RtlWow64GetEquivalentMachineCHPE)(0x14c), 0x14c);
    EXPECT_EQ(UN(RtlWow64GetEquivalentMachineCHPE)(0), 0);

    USHORT a = 1, b = 1;
    EXPECT_EQ(UN(RtlWow64GetProcessMachines)(NT_CUR_PROC, &a, &b), ST_SUCCESS);
    EXPECT_EQ(a, 0); EXPECT_EQ(b, 0x8664);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (h) {
        a = 1; b = 1;
        EXPECT_EQ(UN(RtlWow64GetProcessMachines)(h, &a, &b), ST_SUCCESS);
        EXPECT_EQ(a, 0); EXPECT_EQ(b, 0x8664);
        a = 1;
        EXPECT_EQ(UN(RtlWow64GetProcessMachines)(h, &a, NULL), ST_SUCCESS);
        EXPECT_EQ(a, 0);
        CloseHandle(h);
    } else t_note("OpenProcess(self) failed %lu", GetLastError());
    a = 1; b = 1;
    EXPECT_EQ(UN(RtlWow64GetProcessMachines)((HANDLE)0x12345678, &a, &b), ST_INV_HANDLE);
    EXPECT_EQ(a, 1); EXPECT_EQ(b, 1);
    EXPECT_EQ(UN(RtlWow64GetProcessMachines)(NT_CUR_THREAD, &a, &b), ST_TYPE_MISM);

    BOOLEAN o = 9;
    EXPECT_EQ(UN(RtlWow64IsWowGuestMachineSupported)(0x14c, &o), ST_SUCCESS);
    if (!o) t_skip("x86 WoW64 guest not installed on this image");
    else {
        USHORT bad[] = { 0x1c4, 0x8664, 0xaa64, 0, 0x1c0, 0x3a64, 0x200, 0x1234 };
        for (int i = 0; i < 8; i++) {
            o = 9;
            EXPECT_EQ(UN(RtlWow64IsWowGuestMachineSupported)(bad[i], &o), ST_SUCCESS);
            CHECKF(o == 0, "machine 0x%x reported supported", bad[i]);
        }
    }
}

TEST(cpu_area_info)
{
    REQUIRE(UN(RtlWow64GetCpuAreaInfo));
    struct { USHORT m; ULONG fl; ULONG64 ctx_off, ex_off, flagsloc, end_off; } c[] = {
        { 0x14c,  0x10000,  0x10004, 0x102d0, 0x10004, 0x102d8 },
        { 0x1c4,  0x200000, 0x10008, 0x101a8, 0x10008, 0x101b0 },
        { 0x8664, 0x100000, 0x10010, 0x104e0, 0x10040, 0x104e8 },
        { 0xaa64, 0x400000, 0x10010, 0x103a0, 0x10010, 0x103a8 },
    };
    for (int i = 0; i < 4; i++) {
        ULONG64 inf[6]; memset(inf, 0xcc, sizeof inf);
        EXPECT_EQ(UN(RtlWow64GetCpuAreaInfo)(0x10000, c[i].m, inf), ST_SUCCESS);
        CHECKF(inf[0] == c[i].ctx_off, "m=%x ctx 0x%llx", c[i].m, (unsigned long long)inf[0]);
        CHECKF(inf[1] == c[i].ex_off, "m=%x ex 0x%llx", c[i].m, (unsigned long long)inf[1]);
        CHECKF(inf[2] == c[i].flagsloc, "m=%x flagsloc 0x%llx", c[i].m, (unsigned long long)inf[2]);
        EXPECT_EQ(inf[3], 0x10000);
        EXPECT_EQ((ULONG)inf[4], c[i].fl);
        EXPECT_EQ(*(USHORT *)((BYTE *)inf + 0x24), c[i].m);
        CHECKF(inf[5] == c[i].end_off, "m=%x end 0x%llx", c[i].m, (unsigned long long)inf[5]);
    }
    /* alignment of the context follows the base address */
    ULONG64 inf[6]; memset(inf, 0xcc, sizeof inf);
    EXPECT_EQ(UN(RtlWow64GetCpuAreaInfo)(0x10001, 0x14c, inf), ST_SUCCESS);
    EXPECT_EQ(inf[0], 0x10008); EXPECT_EQ(inf[3], 0x10001); EXPECT_EQ(inf[5], 0x102e0);
    /* unknown machine: only the base is stored */
    memset(inf, 0xcc, sizeof inf);
    EXPECT_EQ(UN(RtlWow64GetCpuAreaInfo)(0x10000, 0x1234, inf), ST_INV_PARAM);
    EXPECT_EQ(inf[3], 0x10000);
    EXPECT_EQ(inf[0], 0xcccccccccccccccc);
}

TEST(shared_info_and_contexts)
{
    REQUIRE(UN(RtlWow64GetSharedInfoProcess)); REQUIRE(UN(RtlWow64GetThreadContext)); REQUIRE(UN(RtlWow64SetThreadContext));
    BYTE sh[0x200]; memset(sh, 0xcc, sizeof sh);
    EXPECT_EQ(UN(RtlWow64GetSharedInfoProcess)(NT_CUR_PROC, sh), ST_SUCCESS);
    EXPECT_EQ(sh[0], 0);          /* not a WoW64 process */
    EXPECT_EQ(sh[1], 0xcc);
    memset(sh, 0xcc, sizeof sh);
    EXPECT_EQ(UN(RtlWow64GetSharedInfoProcess)((HANDLE)0x12345678, sh), ST_INV_HANDLE);
    EXPECT_EQ(sh[0], 0xcc);

    BYTE ctx[0x300]; memset(ctx, 0, sizeof ctx); *(ULONG *)ctx = 0x10001;
    /* native thread has no 32-bit context */
    EXPECT_EQ(UN(RtlWow64GetThreadContext)(NT_CUR_THREAD, ctx), ST_INV_PARAM);
    EXPECT_EQ(UN(RtlWow64SetThreadContext)(NT_CUR_THREAD, ctx), ST_INV_PARAM);
    EXPECT_EQ(UN(RtlWow64GetThreadContext)((HANDLE)0x1234, ctx), ST_INV_HANDLE);
    EXPECT_EQ(UN(RtlWow64SetThreadContext)((HANDLE)0x1234, ctx), ST_INV_HANDLE);
}

static DWORD WINAPI idle_thread(LPVOID p) { Sleep(20000); return 0; }

TEST(selector_entry)
{
    REQUIRE(UN(RtlWow64GetThreadSelectorEntry)); REQUIRE(U(NtQueryInformationThread));
    ULONG e[3], rl;
    /* null selector */
    e[0] = 0; e[1] = e[2] = 0xcccccccc; rl = 99;
    EXPECT_EQ(UN(RtlWow64GetThreadSelectorEntry)(NT_CUR_THREAD, e, 12, &rl), ST_SUCCESS);
    EXPECT_EQ(e[1], 0); EXPECT_EQ(e[2], 0); EXPECT_EQ(rl, 8);
    /* CS 0x23 and SS/DS 0x2b: flat 4G, base 0 */
    e[0] = 0x23; e[1] = e[2] = 0xcccccccc; rl = 99;
    EXPECT_EQ(UN(RtlWow64GetThreadSelectorEntry)(NT_CUR_THREAD, e, 12, &rl), ST_SUCCESS);
    EXPECT_EQ(e[1], 0x0000ffff); EXPECT_EQ(e[2], 0x00cffb00); EXPECT_EQ(rl, 8);
    e[0] = 0x2b; e[1] = e[2] = 0xcccccccc;
    EXPECT_EQ(UN(RtlWow64GetThreadSelectorEntry)(NT_CUR_THREAD, e, 12, &rl), ST_SUCCESS);
    EXPECT_EQ(e[1], 0x0000ffff); EXPECT_EQ(e[2], 0x00cff300);
    /* RPL bits are ignored */
    e[0] = 0x20; e[1] = e[2] = 0xcccccccc;
    EXPECT_EQ(UN(RtlWow64GetThreadSelectorEntry)(NT_CUR_THREAD, e, 12, &rl), ST_SUCCESS);
    EXPECT_EQ(e[1], 0x0000ffff); EXPECT_EQ(e[2], 0x00cffb00);
    /* FS 0x53: base = 32-bit TEB (native TEB + 0x2000), limit 0xfff */
    e[0] = 0x53; e[1] = e[2] = 0xcccccccc; rl = 99;
    EXPECT_EQ(UN(RtlWow64GetThreadSelectorEntry)(NT_CUR_THREAD, e, 12, &rl), ST_SUCCESS);
    ULONG base = (e[1] >> 16) | ((e[2] & 0xff) << 16) | (e[2] & 0xff000000);
    EXPECT_EQ(base, (ULONG)((ULONG_PTR)NtCurrentTeb() + 0x2000));
    EXPECT_EQ(e[1] & 0xffff, 0x0fff);
    EXPECT_EQ(e[2] & 0x00ffff00, 0x0040f300);
    EXPECT_EQ(rl, 8);
    /* same for another thread */
    HANDLE th = CreateThread(NULL, 0, idle_thread, NULL, 0, NULL);
    if (th) {
        struct { NTSTATUS s; PVOID teb; PVOID cid[2]; ULONG_PTR aff; LONG pri, bpri; } tbi;
        if (U(NtQueryInformationThread)(th, 0, &tbi, sizeof tbi, NULL) == 0) {
            e[0] = 0x53; e[1] = e[2] = 0xcccccccc;
            EXPECT_EQ(UN(RtlWow64GetThreadSelectorEntry)(th, e, 12, &rl), ST_SUCCESS);
            base = (e[1] >> 16) | ((e[2] & 0xff) << 16) | (e[2] & 0xff000000);
            EXPECT_EQ(base, (ULONG)((ULONG_PTR)tbi.teb + 0x2000));
        } else t_note("NtQueryInformationThread(basic) failed");
        TerminateThread(th, 0); CloseHandle(th);
    }
    /* errors */
    e[0] = 0x3b; e[1] = e[2] = 0xcccccccc; rl = 99;
    EXPECT_EQ(UN(RtlWow64GetThreadSelectorEntry)(NT_CUR_THREAD, e, 12, &rl), ST_UNSUCC);
    EXPECT_EQ(rl, 99);
    e[0] = 0x100;
    EXPECT_EQ(UN(RtlWow64GetThreadSelectorEntry)(NT_CUR_THREAD, e, 12, &rl), ST_UNSUCC);
    e[0] = 0x23;
    EXPECT_EQ(UN(RtlWow64GetThreadSelectorEntry)(NT_CUR_THREAD, e, 8, &rl), ST_LEN_MISM);
    EXPECT_EQ(UN(RtlWow64GetThreadSelectorEntry)(NT_CUR_THREAD, e, 16, &rl), ST_LEN_MISM);
}

TEST(suspend_thread)
{
    REQUIRE(UN(RtlWow64SuspendThread)); REQUIRE(UN(NtResumeThread));
    EXPECT_EQ(UN(RtlWow64SuspendThread)((HANDLE)0x1234, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(RtlWow64SuspendThread)(NULL, NULL), ST_INV_HANDLE);
    HANDLE th = CreateThread(NULL, 0, idle_thread, NULL, CREATE_SUSPENDED, NULL);
    if (!th) { t_skip("CreateThread failed"); return; }
    ULONG prev = 0xdead;
    EXPECT_EQ(UN(RtlWow64SuspendThread)(th, &prev), ST_SUCCESS);
    EXPECT_EQ(prev, 1);
    prev = 0xdead;
    EXPECT_EQ(UN(RtlWow64SuspendThread)(th, NULL), ST_SUCCESS);
    ULONG cnt = 0xdead;
    EXPECT_EQ(UN(NtResumeThread)(th, &cnt), ST_SUCCESS);
    EXPECT_EQ(cnt, 3);
    EXPECT_EQ(UN(NtResumeThread)(th, &cnt), ST_SUCCESS);
    EXPECT_EQ(cnt, 2);
    TerminateThread(th, 0); CloseHandle(th);
}

CHILD(w64_idle) { Sleep(60000); return 0; }

TEST(suspend_process)
{
    REQUIRE(UN(RtlWow64SuspendProcess)); REQUIRE(UN(NtResumeProcess)); REQUIRE(UN(NtQueryInformationThread));
    EXPECT_EQ(UN(RtlWow64SuspendProcess)((HANDLE)0x1234), ST_INV_HANDLE);
    EXPECT_EQ(UN(RtlWow64SuspendProcess)(NULL), ST_INV_HANDLE);
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof pi);
    t_spawn_child("w64_idle", "", CREATE_SUSPENDED, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!pi.hProcess) { t_skip("child spawn failed"); return; }
    ULONG cnt = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationThread)(pi.hThread, 35, &cnt, 4, NULL), ST_SUCCESS);
    EXPECT_EQ(cnt, 1);
    EXPECT_EQ(UN(RtlWow64SuspendProcess)(pi.hProcess), ST_SUCCESS);
    cnt = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationThread)(pi.hThread, 35, &cnt, 4, NULL), ST_SUCCESS);
    EXPECT_EQ(cnt, 2);
    EXPECT_EQ(UN(NtResumeProcess)(pi.hProcess), ST_SUCCESS);
    cnt = 0xdead;
    EXPECT_EQ(UN(NtQueryInformationThread)(pi.hThread, 35, &cnt, 4, NULL), ST_SUCCESS);
    EXPECT_EQ(cnt, 1);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
}

TEST(not_implemented_stubs)
{
    REQUIRE(UN(RtlWow64CallFunction64)); REQUIRE(UN(RtlWow64EnableFsRedirection)); REQUIRE(UN(RtlWow64EnableFsRedirectionEx));
    /* all three exports are one routine returning STATUS_NOT_IMPLEMENTED on x64 */
    EXPECT_EQ(t_proc("RtlWow64CallFunction64"), t_proc("RtlWow64EnableFsRedirection"));
    EXPECT_EQ(t_proc("RtlWow64CallFunction64"), t_proc("RtlWow64EnableFsRedirectionEx"));
    EXPECT_EQ(UN(RtlWow64CallFunction64)(), ST_NOT_IMPL);
    EXPECT_EQ(UN(RtlWow64EnableFsRedirection)(TRUE), ST_NOT_IMPL);
    EXPECT_EQ(UN(RtlWow64EnableFsRedirection)(FALSE), ST_NOT_IMPL);
    PVOID old = (PVOID)5;
    EXPECT_EQ(UN(RtlWow64EnableFsRedirectionEx)(NULL, &old), ST_NOT_IMPL);
    EXPECT_EQ(old, 5);
}

/* ---- Rtlp context converters ------------------------------------------------- */
UDECL(NTSTATUS, RtlpWow64CtxFromAmd64, (ULONG, PVOID, PVOID));
UDECL(NTSTATUS, RtlpWow64GetContextOnAmd64, (PVOID, PVOID, PVOID));
UDECL(NTSTATUS, RtlpWow64SetContextOnAmd64, (PVOID, PVOID, PVOID, PBOOLEAN));
#define D(b, off) (*(ULONG *)((BYTE *)(b) + (off)))

TEST(ctx_from_amd64)
{
    REQUIRE(UN(RtlpWow64CtxFromAmd64));
    static BYTE a[0x500], w[0x2cc];
    memset(a, 0, sizeof a);
    D(a, 0x44) = 0x246; D(a, 0x78) = 0xa1; D(a, 0x80) = 0xa2; D(a, 0x88) = 0xa3; D(a, 0x90) = 0xa4;
    D(a, 0x98) = 0x3333; D(a, 0xa0) = 0x1111; D(a, 0xa8) = 0xa5; D(a, 0xb0) = 0xa6; D(a, 0xf8) = 0x2222;
    memset(w, 0xcc, sizeof w);
    EXPECT_EQ(UN(RtlpWow64CtxFromAmd64)(0x10001, a, w), ST_SUCCESS);
    EXPECT_EQ(D(w, 0), 0x10001);
    EXPECT_EQ(D(w, 0xb4), 0x1111); EXPECT_EQ(D(w, 0xb8), 0x2222); EXPECT_EQ(D(w, 0xbc), 0x23);
    EXPECT_EQ(D(w, 0xc0), 0x246); EXPECT_EQ(D(w, 0xc4), 0x3333); EXPECT_EQ(D(w, 0xc8), 0x2b);
    EXPECT_EQ(D(w, 0x9c), 0xcccccccc);        /* integer registers untouched */
    memset(w, 0xcc, sizeof w);
    EXPECT_EQ(UN(RtlpWow64CtxFromAmd64)(0x10002, a, w), ST_SUCCESS);
    EXPECT_EQ(D(w, 0x9c), 0xa6); EXPECT_EQ(D(w, 0xa0), 0xa5); EXPECT_EQ(D(w, 0xa4), 0xa4);
    EXPECT_EQ(D(w, 0xa8), 0xa3); EXPECT_EQ(D(w, 0xac), 0xa2); EXPECT_EQ(D(w, 0xb0), 0xa1);
    EXPECT_EQ(D(w, 0xb4), 0xcccccccc);
    memset(w, 0xcc, sizeof w);
    EXPECT_EQ(UN(RtlpWow64CtxFromAmd64)(0x10004, a, w), ST_SUCCESS);
    EXPECT_EQ(D(w, 0x8c), 0x2b); EXPECT_EQ(D(w, 0x90), 0x53); EXPECT_EQ(D(w, 0x94), 0x2b); EXPECT_EQ(D(w, 0x98), 0x2b);
    /* flags without the i386 bit select nothing */
    memset(w, 0xcc, sizeof w);
    EXPECT_EQ(UN(RtlpWow64CtxFromAmd64)(0x1, a, w), ST_SUCCESS);
    EXPECT_EQ(D(w, 0), 1); EXPECT_EQ(D(w, 0xb4), 0xcccccccc);
}

TEST(ctx_on_amd64)
{
    REQUIRE(UN(RtlpWow64GetContextOnAmd64)); REQUIRE(UN(RtlpWow64SetContextOnAmd64));
    static BYTE t[0x200], w[0x2cc];
    memset(t, 0, sizeof t);
    D(t, 0x9c) = 1; D(t, 0xa0) = 2; D(t, 0xa4) = 3; D(t, 0xa8) = 4; D(t, 0xac) = 5; D(t, 0xb0) = 6;
    D(t, 0xb4) = 0x1111; D(t, 0xb8) = 0x2222; D(t, 0xc0) = 0xffffffff; D(t, 0xc4) = 0x3333;
    memset(w, 0, sizeof w); D(w, 0) = 0x10003;
    EXPECT_EQ(UN(RtlpWow64GetContextOnAmd64)(t, NULL, w), ST_SUCCESS);
    EXPECT_EQ(D(w, 0x9c), 1); EXPECT_EQ(D(w, 0xb0), 6);
    EXPECT_EQ(D(w, 0xb4), 0x1111); EXPECT_EQ(D(w, 0xb8), 0x2222); EXPECT_EQ(D(w, 0xbc), 0x23);
    EXPECT_EQ(D(w, 0xc0), (0xffffffffu & 0x3f0dd5) | 0x202); EXPECT_EQ(D(w, 0xc4), 0x3333); EXPECT_EQ(D(w, 0xc8), 0x2b);
    EXPECT_EQ(D(w, 0), 0x10003);
    /* flags outside the supported mask or not i386 */
    D(w, 0) = 0x1;
    EXPECT_EQ(UN(RtlpWow64GetContextOnAmd64)(t, NULL, w), ST_INV_PARAM);
    D(w, 0) = 0x10080;
    EXPECT_EQ(UN(RtlpWow64GetContextOnAmd64)(t, NULL, w), ST_INV_PARAM);

    /* set: write the WOW64 context back into the register file */
    static BYTE d[0x200]; memset(d, 0x11, sizeof d);
    memset(w, 0, sizeof w); D(w, 0) = 0x10003;
    D(w, 0x9c) = 0xa1; D(w, 0xa0) = 0xa2; D(w, 0xa4) = 0xa3; D(w, 0xa8) = 0xa4; D(w, 0xac) = 0xa5; D(w, 0xb0) = 0xa6;
    D(w, 0xb4) = 0xb1; D(w, 0xb8) = 0xb2; D(w, 0xc0) = 0xffffffff; D(w, 0xc4) = 0xb3; D(w, 0xc8) = 0x2b;
    BOOLEAN ch = 9;
    EXPECT_EQ(UN(RtlpWow64SetContextOnAmd64)(d, NULL, w, &ch), ST_SUCCESS);
    EXPECT_EQ(ch, 0);
    EXPECT_EQ(D(d, 0x9c), 0xa1); EXPECT_EQ(D(d, 0xa0), 0xa2); EXPECT_EQ(D(d, 0xa4), 0xa3);
    EXPECT_EQ(D(d, 0xa8), 0xa4); EXPECT_EQ(D(d, 0xac), 0xa5); EXPECT_EQ(D(d, 0xb0), 0xa6);
    EXPECT_EQ(D(d, 0xb4), 0xb1); EXPECT_EQ(D(d, 0xb8), 0xb2); EXPECT_EQ(D(d, 0xbc), 0x23);
    EXPECT_EQ(D(d, 0xc0), (0xffffffffu & 0x3f0dd5) | 0x202); EXPECT_EQ(D(d, 0xc4), 0xb3); EXPECT_EQ(D(d, 0xc8), 0x2b);
    EXPECT_EQ(D(d, 0x90), 0x11111111);
}

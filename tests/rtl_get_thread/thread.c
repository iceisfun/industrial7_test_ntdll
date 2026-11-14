#include "t.h"
#include <stdlib.h>

UDECL(ULONG, RtlGetThreadErrorMode, (void));
UDECL(LONG, RtlGetCriticalSectionRecursionCount, (PRTL_CRITICAL_SECTION));
UDECL(PVOID, RtlGetFrame, (void));
UDECL(VOID, RtlPushFrame, (PVOID));
UDECL(VOID, RtlPopFrame, (PVOID));
UDECL(PVOID, RtlGetCurrentTransaction, (void));
UDECL(BOOLEAN, RtlSetCurrentTransaction, (PVOID));
UDECL(VOID, RtlGetCallersAddress, (PVOID *, PVOID *));
UDECL(NTSTATUS, RtlGetActiveActivationContext, (HANDLE *));
UDECL(NTSTATUS, RtlGetCurrentUmsThread, (PVOID *));
UDECL(NTSTATUS, RtlGetNextUmsListItem, (PVOID *, PVOID *));
UDECL(NTSTATUS, RtlGetUmsCompletionListEvent, (PVOID, HANDLE *));
UDECL(NTSTATUS, RtlGetThreadWorkOnBehalfTicket, (PVOID, ULONG));
UDECL(BOOLEAN, RtlGetSecurityDescriptorRMControl, (PVOID, PUCHAR));
UDECL(PVOID, RtlGetFunctionTableListHead, (void));
UDECL(PVOID, RtlGetUnloadEventTrace, (void));
UDECL(VOID, RtlGetUnloadEventTraceEx, (ULONG **, ULONG **, PVOID *));
UDECL(PVOID, RtlGetReturnAddressHijackTarget, (void));
UDECL(NTSTATUS, RtlGetNonVolatileToken, (PVOID, SIZE_T, PVOID *));
UDECL(NTSTATUS, RtlGetLocaleFileMappingAddress, (PVOID *, ULONG *));
UDECL(BOOLEAN, RtlGetUserInfoHeap, (HANDLE, ULONG, PVOID, PVOID *, ULONG *));
UDECL(BOOLEAN, RtlSetUserValueHeap, (HANDLE, ULONG, PVOID, PVOID));
UDECL(BOOLEAN, RtlSetUserFlagsHeap, (HANDLE, ULONG, PVOID, ULONG, ULONG));
UDECL(BOOLEAN, RtlCreateHashTable, (PVOID *, ULONG, ULONG));
UDECL(VOID, RtlDeleteHashTable, (PVOID));
UDECL(BOOLEAN, RtlInsertEntryHashTable, (PVOID, PVOID, ULONG_PTR, PVOID));
UDECL(PVOID, RtlLookupEntryHashTable, (PVOID, ULONG_PTR, PVOID));
UDECL(PVOID, RtlGetNextEntryHashTable, (PVOID, PVOID));
UDECL(BOOLEAN, RtlRemoveEntryHashTable, (PVOID, PVOID, PVOID));

#define ST_INVALID_PARAM ((NTSTATUS)0xC000000D)
#define ST_INVALID_PARAM_2 ((NTSTATUS)0xC00000F0)

TEST(get_thread_error_mode) {
    REQUIRE(UN(RtlGetThreadErrorMode));
    DWORD old = 0;
    BOOL (WINAPI *set)(DWORD, LPDWORD) = (void *)UIN("kernel32.dll", SetThreadErrorMode);
    DWORD (WINAPI *get)(void) = (void *)UIN("kernel32.dll", GetThreadErrorMode);
    REQUIRE(set); REQUIRE(get);
    ULONG base = UN(RtlGetThreadErrorMode)();
    CHECK(set(0, &old));
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0);
    CHECK(set(SEM_FAILCRITICALERRORS, NULL));
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0x10);
    CHECK(set(SEM_NOGPFAULTERRORBOX, NULL));
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0x20);
    CHECK(set(SEM_NOOPENFILEERRORBOX, NULL));
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0x40);
    CHECK(set(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX, NULL));
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0x70);
    EXPECT_EQ(get(), SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    CHECK(set(0, NULL));
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0);
    set(old, NULL);
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), base);
}

static DWORD WINAPI err_thread(LPVOID p) {
    ULONG *out = p; out[0] = UN(RtlGetThreadErrorMode)();
    BOOL (WINAPI *set)(DWORD, LPDWORD) = (void *)UIN("kernel32.dll", SetThreadErrorMode);
    set(SEM_NOGPFAULTERRORBOX, NULL); out[1] = UN(RtlGetThreadErrorMode)();
    return 0;
}
TEST(get_thread_error_mode_per_thread) {
    REQUIRE(UN(RtlGetThreadErrorMode));
    BOOL (WINAPI *set)(DWORD, LPDWORD) = (void *)UIN("kernel32.dll", SetThreadErrorMode);
    REQUIRE(set);
    DWORD old; set(SEM_FAILCRITICALERRORS, &old);
    ULONG out[2] = { 0xdead, 0xdead };
    HANDLE h = CreateThread(NULL, 0, err_thread, out, 0, NULL);
    REQUIRE(h);
    CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0); CloseHandle(h);
    EXPECT_EQ(out[0], 0);              /* new threads start with no per-thread error mode */
    EXPECT_EQ(out[1], 0x20);
    EXPECT_EQ(UN(RtlGetThreadErrorMode)(), 0x10);   /* unaffected by the other thread */
    set(old, NULL);
}

static DWORD WINAPI rec_thread(LPVOID p) {
    PRTL_CRITICAL_SECTION cs = p;
    return (DWORD)UN(RtlGetCriticalSectionRecursionCount)(cs) + 100;
}
TEST(get_critical_section_recursion_count) {
    REQUIRE(UN(RtlGetCriticalSectionRecursionCount));
    CRITICAL_SECTION cs; InitializeCriticalSection(&cs);
    PRTL_CRITICAL_SECTION p = (PRTL_CRITICAL_SECTION)&cs;
    EXPECT_EQ(UN(RtlGetCriticalSectionRecursionCount)(p), 0);
    EnterCriticalSection(&cs);
    EXPECT_EQ(UN(RtlGetCriticalSectionRecursionCount)(p), 1);
    EnterCriticalSection(&cs); EnterCriticalSection(&cs);
    EXPECT_EQ(UN(RtlGetCriticalSectionRecursionCount)(p), 3);
    HANDLE h = CreateThread(NULL, 0, rec_thread, p, 0, NULL);
    DWORD code = 0xdead;
    if (h) { CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0); GetExitCodeThread(h, &code); CloseHandle(h); }
    EXPECT_EQ(code, 100);                /* a non-owner sees 0 */
    LeaveCriticalSection(&cs);
    EXPECT_EQ(UN(RtlGetCriticalSectionRecursionCount)(p), 2);
    LeaveCriticalSection(&cs); LeaveCriticalSection(&cs);
    EXPECT_EQ(UN(RtlGetCriticalSectionRecursionCount)(p), 0);
    DeleteCriticalSection(&cs);
}

typedef struct _AF { ULONG Flags; struct _AF *Previous; PVOID Context; } AF;
TEST(get_frame) {
    REQUIRE(UN(RtlGetFrame)); REQUIRE(UN(RtlPushFrame)); REQUIRE(UN(RtlPopFrame));
    PVOID saved = UN(RtlGetFrame)();
    EXPECT_EQ(saved, *(PVOID *)((BYTE *)NtCurrentTeb() + 0x17c0));
    AF a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    UN(RtlPushFrame)(&a);
    EXPECT_EQ(UN(RtlGetFrame)(), &a);
    EXPECT_EQ(a.Previous, saved);
    UN(RtlPushFrame)(&b);
    EXPECT_EQ(UN(RtlGetFrame)(), &b);
    EXPECT_EQ(b.Previous, &a);
    UN(RtlPopFrame)(&b);
    EXPECT_EQ(UN(RtlGetFrame)(), &a);
    UN(RtlPopFrame)(&a);
    EXPECT_EQ(UN(RtlGetFrame)(), saved);
}

TEST(get_current_transaction) {
    REQUIRE(UN(RtlGetCurrentTransaction)); REQUIRE(UN(RtlSetCurrentTransaction));
    PVOID saved = UN(RtlGetCurrentTransaction)();
    EXPECT_EQ(saved, NULL);
    EXPECT_EQ(saved, *(PVOID *)((BYTE *)NtCurrentTeb() + 0x17b8));
    UN(RtlSetCurrentTransaction)((PVOID)(ULONG_PTR)0x1234);
    EXPECT_EQ(UN(RtlGetCurrentTransaction)(), (PVOID)(ULONG_PTR)0x1234);
    UN(RtlSetCurrentTransaction)(NULL);
    EXPECT_EQ(UN(RtlGetCurrentTransaction)(), NULL);
}

static __attribute__((noinline)) void callee_fn(PVOID *a, PVOID *b, PVOID *ra) {
    *ra = __builtin_return_address(0);
    UN(RtlGetCallersAddress)(a, b);
    __asm__ volatile("" ::: "memory");
}
static __attribute__((noinline)) void caller_fn(PVOID *a, PVOID *b, PVOID *ra, PVOID *ra2) {
    *ra2 = __builtin_return_address(0);
    callee_fn(a, b, ra);
    __asm__ volatile("" ::: "memory");
}
TEST(get_callers_address) {
    REQUIRE(UN(RtlGetCallersAddress));
    PVOID a = (PVOID)1, b = (PVOID)1, ra = NULL, ra2 = NULL;
    caller_fn(&a, &b, &ra, &ra2);
    EXPECT_EQ(a, ra);          /* address inside the function that called our caller... */
    EXPECT_EQ(b, ra2);
    CHECK(a != NULL && b != NULL);
}

TEST(get_active_activation_context) {
    REQUIRE(UN(RtlGetActiveActivationContext));
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(NULL), ST_INVALID_PARAM);
    HANDLE h = (HANDLE)1;
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&h), 0);
    EXPECT_EQ(h, NULL);
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "act.manifest");
    FILE *f = fopen(path, "wb");
    if (!f) { t_skip("cannot create manifest"); return; }
    fputs("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
          "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
          "<assemblyIdentity type=\"win32\" name=\"RtlGetTest.App\" version=\"1.0.0.0\"/></assembly>", f);
    fclose(f);
    ACTCTXA ac; memset(&ac, 0, sizeof ac); ac.cbSize = sizeof ac; ac.lpSource = path;
    HANDLE ctx = CreateActCtxA(&ac);
    if (ctx == INVALID_HANDLE_VALUE) { DeleteFileA(path); t_skip("CreateActCtxA failed: %lu", GetLastError()); return; }
    ULONG_PTR cookie = 0;
    CHECK(ActivateActCtx(ctx, &cookie));
    HANDLE act = NULL;
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&act), 0);
    EXPECT_EQ(act, ctx);
    if (act) ReleaseActCtx(act);            /* the call added a reference */
    CHECK(DeactivateActCtx(0, cookie));
    act = (HANDLE)1;
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&act), 0);
    EXPECT_EQ(act, NULL);
    ReleaseActCtx(ctx);
    DeleteFileA(path);
}

TEST(get_ums_stubs) {
    REQUIRE(UN(RtlGetCurrentUmsThread)); REQUIRE(UN(RtlGetNextUmsListItem)); REQUIRE(UN(RtlGetUmsCompletionListEvent));
    PVOID ut = (PVOID)1;
    EXPECT_EQ(UN(RtlGetCurrentUmsThread)(NULL), ST_INVALID_PARAM);
    NTSTATUS s = UN(RtlGetCurrentUmsThread)(&ut);
    EXPECT_EQ(s, (NTSTATUS)0xC00000BB);          /* not a UMS thread */
    EXPECT_EQ(ut, NULL);
    /* single-entry list: the head is atomically swapped out */
    PVOID head = (PVOID)(ULONG_PTR)0x1234, item = (PVOID)1;
    EXPECT_EQ(UN(RtlGetNextUmsListItem)(&head, &item), 0);
    EXPECT_EQ(item, (PVOID)(ULONG_PTR)0x1234); EXPECT_EQ(head, NULL);
    EXPECT_EQ(UN(RtlGetNextUmsListItem)(&head, &item), 0);
    EXPECT_EQ(item, NULL);
    item = (PVOID)1;
    EXPECT_EQ(UN(RtlGetNextUmsListItem)(NULL, &item), ST_INVALID_PARAM);
    EXPECT_EQ(item, (PVOID)1);
    HANDLE ev = (HANDLE)1;
    EXPECT_EQ(UN(RtlGetUmsCompletionListEvent)(NULL, &ev), ST_INVALID_PARAM);
    EXPECT_EQ(UN(RtlGetUmsCompletionListEvent)((PVOID)8, NULL), ST_INVALID_PARAM);
    EXPECT_EQ(ev, (HANDLE)1);
    BOOL (WINAPI *create)(PVOID *) = (void *)UIN("kernel32.dll", CreateUmsCompletionList);
    BOOL (WINAPI *del)(PVOID) = (void *)UIN("kernel32.dll", DeleteUmsCompletionList);
    if (create && del) {
        PVOID list = NULL;
        if (create(&list) && list) {
            ev = NULL;
            NTSTATUS e = UN(RtlGetUmsCompletionListEvent)(list, &ev);
            t_note("RtlGetUmsCompletionListEvent(real list) = %08lx", (ULONG)e);
            if (e == 0) { CHECK(ev != NULL); if (ev) { CHECK(SetEvent(ev)); CloseHandle(ev); } }
            del(list);
        } else t_note("CreateUmsCompletionList failed: %lu", GetLastError());
    }
}

TEST(get_thread_work_on_behalf_ticket) {
    REQUIRE(UN(RtlGetThreadWorkOnBehalfTicket));
    ULONGLONG t[2]; memset(t, 0xAA, sizeof t);
    EXPECT_EQ(UN(RtlGetThreadWorkOnBehalfTicket)(t, 0), 0);
    EXPECT_EQ(t[0], *(ULONGLONG *)((BYTE *)NtCurrentTeb() + 0x2b8));
    memset(t, 0xAA, sizeof t);
    EXPECT_EQ(UN(RtlGetThreadWorkOnBehalfTicket)(t, 3), ST_INVALID_PARAM_2);
    EXPECT_EQ(UN(RtlGetThreadWorkOnBehalfTicket)(t, 7), ST_INVALID_PARAM_2);
    EXPECT_EQ(UN(RtlGetThreadWorkOnBehalfTicket)(t, 8), ST_INVALID_PARAM_2);
    EXPECT_EQ(UN(RtlGetThreadWorkOnBehalfTicket)(t, 0x100), ST_INVALID_PARAM_2);
    EXPECT_EQ(t[0], 0xAAAAAAAAAAAAAAAAull);
    NTSTATUS s = UN(RtlGetThreadWorkOnBehalfTicket)(t, 2);
    EXPECT_EQ(s, 0);                                   /* thread-information query form */
}

TEST(get_security_descriptor_rm_control) {
    REQUIRE(UN(RtlGetSecurityDescriptorRMControl));
    union { SECURITY_DESCRIPTOR sd; BYTE raw[64]; } u; memset(&u, 0, sizeof u);
    u.raw[0] = 1;                                         /* Revision */
    UCHAR rm = 0x77;
    EXPECT_EQ(UN(RtlGetSecurityDescriptorRMControl)(&u, &rm), FALSE);
    EXPECT_EQ(rm, 0);
    u.raw[1] = 0x5a; *(USHORT *)&u.raw[2] |= 0x4000;      /* SE_RM_CONTROL_VALID */
    rm = 0;
    EXPECT_EQ(UN(RtlGetSecurityDescriptorRMControl)(&u, &rm), TRUE);
    EXPECT_EQ(rm, 0x5a);
    /* round trip through the setter */
    UDECL(VOID, RtlSetSecurityDescriptorRMControl, (PVOID, PUCHAR));
    if (UN(RtlSetSecurityDescriptorRMControl)) {
        UCHAR v = 0x21; UN(RtlSetSecurityDescriptorRMControl)(&u, &v);
        rm = 0; EXPECT_EQ(UN(RtlGetSecurityDescriptorRMControl)(&u, &rm), TRUE); EXPECT_EQ(rm, 0x21);
        UN(RtlSetSecurityDescriptorRMControl)(&u, NULL);
        rm = 0x77; EXPECT_EQ(UN(RtlGetSecurityDescriptorRMControl)(&u, &rm), FALSE); EXPECT_EQ(rm, 0);
    }
}

TEST(get_function_table_list_head) {
    REQUIRE(UN(RtlGetFunctionTableListHead));
    PLIST_ENTRY head = UN(RtlGetFunctionTableListHead)();
    CHECK(head != NULL);
    EXPECT_EQ(head, UN(RtlGetFunctionTableListHead)());
    if (!head) return;
    CHECK(head->Flink != NULL && head->Blink != NULL);
    int before = 0; for (PLIST_ENTRY e = head->Flink; e != head && before < 100000; e = e->Flink) before++;
    BOOLEAN (WINAPI *add)(PRUNTIME_FUNCTION, DWORD, DWORD64) = (void *)UIN("kernel32.dll", RtlAddFunctionTable);
    BOOLEAN (WINAPI *del)(PRUNTIME_FUNCTION) = (void *)UIN("kernel32.dll", RtlDeleteFunctionTable);
    if (!add || !del) { t_skip("RtlAddFunctionTable not exported by kernel32"); return; }
    static RUNTIME_FUNCTION rf[1];
    DWORD64 base = (DWORD64)(ULONG_PTR)GetModuleHandleW(NULL);
    CHECK(add(rf, 1, base));
    int mid = 0; PLIST_ENTRY found = NULL;
    for (PLIST_ENTRY e = head->Flink; e != head && mid < 100000; e = e->Flink) {
        mid++;
        if (((PVOID *)e)[2] == (PVOID)rf) found = e;     /* dynamic table: list entry, then the table pointer */
    }
    EXPECT_EQ(mid, before + 1);
    CHECK(found != NULL);
    CHECK(del(rf));
    int after = 0; for (PLIST_ENTRY e = head->Flink; e != head && after < 100000; e = e->Flink) after++;
    EXPECT_EQ(after, before);
}

typedef struct { PVOID Base; SIZE_T Size; ULONG Seq, Stamp, Checksum; WCHAR Name[32]; } UT_OLD;
TEST(get_unload_event_trace) {
    REQUIRE(UN(RtlGetUnloadEventTrace)); REQUIRE(UN(RtlGetUnloadEventTraceEx));
    PVOID tr = UN(RtlGetUnloadEventTrace)();
    CHECK(tr != NULL); EXPECT_EQ(tr, UN(RtlGetUnloadEventTrace)());
    ULONG *size = NULL, *num = NULL; PVOID ex = NULL;
    UN(RtlGetUnloadEventTraceEx)(&size, &num, &ex);
    CHECK(size && num && ex);
    if (!size || !num || !ex) return;
    EXPECT_EQ(*size, 104);
    ULONG n0 = *num;
    /* load and unload a module that is not otherwise loaded */
    HMODULE m = LoadLibraryExW(L"mstask.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (m) FreeLibrary(m);
    m = LoadLibraryW(L"msimg32.dll");
    if (!m) { t_skip("cannot load a probe module"); return; }
    HMODULE m2 = GetModuleHandleW(L"msimg32.dll"); (void)m2;
    FreeLibrary(m);
    ULONG n1 = *num;
    CHECK(n1 >= n0 && n1 <= 64);
    int found = 0, found_old = 0;
    for (int i = 0; i < 16; i++) {
        UT_OLD *e = (UT_OLD *)((BYTE *)tr + (size_t)i * 104);
        if (e->Base == (PVOID)m && lstrcmpiW(e->Name, L"msimg32.dll") == 0) { found_old = 1; CHECK(e->Size != 0); }
    }
    (void)found;
    CHECK(found_old);
}

TEST(get_return_address_hijack_target) {
    REQUIRE(UN(RtlGetReturnAddressHijackTarget));
    PVOID p = UN(RtlGetReturnAddressHijackTarget)();
    CHECK(p != NULL);
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    CHECK((BYTE *)p > (BYTE *)nt && (BYTE *)p < (BYTE *)nt + 0x400000);
    PVOID r = (PVOID)t_proc("RtlRaiseExceptionForReturnAddressHijack");
    if (r) EXPECT_EQ(p, r);
    EXPECT_EQ(p, UN(RtlGetReturnAddressHijackTarget)());
}

TEST(get_non_volatile_token) {
    REQUIRE(UN(RtlGetNonVolatileToken));
    PVOID mem = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(mem != NULL);
    PVOID tok = (PVOID)0x77;
    NTSTATUS s = UN(RtlGetNonVolatileToken)(mem, 0x1000, &tok);
    t_note("RtlGetNonVolatileToken(RAM) = %08lx tok=%p", (ULONG)s, tok);
    EXPECT_EQ(s, ST_INVALID_PARAM);                  /* ordinary memory is not non-volatile */
    EXPECT_EQ(tok, (PVOID)0x77);
    s = UN(RtlGetNonVolatileToken)(NULL, 0x1000, &tok);
    EXPECT_EQ(s, (NTSTATUS)0xC0000141);              /* STATUS_INVALID_ADDRESS */
    if (mem) VirtualFree(mem, 0, MEM_RELEASE);
}

TEST(get_locale_file_mapping_address) {
    REQUIRE(UN(RtlGetLocaleFileMappingAddress));
    PVOID base = NULL; ULONG lcid = 0x409;
    EXPECT_EQ(UN(RtlGetLocaleFileMappingAddress)(NULL, &lcid), (NTSTATUS)0xC00000EF);
    EXPECT_EQ(UN(RtlGetLocaleFileMappingAddress)(&base, NULL), (NTSTATUS)0xC00000F0);
    EXPECT_EQ(UN(RtlGetLocaleFileMappingAddress)(&base, &lcid), 0);
    CHECK(base != NULL);
    PVOID b2 = NULL; ULONG l2 = 0xdead;
    EXPECT_EQ(UN(RtlGetLocaleFileMappingAddress)(&b2, &l2), 0);
    EXPECT_EQ(b2, base);
    PVOID b3 = NULL; ULONG l3 = 0xbeef;
    EXPECT_EQ(UN(RtlGetLocaleFileMappingAddress)(&b3, &l3), 0);
    EXPECT_EQ(b3, base); EXPECT_EQ(l3, l2);
    MEMORY_BASIC_INFORMATION mbi;
    if (base && VirtualQuery(base, &mbi, sizeof mbi)) { EXPECT_EQ(mbi.Type, MEM_MAPPED); EXPECT_EQ(mbi.State, MEM_COMMIT); }
}

TEST(get_user_info_heap) {
    REQUIRE(UN(RtlGetUserInfoHeap)); REQUIRE(UN(RtlSetUserValueHeap)); REQUIRE(UN(RtlSetUserFlagsHeap));
    HANDLE h = HeapCreate(0, 0, 0);
    REQUIRE(h);
    PVOID plain = HeapAlloc(h, 0, 64);
    /* a block allocated without HEAP_SETTABLE_USER_VALUE cannot carry a user value */
    EXPECT_EQ(UN(RtlSetUserValueHeap)(h, 0, plain, (PVOID)0x1234), FALSE);
    HeapFree(h, 0, plain);
    PVOID p = HeapAlloc(h, 0x100, 64);                 /* HEAP_SETTABLE_USER_VALUE */
    CHECK(p != NULL);
    PVOID val = (PVOID)0x55; ULONG fl = 0xdead;
    EXPECT_EQ(UN(RtlGetUserInfoHeap)(h, 0, p, &val, &fl), TRUE);
    EXPECT_EQ(fl, 0);
    EXPECT_EQ(UN(RtlSetUserValueHeap)(h, 0, p, (PVOID)0x1234), TRUE);
    val = NULL; fl = 0xdead;
    EXPECT_EQ(UN(RtlGetUserInfoHeap)(h, 0, p, &val, &fl), TRUE);
    EXPECT_EQ(val, (PVOID)0x1234);
    EXPECT_EQ(fl, 0);
    EXPECT_EQ(UN(RtlSetUserFlagsHeap)(h, 0, p, 0, 0x200), TRUE);       /* HEAP_SETTABLE_USER_FLAG1 */
    EXPECT_EQ(UN(RtlGetUserInfoHeap)(h, 0, p, &val, &fl), TRUE);
    EXPECT_EQ(fl, 0x200); EXPECT_EQ(val, (PVOID)0x1234);
    EXPECT_EQ(UN(RtlSetUserFlagsHeap)(h, 0, p, 0, 0xc00), TRUE);
    EXPECT_EQ(UN(RtlGetUserInfoHeap)(h, 0, p, NULL, &fl), TRUE); EXPECT_EQ(fl, 0xe00);
    EXPECT_EQ(UN(RtlSetUserFlagsHeap)(h, 0, p, 0x200, 0), TRUE);
    EXPECT_EQ(UN(RtlGetUserInfoHeap)(h, 0, p, &val, NULL), TRUE);
    EXPECT_EQ(UN(RtlGetUserInfoHeap)(h, 0, p, NULL, &fl), TRUE); EXPECT_EQ(fl, 0xc00);
    /* a second block is independent */
    PVOID q = HeapAlloc(h, 0x100, 64); PVOID v2 = (PVOID)0x9; ULONG f2 = 0xdead;
    EXPECT_EQ(UN(RtlGetUserInfoHeap)(h, 0, q, &v2, &f2), TRUE); EXPECT_EQ(f2, 0);
    HeapFree(h, 0, q); HeapFree(h, 0, p);
    HeapDestroy(h);
}

typedef struct { LIST_ENTRY Link; ULONG_PTR Sig; } HENT;
typedef struct { PLIST_ENTRY ChainHead; PLIST_ENTRY PrevLinkage; ULONG_PTR Signature; } HCTX;
TEST(get_next_entry_hash_table) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlDeleteHashTable)); REQUIRE(UN(RtlInsertEntryHashTable));
    REQUIRE(UN(RtlLookupEntryHashTable)); REQUIRE(UN(RtlGetNextEntryHashTable));
    PVOID tbl = NULL;
    EXPECT_EQ(UN(RtlCreateHashTable)(&tbl, 0, 0), TRUE);
    CHECK(tbl != NULL);
    if (!tbl) return;
    HENT e[5]; memset(e, 0, sizeof e);
    ULONG_PTR sigs[5] = { 100, 100, 100, 200, 300 };
    for (int i = 0; i < 5; i++) EXPECT_EQ(UN(RtlInsertEntryHashTable)(tbl, &e[i], sigs[i], NULL), TRUE);
    HCTX ctx; memset(&ctx, 0, sizeof ctx);
    HENT *f = UN(RtlLookupEntryHashTable)(tbl, 100, &ctx);
    CHECK(f != NULL);
    int seen[5] = {0}, cnt = 0;
    for (HENT *c = f; c && cnt < 10; c = UN(RtlGetNextEntryHashTable)(tbl, &ctx)) {
        cnt++;
        EXPECT_EQ(c->Sig, 100);
        for (int i = 0; i < 5; i++) if (c == &e[i]) seen[i]++;
    }
    EXPECT_EQ(cnt, 3);
    EXPECT_EQ(seen[0] + seen[1] + seen[2], 3);
    EXPECT_EQ(seen[3] + seen[4], 0);
    for (int i = 0; i < 3; i++) EXPECT_EQ(seen[i], 1);
    /* after the chain is exhausted the iterator keeps returning NULL */
    EXPECT_EQ(UN(RtlGetNextEntryHashTable)(tbl, &ctx), NULL);
    /* a signature with a single entry has no successor */
    memset(&ctx, 0, sizeof ctx);
    f = UN(RtlLookupEntryHashTable)(tbl, 200, &ctx);
    EXPECT_EQ(f, &e[3]);
    EXPECT_EQ(UN(RtlGetNextEntryHashTable)(tbl, &ctx), NULL);
    memset(&ctx, 0, sizeof ctx);
    EXPECT_EQ(UN(RtlLookupEntryHashTable)(tbl, 999, &ctx), NULL);
    if (UN(RtlRemoveEntryHashTable)) for (int i = 0; i < 5; i++) UN(RtlRemoveEntryHashTable)(tbl, &e[i], NULL);
    UN(RtlDeleteHashTable)(tbl);
}

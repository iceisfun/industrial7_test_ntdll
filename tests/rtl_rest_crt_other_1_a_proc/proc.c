/* Registry transactions (RXact), legacy timers, activation contexts, heap compaction, cross-VM names,
 * import-table hash, capability checks and process cloning. See EVIDENCE.md. */
#include "t.h"
#include <wchar.h>

#define S(x) ((NTSTATUS)(x))
#define K(name) UIN("kernel32.dll", name)
static void us(UNICODE_STRING *u, const WCHAR *w) { u->Buffer = (PWSTR)w; u->Length = (USHORT)(lstrlenW(w) * 2); u->MaximumLength = u->Length + 2; }
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(NTSTATUS, NtClose, (HANDLE));

/* ------------------------------------------------------------------ RXact */
UDECL(NTSTATUS, RtlInitializeRXact, (HANDLE, BOOLEAN, PVOID *));
UDECL(NTSTATUS, RtlStartRXact, (PVOID));
UDECL(NTSTATUS, RtlAbortRXact, (PVOID));
UDECL(NTSTATUS, RtlAddActionToRXact, (PVOID, ULONG, PUNICODE_STRING, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, RtlApplyRXact, (PVOID));
UDECL(NTSTATUS, RtlApplyRXactNoFlush, (PVOID));
UDECL(PVOID, RtlFreeHeap, (PVOID, ULONG, PVOID));
typedef LONG (WINAPI *RegCreateKeyExW_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG (WINAPI *RegDeleteTreeW_t)(HKEY, LPCWSTR);
typedef LONG (WINAPI *RegCloseKey_t)(HKEY);
typedef LONG (WINAPI *RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

TEST(rxact_flow) {
    REQUIRE(UN(RtlInitializeRXact)); REQUIRE(UN(RtlStartRXact)); REQUIRE(UN(RtlAbortRXact)); REQUIRE(UN(RtlAddActionToRXact));
    REQUIRE(UN(RtlApplyRXact)); REQUIRE(UN(RtlApplyRXactNoFlush));
    RegCreateKeyExW_t rc = (RegCreateKeyExW_t)t_proc_in("advapi32.dll", "RegCreateKeyExW");
    RegDeleteTreeW_t rd = (RegDeleteTreeW_t)t_proc_in("advapi32.dll", "RegDeleteTreeW");
    RegCloseKey_t rk = (RegCloseKey_t)t_proc_in("advapi32.dll", "RegCloseKey");
    RegQueryValueExW_t rq = (RegQueryValueExW_t)t_proc_in("advapi32.dll", "RegQueryValueExW");
    if (!rc || !rd || !rk || !rq) { t_skip("advapi32 registry functions unavailable"); return; }
    HKEY root = NULL, sub = NULL;
    rd(HKEY_CURRENT_USER, L"Software\\ntdllt_rxact");
    if (rc(HKEY_CURRENT_USER, L"Software\\ntdllt_rxact", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &root, NULL) != 0) { t_skip("cannot create a scratch registry key"); return; }
    if (rc(root, L"K1", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &sub, NULL) != 0) { rk(root); rd(HKEY_CURRENT_USER, L"Software\\ntdllt_rxact"); t_skip("cannot create a scratch subkey"); return; }
    rk(sub);
    PVOID *ctx = NULL;
    NTSTATUS s = UN(RtlInitializeRXact)((HANDLE)root, FALSE, (PVOID *)&ctx);
    EXPECT_EQ(s, S(0x40000004));                                /* STATUS_RXACT_STATE_CREATED: first use of the key */
    if (s >= 0 && ctx) {
        EXPECT_EQ(ctx[0], (PVOID)root);
        /* nothing started: abort has no log to discard */
        EXPECT_EQ(UN(RtlAbortRXact)(ctx), S(0xC000011C));
        EXPECT_EQ(UN(RtlStartRXact)(ctx), 0);
        EXPECT_EQ(UN(RtlStartRXact)(ctx), S(0xC000011C));         /* already started */
        EXPECT_EQ(UN(RtlAbortRXact)(ctx), 0);
        EXPECT_EQ(UN(RtlAbortRXact)(ctx), S(0xC000011C));
        /* a queued action is applied by RtlApplyRXact */
        UNICODE_STRING key; us(&key, L"K1"); DWORD v = 0x1234;
        EXPECT_EQ(UN(RtlStartRXact)(ctx), 0);
        s = UN(RtlAddActionToRXact)(ctx, 2, &key, REG_DWORD, &v, 4); EXPECT_EQ(s, 0);
        if (s == 0) {
            s = UN(RtlApplyRXact)(ctx); EXPECT_EQ(s, 0);
            HKEY k; DWORD type = 0, got = 0, sz = 4;
            if (rc(root, L"K1", 0, NULL, 0, KEY_READ, NULL, &k, NULL) == 0) {
                LONG r = rq(k, NULL, NULL, &type, (LPBYTE)&got, &sz);
                if (s == 0) { EXPECT_EQ(r, 0); EXPECT_EQ(type, REG_DWORD); EXPECT_EQ(got, 0x1234); }
                rk(k);
            }
            /* the log is gone after a successful apply: a new transaction can start, and abort discards it */
            EXPECT_EQ(UN(RtlStartRXact)(ctx), 0); EXPECT_EQ(UN(RtlAbortRXact)(ctx), 0);
            /* no-flush variant */
            v = 0x5678; EXPECT_EQ(UN(RtlStartRXact)(ctx), 0);
            EXPECT_EQ(UN(RtlAddActionToRXact)(ctx, 2, &key, REG_DWORD, &v, 4), 0);
            UN(RtlApplyRXactNoFlush)(ctx);
            if (rc(root, L"K1", 0, NULL, 0, KEY_READ, NULL, &k, NULL) == 0) {
                sz = 4; got = 0; LONG r = rq(k, NULL, NULL, &type, (LPBYTE)&got, &sz); EXPECT_EQ(r, 0); EXPECT_EQ(got, 0x5678); rk(k);
            }
            EXPECT_EQ(UN(RtlAbortRXact)(ctx), S(0xC000011C));
        } else UN(RtlAbortRXact)(ctx);
        if (UN(NtClose) && ctx[1]) UN(NtClose)((HANDLE)ctx[1]);
        if (UN(RtlFreeHeap)) UN(RtlFreeHeap)(GetProcessHeap(), 0, ctx);
    }
    rk(root); rd(HKEY_CURRENT_USER, L"Software\\ntdllt_rxact");
}

/* ------------------------------------------------------------- legacy timer */
UDECL(NTSTATUS, RtlCreateTimerQueue, (PHANDLE));
UDECL(NTSTATUS, RtlCreateTimer, (HANDLE, PHANDLE, WAITORTIMERCALLBACKFUNC, PVOID, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, RtlCancelTimer, (HANDLE, HANDLE));
UDECL(NTSTATUS, RtlDeleteTimerQueueEx, (HANDLE, HANDLE));
static volatile LONG tcount; static HANDLE tev;
static VOID NTAPI tcb(PVOID ctx, BOOLEAN fired) { InterlockedIncrement(&tcount); if (tev) SetEvent(tev); }
TEST(cancel_timer) {
    REQUIRE(UN(RtlCreateTimerQueue)); REQUIRE(UN(RtlCreateTimer)); REQUIRE(UN(RtlCancelTimer)); REQUIRE(UN(RtlDeleteTimerQueueEx));
    HANDLE q = NULL, t1 = NULL, t2 = NULL; tcount = 0; tev = CreateEventW(NULL, FALSE, FALSE, NULL);
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0); REQUIRE(q);
    /* a one-shot timer fires once; cancelling it afterwards still succeeds and nothing more fires */
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t1, tcb, NULL, 20, 0, 0), 0);
    EXPECT_EQ(WaitForSingleObject(tev, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(tcount, 1);
    NTSTATUS s = UN(RtlCancelTimer)(q, t1); t_note("cancel after fire: 0x%lx", (unsigned long)s); EXPECT_EQ(s, 0);
    /* a timer cancelled before it is due never fires */
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t2, tcb, NULL, 600000, 0, 0), 0);
    s = UN(RtlCancelTimer)(q, t2); t_note("cancel pending: 0x%lx", (unsigned long)s); EXPECT_EQ(s, 0);
    /* a periodic timer stops ticking once cancelled */
    HANDLE t3 = NULL; tcount = 0;
    EXPECT_EQ(UN(RtlCreateTimer)(q, &t3, tcb, NULL, 10, 10, 0), 0);
    EXPECT_EQ(WaitForSingleObject(tev, 10000), WAIT_OBJECT_0);
    s = UN(RtlCancelTimer)(q, t3); t_note("cancel periodic: 0x%lx", (unsigned long)s); /* STATUS_PENDING while a callback is mid-flight */ CHECKF(s == 0 || s == S(0x103), "cancel periodic status 0x%lx", (unsigned long)s);
    Sleep(100); LONG c0 = tcount; Sleep(150); EXPECT_EQ(tcount, c0);
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
    CloseHandle(tev); tev = NULL;
}

/* ------------------------------------------------------- activation context */
UDECL(NTSTATUS, RtlActivateActivationContext, (ULONG, HANDLE, PULONG_PTR));
UDECL(NTSTATUS, RtlActivateActivationContextEx, (ULONG, PVOID, HANDLE, PULONG_PTR));
UDECL(VOID, RtlDeactivateActivationContext, (ULONG, ULONG_PTR));
UDECL(NTSTATUS, RtlGetActiveActivationContext, (HANDLE *));
UDECL(VOID, RtlReleaseActivationContext, (HANDLE));
UDECL(VOID, RtlActivateActivationContextUnsafeFast, (PVOID, HANDLE));
UDECL(PVOID, RtlDeactivateActivationContextUnsafeFast, (PVOID));
static HANDLE make_actctx(void) {
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "ac.manifest");
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    static const char m[] = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
        "<assemblyIdentity version=\"1.0.0.0\" name=\"ntdllt.actctx.test\" type=\"win32\"/></assembly>";
    DWORD n; WriteFile(f, m, sizeof m - 1, &n, NULL); CloseHandle(f);
    typedef HANDLE (WINAPI *CA)(PACTCTXA); CA ca = (CA)K(CreateActCtxA); if (!ca) { DeleteFileA(path); return INVALID_HANDLE_VALUE; }
    ACTCTXA a; memset(&a, 0, sizeof a); a.cbSize = sizeof a; a.lpSource = path;
    HANDLE h = ca(&a); DeleteFileA(path); return h;
}
TEST(activate_activation_context) {
    REQUIRE(UN(RtlActivateActivationContext)); REQUIRE(UN(RtlActivateActivationContextEx)); REQUIRE(UN(RtlDeactivateActivationContext));
    REQUIRE(UN(RtlGetActiveActivationContext)); REQUIRE(UN(RtlReleaseActivationContext));
    HANDLE ctx = make_actctx(); if (ctx == INVALID_HANDLE_VALUE) { t_skip("cannot create an activation context from a manifest"); return; }
    ULONG_PTR cookie = 0xDEAD; HANDLE cur = NULL;
    EXPECT_EQ(UN(RtlActivateActivationContext)(0, ctx, &cookie), 0); EXPECT_NE(cookie, 0xDEAD); EXPECT_NE(cookie, 0);
    EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, ctx);
    if (cur) UN(RtlReleaseActivationContext)(cur);
    UN(RtlDeactivateActivationContext)(0, cookie);
    cur = NULL; UN(RtlGetActiveActivationContext)(&cur); EXPECT_NE(cur, ctx); if (cur) UN(RtlReleaseActivationContext)(cur);
    /* argument validation: the flags must be zero, the cookie pointer is required, -1 is not a context */
    cookie = 0xDEAD; EXPECT_EQ(UN(RtlActivateActivationContext)(1, ctx, &cookie), S(0xC000000D)); EXPECT_EQ(cookie, 0);
    EXPECT_EQ(UN(RtlActivateActivationContext)(0, ctx, NULL), S(0xC000000D));
    cookie = 0xDEAD; EXPECT_EQ(UN(RtlActivateActivationContext)(0, INVALID_HANDLE_VALUE, &cookie), S(0xC000000D)); EXPECT_EQ(cookie, 0);
    /* Ex form: explicit TEB, optional release-on-deactivate flag, invalid flag bits */
    cookie = 0xDEAD; EXPECT_EQ(UN(RtlActivateActivationContextEx)(2, NtCurrentTeb(), ctx, &cookie), S(0xC000000D)); EXPECT_EQ(cookie, 0);
    EXPECT_EQ(UN(RtlActivateActivationContextEx)(0, NULL, ctx, &cookie), S(0xC000000D));
    EXPECT_EQ(UN(RtlActivateActivationContextEx)(0, NtCurrentTeb(), ctx, NULL), S(0xC000000D));
    cookie = 0; EXPECT_EQ(UN(RtlActivateActivationContextEx)(0, NtCurrentTeb(), ctx, &cookie), 0); EXPECT_NE(cookie, 0);
    UN(RtlDeactivateActivationContext)(0, cookie);
    /* nested activations unwind in order */
    ULONG_PTR c1 = 0, c2 = 0;
    EXPECT_EQ(UN(RtlActivateActivationContext)(0, ctx, &c1), 0); EXPECT_EQ(UN(RtlActivateActivationContext)(0, ctx, &c2), 0);
    EXPECT_NE(c1, c2);
    UN(RtlDeactivateActivationContext)(0, c2);
    cur = NULL; UN(RtlGetActiveActivationContext)(&cur); EXPECT_EQ(cur, ctx); if (cur) UN(RtlReleaseActivationContext)(cur);   /* the outer activation is still current */
    UN(RtlDeactivateActivationContext)(0, c1);
    cur = NULL; UN(RtlGetActiveActivationContext)(&cur); EXPECT_NE(cur, ctx); if (cur) UN(RtlReleaseActivationContext)(cur);
    typedef void (WINAPI *RA)(HANDLE); RA rel = (RA)K(ReleaseActCtx); if (rel) rel(ctx);
}
TEST(activate_unsafe_fast) {
    REQUIRE(UN(RtlActivateActivationContextUnsafeFast)); REQUIRE(UN(RtlDeactivateActivationContextUnsafeFast));
    REQUIRE(UN(RtlGetActiveActivationContext)); REQUIRE(UN(RtlReleaseActivationContext));
    HANDLE ctx = make_actctx(); if (ctx == INVALID_HANDLE_VALUE) { t_skip("cannot create an activation context from a manifest"); return; }
    __attribute__((aligned(16))) ULONG_PTR frame[9]; memset(frame, 0, sizeof frame);
    frame[0] = 0x48; ((ULONG *)frame)[2] = 1;                  /* extended frame size, format */
    UN(RtlActivateActivationContextUnsafeFast)(frame, ctx);
    EXPECT_EQ(frame[3], (ULONG_PTR)ctx);
    HANDLE cur = NULL; EXPECT_EQ(UN(RtlGetActiveActivationContext)(&cur), 0); EXPECT_EQ(cur, ctx); if (cur) UN(RtlReleaseActivationContext)(cur);
    UN(RtlDeactivateActivationContextUnsafeFast)(frame);
    cur = NULL; UN(RtlGetActiveActivationContext)(&cur); EXPECT_NE(cur, ctx); if (cur) UN(RtlReleaseActivationContext)(cur);
    typedef void (WINAPI *RA)(HANDLE); RA rel = (RA)K(ReleaseActCtx); if (rel) rel(ctx);
}

/* -------------------------------------------------------------------- heap */
UDECL(PVOID, RtlCreateHeap, (ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID));
UDECL(PVOID, RtlDestroyHeap, (PVOID));
UDECL(PVOID, RtlAllocateHeap, (PVOID, ULONG, SIZE_T));
UDECL(SIZE_T, RtlCompactHeap, (PVOID, ULONG, PVOID, PVOID));
TEST(compact_heap) {
    REQUIRE(UN(RtlCreateHeap)); REQUIRE(UN(RtlDestroyHeap)); REQUIRE(UN(RtlAllocateHeap)); REQUIRE(UN(RtlFreeHeap)); REQUIRE(UN(RtlCompactHeap));
    PVOID h = UN(RtlCreateHeap)(0x2 /*HEAP_GROWABLE*/, NULL, 0x10000, 0x4000, NULL, NULL); REQUIRE(h);
    PVOID p[64];
    for (int i = 0; i < 64; i++) p[i] = UN(RtlAllocateHeap)(h, 0, 128);
    for (int i = 0; i < 64; i += 2) UN(RtlFreeHeap)(h, 0, p[i]);
    SIZE_T big = UN(RtlCompactHeap)(h, 0, NULL, NULL);
    t_note("RtlCompactHeap largest free block %llu", (unsigned long long)big);
    EXPECT_EQ(big >= 128, 1);
    /* the live allocations are intact and still freeable */
    for (int i = 1; i < 64; i += 2) EXPECT_EQ(UN(RtlFreeHeap)(h, 0, p[i]) != NULL, 1);
    SIZE_T big2 = UN(RtlCompactHeap)(h, 0, NULL, NULL); EXPECT_EQ(big2 >= big, 1);
    EXPECT_EQ(UN(RtlDestroyHeap)(h), NULL);
}

/* -------------------------------------------------- cross-VM object paths */
UDECL(NTSTATUS, RtlConstructCrossVmEventPath, (PUNICODE_STRING, const GUID *, const GUID *));
UDECL(NTSTATUS, RtlConstructCrossVmMutexPath, (PUNICODE_STRING, const GUID *, const GUID *));
UDECL(NTSTATUS, RtlStringFromGUID, (const GUID *, PUNICODE_STRING));
TEST(cross_vm_paths) {
    REQUIRE(UN(RtlConstructCrossVmEventPath)); REQUIRE(UN(RtlConstructCrossVmMutexPath)); REQUIRE(UN(RtlStringFromGUID));
    /* event and mutex path construction share a single implementation */
    EXPECT_EQ(t_proc("RtlConstructCrossVmEventPath"), t_proc("RtlConstructCrossVmMutexPath"));
    GUID g1 = { 0x11223344, 0x5566, 0x7788, { 1, 2, 3, 4, 5, 6, 7, 8 } }, g2 = { 0xAABBCCDD, 0xEEFF, 0x0011, { 9, 8, 7, 6, 5, 4, 3, 2 } };
    UNICODE_STRING o, sg1, sg2; memset(&o, 0, sizeof o);
    NTSTATUS s = UN(RtlConstructCrossVmEventPath)(&o, &g1, NULL); EXPECT_EQ(s, 0);
    if (s == 0) {
        UN(RtlStringFromGUID)(&g1, &sg1);
        t_note("cross-vm path (1 guid): %.*ls", o.Length / 2, o.Buffer);
        EXPECT_EQ(o.Length > sg1.Length, 1);
        EXPECT_EQ(memcmp((UCHAR *)o.Buffer + o.Length - sg1.Length, sg1.Buffer, sg1.Length), 0);
        EXPECT_EQ(o.Buffer[0], L'\\');
        UN(RtlFreeUnicodeString)(&sg1); UN(RtlFreeUnicodeString)(&o);
    }
    memset(&o, 0, sizeof o);
    s = UN(RtlConstructCrossVmMutexPath)(&o, &g1, &g2); EXPECT_EQ(s, 0);
    if (s == 0) {
        UN(RtlStringFromGUID)(&g1, &sg1); UN(RtlStringFromGUID)(&g2, &sg2);
        t_note("cross-vm path (2 guids): %.*ls", o.Length / 2, o.Buffer);
        EXPECT_EQ(o.Length > sg1.Length + sg2.Length, 1);
        /* the first GUID is the trailing component of the path; the second one qualifies it */
        EXPECT_EQ(memcmp((UCHAR *)o.Buffer + o.Length - sg1.Length, sg1.Buffer, sg1.Length), 0);
        EXPECT_EQ(memcmp((UCHAR *)o.Buffer + o.Length - sg1.Length - sg2.Length - 2, sg2.Buffer, sg2.Length), 0);
        EXPECT_EQ(o.Buffer[(o.Length - sg1.Length - 2) / 2], L'\\');
        UN(RtlFreeUnicodeString)(&sg1); UN(RtlFreeUnicodeString)(&sg2); UN(RtlFreeUnicodeString)(&o);
    }
}

/* ------------------------------------------------------- import table hash */
UDECL(NTSTATUS, RtlComputeImportTableHash, (HANDLE, PUCHAR, ULONG));
static HANDLE open_sys(const WCHAR *leaf) {
    typedef HANDLE (WINAPI *CF)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    CF cf = (CF)K(CreateFileW); WCHAR p[MAX_PATH]; GetSystemDirectoryW(p, MAX_PATH); lstrcatW(p, L"\\"); lstrcatW(p, leaf);
    return cf(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
}
TEST(import_table_hash) {
    REQUIRE(UN(RtlComputeImportTableHash));
    HANDLE a = open_sys(L"kernel32.dll"), b = open_sys(L"cmd.exe");
    if (a == INVALID_HANDLE_VALUE || b == INVALID_HANDLE_VALUE) { if (a != INVALID_HANDLE_VALUE) CloseHandle(a); if (b != INVALID_HANDLE_VALUE) CloseHandle(b); t_skip("cannot open system images"); return; }
    UCHAR h1[16], h2[16], h3[16], z[16] = { 0 };
    memset(h1, 0, 16); memset(h2, 0, 16); memset(h3, 0, 16);
    NTSTATUS s1 = UN(RtlComputeImportTableHash)(a, h1, 1);
    NTSTATUS s2 = UN(RtlComputeImportTableHash)(a, h2, 1);
    NTSTATUS s3 = UN(RtlComputeImportTableHash)(b, h3, 1);
    EXPECT_EQ(s1, 0); EXPECT_EQ(s2, 0); EXPECT_EQ(s3, 0);
    if (s1 == 0 && s2 == 0 && s3 == 0) {
        EXPECT_EQ(memcmp(h1, h2, 16), 0);          /* deterministic */
        EXPECT_NE(memcmp(h1, h3, 16), 0);          /* depends on the import table */
        EXPECT_NE(memcmp(h1, z, 16), 0);
    }
    /* unknown revisions are rejected without touching the output */
    memset(h1, 0x5A, 16);
    EXPECT_EQ(UN(RtlComputeImportTableHash)(a, h1, 0), S(0xC0000058));
    EXPECT_EQ(UN(RtlComputeImportTableHash)(a, h1, 2), S(0xC0000058));
    UCHAR m[16]; memset(m, 0x5A, 16); EXPECT_EQ(memcmp(h1, m, 16), 0);
    /* not an image file */
    HANDLE c = open_sys(L"drivers\\etc\\hosts");
    if (c != INVALID_HANDLE_VALUE) { NTSTATUS s = UN(RtlComputeImportTableHash)(c, h1, 1); EXPECT_EQ(s < 0, 1); t_note("non-image file: 0x%lx", (unsigned long)s); CloseHandle(c); }
    NTSTATUS s = UN(RtlComputeImportTableHash)((HANDLE)(ULONG_PTR)0xFFFC, h1, 1); EXPECT_EQ(s, S(0xC0000008)); t_note("bad handle: 0x%lx", (unsigned long)s);
    CloseHandle(a); CloseHandle(b);
}

/* ------------------------------------------------------------ capabilities */
UDECL(NTSTATUS, RtlCapabilityCheck, (HANDLE, PUNICODE_STRING, PBOOLEAN));
UDECL(NTSTATUS, RtlCapabilityCheckForSingleSessionSku, (HANDLE, PUNICODE_STRING, PBOOLEAN));
TEST(capability_check) {
    REQUIRE(UN(RtlCapabilityCheck)); REQUIRE(UN(RtlCapabilityCheckForSingleSessionSku));
    UNICODE_STRING cap; us(&cap, L"internetClient"); BOOLEAN r = 0xEE;
    EXPECT_EQ(UN(RtlCapabilityCheckForSingleSessionSku)(NULL, &cap, NULL), S(0xC000000D));
    NTSTATUS s = UN(RtlCapabilityCheck)(NULL, &cap, &r);
    /* a normal (non-AppContainer) token is not restricted by capabilities */
    EXPECT_EQ(s, 0); EXPECT_EQ(r, 1);
    NTSTATUS s2; BOOLEAN r2 = 0xEE;
    s2 = UN(RtlCapabilityCheckForSingleSessionSku)(NULL, &cap, &r2);
    EXPECT_EQ(s2, 0);
    /* multi-session SKUs report FALSE without evaluating the token; other SKUs behave like RtlCapabilityCheck */
    CHECKF(r2 == 0 || r2 == 1, "result %d", r2); if (r2 == 0) t_note("multi-session SKU: capability reported absent"); else EXPECT_EQ(r2, r);
    /* for such a token even a name that is not a capability passes */
    UNICODE_STRING bad; us(&bad, L"ntdllt-no-such-capability"); r = 0xEE;
    s = UN(RtlCapabilityCheck)(NULL, &bad, &r); EXPECT_EQ(s, 0); EXPECT_EQ(r, 1);
}

/* ------------------------------------------------------ privatized DLL name */
UDECL(NTSTATUS, RtlComputePrivatizedDllName_U, (PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING));
TEST(privatized_dll_name) {
    REQUIRE(UN(RtlComputePrivatizedDllName_U));
    UNICODE_STRING dn, real, local; us(&dn, L"foo.dll"); memset(&real, 0, sizeof real); memset(&local, 0, sizeof local);
    NTSTATUS s = UN(RtlComputePrivatizedDllName_U)(&dn, &real, &local); EXPECT_EQ(s, 0);
    if (s == 0) {
        WCHAR exe[MAX_PATH], want[2 * MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
        WCHAR *leaf = wcsrchr(exe, L'\\'); REQUIRE(leaf);
        /* real name: DLL leaf in the executable's directory */
        size_t dirlen = (size_t)(leaf - exe) + 1;
        lstrcpynW(want, exe, (int)dirlen + 1); lstrcatW(want, L"foo.dll");
        EXPECT_EQ(real.Length, lstrlenW(want) * 2); EXPECT_EQ(_wcsnicmp(real.Buffer, want, real.Length / 2), 0);
        /* local (".Local" redirection) name: <exe>.Local\leaf */
        lstrcpynW(want, exe, (int)dirlen + 1); lstrcatW(want, leaf + 1); lstrcatW(want, L".Local\\foo.dll");
        EXPECT_EQ(local.Length, lstrlenW(want) * 2); EXPECT_EQ(_wcsnicmp(local.Buffer, want, local.Length / 2), 0);
        UN(RtlFreeUnicodeString)(&real); UN(RtlFreeUnicodeString)(&local);
    }
    /* only the leaf of a path is used, and a missing extension gets ".DLL" */
    UNICODE_STRING dn2; us(&dn2, L"C:\\some\\dir\\bar"); memset(&real, 0, sizeof real); memset(&local, 0, sizeof local);
    s = UN(RtlComputePrivatizedDllName_U)(&dn2, &real, &local); EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(real.Length >= 16 && _wcsnicmp(real.Buffer + real.Length / 2 - 8, L"\\bar.DLL", 8) == 0, 1);
        EXPECT_EQ(local.Length >= 16 && _wcsnicmp(local.Buffer + local.Length / 2 - 8, L"\\bar.DLL", 8) == 0, 1);
        UN(RtlFreeUnicodeString)(&real); UN(RtlFreeUnicodeString)(&local);
    }
}

/* --------------------------------------------------------- process cloning */
UDECL(NTSTATUS, RtlCloneUserProcess, (ULONG, PVOID, PVOID, HANDLE, PVOID));
UDECL(NTSTATUS, NtTerminateProcess, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, NtResumeThread, (HANDLE, PULONG));
CHILD(clone_parent) {
    if (!UN(RtlCloneUserProcess) || !UN(NtTerminateProcess)) return 90;
    __attribute__((aligned(16))) UCHAR info[0x100]; memset(info, 0, sizeof info); *(ULONG *)info = 0x68;
    NTSTATUS s = UN(RtlCloneUserProcess)(3 /*create suspended | inherit handles*/, NULL, NULL, NULL, info);
    if (s == S(0x129)) { UN(NtTerminateProcess)((HANDLE)(LONG_PTR)-1, 77); for (;;) Sleep(1000); }
    if (s != 0) return 91;
    HANDLE hp = *(HANDLE *)(info + 8), ht = *(HANDLE *)(info + 16);
    ULONG prev = 0xFF; NTSTATUS rs = UN(NtResumeThread)(ht, &prev);
    if (rs != 0) { TerminateProcess(hp, 1); return 92; }
    if (prev != 1) { TerminateProcess(hp, 1); return 93; }
    if (WaitForSingleObject(hp, 20000) != WAIT_OBJECT_0) { TerminateProcess(hp, 1); return 94; }
    DWORD code = 0; GetExitCodeProcess(hp, &code);
    CloseHandle(hp); CloseHandle(ht);
    return code == 77 ? 0 : 95;
}
TEST(clone_user_process) {
    REQUIRE(UN(RtlCloneUserProcess)); REQUIRE(UN(NtTerminateProcess)); REQUIRE(UN(NtResumeThread));
    DWORD rc = t_run_child("clone_parent", "", 60000);
    if (rc == 90 || rc == 91) { t_skip("process cloning is not available here (child result %lu)", rc); return; }
    EXPECT_EQ(rc, 0);
}

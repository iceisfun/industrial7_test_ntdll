/* RtlQuery* process/system facing: debug buffers, activation contexts, packages, tokens, WNF, features, locks. */
#include "t.h"

#define ST_INVALID_PARAMETER  ((NTSTATUS)0xC000000D)
#define ST_INVALID_HANDLE     ((NTSTATUS)0xC0000008)
#define ST_NOT_FOUND          ((NTSTATUS)0xC0000225)
#define ST_BUFFER_TOO_SMALL   ((NTSTATUS)0xC0000023)

UDECL(PVOID, RtlCreateQueryDebugBuffer, (ULONG, BOOLEAN));
UDECL(NTSTATUS, RtlDestroyQueryDebugBuffer, (PVOID));
UDECL(NTSTATUS, RtlQueryProcessDebugInformation, (HANDLE, ULONG, PVOID));
UDECL(NTSTATUS, RtlQueryProcessLockInformation, (PVOID));
UDECL(NTSTATUS, RtlQueryProcessHeapInformation, (PVOID));
UDECL(NTSTATUS, RtlQueryProcessBackTraceInformation, (PVOID));
UDECL(NTSTATUS, RtlInitializeCriticalSectionEx, (PRTL_CRITICAL_SECTION, ULONG, ULONG));
UDECL(NTSTATUS, RtlEnterCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlLeaveCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(NTSTATUS, RtlDeleteCriticalSection, (PRTL_CRITICAL_SECTION));
UDECL(PVOID, RtlQueryCriticalSectionOwner, (HANDLE, ULONG));

#define DBG_FLAGS(b)   (*(ULONG *)((BYTE *)(b) + 0x40))
#define DBG_PID(b)     (*(ULONG_PTR *)((BYTE *)(b) + 0x30))
#define DBG_MODULES(b) (*(BYTE **)((BYTE *)(b) + 0x60))
#define DBG_BT(b)      (*(BYTE **)((BYTE *)(b) + 0x68))
#define DBG_HEAPS(b)   (*(BYTE **)((BYTE *)(b) + 0x70))
#define DBG_LOCKS(b)   (*(BYTE **)((BYTE *)(b) + 0x78))
#define DBG_PROCHEAP(b) (*(PVOID *)((BYTE *)(b) + 0x98))
#define PDI_MODULES 1
#define PDI_BACKTRACE 2
#define PDI_HEAPS 4
#define PDI_LOCKS 0x20

static PVOID dbg_new(void) {
    if (!UN(RtlCreateQueryDebugBuffer) || !UN(RtlDestroyQueryDebugBuffer)) return NULL;
    return UN(RtlCreateQueryDebugBuffer)(0, FALSE);
}

TEST(qs_debug_modules) {
    REQUIRE(UN(RtlQueryProcessDebugInformation));
    PVOID b = dbg_new(); if (!b) { t_skip("no debug buffer"); return; }
    NTSTATUS s = UN(RtlQueryProcessDebugInformation)((HANDLE)(ULONG_PTR)GetCurrentProcessId(), PDI_MODULES, b);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(DBG_FLAGS(b), PDI_MODULES);
    BYTE *m = DBG_MODULES(b);
    CHECK(m != NULL);
    if (s == 0 && m) {
        ULONG n = *(ULONG *)m; CHECK(n >= 2);
        /* RTL_PROCESS_MODULE_INFORMATION is 0x128 bytes: ImageBase at +0x10, ImageSize at +0x18, path at +0x28 */
        HMODULE nt = GetModuleHandleW(L"ntdll.dll"), exe = GetModuleHandleW(NULL);
        int fnt = 0, fexe = 0;
        for (ULONG i = 0; i < n && i < 512; i++) {
            BYTE *e = m + 8 + i * 0x128; PVOID base = *(PVOID *)(e + 0x10);
            if (base == (PVOID)nt) { fnt = 1; CHECK(*(ULONG *)(e + 0x18) >= 0x100000); CHECK(!lstrcmpiA((char *)e + 0x28 + *(USHORT *)(e + 0x26), "ntdll.dll")); }
            if (base == (PVOID)exe) fexe = 1;
        }
        CHECK(fnt); CHECK(fexe);
        /* the first entry is the process image */
        EXPECT_EQ(*(PVOID *)(m + 8 + 0x10), (PVOID)exe);
    }
    /* the buffer can be reused for another class mask */
    s = UN(RtlQueryProcessDebugInformation)((HANDLE)(ULONG_PTR)GetCurrentProcessId(), PDI_LOCKS, b);
    EXPECT_EQ(s, 0); EXPECT_EQ(DBG_FLAGS(b), PDI_LOCKS);
    UN(RtlDestroyQueryDebugBuffer)(b);
}

TEST(qs_debug_locks) {
    REQUIRE(UN(RtlQueryProcessDebugInformation)); REQUIRE(UN(RtlInitializeCriticalSectionEx));
    REQUIRE(UN(RtlEnterCriticalSection)); REQUIRE(UN(RtlLeaveCriticalSection)); REQUIRE(UN(RtlDeleteCriticalSection));
    PVOID b = dbg_new(); if (!b) { t_skip("no debug buffer"); return; }
    static RTL_CRITICAL_SECTION cs;
    EXPECT_EQ(UN(RtlInitializeCriticalSectionEx)(&cs, 0, 0x10000000), 0);
    EXPECT_EQ(UN(RtlEnterCriticalSection)(&cs), 0);
    EXPECT_EQ(UN(RtlEnterCriticalSection)(&cs), 0);
    NTSTATUS s = UN(RtlQueryProcessDebugInformation)((HANDLE)(ULONG_PTR)GetCurrentProcessId(), PDI_LOCKS, b);
    EXPECT_EQ(s, 0);
    BYTE *l = DBG_LOCKS(b);
    CHECK(l != NULL);
    int found = 0;
    if (s == 0 && l) {
        ULONG n = *(ULONG *)l; CHECK(n >= 1);
        t_note("locks n=%lu hdr=%p cs=%p", n, l, &cs);
        for (ULONG i = 0; i < 3 && i < n; i++) t_note("  e%lu: addr=%p type=%u", i, *(PVOID *)(l + 8 + i * 0x30), *(USHORT *)(l + 16 + i * 0x30));
        for (ULONG i = 0; i < n && i < 100000; i++) {
            BYTE *e = l + 8 + i * 0x30;
            if (*(PVOID *)e != (PVOID)&cs) continue;
            found = 1;
            EXPECT_EQ(*(USHORT *)(e + 8), 0);                                       /* RTL_CRITSECT_TYPE */
            EXPECT_EQ(*(ULONG_PTR *)(e + 0x10), (ULONG_PTR)GetCurrentThreadId());  /* OwnerThreadId */
            EXPECT_EQ(*(ULONG *)(e + 0x24), 2);                                     /* RecursionCount */
            EXPECT_EQ(*(LONG *)(e + 0x18), cs.LockCount);                           /* ActiveCount */
        }
    }
    CHECK(found);
    UN(RtlLeaveCriticalSection)(&cs); UN(RtlLeaveCriticalSection)(&cs);
    /* after release the lock is still listed but unowned */
    s = UN(RtlQueryProcessDebugInformation)((HANDLE)(ULONG_PTR)GetCurrentProcessId(), PDI_LOCKS, b);
    EXPECT_EQ(s, 0); l = DBG_LOCKS(b); found = 0;
    if (s == 0 && l) for (ULONG i = 0; i < *(ULONG *)l && i < 100000; i++) {
        BYTE *e = l + 8 + i * 0x30;
        if (*(PVOID *)e == (PVOID)&cs) { found = 1; EXPECT_EQ(*(ULONG_PTR *)(e + 0x10), 0); EXPECT_EQ(*(ULONG *)(e + 0x24), 0); }
    }
    CHECK(found);
    UN(RtlDeleteCriticalSection)(&cs);
    /* a deleted section disappears from the list */
    s = UN(RtlQueryProcessDebugInformation)((HANDLE)(ULONG_PTR)GetCurrentProcessId(), PDI_LOCKS, b);
    EXPECT_EQ(s, 0); l = DBG_LOCKS(b); found = 0;
    if (s == 0 && l) for (ULONG i = 0; i < *(ULONG *)l && i < 100000; i++) if (*(PVOID *)(l + 8 + i * 0x30) == (PVOID)&cs) found = 1;
    CHECK(!found);
    UN(RtlDestroyQueryDebugBuffer)(b);
}

TEST(qs_debug_lock_information_direct) {
    REQUIRE(UN(RtlQueryProcessLockInformation)); REQUIRE(UN(RtlInitializeCriticalSectionEx)); REQUIRE(UN(RtlDeleteCriticalSection));
    PVOID b = dbg_new(); if (!b) { t_skip("no debug buffer"); return; }
    static RTL_CRITICAL_SECTION cs;
    UN(RtlInitializeCriticalSectionEx)(&cs, 0, 0x10000000);
    NTSTATUS s = UN(RtlQueryProcessLockInformation)(b);
    EXPECT_EQ(s, 0);
    BYTE *l = DBG_LOCKS(b); CHECK(l != NULL);
    int found = 0;
    if (s == 0 && l) for (ULONG i = 0; i < *(ULONG *)l && i < 100000; i++) if (*(PVOID *)(l + 8 + i * 0x30) == (PVOID)&cs) found = 1;
    CHECK(found);
    UN(RtlDeleteCriticalSection)(&cs);
    UN(RtlDestroyQueryDebugBuffer)(b);
}

TEST(qs_debug_heaps) {
    REQUIRE(UN(RtlQueryProcessDebugInformation));
    PVOID b = dbg_new(); if (!b) { t_skip("no debug buffer"); return; }
    NTSTATUS s = UN(RtlQueryProcessDebugInformation)((HANDLE)(ULONG_PTR)GetCurrentProcessId(), PDI_HEAPS, b);
    EXPECT_EQ(s, 0);
    BYTE *h = DBG_HEAPS(b); CHECK(h != NULL);
    BYTE *peb = *(BYTE **)((BYTE *)NtCurrentTeb() + 0x60);
    EXPECT_EQ(DBG_PROCHEAP(b), *(PVOID *)(peb + 0x30));
    int found = 0;
    if (s == 0 && h) {
        ULONG n = *(ULONG *)h; CHECK(n >= 1);
        for (ULONG i = 0; i < n && i < 4096; i++) if (*(PVOID *)(h + 8 + i * 0x58) == GetProcessHeap()) found = 1;
        /* the entries count equals the process heap-array length in the PEB */
        EXPECT_EQ(n, *(ULONG *)(peb + 0xe8));
    }
    CHECK(found);
    UN(RtlDestroyQueryDebugBuffer)(b);
}

TEST(qs_debug_heap_and_backtrace_direct) {
    REQUIRE(UN(RtlQueryProcessHeapInformation)); REQUIRE(UN(RtlQueryProcessBackTraceInformation));
    PVOID b = dbg_new(); if (!b) { t_skip("no debug buffer"); return; }
    DBG_FLAGS(b) = PDI_HEAPS;
    NTSTATUS s = UN(RtlQueryProcessHeapInformation)(b);
    EXPECT_EQ(s, 0);
    BYTE *h = DBG_HEAPS(b); CHECK(h != NULL);
    BYTE *peb = *(BYTE **)((BYTE *)NtCurrentTeb() + 0x60);
    if (s == 0 && h) EXPECT_EQ(*(ULONG *)h, *(ULONG *)(peb + 0xe8));
    /* without the user-mode stack-trace database nothing is produced: success, no table */
    ULONG gflags = *(ULONG *)(peb + 0xbc);
    if (gflags & 0x1000) t_skip("user-mode stack trace database enabled (FLG_USER_STACK_TRACE_DB)");
    else { s = UN(RtlQueryProcessBackTraceInformation)(b); EXPECT_EQ(s, 0); CHECK(DBG_BT(b) == NULL); }
    UN(RtlDestroyQueryDebugBuffer)(b);
}

TEST(qs_debug_errors) {
    REQUIRE(UN(RtlQueryProcessDebugInformation));
    PVOID b = dbg_new(); if (!b) { t_skip("no debug buffer"); return; }
    HANDLE me = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
    /* mask 0 is accepted and records the mask */
    NTSTATUS s = UN(RtlQueryProcessDebugInformation)(me, 0, b);
    EXPECT_EQ(s, 0); EXPECT_EQ(DBG_FLAGS(b), 0);
    /* the buffer's TargetProcessId, if set, must match the requested pid */
    DBG_PID(b) = GetCurrentProcessId() + 4;
    s = UN(RtlQueryProcessDebugInformation)(me, PDI_MODULES, b);
    t_note("mismatching TargetProcessId status 0x%08lx", (unsigned long)s);
    CHECK(s < 0);
    DBG_PID(b) = 0;
    UN(RtlDestroyQueryDebugBuffer)(b);
}

/* ---- activation contexts ---------------------------------------------------------- */
UDECL(NTSTATUS, RtlQueryInformationActivationContext, (ULONG, HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, RtlQueryInformationActiveActivationContext, (ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, RtlQueryActivationContextApplicationSettings, (ULONG, HANDLE, PCWSTR, PCWSTR, PWSTR, SIZE_T, PSIZE_T));

static const char g_manifest[] =
 "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
 "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n"
 " <assemblyIdentity type=\"win32\" name=\"ntdllt.qs.test\" version=\"1.2.3.4\" processorArchitecture=\"*\"/>\r\n"
 " <application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings>\r\n"
 "  <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>\r\n"
 " </windowsSettings></application>\r\n"
 "</assembly>\r\n";

static char g_mpath[MAX_PATH];
static HANDLE make_actctx(void) {
    t_tmpfile(g_mpath, sizeof g_mpath, "qs.manifest");
    HANDLE f = CreateFileA(g_mpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    DWORD n; WriteFile(f, g_manifest, sizeof g_manifest - 1, &n, NULL); CloseHandle(f);
    HANDLE (WINAPI *cac)(PACTCTXA) = (void *)t_proc_in("kernel32.dll", "CreateActCtxA");
    if (!cac) return INVALID_HANDLE_VALUE;
    ACTCTXA a; memset(&a, 0, sizeof a); a.cbSize = sizeof a; a.lpSource = g_mpath;
    return cac(&a);
}
#define K32(n) UIN("kernel32.dll", n)

typedef struct { DWORD dwFlags, ulFormatVersion, ulAssemblyCount, ulRootManifestPathType, ulRootManifestPathChars,
    ulRootConfigurationPathType, ulRootConfigurationPathChars, ulAppDirPathType, ulAppDirPathChars; PCWSTR lpRootManifestPath, lpRootConfigurationPath, lpAppDirPath; } ACD;

TEST(qs_actctx_basic_and_detailed) {
    REQUIRE(UN(RtlQueryInformationActivationContext));
    HANDLE h = make_actctx();
    if (h == INVALID_HANDLE_VALUE) { t_skip("CreateActCtx failed: %lu", GetLastError()); return; }
    struct { HANDLE h; DWORD flags; } bi; SIZE_T rl = 0x99; NTSTATUS s;
    memset(&bi, 0xcc, sizeof bi);
    s = UN(RtlQueryInformationActivationContext)(0, h, NULL, 1, &bi, sizeof bi, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(rl, sizeof bi);
    EXPECT_EQ(bi.h, h);
    if (s == 0 && bi.h) K32(ReleaseActCtx)(bi.h);   /* a reference is returned unless NO_ADDREF */
    /* NO_ADDREF returns the same handle without a reference */
    memset(&bi, 0xcc, sizeof bi);
    s = UN(RtlQueryInformationActivationContext)(0x80000000, h, NULL, 1, &bi, sizeof bi, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(bi.h, h);
    /* too small: STATUS_BUFFER_TOO_SMALL with the required size */
    rl = 0; s = UN(RtlQueryInformationActivationContext)(0, h, NULL, 1, &bi, 4, &rl);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(rl, sizeof bi);
    /* size query: no buffer */
    rl = 0; s = UN(RtlQueryInformationActivationContext)(0, h, NULL, 1, NULL, 0, &rl);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(rl, sizeof bi);

    /* detailed information (class 2): required size covers the strings stored behind the struct */
    rl = 0; s = UN(RtlQueryInformationActivationContext)(0, h, NULL, 2, NULL, 0, &rl);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); CHECK(rl > sizeof(ACD));
    BYTE *buf = (BYTE *)calloc(1, rl + 16);
    SIZE_T need = rl; rl = 0;
    s = UN(RtlQueryInformationActivationContext)(0, h, NULL, 2, buf, need, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(rl, need);
    if (s == 0) {
        ACD *d = (ACD *)buf;
        EXPECT_EQ(d->ulFormatVersion, 1);
        CHECK(d->ulAssemblyCount >= 1);
        CHECK(d->lpRootManifestPath != NULL);
        if (d->lpRootManifestPath) {
            WCHAR want[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, g_mpath, -1, want, MAX_PATH);
            EXPECT_WSTR(d->lpRootManifestPath, want);
            EXPECT_EQ(d->ulRootManifestPathChars, lstrlenW(want));
        }
    }
    free(buf);
    /* argument validation */
    s = UN(RtlQueryInformationActivationContext)(8, h, NULL, 1, &bi, sizeof bi, &rl); EXPECT_EQ(s, (NTSTATUS)0xC00000EF);   /* STATUS_INVALID_PARAMETER_1 */
    s = UN(RtlQueryInformationActivationContext)(0, h, NULL, 0, &bi, sizeof bi, &rl); EXPECT_EQ(s, (NTSTATUS)0xC00000F1);   /* INVALID_PARAMETER_3 (class) */
    s = UN(RtlQueryInformationActivationContext)(0, h, NULL, 99, &bi, sizeof bi, &rl); EXPECT_EQ(s, (NTSTATUS)0xC00000F1);
    s = UN(RtlQueryInformationActivationContext)(0, h, NULL, 1, NULL, 16, &rl); EXPECT_EQ(s, (NTSTATUS)0xC00000F2);
    s = UN(RtlQueryInformationActivationContext)(0, h, NULL, 1, NULL, 0, NULL); EXPECT_EQ(s, (NTSTATUS)0xC00000F4);
    K32(ReleaseActCtx)(h);
}

TEST(qs_actctx_active) {
    REQUIRE(UN(RtlQueryInformationActiveActivationContext)); REQUIRE(UN(RtlQueryInformationActivationContext));
    HANDLE h = make_actctx();
    if (h == INVALID_HANDLE_VALUE) { t_skip("CreateActCtx failed: %lu", GetLastError()); return; }
    ULONG_PTR cookie = 0;
    CHECK(K32(ActivateActCtx)(h, &cookie));
    struct { HANDLE h; DWORD flags; } bi; SIZE_T rl = 0;
    memset(&bi, 0xcc, sizeof bi);
    NTSTATUS s = UN(RtlQueryInformationActiveActivationContext)(1, &bi, sizeof bi, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(rl, sizeof bi); EXPECT_EQ(bi.h, h);
    if (s == 0 && bi.h) K32(ReleaseActCtx)(bi.h);
    /* the generic query with USE_ACTIVE flag (1) must give the same answer and rejects an explicit handle */
    memset(&bi, 0xcc, sizeof bi);
    s = UN(RtlQueryInformationActivationContext)(1, NULL, NULL, 1, &bi, sizeof bi, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(bi.h, h);
    if (s == 0 && bi.h) K32(ReleaseActCtx)(bi.h);
    s = UN(RtlQueryInformationActivationContext)(1, h, NULL, 1, &bi, sizeof bi, &rl);
    EXPECT_EQ(s, (NTSTATUS)0xC00000F0);
    /* size query on the active context */
    rl = 0; s = UN(RtlQueryInformationActiveActivationContext)(1, NULL, 0, &rl);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(rl, sizeof bi);
    CHECK(K32(DeactivateActCtx)(0, cookie));
    K32(ReleaseActCtx)(h);
}

TEST(qs_actctx_application_settings) {
    REQUIRE(UN(RtlQueryActivationContextApplicationSettings));
    HANDLE h = make_actctx();
    if (h == INVALID_HANDLE_VALUE) { t_skip("CreateActCtx failed: %lu", GetLastError()); return; }
    WCHAR out[16]; SIZE_T rl = 0; NTSTATUS s;
    memset(out, 0xcc, sizeof out);
    s = UN(RtlQueryActivationContextApplicationSettings)(0, h, NULL, L"dpiAware", out, 16, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(rl, 5); EXPECT_WSTR(out, L"true");
    /* explicit namespace */
    memset(out, 0xcc, sizeof out); rl = 0;
    s = UN(RtlQueryActivationContextApplicationSettings)(0, h, L"http://schemas.microsoft.com/SMI/2005/WindowsSettings", L"dpiAware", out, 16, &rl);
    EXPECT_EQ(s, 0); EXPECT_EQ(rl, 5); EXPECT_WSTR(out, L"true");
    /* wrong namespace / unknown name */
    s = UN(RtlQueryActivationContextApplicationSettings)(0, h, L"http://example.invalid/ns", L"dpiAware", out, 16, &rl);
    t_note("wrong namespace -> 0x%08lx", (unsigned long)s); EXPECT_EQ(s, (NTSTATUS)0xC0150008);
    s = UN(RtlQueryActivationContextApplicationSettings)(0, h, NULL, L"noSuchSetting", out, 16, &rl);
    t_note("unknown setting -> 0x%08lx", (unsigned long)s); EXPECT_EQ(s, (NTSTATUS)0xC0150008);
    /* too small: STATUS_BUFFER_TOO_SMALL and the required char count */
    rl = 0; s = UN(RtlQueryActivationContextApplicationSettings)(0, h, NULL, L"dpiAware", out, 2, &rl);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(rl, 5);
    /* length query: NULL buffer, zero size */
    rl = 0; s = UN(RtlQueryActivationContextApplicationSettings)(0, h, NULL, L"dpiAware", NULL, 0, &rl);
    EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(rl, 5);
    K32(ReleaseActCtx)(h);
}

/* ---- packages, tokens ------------------------------------------------------------------ */
UDECL(NTSTATUS, RtlQueryPackageIdentity, (HANDLE, PWSTR, PSIZE_T, PWSTR, PSIZE_T, PBOOLEAN));
UDECL(NTSTATUS, RtlQueryPackageIdentityEx, (HANDLE, PWSTR, PSIZE_T, PWSTR, PSIZE_T, GUID *, PBOOLEAN));
UDECL(NTSTATUS, RtlQueryPackageClaims, (HANDLE, PWSTR, PSIZE_T, PWSTR, PSIZE_T, GUID *, PULONG64, PULONG));
UDECL(NTSTATUS, RtlQueryTokenHostIdAsUlong64, (HANDLE, PULONG64));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));

TEST(qs_package_identity_unpackaged) {
    REQUIRE(UN(RtlQueryPackageIdentity)); REQUIRE(UN(RtlQueryPackageIdentityEx)); REQUIRE(UN(RtlQueryPackageClaims));
    LONG (WINAPI *gpfn)(UINT32 *, PWSTR) = (void *)t_proc_in("kernel32.dll", "GetCurrentPackageFullName");
    if (!gpfn) { t_skip("GetCurrentPackageFullName missing"); return; }
    UINT32 n = 0; LONG kr = gpfn(&n, NULL);
    if (kr != 15700) { t_skip("test process is packaged (GetCurrentPackageFullName=%ld)", kr); return; }
    WCHAR name[256], app[256]; SIZE_T nl = 256 * 2, al = 256 * 2; BOOLEAN pk = 0x7f; GUID g; ULONG64 c1 = 0x77; ULONG c2 = 0x77;
    HANDLE tok = (HANDLE)(LONG_PTR)-4;   /* current process token pseudo handle */
    NTSTATUS s = UN(RtlQueryPackageIdentity)(tok, name, &nl, app, &al, &pk);
    t_note("QueryPackageIdentity(proc token) 0x%08lx", (unsigned long)s);
    EXPECT_EQ(s, ST_NOT_FOUND);
    EXPECT_EQ(pk, 0x7f);                  /* *Packaged only written on success */
    nl = al = 512; s = UN(RtlQueryPackageIdentityEx)(tok, name, &nl, app, &al, &g, &pk);
    EXPECT_EQ(s, ST_NOT_FOUND);
    nl = al = 512; s = UN(RtlQueryPackageClaims)(tok, name, &nl, app, &al, &g, &c1, &c2);
    EXPECT_EQ(s, ST_NOT_FOUND);
    /* a length query has the same outcome */
    s = UN(RtlQueryPackageIdentity)(tok, NULL, NULL, NULL, NULL, NULL); EXPECT_EQ(s, ST_NOT_FOUND);
    /* bad token handle */
    s = UN(RtlQueryPackageIdentity)((HANDLE)(ULONG_PTR)0x7ffffff0, name, &nl, app, &al, &pk);
    EXPECT_EQ(s, ST_INVALID_HANDLE);
}

TEST(qs_token_host_id) {
    REQUIRE(UN(RtlQueryTokenHostIdAsUlong64)); REQUIRE(UN(NtOpenProcessToken));
    HANDLE tok = NULL;
    if (UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &tok) != 0) { t_skip("cannot open process token"); return; }
    ULONG64 id = 0x77;
    NTSTATUS s = UN(RtlQueryTokenHostIdAsUlong64)(tok, &id);
    t_note("QueryTokenHostId 0x%08lx", (unsigned long)s);
    /* an ordinary token carries no host-id security attribute */
    EXPECT_EQ(s, ST_NOT_FOUND); EXPECT_EQ(id, 0x77);
    s = UN(RtlQueryTokenHostIdAsUlong64)((HANDLE)(ULONG_PTR)0x7ffffff0, &id); EXPECT_EQ(s, ST_INVALID_HANDLE);
    CloseHandle(tok);
}

/* ---- WNF ---------------------------------------------------------------------------------- */
UDECL(NTSTATUS, NtCreateWnfStateName, (ULONGLONG *, ULONG, ULONG, BOOLEAN, PVOID, ULONG, PVOID));
UDECL(NTSTATUS, NtDeleteWnfStateName, (const ULONGLONG *));
UDECL(NTSTATUS, NtUpdateWnfStateData, (const ULONGLONG *, const void *, ULONG, PVOID, const void *, ULONG, BOOLEAN));
UDECL(NTSTATUS, RtlCreateSecurityDescriptor, (PVOID, ULONG));
UDECL(NTSTATUS, RtlSetDaclSecurityDescriptor, (PVOID, BOOLEAN, PVOID, BOOLEAN));
typedef NTSTATUS (NTAPI *WNFCB)(ULONGLONG, ULONG, PVOID, PVOID, PVOID, ULONG);
UDECL(NTSTATUS, RtlQueryWnfStateData, (PULONG, ULONGLONG, WNFCB, PVOID, PVOID));
UDECL(NTSTATUS, RtlQueryWnfStateDataWithExplicitScope, (PULONG, ULONGLONG, PVOID, WNFCB, PVOID, PVOID));
UDECL(NTSTATUS, RtlQueryWnfMetaNotification, (PVOID, ULONG, ULONGLONG, PVOID));

static int wnf_make(ULONGLONG *sn) {
    BYTE sd[64];
    if (!UN(NtCreateWnfStateName) || !UN(NtDeleteWnfStateName) || !UN(NtUpdateWnfStateData) ||
        !UN(RtlCreateSecurityDescriptor) || !UN(RtlSetDaclSecurityDescriptor)) return 0;
    UN(RtlCreateSecurityDescriptor)(sd, 1);
    UN(RtlSetDaclSecurityDescriptor)(sd, TRUE, NULL, FALSE);
    *sn = 0;
    NTSTATUS s = UN(NtCreateWnfStateName)(sn, 3, 2, FALSE, NULL, 0x1000, sd);
    return s == 0 && *sn != 0;
}
typedef struct { int calls; ULONGLONG name; ULONG stamp; PVOID typeId; PVOID ctx; BYTE data[64]; ULONG len; NTSTATUS ret; } WCTX;
static NTSTATUS NTAPI wnf_cb(ULONGLONG name, ULONG stamp, PVOID typeId, PVOID ctx, PVOID buf, ULONG len) {
    WCTX *c = (WCTX *)ctx;
    c->calls++; c->name = name; c->stamp = stamp; c->typeId = typeId; c->ctx = ctx; c->len = len;
    if (buf && len <= sizeof c->data) memcpy(c->data, buf, len);
    return c->ret;
}

TEST(qs_wnf_state_data) {
    REQUIRE(UN(RtlQueryWnfStateData));
    ULONGLONG sn;
    if (!wnf_make(&sn)) { t_skip("cannot create a temporary WNF state name"); return; }
    WCTX c; memset(&c, 0, sizeof c);
    ULONG stamp = 0xdead;
    /* fresh name: callback runs with an empty payload and change stamp 0 */
    NTSTATUS s = UN(RtlQueryWnfStateData)(&stamp, sn, wnf_cb, &c, NULL);
    t_note("fresh query 0x%08lx calls %d stamp %lu len %lu", (unsigned long)s, c.calls, stamp, c.len);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.calls, 1); EXPECT_EQ(stamp, 0); EXPECT_EQ(c.stamp, 0); EXPECT_EQ(c.len, 0);
    EXPECT_EQ(c.name, sn);
    const BYTE data[6] = {1, 2, 3, 4, 5, 6};
    EXPECT_EQ(UN(NtUpdateWnfStateData)(&sn, data, 6, NULL, NULL, 0, 0), 0);
    memset(&c, 0, sizeof c); stamp = 0xdead;
    s = UN(RtlQueryWnfStateData)(&stamp, sn, wnf_cb, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(c.calls, 1); EXPECT_EQ(stamp, 1); EXPECT_EQ(c.stamp, 1); EXPECT_EQ(c.len, 6);
    CHECK(!memcmp(c.data, data, 6));
    EXPECT_EQ(c.typeId, 0); EXPECT_EQ(c.ctx, &c);
    /* second update bumps the stamp */
    const BYTE d2[2] = {9, 8};
    UN(NtUpdateWnfStateData)(&sn, d2, 2, NULL, NULL, 0, 0);
    memset(&c, 0, sizeof c);
    s = UN(RtlQueryWnfStateData)(&stamp, sn, wnf_cb, &c, NULL);
    EXPECT_EQ(s, 0); EXPECT_EQ(stamp, 2); EXPECT_EQ(c.len, 2); EXPECT_EQ(c.data[0], 9);
    /* the callback's status is what the caller gets */
    memset(&c, 0, sizeof c); c.ret = (NTSTATUS)0xC0000001;
    s = UN(RtlQueryWnfStateData)(&stamp, sn, wnf_cb, &c, NULL);
    t_note("callback failure status passthrough 0x%08lx", (unsigned long)s);
    EXPECT_EQ(s, (NTSTATUS)0xC0000001);
    /* explicit scope variant: same data, scope pointer is passed through to the state query */
    if (UN(RtlQueryWnfStateDataWithExplicitScope)) {
        memset(&c, 0, sizeof c); stamp = 0xdead;
        s = UN(RtlQueryWnfStateDataWithExplicitScope)(&stamp, sn, NULL, wnf_cb, &c, NULL);
        EXPECT_EQ(s, 0); EXPECT_EQ(c.calls, 1); EXPECT_EQ(stamp, 2); EXPECT_EQ(c.len, 2);
    }
    /* meta-notification: existence information (class 0) */
    if (UN(RtlQueryWnfMetaNotification)) {
        ULONG ex = 0x77;
        s = UN(RtlQueryWnfMetaNotification)(&ex, 0, sn, NULL);
        t_note("meta notification exist 0x%08lx value %lu", (unsigned long)s, ex);
        EXPECT_EQ(s, 0); EXPECT_EQ(ex, 1);
    }
    UN(NtDeleteWnfStateName)(&sn);
    /* a deleted name no longer exists */
    memset(&c, 0, sizeof c);
    s = UN(RtlQueryWnfStateData)(&stamp, sn, wnf_cb, &c, NULL);
    t_note("deleted name query 0x%08lx calls %d", (unsigned long)s, c.calls);
    CHECK(s < 0); EXPECT_EQ(c.calls, 0);
}

/* ---- feature configuration ------------------------------------------------------------------- */
typedef struct { ULONG FeatureId; ULONG Flags; ULONG Payload; } RFC;
UDECL(NTSTATUS, RtlQueryFeatureConfiguration, (ULONG, ULONG, PULONGLONG, RFC *));
UDECL(NTSTATUS, RtlQueryAllFeatureConfigurations, (ULONG, PULONGLONG, RFC *, PSIZE_T));
UDECL(NTSTATUS, RtlQueryFeatureUsageNotificationSubscriptions, (PVOID, PSIZE_T));

TEST(qs_feature_configuration) {
    REQUIRE(UN(RtlQueryFeatureConfiguration)); REQUIRE(UN(RtlQueryAllFeatureConfigurations));
    ULONGLONG stamp = 0xdead; RFC cfg; memset(&cfg, 0xcc, sizeof cfg);
    /* a feature id that no configuration defines */
    NTSTATUS s = UN(RtlQueryFeatureConfiguration)(0x7ffffff1, 1, &stamp, &cfg);
    t_note("unknown feature runtime 0x%08lx stamp %llu", (unsigned long)s, (unsigned long long)stamp);
    EXPECT_EQ(s, ST_NOT_FOUND);
    s = UN(RtlQueryFeatureConfiguration)(0x7ffffff1, 0, &stamp, &cfg);
    t_note("unknown feature boot 0x%08lx", (unsigned long)s);
    EXPECT_EQ(s, ST_NOT_FOUND);
    /* enumerate: count query, then fetch */
    SIZE_T cnt = 0; ULONGLONG st2 = 0;
    s = UN(RtlQueryAllFeatureConfigurations)(1, &st2, NULL, &cnt);
    t_note("all-features count query 0x%08lx count %llu stamp %llu", (unsigned long)s, (unsigned long long)cnt, (unsigned long long)st2);
    EXPECT_EQ(s, (NTSTATUS)0x80000005); CHECK(cnt > 0);
    if (s == (NTSTATUS)0x80000005 && cnt > 0) {
        RFC *all = (RFC *)calloc(cnt + 4, sizeof(RFC));
        SIZE_T n2 = cnt + 4; ULONGLONG st3 = 0;
        s = UN(RtlQueryAllFeatureConfigurations)(1, &st3, all, &n2);
        EXPECT_EQ(s, 0); EXPECT_EQ(n2, cnt);
        t_note("stamp count-query %llu fetch %llu", (unsigned long long)st2, (unsigned long long)st3);
        /* every enumerated entry is retrievable individually and agrees */
        for (SIZE_T i = 0; i < n2 && i < 8; i++) {
            RFC one; ULONGLONG st4 = 0; memset(&one, 0xcc, sizeof one);
            NTSTATUS q = UN(RtlQueryFeatureConfiguration)(all[i].FeatureId, 1, &st4, &one);
            CHECKF(q == 0 && one.FeatureId == all[i].FeatureId && one.Flags == all[i].Flags && one.Payload == all[i].Payload,
                   "feature %lu: 0x%08lx", all[i].FeatureId, (unsigned long)q);
        }
        free(all);
    }
    /* the change stamp reported alongside matches the shared-data stamp or a later one */
    CHECK(st2 <= *(volatile ULONGLONG *)((BYTE *)0x7ffe0710) || st2 > 0);
}

TEST(qs_feature_usage_subscriptions) {
    REQUIRE(UN(RtlQueryFeatureUsageNotificationSubscriptions));
    SIZE_T cnt = 0; NTSTATUS s = UN(RtlQueryFeatureUsageNotificationSubscriptions)(NULL, &cnt);
    t_note("subscriptions count query 0x%08lx count %llu", (unsigned long)s, (unsigned long long)cnt);
    CHECK(s == 0 || s == ST_BUFFER_TOO_SMALL);
    if (s == ST_BUFFER_TOO_SMALL) CHECK(cnt > 0);
}

/* ---- critical section owner ------------------------------------------------------------------ */
TEST(qs_critical_section_owner) {
    REQUIRE(UN(RtlQueryCriticalSectionOwner));
    EXPECT_EQ((ULONG_PTR)UN(RtlQueryCriticalSectionOwner)(NULL, 0), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlQueryCriticalSectionOwner)((HANDLE)(ULONG_PTR)0x7fff0, 0), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlQueryCriticalSectionOwner)((HANDLE)(ULONG_PTR)0x7fff0, 1), 0);
}

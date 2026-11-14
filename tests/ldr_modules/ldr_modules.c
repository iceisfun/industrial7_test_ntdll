/* Loader module bookkeeping: handle lookup by name and by mapping, full name, process module listing,
 * service tags, known-DLL sections, DLL notifications, per-module flags and failure data. */
#include "t.h"
#include "pebuild.h"

UDECL(NTSTATUS, LdrGetDllHandleByName, (PUNICODE_STRING, PUNICODE_STRING, PVOID *));
UDECL(NTSTATUS, LdrGetDllHandleByMapping, (PVOID, PVOID *));
UDECL(NTSTATUS, LdrGetDllFullName, (PVOID, PUNICODE_STRING));
UDECL(NTSTATUS, LdrDisableThreadCalloutsForDll, (PVOID));
UDECL(ULONG, LdrIsModuleSxsRedirected, (PVOID));
UDECL(NTSTATUS, LdrQueryProcessModuleInformation, (PVOID, ULONG, PULONG));
UDECL(NTSTATUS, LdrQueryModuleServiceTags, (PVOID, PULONG, PULONG));
UDECL(NTSTATUS, LdrGetKnownDllSectionHandle, (PCWSTR, BOOLEAN, PHANDLE));
UDECL(ULONG, LdrControlFlowGuardEnforced, (void));
UDECL(PVOID, LdrGetFailureData, (void));
UDECL(NTSTATUS, LdrRegisterDllNotification, (ULONG, PVOID, PVOID, PVOID *));
UDECL(NTSTATUS, LdrUnregisterDllNotification, (PVOID));
UDECL(NTSTATUS, LdrGetProcedureAddressForCaller, (PVOID, PANSI_STRING, ULONG, PVOID *, ULONG, PVOID *));
UDECL(NTSTATUS, LdrSetImplicitPathOptions, (PVOID, ULONG));
UDECL(NTSTATUS, LdrAddRefDll, (ULONG, PVOID));
UDECL(NTSTATUS, LdrGetDllHandleEx, (ULONG, PWSTR, PULONG, PUNICODE_STRING, PVOID *));
UDECL(NTSTATUS, LdrGetProcedureAddressEx, (PVOID, PANSI_STRING, ULONG, PVOID *, ULONG));
UDECL(NTSTATUS, LdrFindEntryForAddress, (PVOID, PVOID *));
UDECL(NTSTATUS, LdrEnumerateLoadedModules, (ULONG, PVOID, PVOID));
UDECL(NTSTATUS, LdrLockLoaderLock, (ULONG, PULONG, PULONG_PTR));
UDECL(NTSTATUS, LdrUnlockLoaderLock, (ULONG, ULONG_PTR));
UDECL(NTSTATUS, NtQuerySection, (HANDLE, ULONG, PVOID, SIZE_T, PSIZE_T));

#define S(x) ((NTSTATUS)(x))
#define ST_BAD_PARAM    S(0xC000000D)
#define ST_DLL_NOTFOUND S(0xC0000135)
#define ST_BAD_IMAGE    S(0xC000007B)
#define ST_LEN_MISMATCH S(0xC0000004)
#define ST_BUF_TOO_SMALL S(0xC0000023)
#define ST_PROC_NOTFOUND S(0xC0000139)   /* STATUS_ENTRYPOINT_NOT_FOUND */

static UNICODE_STRING us(const WCHAR *s)
{
    UNICODE_STRING u;
    u.Buffer = (PWSTR)s; u.Length = (USHORT)(lstrlenW(s) * 2); u.MaximumLength = u.Length + 2;
    return u;
}
static HMODULE g_ntdll;
static void need_ntdll(void) { g_ntdll = GetModuleHandleW(L"ntdll.dll"); }

/* Loads the code-free fixture DLL under a unique name; leaf is returned (wide) for notification checks. */
static HMODULE load_fixture(char *path, size_t cap, WCHAR *leafw)
{
    static int seq;
    char leaf[40];
    wsprintfA(leaf, "mod%d.dll", ++seq);
    t_tmpfile(path, cap, leaf);
    if (leafw) MultiByteToWideChar(CP_ACP, 0, leaf, -1, leafw, 40);
    if (!peb_write(path, 1, NULL)) { t_skip("cannot write fixture dll (err %lu)", GetLastError()); return NULL; }
    HMODULE h = LoadLibraryA(path);
    if (!h) t_skip("fixture dll cannot be loaded (err %lu)", GetLastError());
    return h;
}

TEST(ldr_mod_handle_by_name)
{
    REQUIRE(UN(LdrGetDllHandleByName)); need_ntdll();
    UNICODE_STRING n = us(L"ntdll.dll"), up = us(L"NTDLL.DLL"), noext = us(L"ntdll"), none = us(L"corpus_no_such_module.dll"), empty = us(L"");
    PVOID h = NULL;
    EXPECT_EQ(UN(LdrGetDllHandleByName)(&n, NULL, &h), 0);
    EXPECT_EQ(h, g_ntdll);
    h = NULL;
    EXPECT_EQ(UN(LdrGetDllHandleByName)(&up, NULL, &h), 0);
    EXPECT_EQ(h, g_ntdll);
    /* no default extension is appended on this path */
    EXPECT_EQ(UN(LdrGetDllHandleByName)(&noext, NULL, &h), ST_DLL_NOTFOUND);
    EXPECT_EQ(UN(LdrGetDllHandleByName)(&none, NULL, &h), ST_DLL_NOTFOUND);
    EXPECT_EQ(UN(LdrGetDllHandleByName)(&empty, NULL, &h), ST_DLL_NOTFOUND);
    /* lookup by full path */
    WCHAR full[MAX_PATH];
    DWORD n2 = GetModuleFileNameW(g_ntdll, full, MAX_PATH);
    if (n2 && n2 < MAX_PATH) {
        UNICODE_STRING f = us(full); h = NULL;
        EXPECT_EQ(UN(LdrGetDllHandleByName)(NULL, &f, &h), 0);
        EXPECT_EQ(h, g_ntdll);
    }
}

TEST(ldr_mod_handle_by_name_takes_reference)
{
    REQUIRE(UN(LdrGetDllHandleByName)); REQUIRE(UN(LdrGetDllHandleByMapping));
    char path[MAX_PATH]; WCHAR leaf[40];
    HMODULE m = load_fixture(path, sizeof path, leaf);
    if (!m) return;
    UNICODE_STRING n = us(leaf); PVOID h = NULL;
    EXPECT_EQ(UN(LdrGetDllHandleByName)(&n, NULL, &h), 0);
    EXPECT_EQ(h, m);
    /* by-mapping lookup of any address inside the image's mapping base */
    PVOID h2 = NULL;
    EXPECT_EQ(UN(LdrGetDllHandleByMapping)(m, &h2), 0);
    EXPECT_EQ(h2, m);
    /* two extra references were taken: the module survives two frees and goes on the third */
    EXPECT_EQ(FreeLibrary(m), TRUE);
    EXPECT_EQ(FreeLibrary(m), TRUE);
    CHECK(GetModuleHandleW(leaf) == m);
    EXPECT_EQ(FreeLibrary(m), TRUE);
    CHECK(GetModuleHandleW(leaf) == NULL);
    h = (PVOID)1;
    EXPECT_EQ(UN(LdrGetDllHandleByName)(&n, NULL, &h), ST_DLL_NOTFOUND);
}

TEST(ldr_mod_handle_by_mapping)
{
    REQUIRE(UN(LdrGetDllHandleByMapping)); need_ntdll();
    PVOID h = NULL;
    EXPECT_EQ(UN(LdrGetDllHandleByMapping)(g_ntdll, &h), 0);
    EXPECT_EQ(h, g_ntdll);
    /* not the start of a mapped image: no PE header there */
    EXPECT_EQ(UN(LdrGetDllHandleByMapping)((BYTE *)g_ntdll + 0x1000, &h), ST_BAD_IMAGE);
    EXPECT_EQ(UN(LdrGetDllHandleByMapping)(NULL, &h), ST_BAD_PARAM);
    /* a valid image that is mapped but not in the loader list */
    char path[MAX_PATH];
    t_tmpfile(path, sizeof path, "bymap.dll");
    if (peb_write(path, 1, NULL)) {
        HMODULE d = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if (d) {
            PVOID base = (PVOID)((ULONG_PTR)d & ~(ULONG_PTR)3);
            NTSTATUS s = UN(LdrGetDllHandleByMapping)(base, &h);
            t_note("by-mapping of an image-resource view: %08lx", s);
            EXPECT_EQ(s, ST_DLL_NOTFOUND);              /* mapped but never registered with the loader */
            FreeLibrary(d);
        }
    }
}

TEST(ldr_mod_full_name)
{
    REQUIRE(UN(LdrGetDllFullName)); need_ntdll();
    WCHAR buf[MAX_PATH], want[MAX_PATH];
    UNICODE_STRING b; b.Buffer = buf; b.Length = 0; b.MaximumLength = sizeof buf;
    DWORD n = GetModuleFileNameW(g_ntdll, want, MAX_PATH);
    if (!n || n >= MAX_PATH) { t_skip("GetModuleFileName failed"); return; }
    EXPECT_EQ(UN(LdrGetDllFullName)(g_ntdll, &b), 0);
    EXPECT_EQ(b.Length, n * 2);
    CHECK(b.Length == n * 2 && !_wcsnicmp(buf, want, n));
    /* truncated copy: the status reports the shortage, Length is what fit */
    WCHAR small[5]; UNICODE_STRING sb; sb.Buffer = small; sb.Length = 0; sb.MaximumLength = 10;
    EXPECT_EQ(UN(LdrGetDllFullName)(g_ntdll, &sb), ST_BUF_TOO_SMALL);
    EXPECT_EQ(sb.Length, 10);
    CHECK(!_wcsnicmp(small, want, 5));
    /* exactly the right size */
    WCHAR exact[MAX_PATH]; UNICODE_STRING eb; eb.Buffer = exact; eb.Length = 0; eb.MaximumLength = (USHORT)(n * 2);
    EXPECT_EQ(UN(LdrGetDllFullName)(g_ntdll, &eb), 0);
    EXPECT_EQ(eb.Length, n * 2);
    /* NULL handle means the process image */
    DWORD m = GetModuleFileNameW(NULL, want, MAX_PATH);
    b.Length = 0;
    EXPECT_EQ(UN(LdrGetDllFullName)(NULL, &b), 0);
    CHECK(m && b.Length == m * 2 && !_wcsnicmp(buf, want, m));
    b.Length = 0;
    EXPECT_EQ(UN(LdrGetDllFullName)((PVOID)0x12340000, &b), ST_DLL_NOTFOUND);
    EXPECT_EQ(UN(LdrGetDllFullName)((BYTE *)g_ntdll + 0x10, &b), ST_DLL_NOTFOUND);
}

TEST(ldr_mod_thread_callouts_and_sxs)
{
    REQUIRE(UN(LdrDisableThreadCalloutsForDll)); REQUIRE(UN(LdrIsModuleSxsRedirected)); need_ntdll();
    char path[MAX_PATH];
    HMODULE m = load_fixture(path, sizeof path, NULL);
    if (!m) return;
    EXPECT_EQ(UN(LdrDisableThreadCalloutsForDll)(m), 0);
    EXPECT_EQ(UN(LdrDisableThreadCalloutsForDll)(m), 0);      /* idempotent */
    EXPECT_EQ(UN(LdrDisableThreadCalloutsForDll)((PVOID)0x12340000), ST_DLL_NOTFOUND);
    EXPECT_EQ(UN(LdrDisableThreadCalloutsForDll)(NULL), ST_DLL_NOTFOUND);
    /* only the low byte of the return value is defined (BOOLEAN) */
    EXPECT_EQ(UN(LdrIsModuleSxsRedirected)(m) & 0xff, 0);
    EXPECT_EQ(UN(LdrIsModuleSxsRedirected)(g_ntdll) & 0xff, 0);
    EXPECT_EQ(UN(LdrIsModuleSxsRedirected)(GetModuleHandleW(NULL)) & 0xff, 0);
    EXPECT_EQ(UN(LdrIsModuleSxsRedirected)(NULL) & 0xff, 0);
    EXPECT_EQ(UN(LdrIsModuleSxsRedirected)((PVOID)0x12340000) & 0xff, 0);
    FreeLibrary(m);
}

typedef struct {
    PVOID Section, MappedBase, ImageBase;
    ULONG ImageSize, Flags;
    USHORT LoadOrderIndex, InitOrderIndex, LoadCount, OffsetToFileName;
    UCHAR FullPathName[256];
} PMI;
static ULONG pmi_size(void)
{
    ULONG need = 0;
    NTSTATUS s = UN(LdrQueryProcessModuleInformation)(NULL, 0, &need);
    EXPECT_EQ(s, ST_LEN_MISMATCH);
    return need;
}
static const PMI *pmi_find(const BYTE *buf, PVOID base)
{
    ULONG cnt = *(const ULONG *)buf;
    const PMI *m = (const PMI *)(buf + 8);
    for (ULONG i = 0; i < cnt; i++) if (m[i].ImageBase == base) return &m[i];
    return NULL;
}
TEST(ldr_mod_query_process_modules)
{
    REQUIRE(UN(LdrQueryProcessModuleInformation)); need_ntdll();
    ULONG need = pmi_size(), ret = 0;
    CHECK(need >= 8 + 3 * sizeof(PMI));
    BYTE *buf = (BYTE *)malloc(need + 4096);
    memset(buf, 0xCC, need + 4096);
    EXPECT_EQ(UN(LdrQueryProcessModuleInformation)(buf, need, &ret), 0);
    EXPECT_EQ(ret, need);
    ULONG cnt = *(ULONG *)buf;
    EXPECT_EQ(need, 8 + cnt * sizeof(PMI));
    const PMI *exe = pmi_find(buf, GetModuleHandleW(NULL)), *nt = pmi_find(buf, g_ntdll), *k32 = pmi_find(buf, GetModuleHandleW(L"kernel32.dll"));
    CHECK(exe && nt && k32);
    if (exe && nt) {
        /* the process image is listed first, ntdll second */
        CHECK(exe < nt);
        PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)((BYTE *)g_ntdll + ((PIMAGE_DOS_HEADER)g_ntdll)->e_lfanew);
        EXPECT_EQ(nt->ImageSize, h->OptionalHeader.SizeOfImage);
        char want[MAX_PATH]; GetModuleFileNameA(g_ntdll, want, MAX_PATH);
        CHECK(!_stricmp((const char *)nt->FullPathName, want));
        CHECK(nt->OffsetToFileName > 0 && !_stricmp((const char *)nt->FullPathName + nt->OffsetToFileName, "ntdll.dll"));
        EXPECT_EQ(nt->FullPathName[nt->OffsetToFileName - 1], '\\');
        GetModuleFileNameA(NULL, want, MAX_PATH);
        CHECK(!_stricmp((const char *)exe->FullPathName, want));
    }
    /* too small by one byte, and a header-only buffer: the required size comes back */
    ret = 0;
    EXPECT_EQ(UN(LdrQueryProcessModuleInformation)(buf, need - 1, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(ret, need);
    ret = 0;
    EXPECT_EQ(UN(LdrQueryProcessModuleInformation)(buf, 8, &ret), ST_LEN_MISMATCH);
    EXPECT_EQ(ret, need);
    free(buf);
}

TEST(ldr_mod_query_process_modules_tracks_loads)
{
    REQUIRE(UN(LdrQueryProcessModuleInformation));
    ULONG before = pmi_size();
    char path[MAX_PATH];
    HMODULE m = load_fixture(path, sizeof path, NULL);
    if (!m) return;
    ULONG need = pmi_size(), ret = 0;
    EXPECT_EQ(need, before + sizeof(PMI));
    BYTE *buf = (BYTE *)malloc(need);
    EXPECT_EQ(UN(LdrQueryProcessModuleInformation)(buf, need, &ret), 0);
    const PMI *e = pmi_find(buf, m);
    CHECK(e != NULL);
    if (e) {
        EXPECT_EQ(e->ImageSize, 0x2000);
        EXPECT_EQ(e->LoadCount, 1);
        CHECK(!_stricmp((const char *)e->FullPathName, path));
    }
    free(buf);
    FreeLibrary(m);
    EXPECT_EQ(pmi_size(), before);
}

TEST(ldr_mod_service_tags)
{
    REQUIRE(UN(LdrQueryModuleServiceTags)); need_ntdll();
    ULONG tags[4] = {0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA}, cnt = 4;
    /* a module that belongs to no service has no tags */
    EXPECT_EQ(UN(LdrQueryModuleServiceTags)(g_ntdll, tags, &cnt), 0);
    EXPECT_EQ(cnt, 0);
    EXPECT_EQ(tags[0], 0xAAAAAAAA);
    cnt = 0;
    EXPECT_EQ(UN(LdrQueryModuleServiceTags)(g_ntdll, tags, &cnt), 0);
    EXPECT_EQ(cnt, 0);
    EXPECT_EQ(UN(LdrQueryModuleServiceTags)((PVOID)0x12340000, tags, &cnt), ST_DLL_NOTFOUND);
}

TEST(ldr_mod_known_dll_section)
{
    REQUIRE(UN(LdrGetKnownDllSectionHandle)); REQUIRE(UN(NtQuerySection));
    HANDLE h = NULL;
    NTSTATUS s = UN(LdrGetKnownDllSectionHandle)(L"kernel32.dll", 0, &h);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        CHECK(h != NULL);
        struct { PVOID base; ULONG attr; LARGE_INTEGER size; } bi; memset(&bi, 0, sizeof bi);
        NTSTATUS q = UN(NtQuerySection)(h, 0, &bi, sizeof bi, NULL);
        EXPECT_EQ(q, 0);
        CHECK(q != 0 || (bi.attr & SEC_IMAGE) != 0);
        CloseHandle(h);
    }
    h = NULL;
    EXPECT_EQ(UN(LdrGetKnownDllSectionHandle)(L"KERNEL32.DLL", 0, &h), 0);          /* object names are case-insensitive */
    if (h) CloseHandle(h);
    h = NULL;
    EXPECT_EQ(UN(LdrGetKnownDllSectionHandle)(L"corpus_no_such_known.dll", 0, &h), S(0xC0000034));
    EXPECT_EQ(UN(LdrGetKnownDllSectionHandle)(L"kernel32.dll", 1, &h), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrGetKnownDllSectionHandle)(L"C:\\Windows\\System32\\kernel32.dll", 0, &h), S(0xC000003A));
    EXPECT_EQ(UN(LdrGetKnownDllSectionHandle)(NULL, 0, &h), S(0xC0000024));
    EXPECT_EQ(UN(LdrGetKnownDllSectionHandle)(L"", 0, &h), S(0xC0000024));
}

TEST(ldr_mod_cfg_and_failure_data)
{
    REQUIRE(UN(LdrControlFlowGuardEnforced)); REQUIRE(UN(LdrGetFailureData)); need_ntdll();
    ULONG c = UN(LdrControlFlowGuardEnforced)();
    CHECKF(c == 0 || c == 1, "returned %lu", c);
    EXPECT_EQ(UN(LdrControlFlowGuardEnforced)(), c);
    PVOID a = UN(LdrGetFailureData)(), b = UN(LdrGetFailureData)();
    EXPECT_EQ(a, b);
    PIMAGE_NT_HEADERS h = (PIMAGE_NT_HEADERS)((BYTE *)g_ntdll + ((PIMAGE_DOS_HEADER)g_ntdll)->e_lfanew);
    CHECK((BYTE *)a > (BYTE *)g_ntdll && (BYTE *)a < (BYTE *)g_ntdll + h->OptionalHeader.SizeOfImage);
}

static void export_ordinal_of(HMODULE m, const char *name, ULONG *ord)
{
    BYTE *b = (BYTE *)m;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(b + ((PIMAGE_DOS_HEADER)b)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)(b + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    ULONG *names = (ULONG *)(b + ed->AddressOfNames); USHORT *ords = (USHORT *)(b + ed->AddressOfNameOrdinals);
    *ord = 0;
    for (ULONG i = 0; i < ed->NumberOfNames; i++)
        if (!strcmp((char *)b + names[i], name)) { *ord = ords[i] + ed->Base; return; }
}
TEST(ldr_mod_procedure_address_for_caller)
{
    REQUIRE(UN(LdrGetProcedureAddressForCaller)); need_ntdll();
    PVOID want = (PVOID)GetProcAddress(g_ntdll, "NtClose"), a = NULL;
    char nm[] = "NtClose"; ANSI_STRING as = {7, 8, nm};
    EXPECT_EQ(UN(LdrGetProcedureAddressForCaller)(g_ntdll, &as, 0, &a, 0, NULL), 0);
    EXPECT_EQ(a, want);
    ULONG ord = 0; export_ordinal_of(g_ntdll, "NtClose", &ord);
    a = NULL;
    EXPECT_EQ(UN(LdrGetProcedureAddressForCaller)(g_ntdll, NULL, ord, &a, 0, NULL), 0);
    EXPECT_EQ(a, want);
    char bad[] = "CorpusNoSuchExport"; ANSI_STRING bs = {18, 19, bad};
    a = (PVOID)1;
    EXPECT_EQ(UN(LdrGetProcedureAddressForCaller)(g_ntdll, &bs, 0, &a, 0, NULL), ST_PROC_NOTFOUND);
    a = NULL;
    EXPECT_EQ(UN(LdrGetProcedureAddressForCaller)((PVOID)0x12340000, &as, 0, &a, 0, NULL), ST_DLL_NOTFOUND);
    /* a counted name need not be NUL terminated */
    char raw[4] = {'N', 't', 'X', 'Y'}; ANSI_STRING cs = {2, 4, raw};
    a = NULL;
    EXPECT_EQ(UN(LdrGetProcedureAddressForCaller)(g_ntdll, &cs, 0, &a, 0, NULL), ST_PROC_NOTFOUND);
}

/* ---- DLL notifications ------------------------------------------------------------------- */
typedef struct { ULONG Flags; const UNICODE_STRING *FullDllName, *BaseDllName; PVOID DllBase; ULONG SizeOfImage; } NOTIF;
static struct { volatile LONG loads, unloads; PVOID base; ULONG size; WCHAR name[40]; WCHAR full[MAX_PATH]; PVOID ctx_seen; LONG other; } g_n;
static WCHAR g_want_leaf[40];
static void CALLBACK on_dll(ULONG reason, const NOTIF *d, PVOID ctx)
{
    if (!d || !d->BaseDllName || lstrcmpiW(d->BaseDllName->Buffer, g_want_leaf) != 0) { InterlockedIncrement(&g_n.other); return; }
    g_n.ctx_seen = ctx; g_n.base = d->DllBase; g_n.size = d->SizeOfImage;
    lstrcpynW(g_n.name, d->BaseDllName->Buffer, 40);
    lstrcpynW(g_n.full, d->FullDllName->Buffer, MAX_PATH);
    if (reason == 1) InterlockedIncrement(&g_n.loads);
    else if (reason == 2) InterlockedIncrement(&g_n.unloads);
}
TEST(ldr_mod_dll_notifications)
{
    REQUIRE(UN(LdrRegisterDllNotification)); REQUIRE(UN(LdrUnregisterDllNotification));
    char path[MAX_PATH]; WCHAR leaf[40];
    t_tmpfile(path, sizeof path, "notif.dll");
    MultiByteToWideChar(CP_ACP, 0, "notif.dll", -1, leaf, 40);
    if (!peb_write(path, 1, NULL)) { t_skip("cannot write fixture"); return; }
    lstrcpyW(g_want_leaf, leaf);
    memset((void *)&g_n, 0, sizeof g_n);
    PVOID cookie = NULL, ctx = (PVOID)0x5151;
    EXPECT_EQ(UN(LdrRegisterDllNotification)(0, (PVOID)on_dll, ctx, &cookie), 0);
    CHECK(cookie != NULL);
    if (!cookie) return;
    HMODULE m = LoadLibraryA(path);
    if (!m) { t_skip("fixture cannot be loaded"); UN(LdrUnregisterDllNotification)(cookie); return; }
    EXPECT_EQ(g_n.loads, 1);
    EXPECT_EQ(g_n.base, m);
    EXPECT_EQ(g_n.size, 0x2000);
    EXPECT_EQ(g_n.ctx_seen, ctx);
    CHECK(!lstrcmpiW(g_n.name, leaf));
    WCHAR wpath[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
    CHECK(!lstrcmpiW(g_n.full, wpath));
    EXPECT_EQ(g_n.unloads, 0);
    EXPECT_EQ(FreeLibrary(m), TRUE);
    EXPECT_EQ(g_n.unloads, 1);
    /* unregister: a second unregister of the same cookie fails and no further callbacks arrive */
    EXPECT_EQ(UN(LdrUnregisterDllNotification)(cookie), 0);
    EXPECT_EQ(UN(LdrUnregisterDllNotification)(cookie), ST_DLL_NOTFOUND);
    m = LoadLibraryA(path);
    EXPECT_EQ(g_n.loads, 1);
    if (m) FreeLibrary(m);
    /* argument validation */
    PVOID c2 = NULL;
    EXPECT_EQ(UN(LdrRegisterDllNotification)(1, (PVOID)on_dll, NULL, &c2), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrRegisterDllNotification)(0, NULL, NULL, &c2), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrRegisterDllNotification)(0, (PVOID)on_dll, NULL, NULL), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrUnregisterDllNotification)(NULL), ST_DLL_NOTFOUND);
}
TEST(ldr_mod_dll_notifications_multiple)
{
    REQUIRE(UN(LdrRegisterDllNotification)); REQUIRE(UN(LdrUnregisterDllNotification));
    char path[MAX_PATH];
    t_tmpfile(path, sizeof path, "notif2.dll");
    MultiByteToWideChar(CP_ACP, 0, "notif2.dll", -1, g_want_leaf, 40);
    if (!peb_write(path, 1, NULL)) { t_skip("cannot write fixture"); return; }
    memset((void *)&g_n, 0, sizeof g_n);
    PVOID c1 = NULL, c2 = NULL;
    EXPECT_EQ(UN(LdrRegisterDllNotification)(0, (PVOID)on_dll, NULL, &c1), 0);
    EXPECT_EQ(UN(LdrRegisterDllNotification)(0, (PVOID)on_dll, NULL, &c2), 0);
    CHECK(c1 && c2 && c1 != c2);
    HMODULE m = LoadLibraryA(path);
    if (m) {
        EXPECT_EQ(g_n.loads, 2);            /* both registrations are called */
        UN(LdrUnregisterDllNotification)(c1);
        FreeLibrary(m);
        EXPECT_EQ(g_n.unloads, 1);          /* only the remaining one */
    } else t_skip("fixture cannot be loaded");
    if (c1) UN(LdrUnregisterDllNotification)(c1);
    if (c2) EXPECT_EQ(UN(LdrUnregisterDllNotification)(c2), 0);
}

TEST(ldr_mod_implicit_path_options)
{
    REQUIRE(UN(LdrSetImplicitPathOptions)); need_ntdll();
    char path[MAX_PATH];
    HMODULE m = load_fixture(path, sizeof path, NULL);
    if (!m) return;
    EXPECT_EQ(UN(LdrSetImplicitPathOptions)(m, 0x100), 0);
    EXPECT_EQ(UN(LdrSetImplicitPathOptions)(m, 0x800), 0);
    EXPECT_EQ(UN(LdrSetImplicitPathOptions)(m, 0), ST_BAD_PARAM);       /* at least one option required */
    EXPECT_EQ(UN(LdrSetImplicitPathOptions)(m, 0x1), ST_BAD_PARAM);     /* options live in bits 8..14 */
    EXPECT_EQ(UN(LdrSetImplicitPathOptions)(m, 0x8000), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrSetImplicitPathOptions)(m, 0x80000000u), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrSetImplicitPathOptions)((PVOID)0x12340000, 0x100), ST_DLL_NOTFOUND);
    FreeLibrary(m);
}

/* ---- a freshly loaded module as seen through the generic loader queries ------------------- */
typedef struct { PVOID want; int seen, index, at; } enum_ctx;
static void NTAPI enum_one(PVOID entry, PVOID ctx, BOOLEAN *stop)
{
    enum_ctx *c = (enum_ctx *)ctx;
    PVOID base = *(PVOID *)((BYTE *)entry + 0x30);            /* LDR_DATA_TABLE_ENTRY.DllBase */
    if (base == c->want) { c->seen++; c->at = c->index; }
    c->index++;
}
TEST(ldr_mod_fixture_in_loader_queries)
{
    REQUIRE(UN(LdrAddRefDll)); REQUIRE(UN(LdrGetDllHandleEx)); REQUIRE(UN(LdrFindEntryForAddress));
    REQUIRE(UN(LdrEnumerateLoadedModules)); REQUIRE(UN(LdrLockLoaderLock)); REQUIRE(UN(LdrUnlockLoaderLock)); REQUIRE(UN(LdrGetProcedureAddressEx));
    char path[MAX_PATH]; WCHAR leaf[40];
    HMODULE m = load_fixture(path, sizeof path, leaf);
    if (!m) return;
    PVOID entry = NULL;
    EXPECT_EQ(UN(LdrFindEntryForAddress)((BYTE *)m + 0x1004, &entry), 0);
    CHECK(entry != NULL);
    if (entry) {
        EXPECT_EQ(*(PVOID *)((BYTE *)entry + 0x30), m);                          /* DllBase */
        EXPECT_EQ(*(ULONG *)((BYTE *)entry + 0x40), 0x2000);                     /* SizeOfImage */
        UNICODE_STRING *bn = (UNICODE_STRING *)((BYTE *)entry + 0x58);           /* BaseDllName */
        CHECK(bn->Buffer && !lstrcmpiW(bn->Buffer, leaf));
    }
    enum_ctx ec = {m, 0, 0, -1};
    EXPECT_EQ(UN(LdrEnumerateLoadedModules)(0, (PVOID)enum_one, &ec), 0);
    EXPECT_EQ(ec.seen, 1);
    CHECK(ec.at >= 2);                                                           /* after the image and ntdll */
    /* explicit reference: needs one more free */
    EXPECT_EQ(UN(LdrAddRefDll)(0, m), 0);
    EXPECT_EQ(FreeLibrary(m), TRUE);
    CHECK(GetModuleHandleW(leaf) == m);
    /* lookup without taking a reference (flag 1) */
    UNICODE_STRING n = us(leaf); PVOID h = NULL;
    EXPECT_EQ(UN(LdrGetDllHandleEx)(1, NULL, NULL, &n, &h), 0);
    EXPECT_EQ(h, m);
    /* the loader lock can be taken around queries */
    ULONG st = 0; ULONG_PTR ck = 0;
    EXPECT_EQ(UN(LdrLockLoaderLock)(0, &st, &ck), 0);
    EXPECT_EQ(st, 1);
    EXPECT_EQ(UN(LdrFindEntryForAddress)(m, &entry), 0);
    EXPECT_EQ(UN(LdrUnlockLoaderLock)(0, ck), 0);
    /* the fixture has no exports */
    char nm[] = "NtClose"; ANSI_STRING as = {7, 8, nm}; PVOID a = NULL;
    EXPECT_EQ(UN(LdrGetProcedureAddressEx)(m, &as, 0, &a, 0), ST_PROC_NOTFOUND);
    need_ntdll();
    EXPECT_EQ(UN(LdrGetProcedureAddressEx)(g_ntdll, &as, 0, &a, 0), 0);
    EXPECT_EQ(a, GetProcAddress(g_ntdll, "NtClose"));
    EXPECT_EQ(FreeLibrary(m), TRUE);
    CHECK(GetModuleHandleW(leaf) == NULL);
    EXPECT_EQ(UN(LdrFindEntryForAddress)((BYTE *)m + 0x1004, &entry), ST_DLL_NOTFOUND);
}

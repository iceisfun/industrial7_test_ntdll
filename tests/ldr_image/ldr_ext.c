/* Loader: module reference counting, handle lookup flags, enumeration, loader lock,
 * procedure resolution by ordinal and forwarder, and PE header helpers on synthetic images. */
#include "t.h"
#include <stdlib.h>

UDECL(NTSTATUS, LdrLoadDll, (PWSTR, PULONG, PUNICODE_STRING, PVOID *));
UDECL(NTSTATUS, LdrUnloadDll, (PVOID));
UDECL(NTSTATUS, LdrAddRefDll, (ULONG, PVOID));
UDECL(NTSTATUS, LdrGetDllHandle, (PWSTR, PULONG, PUNICODE_STRING, PVOID *));
UDECL(NTSTATUS, LdrGetDllHandleEx, (ULONG, PWSTR, PULONG, PUNICODE_STRING, PVOID *));
UDECL(NTSTATUS, LdrGetProcedureAddress, (PVOID, PANSI_STRING, ULONG, PVOID *));
UDECL(NTSTATUS, LdrGetProcedureAddressEx, (PVOID, PANSI_STRING, ULONG, PVOID *, ULONG));
UDECL(NTSTATUS, LdrFindEntryForAddress, (PVOID, PVOID *));
UDECL(NTSTATUS, LdrEnumerateLoadedModules, (ULONG, PVOID, PVOID));
UDECL(NTSTATUS, LdrLockLoaderLock, (ULONG, PULONG, PULONG_PTR));
UDECL(NTSTATUS, LdrUnlockLoaderLock, (ULONG, ULONG_PTR));
UDECL(PVOID, RtlPcToFileHeader, (PVOID, PVOID *));
UDECL(NTSTATUS, RtlImageNtHeaderEx, (ULONG, PVOID, ULONG64, PIMAGE_NT_HEADERS *));
UDECL(PIMAGE_NT_HEADERS, RtlImageNtHeader, (PVOID));
UDECL(PIMAGE_SECTION_HEADER, RtlImageRvaToSection, (PIMAGE_NT_HEADERS, PVOID, ULONG));

#define S(x) ((NTSTATUS)(x))
#define DLL_NOT_FOUND S(0xc0000135)
#define BAD_PARAM S(0xc000000d)
#define BAD_IMAGE S(0xc000007b)
#define NO_MORE_ENTRIES S(0x8000001a)
#define EX_UNCHANGED 1
#define EX_PIN 2
/* A system library that a console test program does not otherwise load. */
#define PROBE_DLL L"version.dll"

static UNICODE_STRING us(const WCHAR *s)
{
    UNICODE_STRING u;
    u.Buffer = (PWSTR)s; u.Length = (USHORT)(lstrlenW(s) * 2); u.MaximumLength = u.Length + 2;
    return u;
}
static int present(PVOID base_expected)
{
    UNICODE_STRING n = us(PROBE_DLL); PVOID h = NULL;
    NTSTATUS s = UN(LdrGetDllHandleEx)(EX_UNCHANGED, NULL, NULL, &n, &h);
    if (s == 0) { if (base_expected) EXPECT_EQ(h, base_expected); return 1; }
    EXPECT_EQ(s, DLL_NOT_FOUND);
    return 0;
}
#define LOADER_EXPORTS \
    do { if (!UN(LdrLoadDll) || !UN(LdrUnloadDll) || !UN(LdrAddRefDll) || !UN(LdrGetDllHandleEx)) { t_skip("loader exports missing"); return; } \
         if (GetModuleHandleW(PROBE_DLL)) { t_skip("probe library already loaded"); return; } } while (0)
static PVOID load_probe(void)
{
    UNICODE_STRING n = us(PROBE_DLL); PVOID h = NULL;
    NTSTATUS s = UN(LdrLoadDll)(NULL, NULL, &n, &h);
    EXPECT_EQ(s, 0);
    return s == 0 ? h : NULL;
}

TEST(ldr_ext_load_missing_module)
{
    UNICODE_STRING n = us(L"corpus_no_such_module_9f3a.dll"); PVOID h = (PVOID)0x1234;
    REQUIRE(UN(LdrLoadDll));
    EXPECT_EQ(UN(LdrLoadDll)(NULL, NULL, &n, &h), DLL_NOT_FOUND);
    CHECK(h == NULL || h == (PVOID)0x1234);
    t_note("handle after failed load: %p", h);
}
TEST(ldr_ext_unload_balances_loads)
{
    PVOID a, b;
    LOADER_EXPORTS;
    a = load_probe(); if (!a) return;
    b = load_probe();
    EXPECT_EQ(a, b);
    CHECK(present(a));
    EXPECT_EQ(UN(LdrUnloadDll)(b), 0);
    CHECK(present(a));          /* still referenced once */
    EXPECT_EQ(UN(LdrUnloadDll)(a), 0);
    CHECK(!present(NULL));      /* last reference gone */
}
TEST(ldr_ext_addref_requires_extra_unload)
{
    PVOID h;
    LOADER_EXPORTS;
    h = load_probe(); if (!h) return;
    EXPECT_EQ(UN(LdrAddRefDll)(0, h), 0);
    EXPECT_EQ(UN(LdrUnloadDll)(h), 0);
    CHECK(present(h));
    EXPECT_EQ(UN(LdrUnloadDll)(h), 0);
    CHECK(!present(NULL));
}
TEST(ldr_ext_get_handle_default_adds_reference)
{
    PVOID h, h2 = NULL; UNICODE_STRING n = us(PROBE_DLL);
    LOADER_EXPORTS;
    h = load_probe(); if (!h) return;
    EXPECT_EQ(UN(LdrGetDllHandleEx)(0, NULL, NULL, &n, &h2), 0); /* like GetModuleHandleEx without UNCHANGED_REFCOUNT */
    EXPECT_EQ(h2, h);
    EXPECT_EQ(UN(LdrUnloadDll)(h), 0);
    CHECK(present(h));
    EXPECT_EQ(UN(LdrUnloadDll)(h), 0);
    CHECK(!present(NULL));
}
TEST(ldr_ext_get_handle_unchanged_refcount)
{
    PVOID h, h2 = NULL; UNICODE_STRING n = us(PROBE_DLL);
    LOADER_EXPORTS;
    h = load_probe(); if (!h) return;
    for (int i = 0; i < 5; i++) { h2 = NULL; EXPECT_EQ(UN(LdrGetDllHandleEx)(EX_UNCHANGED, NULL, NULL, &n, &h2), 0); EXPECT_EQ(h2, h); }
    EXPECT_EQ(UN(LdrUnloadDll)(h), 0);
    CHECK(!present(NULL));
}
TEST(ldr_ext_get_handle_missing_module)
{
    PVOID h = (PVOID)0x1234; UNICODE_STRING n = us(L"corpus_no_such_module_9f3a.dll");
    REQUIRE(UN(LdrGetDllHandleEx));
    EXPECT_EQ(UN(LdrGetDllHandleEx)(EX_UNCHANGED, NULL, NULL, &n, &h), DLL_NOT_FOUND);
}
TEST(ldr_ext_get_handle_pin_and_unchanged_conflict)
{
    PVOID h = NULL; UNICODE_STRING n = us(L"ntdll.dll"); NTSTATUS s;
    REQUIRE(UN(LdrGetDllHandleEx));
    s = UN(LdrGetDllHandleEx)(EX_UNCHANGED | EX_PIN, NULL, NULL, &n, &h);
    CHECK(s < 0); /* the two flags are mutually exclusive */
    t_note("pin|unchanged status=%08lx", (ULONG)s);
}
TEST(ldr_ext_get_handle_full_path)
{
    WCHAR path[MAX_PATH + 16]; UNICODE_STRING n; PVOID h = NULL; UINT len;
    REQUIRE(UN(LdrGetDllHandleEx));
    len = GetSystemDirectoryW(path, MAX_PATH);
    if (!len || len >= MAX_PATH) { t_skip("system directory unavailable"); return; }
    lstrcatW(path, L"\\kernel32.dll");
    n = us(path);
    EXPECT_EQ(UN(LdrGetDllHandleEx)(EX_UNCHANGED, NULL, NULL, &n, &h), 0);
    EXPECT_EQ(h, GetModuleHandleW(L"kernel32.dll"));
}
TEST(ldr_ext_get_handle_matches_base_name_case)
{
    PVOID h = NULL; UNICODE_STRING n = us(L"KeRnEl32.DLL");
    REQUIRE(UN(LdrGetDllHandleEx));
    EXPECT_EQ(UN(LdrGetDllHandleEx)(EX_UNCHANGED, NULL, NULL, &n, &h), 0);
    EXPECT_EQ(h, GetModuleHandleW(L"kernel32.dll"));
}
CHILD(ldr_ext_pin)
{
    PVOID h; UNICODE_STRING n = us(PROBE_DLL);
    if (GetModuleHandleW(PROBE_DLL)) return 90;
    if (UN(LdrLoadDll)(NULL, NULL, &n, &h) != 0) return 91;
    if (UN(LdrAddRefDll)(1 /* LDR_ADDREF_DLL_PIN */, h) != 0) return 92;
    for (int i = 0; i < 4; i++) UN(LdrUnloadDll)(h);
    return GetModuleHandleW(PROBE_DLL) == h ? 0 : 93;
}
TEST(ldr_ext_pinned_module_survives_unload)
{
    DWORD rc;
    LOADER_EXPORTS;
    rc = t_run_child("ldr_ext_pin", "", 20000);
    EXPECT_EQ(rc, 0);
}
TEST(ldr_ext_unload_invalid_handle)
{
    NTSTATUS s;
    REQUIRE(UN(LdrUnloadDll));
    s = UN(LdrUnloadDll)((PVOID)0x10000);
    CHECK(s < 0);
    t_note("unload of a non-module address: %08lx", (ULONG)s);
    s = UN(LdrAddRefDll)(0, (PVOID)0x10000);
    CHECK(s < 0);
    t_note("addref of a non-module address: %08lx", (ULONG)s);
}

/* ---------------- procedure resolution ---------------- */
static DWORD export_ordinal(HMODULE m, const char *name)
{
    BYTE *b = (BYTE *)m; IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *ed = (IMAGE_EXPORT_DIRECTORY *)(b + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    DWORD *names = (DWORD *)(b + ed->AddressOfNames); WORD *ords = (WORD *)(b + ed->AddressOfNameOrdinals);
    for (DWORD i = 0; i < ed->NumberOfNames; i++) if (!strcmp((char *)b + names[i], name)) return ords[i] + ed->Base;
    return 0;
}
TEST(ldr_ext_proc_by_ordinal)
{
    HMODULE n = GetModuleHandleA("ntdll.dll"); DWORD ord = export_ordinal(n, "NtClose"); PVOID p = NULL;
    REQUIRE(UN(LdrGetProcedureAddress));
    CHECK(ord != 0);
    EXPECT_EQ(UN(LdrGetProcedureAddress)(n, NULL, ord, &p), 0);
    EXPECT_EQ(p, GetProcAddress(n, "NtClose"));
}
TEST(ldr_ext_proc_ordinal_out_of_range)
{
    HMODULE n = GetModuleHandleA("ntdll.dll"); PVOID p = (PVOID)0x1234; NTSTATUS s;
    REQUIRE(UN(LdrGetProcedureAddress));
    s = UN(LdrGetProcedureAddress)(n, NULL, 0xfffe, &p);
    CHECK(s < 0);
    t_note("ordinal 0xfffe status=%08lx", (ULONG)s);
}
TEST(ldr_ext_proc_ex_matches_plain)
{
    HMODULE n = GetModuleHandleA("ntdll.dll"); PVOID p = NULL, q = NULL; ANSI_STRING a; char name[] = "RtlInitUnicodeString";
    REQUIRE(UN(LdrGetProcedureAddressEx));
    a.Buffer = name; a.Length = (USHORT)strlen(name); a.MaximumLength = a.Length + 1;
    EXPECT_EQ(UN(LdrGetProcedureAddressEx)(n, &a, 0, &p, 0), 0);
    EXPECT_EQ(UN(LdrGetProcedureAddress)(n, &a, 0, &q), 0);
    EXPECT_EQ(p, q);
    EXPECT_EQ(p, GetProcAddress(n, name));
}
TEST(ldr_ext_proc_through_forwarder)
{
    HMODULE k = GetModuleHandleA("kernel32.dll"); PVOID p = NULL; ANSI_STRING a; char name[] = "HeapAlloc";
    REQUIRE(UN(LdrGetProcedureAddress));
    a.Buffer = name; a.Length = (USHORT)strlen(name); a.MaximumLength = a.Length + 1;
    EXPECT_EQ(UN(LdrGetProcedureAddress)(k, &a, 0, &p), 0);
    EXPECT_EQ(p, GetProcAddress(k, name));
    if (p == GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAllocateHeap")) t_note("HeapAlloc forwards to ntdll!RtlAllocateHeap");
    else t_note("HeapAlloc resolves to %p (not the ntdll entry)", p);
}
TEST(ldr_ext_proc_missing_leaves_output_null)
{
    HMODULE k = GetModuleHandleA("kernel32.dll"); PVOID p = (PVOID)0x1234; ANSI_STRING a; char name[] = "NoSuchExport_77c1";
    REQUIRE(UN(LdrGetProcedureAddress));
    a.Buffer = name; a.Length = (USHORT)strlen(name); a.MaximumLength = a.Length + 1;
    EXPECT_EQ(UN(LdrGetProcedureAddress)(k, &a, 0, &p) < 0, 1);
    CHECK(p == NULL || p == (PVOID)0x1234);
}

/* ---------------- module list ---------------- */
static PVOID entry_base(PVOID e) { return *(PVOID *)((BYTE *)e + 0x30); }
static PVOID entry_size(PVOID e) { return (PVOID)(ULONG_PTR)*(ULONG *)((BYTE *)e + 0x40); }
TEST(ldr_ext_find_entry_for_address)
{
    PVOID e = NULL; HMODULE k = GetModuleHandleA("kernel32.dll"); PVOID inside = GetProcAddress(k, "Sleep");
    UNICODE_STRING *base_name;
    REQUIRE(UN(LdrFindEntryForAddress));
    EXPECT_EQ(UN(LdrFindEntryForAddress)(inside, &e), 0);
    CHECK(e != NULL);
    if (!e) return;
    EXPECT_EQ(entry_base(e), k);
    base_name = (UNICODE_STRING *)((BYTE *)e + 0x58);
    CHECK(base_name->Length == 24 && !_wcsnicmp(base_name->Buffer, L"kernel32.dll", 12));
    CHECK((ULONG_PTR)inside < (ULONG_PTR)k + (ULONG_PTR)entry_size(e));
}
TEST(ldr_ext_find_entry_image_edges)
{
    PVOID e = NULL; HMODULE n = GetModuleHandleA("ntdll.dll"); PVOID size; PVOID ent = NULL;
    REQUIRE(UN(LdrFindEntryForAddress));
    EXPECT_EQ(UN(LdrFindEntryForAddress)((PVOID)n, &ent), 0);  /* first byte of the image */
    if (!ent) return;
    size = entry_size(ent);
    EXPECT_EQ(UN(LdrFindEntryForAddress)((BYTE *)n + (ULONG_PTR)size - 1, &e), 0);
    EXPECT_EQ(e, ent);
    e = NULL;
    NTSTATUS s = UN(LdrFindEntryForAddress)((BYTE *)n + (ULONG_PTR)size, &e);   /* one past the end belongs to no list entry that is ntdll */
    CHECK(s < 0 || e != ent);
}
TEST(ldr_ext_find_entry_unmapped_and_heap)
{
    PVOID e = (PVOID)0x1234; int local = 0; void *heap = malloc(64);
    REQUIRE(UN(LdrFindEntryForAddress));
    /* Windows 10 reports STATUS_DLL_NOT_FOUND for an address outside every loaded image. */
    EXPECT_EQ(UN(LdrFindEntryForAddress)((PVOID)0x10, &e), (NTSTATUS)0xC0000135);
    e = NULL;
    EXPECT_EQ(UN(LdrFindEntryForAddress)(&local, &e), (NTSTATUS)0xC0000135);
    e = NULL;
    EXPECT_EQ(UN(LdrFindEntryForAddress)(heap, &e), (NTSTATUS)0xC0000135);
    free(heap);
}

typedef struct { int count; int saw_image, saw_ntdll, saw_k32; int stop_after; PVOID first; PVOID second; } enum_t;
static void NTAPI enum_cb(PVOID entry, PVOID ctx, BOOLEAN *stop)
{
    enum_t *c = ctx; PVOID b = entry_base(entry);
    if (c->count == 0) c->first = b; else if (c->count == 1) c->second = b;
    c->count++;
    if (b == (PVOID)GetModuleHandleA(NULL)) c->saw_image = 1;
    if (b == (PVOID)GetModuleHandleA("ntdll.dll")) c->saw_ntdll = 1;
    if (b == (PVOID)GetModuleHandleA("kernel32.dll")) c->saw_k32 = 1;
    if (c->stop_after && c->count >= c->stop_after) *stop = TRUE;
}
TEST(ldr_ext_enumerate_visits_core_modules)
{
    enum_t c; memset(&c, 0, sizeof c);
    REQUIRE(UN(LdrEnumerateLoadedModules));
    EXPECT_EQ(UN(LdrEnumerateLoadedModules)(0, (PVOID)enum_cb, &c), 0);
    CHECK(c.count >= 3);
    CHECK(c.saw_image && c.saw_ntdll && c.saw_k32);
    EXPECT_EQ(c.first, GetModuleHandleA(NULL));            /* load order starts with the executable */
    EXPECT_EQ(c.second, GetModuleHandleA("ntdll.dll"));
}
TEST(ldr_ext_enumerate_stop_flag)
{
    enum_t c; memset(&c, 0, sizeof c); c.stop_after = 1;
    REQUIRE(UN(LdrEnumerateLoadedModules));
    EXPECT_EQ(UN(LdrEnumerateLoadedModules)(0, (PVOID)enum_cb, &c), 0);
    EXPECT_EQ(c.count, 1);
    memset(&c, 0, sizeof c); c.stop_after = 2;
    EXPECT_EQ(UN(LdrEnumerateLoadedModules)(0, (PVOID)enum_cb, &c), 0);
    EXPECT_EQ(c.count, 2);
}
TEST(ldr_ext_enumerate_invalid_arguments)
{
    enum_t c; NTSTATUS s; memset(&c, 0, sizeof c);
    REQUIRE(UN(LdrEnumerateLoadedModules));
    s = UN(LdrEnumerateLoadedModules)(0, NULL, &c);
    EXPECT_EQ(s, BAD_PARAM);
    s = UN(LdrEnumerateLoadedModules)(1, (PVOID)enum_cb, &c);
    EXPECT_EQ(s, BAD_PARAM);
    EXPECT_EQ(c.count, 0);
}

/* ---------------- loader lock ---------------- */
#define LOCK_RAISE 1
#define LOCK_TRY 2
TEST(ldr_ext_loader_lock_acquire_release)
{
    ULONG st = 0; ULONG_PTR cookie = 0;
    RTL_CRITICAL_SECTION *cs = *(RTL_CRITICAL_SECTION **)(*(BYTE **)((BYTE *)NtCurrentTeb() + 0x60) + 0x110); /* PEB loader-lock pointer */
    REQUIRE(UN(LdrLockLoaderLock)); REQUIRE(UN(LdrUnlockLoaderLock));
    EXPECT_EQ(UN(LdrLockLoaderLock)(0, &st, &cookie), 0);
    EXPECT_EQ(st, 1);     /* LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED */
    CHECK(cookie != 0);
    if (cs) { EXPECT_EQ((ULONG_PTR)cs->OwningThread, GetCurrentThreadId()); CHECK(cs->RecursionCount >= 1); }
    EXPECT_EQ(UN(LdrUnlockLoaderLock)(0, cookie), 0);
    if (cs) CHECK(cs->OwningThread == NULL);
}
TEST(ldr_ext_loader_lock_recursive)
{
    ULONG s1 = 0, s2 = 0; ULONG_PTR c1 = 0, c2 = 0;
    REQUIRE(UN(LdrLockLoaderLock)); REQUIRE(UN(LdrUnlockLoaderLock));
    EXPECT_EQ(UN(LdrLockLoaderLock)(0, &s1, &c1), 0);
    EXPECT_EQ(UN(LdrLockLoaderLock)(LOCK_TRY, &s2, &c2), 0);
    EXPECT_EQ(s1, 1);
    EXPECT_EQ(s2, 1);     /* the owner can always re-enter */
    EXPECT_EQ(UN(LdrUnlockLoaderLock)(0, c2), 0);
    EXPECT_EQ(UN(LdrUnlockLoaderLock)(0, c1), 0);
}
typedef struct { HANDLE go, done; volatile NTSTATUS status; volatile ULONG state; volatile ULONG_PTR cookie; } lock_t;
static DWORD WINAPI try_lock_thread(PVOID p)
{
    lock_t *l = p; ULONG st = 0; ULONG_PTR ck = 0;
    WaitForSingleObject(l->go, 10000);
    l->status = UN(LdrLockLoaderLock)(LOCK_TRY, &st, &ck);
    l->state = st; l->cookie = ck;
    if (l->status == 0 && st == 1) UN(LdrUnlockLoaderLock)(0, ck);
    SetEvent(l->done);
    return 0;
}
static void foreign_try(int hold)
{
    lock_t l; HANDLE th; ULONG st = 0; ULONG_PTR ck = 0;
    REQUIRE(UN(LdrLockLoaderLock)); REQUIRE(UN(LdrUnlockLoaderLock));
    memset(&l, 0, sizeof l);
    l.go = CreateEventA(NULL, TRUE, FALSE, NULL); l.done = CreateEventA(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, try_lock_thread, &l, 0, NULL);   /* created before the lock is taken */
    if (!th) { t_skip("CreateThread failed"); return; }
    Sleep(50);
    if (hold) EXPECT_EQ(UN(LdrLockLoaderLock)(0, &st, &ck), 0);
    SetEvent(l.go);
    EXPECT_EQ(WaitForSingleObject(l.done, 10000), WAIT_OBJECT_0);
    if (hold) EXPECT_EQ(UN(LdrUnlockLoaderLock)(0, ck), 0);
    WaitForSingleObject(th, 10000);
    CloseHandle(th); CloseHandle(l.go); CloseHandle(l.done);
    EXPECT_EQ(l.status, 0);
    EXPECT_EQ(l.state, hold ? 2 : 1);   /* NOT_ACQUIRED while another thread owns the lock */
}
TEST(ldr_ext_loader_lock_try_while_foreign_owner) { foreign_try(1); }
TEST(ldr_ext_loader_lock_try_when_free) { foreign_try(0); }
TEST(ldr_ext_loader_lock_invalid_flags)
{
    ULONG st = 0; ULONG_PTR ck = 0; NTSTATUS s;
    REQUIRE(UN(LdrLockLoaderLock)); REQUIRE(UN(LdrUnlockLoaderLock));
    s = UN(LdrLockLoaderLock)(0x4, &st, &ck);
    CHECK(s < 0);
    t_note("unknown flag status=%08lx", (ULONG)s);
    if (s >= 0) UN(LdrUnlockLoaderLock)(0, ck);
}

/* ---------------- file header lookups ---------------- */
TEST(ldr_ext_pc_to_file_header_cases)
{
    PVOID base = (PVOID)0x1234, r; int local = 0; void *heap = malloc(32);
    HMODULE k = GetModuleHandleA("kernel32.dll");
    REQUIRE(UN(RtlPcToFileHeader));
    r = UN(RtlPcToFileHeader)(GetProcAddress(k, "Sleep"), &base);
    EXPECT_EQ(r, (PVOID)k);
    EXPECT_EQ(base, (PVOID)k);
    r = UN(RtlPcToFileHeader)((BYTE *)k + 0x10, &base);          /* inside the header page */
    EXPECT_EQ(r, (PVOID)k);
    base = (PVOID)0x1234;
    r = UN(RtlPcToFileHeader)((PVOID)0x10, &base);
    CHECK(r == NULL); CHECK(base == NULL);
    base = (PVOID)0x1234;
    r = UN(RtlPcToFileHeader)(&local, &base);
    CHECK(r == NULL); CHECK(base == NULL);
    base = (PVOID)0x1234;
    r = UN(RtlPcToFileHeader)(heap, &base);
    CHECK(r == NULL); CHECK(base == NULL);
    free(heap);
}

#define IMG_SIZE 0x400
#define LFANEW 0x80
static BYTE *make_image(void)
{
    BYTE *b = calloc(1, IMG_SIZE);
    IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER *)b;
    d->e_magic = IMAGE_DOS_SIGNATURE; d->e_lfanew = LFANEW;
    *(DWORD *)(b + LFANEW) = IMAGE_NT_SIGNATURE;
    return b;
}
TEST(ldr_ext_image_headers_synthetic_valid)
{
    BYTE *b = make_image(); IMAGE_NT_HEADERS *nt = NULL;
    REQUIRE(UN(RtlImageNtHeaderEx));
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, b, IMG_SIZE, &nt), 0);
    EXPECT_EQ(nt, (PVOID)(b + LFANEW));
    nt = NULL;
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(1 /* RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK */, b, 0, &nt), 0);
    EXPECT_EQ(nt, (PVOID)(b + LFANEW));
    if (UN(RtlImageNtHeader)) EXPECT_EQ(UN(RtlImageNtHeader)(b), (PVOID)(b + LFANEW));
    free(b);
}
TEST(ldr_ext_image_headers_range_checked)
{
    BYTE *b = make_image(); IMAGE_NT_HEADERS *nt = (PVOID)1;
    REQUIRE(UN(RtlImageNtHeaderEx));
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, b, 0x40, &nt), BAD_IMAGE);       /* smaller than the DOS header */
    CHECK(nt == NULL);
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, b, LFANEW, &nt), BAD_IMAGE);     /* NT headers start outside the range */
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, b, LFANEW + 4, &nt), BAD_IMAGE); /* only the signature fits */
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, b, 0x10, &nt), BAD_IMAGE);       /* smaller than the DOS header */
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, b, LFANEW + sizeof(IMAGE_NT_HEADERS), &nt), 0);
    nt = NULL;
    t_note("range ending inside the optional header: status=%08lx",
           (ULONG)UN(RtlImageNtHeaderEx)(0, b, LFANEW + sizeof(IMAGE_NT_HEADERS) - 1, &nt));
    free(b);
}
TEST(ldr_ext_image_headers_bad_signatures)
{
    BYTE *b = make_image(); IMAGE_NT_HEADERS *nt = (PVOID)1;
    REQUIRE(UN(RtlImageNtHeaderEx));
    b[0] = 0x58;
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, b, IMG_SIZE, &nt), BAD_IMAGE);
    CHECK(nt == NULL);
    if (UN(RtlImageNtHeader)) CHECK(UN(RtlImageNtHeader)(b) == NULL);
    b[0] = 0x4d;
    b[LFANEW] = 0x58;
    nt = (PVOID)1;
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, b, IMG_SIZE, &nt), BAD_IMAGE);
    CHECK(nt == NULL);
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(1, b, IMG_SIZE, &nt), BAD_IMAGE);
    free(b);
}
TEST(ldr_ext_image_headers_invalid_arguments)
{
    BYTE *b = make_image(); IMAGE_NT_HEADERS *nt = NULL;
    REQUIRE(UN(RtlImageNtHeaderEx));
    NTSTATUS s1 = UN(RtlImageNtHeaderEx)(0, NULL, IMG_SIZE, &nt);
    NTSTATUS s2 = UN(RtlImageNtHeaderEx)(0, b, IMG_SIZE, NULL);
    NTSTATUS s3 = UN(RtlImageNtHeaderEx)(2, b, IMG_SIZE, &nt);   /* unknown flag: not validated, observed to succeed */
    CHECK(s1 < 0 && s2 < 0);
    EXPECT_EQ(s3, 0);
    t_note("null base=%08lx null output=%08lx unknown flag=%08lx", (ULONG)s1, (ULONG)s2, (ULONG)s3);
    free(b);
}
TEST(ldr_ext_image_headers_real_module)
{
    HMODULE k = GetModuleHandleA("kernel32.dll"); IMAGE_NT_HEADERS *nt = NULL;
    REQUIRE(UN(RtlImageNtHeaderEx));
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, k, ((IMAGE_NT_HEADERS *)((BYTE *)k + ((IMAGE_DOS_HEADER *)k)->e_lfanew))->OptionalHeader.SizeOfImage, &nt), 0);
    EXPECT_EQ(nt, (PVOID)((BYTE *)k + ((IMAGE_DOS_HEADER *)k)->e_lfanew));
    CHECK(nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
}
TEST(ldr_ext_rva_to_section)
{
    HMODULE self = GetModuleHandleA(NULL); IMAGE_NT_HEADERS *nt; IMAGE_SECTION_HEADER *sec;
    REQUIRE(UN(RtlImageRvaToSection)); REQUIRE(UN(RtlImageNtHeader));
    nt = UN(RtlImageNtHeader)(self);
    CHECK(nt != NULL);
    if (!nt) return;
    sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!sec[i].SizeOfRawData) continue;
        EXPECT_EQ(UN(RtlImageRvaToSection)(nt, self, sec[i].VirtualAddress), &sec[i]);
        EXPECT_EQ(UN(RtlImageRvaToSection)(nt, self, sec[i].VirtualAddress + 1), &sec[i]);
    }
    CHECK(UN(RtlImageRvaToSection)(nt, self, 0) == NULL);                         /* headers belong to no section */
    CHECK(UN(RtlImageRvaToSection)(nt, self, nt->OptionalHeader.SizeOfImage + 0x1000) == NULL);
    CHECK(UN(RtlImageRvaToSection)(nt, self, 0xffffffff) == NULL);
}

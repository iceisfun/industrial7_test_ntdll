/* Hash tables, memory zones and lookaside blocks, environment blocks, process parameters, unicode string creation,
 * function tables, section-table lookup, registry key helpers, activation contexts, debug buffers, UMS objects,
 * boot-status data and a few trivial stubs. */
#include "t.h"
#include <stdlib.h>

#define RTL_REGISTRY_ABSOLUTE 0
#define RTL_REGISTRY_SERVICES 1
#define RTL_REGISTRY_CONTROL 2
#define RTL_REGISTRY_WINDOWS_NT 3
#define RTL_REGISTRY_USER 5
#define RTL_REGISTRY_MAXIMUM 6
#define S(x)            ((NTSTATUS)(x))
#define ST_INVPARAM     S(0xC000000D)
#define ST_NOTFOUND     S(0xC0000034)
#define ST_NOMEM        S(0xC0000017)
#define ST_MIX          S(0xC0000030)
#define ST_INVPARAM2    S(0xC00000F0)
#define ST_INVPARAM3    S(0xC00000F1)

/* ---------------- hash tables ---------------- */
typedef struct { ULONG Flags, Shift, TableSize, Pivot, DivisorMask, NumEntries, NonEmptyBuckets, NumEnumerators; PVOID Directory; } HT;
typedef struct { LIST_ENTRY Linkage; ULONG_PTR Signature; } HT_ENTRY;
typedef struct { PLIST_ENTRY ChainHead, PrevLinkage; ULONG_PTR Signature; } HT_CTX;
UDECL(BOOLEAN, RtlCreateHashTable, (HT **, ULONG, ULONG));
UDECL(BOOLEAN, RtlCreateHashTableEx, (HT **, ULONG, ULONG, ULONG));
UDECL(VOID, RtlDeleteHashTable, (HT *));
UDECL(BOOLEAN, RtlInsertEntryHashTable, (HT *, HT_ENTRY *, ULONG_PTR, HT_CTX *));
UDECL(HT_ENTRY *, RtlLookupEntryHashTable, (HT *, ULONG_PTR, HT_CTX *));
UDECL(BOOLEAN, RtlRemoveEntryHashTable, (HT *, HT_ENTRY *, HT_CTX *));

TEST(rtl_create_hash_table) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlDeleteHashTable));
    HT *t = NULL;
    EXPECT_EQ(UN(RtlCreateHashTable)(&t, 0, 0), TRUE);
    EXPECT_NE(t, NULL);
    if (!t) return;
    EXPECT_EQ(t->Flags & 1, 1);                       /* allocated by the library */
    EXPECT_EQ(t->Shift, 0); EXPECT_EQ(t->TableSize, 0x80); EXPECT_EQ(t->DivisorMask, 0x7F);
    EXPECT_EQ(t->Pivot, 0); EXPECT_EQ(t->NumEntries, 0); EXPECT_EQ(t->NonEmptyBuckets, 0);
    UN(RtlDeleteHashTable)(t);
    /* caller-provided storage is initialised in place and not owned by the library */
    HT mine; memset(&mine, 0xAA, sizeof mine);
    HT *pm = &mine;
    EXPECT_EQ(UN(RtlCreateHashTable)(&pm, 3, 0), TRUE);
    EXPECT_EQ(pm, &mine);
    EXPECT_EQ(mine.Flags & 1, 0); EXPECT_EQ(mine.Shift, 3); EXPECT_EQ(mine.TableSize, 0x80); EXPECT_EQ(mine.NumEntries, 0);
    UN(RtlDeleteHashTable)(&mine);
}
TEST(rtl_create_hash_table_ex) {
    REQUIRE(UN(RtlCreateHashTableEx)); REQUIRE(UN(RtlDeleteHashTable));
    static const ULONG good[] = {0x80, 0x100, 0x1000, 0x20000};
    for (unsigned i = 0; i < sizeof good / sizeof *good; i++) {
        HT *t = NULL;
        EXPECT_EQ(UN(RtlCreateHashTableEx)(&t, good[i], 2, 0), TRUE);
        EXPECT_NE(t, NULL);
        if (t) { EXPECT_EQ(t->TableSize, good[i]); EXPECT_EQ(t->DivisorMask, good[i] - 1); EXPECT_EQ(t->Shift, 2); EXPECT_EQ(t->Flags & 1, 1); UN(RtlDeleteHashTable)(t); }
    }
    static const ULONG bad[] = {0, 1, 0x40, 0x7F, 0x81, 0x180, 0x3000, 0x1000000, 0x80000000};
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        HT *t = NULL;
        CHECKF(UN(RtlCreateHashTableEx)(&t, bad[i], 0, 0) == FALSE, "size 0x%lx must be rejected", (unsigned long)bad[i]);
        EXPECT_EQ(t, NULL);
    }
    /* caller-provided table with a user flag bit preserved */
    HT mine; memset(&mine, 0, sizeof mine); HT *pm = &mine;
    EXPECT_EQ(UN(RtlCreateHashTableEx)(&pm, 0x100, 0, 0x10), TRUE);
    EXPECT_EQ(mine.Flags, 0x10); EXPECT_EQ(mine.TableSize, 0x100);
    UN(RtlDeleteHashTable)(&mine);
}
TEST(rtl_hash_table_insert_lookup) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlDeleteHashTable)); REQUIRE(UN(RtlInsertEntryHashTable));
    REQUIRE(UN(RtlLookupEntryHashTable)); REQUIRE(UN(RtlRemoveEntryHashTable));
    HT *t = NULL;
    if (!UN(RtlCreateHashTable)(&t, 0, 0) || !t) { t_skip("hash table creation failed"); return; }
    HT_ENTRY e[4]; HT_CTX cx;
    ULONG_PTR sig[4] = {5, 6, 5 + 0x80, 1000};
    for (int i = 0; i < 4; i++) { memset(&e[i], 0, sizeof e[i]); memset(&cx, 0, sizeof cx); EXPECT_EQ(UN(RtlInsertEntryHashTable)(t, &e[i], sig[i], &cx), TRUE); }
    EXPECT_EQ(t->NumEntries, 4);
    for (int i = 0; i < 4; i++) {
        memset(&cx, 0, sizeof cx);
        HT_ENTRY *f = UN(RtlLookupEntryHashTable)(t, sig[i], &cx);
        EXPECT_EQ(f, &e[i]);
        if (f) EXPECT_EQ(f->Signature, sig[i]);
    }
    memset(&cx, 0, sizeof cx);
    EXPECT_EQ(UN(RtlLookupEntryHashTable)(t, 7, &cx), NULL);
    EXPECT_EQ(UN(RtlRemoveEntryHashTable)(t, &e[1], &cx), TRUE);
    EXPECT_EQ(t->NumEntries, 3);
    memset(&cx, 0, sizeof cx);
    EXPECT_EQ(UN(RtlLookupEntryHashTable)(t, sig[1], &cx), NULL);
    EXPECT_EQ(UN(RtlLookupEntryHashTable)(t, sig[0], &cx), &e[0]);
    for (int i = 0; i < 4; i++) if (i != 1) { memset(&cx, 0, sizeof cx); UN(RtlRemoveEntryHashTable)(t, &e[i], &cx); }
    EXPECT_EQ(t->NumEntries, 0);
    UN(RtlDeleteHashTable)(t);
}

/* ---------------- memory zone / lookaside ---------------- */
UDECL(NTSTATUS, RtlCreateMemoryZone, (PVOID *, SIZE_T, ULONG));
UDECL(NTSTATUS, RtlAllocateMemoryZone, (PVOID, SIZE_T, PVOID *));
UDECL(NTSTATUS, RtlResetMemoryZone, (PVOID));
UDECL(NTSTATUS, RtlDestroyMemoryZone, (PVOID));
UDECL(NTSTATUS, RtlCreateMemoryBlockLookaside, (PVOID *, ULONG, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, RtlAllocateMemoryBlockLookaside, (PVOID, ULONG, PVOID *));
UDECL(NTSTATUS, RtlFreeMemoryBlockLookaside, (PVOID, PVOID));
UDECL(NTSTATUS, RtlDestroyMemoryBlockLookaside, (PVOID));

TEST(rtl_create_memory_zone) {
    REQUIRE(UN(RtlCreateMemoryZone)); REQUIRE(UN(RtlAllocateMemoryZone)); REQUIRE(UN(RtlDestroyMemoryZone));
    PVOID z = (PVOID)1;
    NTSTATUS s = UN(RtlCreateMemoryZone)(&z, 0x10000, 0);
    EXPECT_EQ(s, 0); EXPECT_NE(z, NULL); EXPECT_NE(z, (PVOID)1);
    if (s < 0 || !z || z == (PVOID)1) return;
    PVOID a = NULL, b = NULL, c = NULL;
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(z, 100, &a), 0);
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(z, 200, &b), 0);
    EXPECT_NE(a, NULL); EXPECT_NE(b, NULL);
    if (a && b) {
        EXPECT_EQ(((ULONG_PTR)a & 7), 0); EXPECT_EQ(((ULONG_PTR)b & 7), 0);       /* 8-byte granularity */
        EXPECT_EQ((ULONG_PTR)b >= (ULONG_PTR)a + 100, 1);                            /* sequential, no overlap */
        memset(a, 0x11, 100); memset(b, 0x22, 200);                                   /* writable */
        EXPECT_EQ(((BYTE *)a)[99], 0x11);
    }
    /* more than the zone can hold */
    s = UN(RtlAllocateMemoryZone)(z, 0x100000, &c);
    EXPECT_EQ(s, S(0xC000009A));                                                       /* STATUS_INSUFFICIENT_RESOURCES */
    /* reset hands out the zone from the start again */
    if (UN(RtlResetMemoryZone)) {
        EXPECT_EQ(UN(RtlResetMemoryZone)(z), 0);
        PVOID d = NULL;
        EXPECT_EQ(UN(RtlAllocateMemoryZone)(z, 100, &d), 0);
        EXPECT_EQ(d, a);
    }
    EXPECT_EQ(UN(RtlDestroyMemoryZone)(z), 0);
    /* invalid arguments */
    PVOID z2 = (PVOID)1;
    EXPECT_EQ(UN(RtlCreateMemoryZone)(&z2, 0, 0), ST_INVPARAM);
    EXPECT_EQ(UN(RtlCreateMemoryZone)(&z2, 0x1000, 1), ST_INVPARAM);
    EXPECT_EQ(z2, NULL);                                                              /* output cleared on failure */
}
TEST(rtl_create_memory_block_lookaside) {
    REQUIRE(UN(RtlCreateMemoryBlockLookaside)); REQUIRE(UN(RtlAllocateMemoryBlockLookaside));
    REQUIRE(UN(RtlFreeMemoryBlockLookaside)); REQUIRE(UN(RtlDestroyMemoryBlockLookaside));
    PVOID la = NULL;
    NTSTATUS s = UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0x10000, 0x10, 0x100);
    EXPECT_EQ(s, 0); EXPECT_NE(la, NULL);
    if (s < 0 || !la) return;
    PVOID a = NULL, b = NULL, c = NULL;
    EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 0x20, &a), 0);
    EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 0x100, &b), 0);
    EXPECT_NE(a, NULL); EXPECT_NE(b, NULL);
    if (a && b) {
        EXPECT_NE(a, b);
        memset(a, 0x5A, 0x20); memset(b, 0xA5, 0x100);
        EXPECT_EQ(((BYTE *)a)[0x1F], 0x5A); EXPECT_EQ(((BYTE *)b)[0xFF], 0xA5);
        EXPECT_EQ(UN(RtlFreeMemoryBlockLookaside)(la, a), 0);
        EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 0x20, &c), 0);
        EXPECT_EQ(c, a);                                                              /* freed block is recycled */
        UN(RtlFreeMemoryBlockLookaside)(la, c); UN(RtlFreeMemoryBlockLookaside)(la, b);
    }
    EXPECT_EQ(UN(RtlDestroyMemoryBlockLookaside)(la), 0);
    /* invalid parameter combinations leave the output cleared */
    la = (PVOID)1;
    EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 1, 0x1000, 0x10, 0x100), ST_INVPARAM); EXPECT_EQ(la, NULL);
    la = (PVOID)1; EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0, 0x10, 0x100), ST_INVPARAM);
    la = (PVOID)1; EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0x1000, 0, 0x100), ST_INVPARAM);
    la = (PVOID)1; EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0x1000, 0x10, 0), ST_INVPARAM);
    la = (PVOID)1; EXPECT_EQ(UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0x1000, 0x200, 0x100), ST_INVPARAM);   /* min > max */
}

/* ---------------- environment blocks ---------------- */
UDECL(NTSTATUS, RtlCreateEnvironmentEx, (PVOID, PVOID *, ULONG));
UDECL(NTSTATUS, RtlDestroyEnvironment, (PVOID));
static size_t env_chars(const WCHAR *e) { size_t n = 0; while (e[n] || e[n + 1]) n++; return n + 2; }   /* including the double terminator */
static const WCHAR *env_find(const WCHAR *e, const WCHAR *name) {
    size_t nl = wcslen(name);
    for (; *e; e += wcslen(e) + 1) if (!_wcsnicmp(e, name, nl) && e[nl] == L'=') return e + nl + 1;
    return NULL;
}
TEST(rtl_create_environment_ex) {
    REQUIRE(UN(RtlCreateEnvironmentEx)); REQUIRE(UN(RtlDestroyEnvironment));
    /* NULL source, flags 0: a copy of the process environment */
    PVOID env = NULL;
    NTSTATUS s = UN(RtlCreateEnvironmentEx)(NULL, &env, 0);
    EXPECT_EQ(s, 0); EXPECT_NE(env, NULL);
    if (s == 0 && env) {
        const WCHAR *cur = *(const WCHAR **)((BYTE *)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters + 0x80);
        EXPECT_EQ(env_chars(env), env_chars(cur));
        EXPECT_EQ(memcmp(env, cur, env_chars(cur) * 2), 0);
        EXPECT_NE(env, (PVOID)cur);                                                   /* a separate copy */
        UN(RtlDestroyEnvironment)(env);
    }
    /* explicit unicode source */
    static const WCHAR src[] = L"AAA=1\0BBB=two\0\0";
    PVOID e2 = NULL;
    s = UN(RtlCreateEnvironmentEx)((PVOID)src, &e2, 0);
    EXPECT_EQ(s, 0);
    if (s == 0 && e2) {
        EXPECT_EQ(env_chars(e2), env_chars(src));
        EXPECT_EQ(memcmp(e2, src, env_chars(src) * 2), 0);
        UN(RtlDestroyEnvironment)(e2);
    }
    /* flag 1: the source is an ANSI block that is converted to unicode */
    static const char ansi[] = "CCC=3\0DDD=four\0";      /* the string literal terminator ends the block */
    e2 = NULL;
    s = UN(RtlCreateEnvironmentEx)((PVOID)ansi, &e2, 1);
    EXPECT_EQ(s, 0);
    if (s == 0 && e2) {
        const WCHAR *v = env_find(e2, L"DDD");
        CHECK(v && !wcscmp(v, L"four"));
        v = env_find(e2, L"CCC");
        CHECK(v && !wcscmp(v, L"3"));
        UN(RtlDestroyEnvironment)(e2);
    }
    /* flag 4 builds an empty environment and cannot be combined with a source block */
    e2 = NULL;
    EXPECT_EQ(UN(RtlCreateEnvironmentEx)((PVOID)src, &e2, 4), ST_MIX);
    s = UN(RtlCreateEnvironmentEx)(NULL, &e2, 4);
    EXPECT_EQ(s, 0);
    if (s == 0 && e2) { t_note("empty environment: %lu characters", (unsigned long)env_chars(e2)); CHECK(env_find(e2, L"AAA") == NULL); UN(RtlDestroyEnvironment)(e2); }
    /* invalid flag combinations */
    e2 = NULL;
    EXPECT_EQ(UN(RtlCreateEnvironmentEx)(NULL, &e2, 8), ST_INVPARAM3);
    EXPECT_EQ(UN(RtlCreateEnvironmentEx)(NULL, &e2, 2), ST_INVPARAM3);               /* OEM translation needs flag 1 */
    EXPECT_EQ(UN(RtlCreateEnvironmentEx)((PVOID)src, &e2, 5), ST_INVPARAM3);         /* translate and empty are exclusive */
    EXPECT_EQ(UN(RtlCreateEnvironmentEx)((PVOID)src, &e2, 0x80000000), ST_INVPARAM3);
    EXPECT_EQ(UN(RtlCreateEnvironmentEx)(NULL, &e2, 1), ST_MIX);                     /* nothing to translate */
}

/* ---------------- process parameters ---------------- */
typedef struct { ULONG MaximumLength, Length, Flags, DebugFlags; PVOID ConsoleHandle; ULONG ConsoleFlags; PVOID pad1[3];
                 UNICODE_STRING CurrentDirectoryPath; PVOID CurrentDirectoryHandle; UNICODE_STRING DllPath, ImagePathName, CommandLine;
                 PVOID Environment; ULONG StartingX, StartingY, CountX, CountY, CountCharsX, CountCharsY, FillAttribute, WindowFlags, ShowWindowFlags;
                 UNICODE_STRING WindowTitle, DesktopInfo, ShellInfo, RuntimeData; BYTE cur[0x20 * 24]; ULONG_PTR EnvironmentSize; } PP;
UDECL(NTSTATUS, RtlCreateProcessParameters, (PP **, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING));
UDECL(NTSTATUS, RtlCreateProcessParametersEx, (PP **, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG));
UDECL(NTSTATUS, RtlCreateProcessParametersWithTemplate, (PP **, PP *, ULONG));
UDECL(PP *, RtlNormalizeProcessParams, (PP *));
UDECL(PP *, RtlDeNormalizeProcessParams, (PP *));
UDECL(NTSTATUS, RtlDestroyProcessParameters, (PP *));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));
#define PP_NORMALIZED 1
static int us_is(const UNICODE_STRING *u, const WCHAR *w) { size_t n = wcslen(w); return u->Length == n * 2 && u->Buffer && !memcmp(u->Buffer, w, n * 2); }
static int pp_normalized_ok(PP *p) {
    /* every string buffer must point inside the block */
    BYTE *lo = (BYTE *)p, *hi = (BYTE *)p + p->Length;
    const UNICODE_STRING *u[] = {&p->CurrentDirectoryPath, &p->DllPath, &p->ImagePathName, &p->CommandLine, &p->WindowTitle, &p->DesktopInfo, &p->ShellInfo};
    for (int i = 0; i < 7; i++) if (u[i]->Length && ((BYTE *)u[i]->Buffer < lo || (BYTE *)u[i]->Buffer >= hi)) return 0;
    return 1;
}
TEST(rtl_create_process_parameters) {
    REQUIRE(UN(RtlCreateProcessParameters)); REQUIRE(UN(RtlCreateProcessParametersEx)); REQUIRE(UN(RtlNormalizeProcessParams));
    REQUIRE(UN(RtlDestroyProcessParameters)); REQUIRE(UN(RtlInitUnicodeString));
    UNICODE_STRING img, cmd, cwd, dll, title, desk, shell, rt;
    UN(RtlInitUnicodeString)(&img, L"C:\\Test\\prog.exe"); UN(RtlInitUnicodeString)(&cmd, L"prog.exe /x /y");
    UN(RtlInitUnicodeString)(&cwd, L"C:\\Test\\Work"); UN(RtlInitUnicodeString)(&dll, L"C:\\Test;C:\\Dll");
    UN(RtlInitUnicodeString)(&title, L"Title"); UN(RtlInitUnicodeString)(&desk, L"Winsta0\\Default");
    UN(RtlInitUnicodeString)(&shell, L"shellinfo"); UN(RtlInitUnicodeString)(&rt, L"runtime");
    static const WCHAR env[] = L"EEE=5\0FFF=six\0\0";
    PP *pp = NULL;
    NTSTATUS s = UN(RtlCreateProcessParameters)(&pp, &img, &dll, &cwd, &cmd, (PVOID)env, &title, &desk, &shell, &rt);
    EXPECT_EQ(s, 0); EXPECT_NE(pp, NULL);
    if (s < 0 || !pp) return;
    /* a freshly created block is de-normalized: string buffers hold offsets from the block start */
    EXPECT_EQ(pp->Flags & PP_NORMALIZED, 0);
    EXPECT_EQ(pp->Length, pp->MaximumLength);
    UN(RtlNormalizeProcessParams)(pp);
    EXPECT_EQ(pp->Flags & PP_NORMALIZED, PP_NORMALIZED);
    EXPECT_EQ(pp_normalized_ok(pp), 1);
    CHECK(us_is(&pp->ImagePathName, L"C:\\Test\\prog.exe"));
    CHECK(us_is(&pp->CommandLine, L"prog.exe /x /y"));
    CHECK(us_is(&pp->DllPath, L"C:\\Test;C:\\Dll"));
    CHECK(us_is(&pp->WindowTitle, L"Title"));
    CHECK(us_is(&pp->DesktopInfo, L"Winsta0\\Default"));
    CHECK(us_is(&pp->ShellInfo, L"shellinfo"));
    CHECK(us_is(&pp->RuntimeData, L"runtime"));
    CHECK(us_is(&pp->CurrentDirectoryPath, L"C:\\Test\\Work\\"));                    /* a trailing backslash is added */
    EXPECT_EQ(pp->ImagePathName.MaximumLength >= pp->ImagePathName.Length, 1);
    EXPECT_NE(pp->Environment, NULL);
    if (pp->Environment) {
        CHECK(env_find(pp->Environment, L"EEE") && !wcscmp(env_find(pp->Environment, L"EEE"), L"5"));
        CHECK(env_find(pp->Environment, L"FFF") && !wcscmp(env_find(pp->Environment, L"FFF"), L"six"));
        EXPECT_EQ(pp->EnvironmentSize >= env_chars(env) * 2, 1);
        EXPECT_EQ(memcmp(pp->Environment, env, env_chars(env) * 2), 0);
    }
    if (UN(RtlDeNormalizeProcessParams)) {
        UN(RtlDeNormalizeProcessParams)(pp);
        EXPECT_EQ(pp->Flags & PP_NORMALIZED, 0);
        UN(RtlNormalizeProcessParams)(pp);
        CHECK(us_is(&pp->ImagePathName, L"C:\\Test\\prog.exe"));
    }
    UN(RtlDestroyProcessParameters)(pp);

    /* defaults: NULL command line = image path; NULL directory = current directory; NULL environment = current environment */
    pp = NULL;
    s = UN(RtlCreateProcessParametersEx)(&pp, &img, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, PP_NORMALIZED);
    EXPECT_EQ(s, 0);
    if (s == 0 && pp) {
        EXPECT_EQ(pp->Flags & PP_NORMALIZED, PP_NORMALIZED);                         /* flag 1 keeps the block normalized */
        EXPECT_EQ(pp_normalized_ok(pp), 1);
        CHECK(us_is(&pp->ImagePathName, L"C:\\Test\\prog.exe"));
        CHECK(us_is(&pp->CommandLine, L"C:\\Test\\prog.exe"));
        EXPECT_EQ(pp->DllPath.Length, 0); EXPECT_EQ(pp->WindowTitle.Length, 0); EXPECT_EQ(pp->DesktopInfo.Length, 0); EXPECT_EQ(pp->ShellInfo.Length, 0);
        WCHAR now[MAX_PATH]; DWORD n = GetCurrentDirectoryW(MAX_PATH, now);
        if (n && n < MAX_PATH - 1) { if (now[n - 1] != L'\\') { now[n++] = L'\\'; now[n] = 0; } CHECK(us_is(&pp->CurrentDirectoryPath, now)); }
        PP *cur = (PP *)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters;
        EXPECT_NE(pp->Environment, NULL);
        if (pp->Environment && cur->Environment) EXPECT_EQ(memcmp(pp->Environment, cur->Environment, env_chars(cur->Environment) * 2), 0);
        UN(RtlDestroyProcessParameters)(pp);
    }
    /* directory with a trailing backslash is kept as is */
    UNICODE_STRING cwd2; UN(RtlInitUnicodeString)(&cwd2, L"C:\\Test\\Work\\");
    pp = NULL;
    s = UN(RtlCreateProcessParametersEx)(&pp, &img, NULL, &cwd2, NULL, NULL, NULL, NULL, NULL, NULL, PP_NORMALIZED);
    EXPECT_EQ(s, 0);
    if (s == 0 && pp) { CHECK(us_is(&pp->CurrentDirectoryPath, L"C:\\Test\\Work\\")); UN(RtlDestroyProcessParameters)(pp); }
    /* errors */
    pp = NULL;
    EXPECT_EQ(UN(RtlCreateProcessParametersEx)(&pp, &img, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 2), ST_INVPARAM);   /* unknown flag */
    EXPECT_EQ(UN(RtlCreateProcessParametersEx)(&pp, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0), ST_INVPARAM);    /* image path required */
    UNICODE_STRING empty = {0, 2, (PWSTR)L""};
    EXPECT_EQ(UN(RtlCreateProcessParametersEx)(&pp, &img, NULL, &empty, NULL, NULL, NULL, NULL, NULL, NULL, 0), ST_INVPARAM);  /* empty directory */
    UNICODE_STRING badlen = {8, 6, (PWSTR)L"abc"};
    EXPECT_EQ(UN(RtlCreateProcessParametersEx)(&pp, &badlen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0), ST_INVPARAM);  /* Length > MaximumLength */
    UNICODE_STRING longdir; WCHAR lb[300]; for (int i = 0; i < 299; i++) lb[i] = L'a'; lb[299] = 0;
    UN(RtlInitUnicodeString)(&longdir, lb);
    EXPECT_EQ(UN(RtlCreateProcessParametersEx)(&pp, &img, NULL, &longdir, NULL, NULL, NULL, NULL, NULL, NULL, 0), ST_INVPARAM); /* too long to append a backslash */
    EXPECT_EQ(pp, NULL);
}
TEST(rtl_create_process_parameters_with_template) {
    REQUIRE(UN(RtlCreateProcessParametersEx)); REQUIRE(UN(RtlCreateProcessParametersWithTemplate)); REQUIRE(UN(RtlDestroyProcessParameters)); REQUIRE(UN(RtlInitUnicodeString));
    UNICODE_STRING img, cmd, cwd, dll, title, desk, shell, rt;
    UN(RtlInitUnicodeString)(&img, L"C:\\T\\a.exe"); UN(RtlInitUnicodeString)(&cmd, L"a.exe one two");
    UN(RtlInitUnicodeString)(&cwd, L"C:\\T"); UN(RtlInitUnicodeString)(&dll, L"C:\\Dlls");
    UN(RtlInitUnicodeString)(&title, L"tt"); UN(RtlInitUnicodeString)(&desk, L"dd");
    UN(RtlInitUnicodeString)(&shell, L"ss"); UN(RtlInitUnicodeString)(&rt, L"rr");
    static const WCHAR env[] = L"X=1\0\0";
    PP *tpl = NULL, *pp = NULL;
    NTSTATUS s = UN(RtlCreateProcessParametersEx)(&tpl, &img, &dll, &cwd, &cmd, (PVOID)env, &title, &desk, &shell, &rt, PP_NORMALIZED);
    EXPECT_EQ(s, 0);
    if (s < 0 || !tpl) return;
    s = UN(RtlCreateProcessParametersWithTemplate)(&pp, tpl, PP_NORMALIZED);
    EXPECT_EQ(s, 0); EXPECT_NE(pp, NULL); EXPECT_NE(pp, tpl);
    if (s == 0 && pp) {
        EXPECT_EQ(pp->Flags & PP_NORMALIZED, PP_NORMALIZED);
        CHECK(us_is(&pp->ImagePathName, L"C:\\T\\a.exe")); CHECK(us_is(&pp->CommandLine, L"a.exe one two"));
        CHECK(us_is(&pp->DllPath, L"C:\\Dlls")); CHECK(us_is(&pp->CurrentDirectoryPath, L"C:\\T\\"));
        CHECK(us_is(&pp->WindowTitle, L"tt")); CHECK(us_is(&pp->DesktopInfo, L"dd"));
        CHECK(us_is(&pp->ShellInfo, L"ss")); CHECK(us_is(&pp->RuntimeData, L"rr"));
        EXPECT_NE(pp->ImagePathName.Buffer, tpl->ImagePathName.Buffer);              /* deep copy */
        EXPECT_NE(pp->Environment, NULL);
        if (pp->Environment) CHECK(env_find(pp->Environment, L"X") && !wcscmp(env_find(pp->Environment, L"X"), L"1"));
        UN(RtlDestroyProcessParameters)(pp);
    }
    pp = NULL;
    EXPECT_EQ(UN(RtlCreateProcessParametersWithTemplate)(&pp, tpl, 2), ST_INVPARAM);
    UN(RtlDestroyProcessParameters)(tpl);
}

/* ---------------- unicode string creation ---------------- */
UDECL(BOOLEAN, RtlCreateUnicodeString, (PUNICODE_STRING, PCWSTR));
UDECL(BOOLEAN, RtlCreateUnicodeStringFromAsciiz, (PUNICODE_STRING, PCSTR));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
TEST(rtl_create_unicode_string) {
    REQUIRE(UN(RtlCreateUnicodeString)); REQUIRE(UN(RtlFreeUnicodeString));
    UNICODE_STRING u; memset(&u, 0xCC, sizeof u);
    EXPECT_EQ(UN(RtlCreateUnicodeString)(&u, L"abc"), TRUE);
    EXPECT_EQ(u.Length, 6); EXPECT_EQ(u.MaximumLength, 8);
    EXPECT_NE(u.Buffer, NULL);
    if (u.Buffer) { EXPECT_EQ(memcmp(u.Buffer, L"abc\0", 8), 0); UN(RtlFreeUnicodeString)(&u); EXPECT_EQ(u.Buffer, NULL); }
    memset(&u, 0xCC, sizeof u);
    EXPECT_EQ(UN(RtlCreateUnicodeString)(&u, L""), TRUE);
    EXPECT_EQ(u.Length, 0); EXPECT_EQ(u.MaximumLength, 2);
    if (u.Buffer) { EXPECT_EQ(u.Buffer[0], 0); UN(RtlFreeUnicodeString)(&u); }
    /* length limit: Length (bytes) must fit in 16 bits with room for the terminator */
    size_t big = 0x7FFE;
    WCHAR *w = malloc((big + 2) * 2);
    if (w) {
        for (size_t i = 0; i < big; i++) w[i] = L'z';
        w[big] = 0;
        memset(&u, 0xCC, sizeof u);
        EXPECT_EQ(UN(RtlCreateUnicodeString)(&u, w), TRUE);
        EXPECT_EQ(u.Length, 0xFFFC); EXPECT_EQ(u.MaximumLength, 0xFFFE);
        if (u.Buffer) UN(RtlFreeUnicodeString)(&u);
        w[big] = L'z'; w[big + 1] = 0;                                               /* 0x7FFF characters */
        memset(&u, 0, sizeof u);
        EXPECT_EQ(UN(RtlCreateUnicodeString)(&u, w), FALSE);
        free(w);
    }
}
TEST(rtl_create_unicode_string_from_asciiz) {
    REQUIRE(UN(RtlCreateUnicodeStringFromAsciiz)); REQUIRE(UN(RtlFreeUnicodeString));
    UNICODE_STRING u; memset(&u, 0xCC, sizeof u);
    EXPECT_EQ(UN(RtlCreateUnicodeStringFromAsciiz)(&u, "Hello"), TRUE);
    EXPECT_EQ(u.Length, 10); EXPECT_EQ(u.MaximumLength, 12);
    if (u.Buffer) { EXPECT_EQ(memcmp(u.Buffer, L"Hello\0", 12), 0); UN(RtlFreeUnicodeString)(&u); }
    memset(&u, 0xCC, sizeof u);
    EXPECT_EQ(UN(RtlCreateUnicodeStringFromAsciiz)(&u, ""), TRUE);
    EXPECT_EQ(u.Length, 0);
    if (u.Buffer) UN(RtlFreeUnicodeString)(&u);
    /* 0xFFFF bytes is too long for an ANSI_STRING */
    size_t n = 70000; char *a = malloc(n + 1);
    if (a) { memset(a, 'q', n); a[n] = 0; memset(&u, 0, sizeof u); EXPECT_EQ(UN(RtlCreateUnicodeStringFromAsciiz)(&u, a), FALSE); free(a); }
}

/* ---------------- function tables ---------------- */
typedef struct { ULONG Begin, End, Unwind; } RF;
UDECL(BOOLEAN, RtlAddFunctionTable, (RF *, ULONG, ULONG64));
UDECL(BOOLEAN, RtlDeleteFunctionTable, (RF *));
UDECL(NTSTATUS, RtlAddGrowableFunctionTable, (PVOID *, RF *, ULONG, ULONG, ULONG_PTR, ULONG_PTR));
UDECL(VOID, RtlGrowFunctionTable, (PVOID, ULONG));
UDECL(VOID, RtlDeleteGrowableFunctionTable, (PVOID));
UDECL(RF *, RtlLookupFunctionEntry, (ULONG64, PULONG64, PVOID));
static BYTE *region(void) {
    BYTE *b = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (b) { b[0x300] = 1; b[0x400] = 1; }          /* minimal UNWIND_INFO: version 1, no codes */
    return b;
}
TEST(rtl_add_function_table) {
    REQUIRE(UN(RtlAddFunctionTable)); REQUIRE(UN(RtlDeleteFunctionTable)); REQUIRE(UN(RtlLookupFunctionEntry));
    BYTE *base = region();
    if (!base) { t_skip("no memory"); return; }
    static RF tab[2] __attribute__((aligned(4)));
    tab[0] = (RF){0x100, 0x200, 0x300}; tab[1] = (RF){0x1000, 0x1100, 0x400};
    EXPECT_EQ(UN(RtlAddFunctionTable)(tab, 2, (ULONG64)base), TRUE);
    ULONG64 ib = 0;
    RF *f = UN(RtlLookupFunctionEntry)((ULONG64)base + 0x150, &ib, NULL);
    EXPECT_EQ(f, &tab[0]); EXPECT_EQ(ib, (ULONG64)base);
    ib = 0; f = UN(RtlLookupFunctionEntry)((ULONG64)base + 0x1000, &ib, NULL);
    EXPECT_EQ(f, &tab[1]); EXPECT_EQ(ib, (ULONG64)base);
    f = UN(RtlLookupFunctionEntry)((ULONG64)base + 0x1100, &ib, NULL);               /* End is exclusive */
    EXPECT_EQ(f, NULL);
    f = UN(RtlLookupFunctionEntry)((ULONG64)base + 0x500, &ib, NULL);                 /* gap between functions */
    EXPECT_EQ(f, NULL);
    EXPECT_EQ(UN(RtlDeleteFunctionTable)(tab), TRUE);
    f = UN(RtlLookupFunctionEntry)((ULONG64)base + 0x150, &ib, NULL);
    EXPECT_EQ(f, NULL);
    EXPECT_EQ(UN(RtlDeleteFunctionTable)(tab), FALSE);                               /* no longer registered */
    VirtualFree(base, 0, MEM_RELEASE);
}
TEST(rtl_add_growable_function_table) {
    REQUIRE(UN(RtlAddGrowableFunctionTable)); REQUIRE(UN(RtlDeleteGrowableFunctionTable)); REQUIRE(UN(RtlLookupFunctionEntry));
    BYTE *base = region();
    if (!base) { t_skip("no memory"); return; }
    static RF tab[4] __attribute__((aligned(4)));
    memset(tab, 0, sizeof tab);
    tab[0] = (RF){0x100, 0x200, 0x300};
    PVOID h = NULL;
    NTSTATUS s = UN(RtlAddGrowableFunctionTable)(&h, tab, 1, 4, (ULONG_PTR)base, (ULONG_PTR)base + 0x10000);
    EXPECT_EQ(s, 0); EXPECT_NE(h, NULL);
    if (s < 0 || !h) { VirtualFree(base, 0, MEM_RELEASE); return; }
    ULONG64 ib = 0;
    RF *f = UN(RtlLookupFunctionEntry)((ULONG64)base + 0x150, &ib, NULL);
    EXPECT_EQ(f, &tab[0]); EXPECT_EQ(ib, (ULONG64)base);
    EXPECT_EQ(UN(RtlLookupFunctionEntry)((ULONG64)base + 0x1010, &ib, NULL), NULL);  /* not in the table yet */
    if (UN(RtlGrowFunctionTable)) {
        tab[1] = (RF){0x1000, 0x1100, 0x400};
        UN(RtlGrowFunctionTable)(h, 2);
        f = UN(RtlLookupFunctionEntry)((ULONG64)base + 0x1010, &ib, NULL);
        EXPECT_EQ(f, &tab[1]);
    }
    UN(RtlDeleteGrowableFunctionTable)(h);
    EXPECT_EQ(UN(RtlLookupFunctionEntry)((ULONG64)base + 0x150, &ib, NULL), NULL);
    VirtualFree(base, 0, MEM_RELEASE);
}

/* ---------------- section table lookup ---------------- */
UDECL(PVOID, RtlAddressInSectionTable, (PIMAGE_NT_HEADERS, PVOID, ULONG));
TEST(rtl_address_in_section_table) {
    REQUIRE(UN(RtlAddressInSectionTable));
    BYTE *base = (BYTE *)GetModuleHandleW(NULL);
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    int n = nt->FileHeader.NumberOfSections;
    EXPECT_EQ(n > 0, 1);
    for (int i = 0; i < n; i++) {
        ULONG va = sec[i].VirtualAddress, raw = sec[i].PointerToRawData;
        ULONG span = sec[i].SizeOfRawData;                 /* sections without file data (.bss) are not found */
        if (!span) { EXPECT_EQ(UN(RtlAddressInSectionTable)(nt, base, va), NULL); continue; }
        PVOID p = UN(RtlAddressInSectionTable)(nt, base, va);
        EXPECT_EQ(p, base + raw);                                                    /* file-offset style: Base + raw + (Rva - VA) */
        p = UN(RtlAddressInSectionTable)(nt, base, va + span - 1);
        EXPECT_EQ(p, base + raw + span - 1);
        p = UN(RtlAddressInSectionTable)(nt, base, va + 0x10);
        if (span > 0x10) EXPECT_EQ(p, base + raw + 0x10);
    }
    EXPECT_EQ(UN(RtlAddressInSectionTable)(nt, base, 0), NULL);                      /* headers are not in a section */
    EXPECT_EQ(UN(RtlAddressInSectionTable)(nt, base, nt->OptionalHeader.SizeOfImage + 0x100000), NULL);
    EXPECT_EQ(UN(RtlAddressInSectionTable)(nt, base, sec[0].VirtualAddress - 1), NULL);
}

/* ---------------- registry helpers ---------------- */
UDECL(NTSTATUS, RtlCheckRegistryKey, (ULONG, PWSTR));
UDECL(NTSTATUS, RtlCreateRegistryKey, (ULONG, PWSTR));
UDECL(NTSTATUS, RtlCheckPortableOperatingSystem, (PBOOLEAN));
TEST(rtl_check_registry_key) {
    REQUIRE(UN(RtlCheckRegistryKey));
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\Software\\Microsoft"), 0);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\Software\\NtdlltNoSuchKey"), ST_NOTFOUND);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_CONTROL, L"Session Manager"), 0);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_CONTROL, L"NtdlltNoSuchKey"), ST_NOTFOUND);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_SERVICES, L"EventLog"), 0);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_WINDOWS_NT, L"Winlogon"), 0);               /* relative to ...\Windows NT\CurrentVersion */
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_USER, L"Software"), 0);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_USER, L"NtdlltNoSuchKey"), ST_NOTFOUND);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_MAXIMUM + 5, L"x"), ST_INVPARAM);
}
TEST(rtl_create_registry_key) {
    REQUIRE(UN(RtlCreateRegistryKey)); REQUIRE(UN(RtlCheckRegistryKey));
    LONG (WINAPI *del)(HKEY, LPCWSTR) = (void *)t_proc_in("advapi32.dll", "RegDeleteKeyW");
    if (!del) { t_skip("advapi32 RegDeleteKeyW unavailable for cleanup"); return; }
    HKEY hcu = HKEY_CURRENT_USER;
    del(hcu, L"NtdlltCreateRegKeyTest\\Sub\\Leaf"); del(hcu, L"NtdlltCreateRegKeyTest\\Sub"); del(hcu, L"NtdlltCreateRegKeyTest");
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_USER, L"NtdlltCreateRegKeyTest"), ST_NOTFOUND);
    EXPECT_EQ(UN(RtlCreateRegistryKey)(RTL_REGISTRY_USER, L"NtdlltCreateRegKeyTest"), 0);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_USER, L"NtdlltCreateRegKeyTest"), 0);
    EXPECT_EQ(UN(RtlCreateRegistryKey)(RTL_REGISTRY_USER, L"NtdlltCreateRegKeyTest"), 0);        /* creating an existing key succeeds */
    EXPECT_EQ(UN(RtlCreateRegistryKey)(RTL_REGISTRY_USER, L"NtdlltCreateRegKeyTest\\Sub\\Leaf"), ST_NOTFOUND);   /* intermediate keys are not created */
    EXPECT_EQ(UN(RtlCreateRegistryKey)(RTL_REGISTRY_USER, L"NtdlltCreateRegKeyTest\\Sub"), 0);
    EXPECT_EQ(UN(RtlCreateRegistryKey)(RTL_REGISTRY_USER, L"NtdlltCreateRegKeyTest\\Sub\\Leaf"), 0);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_USER, L"NtdlltCreateRegKeyTest\\Sub\\Leaf"), 0);
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_USER, L"NtdlltCreateRegKeyTest\\Sub"), 0);
    EXPECT_EQ(UN(RtlCreateRegistryKey)(RTL_REGISTRY_MAXIMUM + 5, L"x"), ST_INVPARAM);
    del(hcu, L"NtdlltCreateRegKeyTest\\Sub\\Leaf"); del(hcu, L"NtdlltCreateRegKeyTest\\Sub"); del(hcu, L"NtdlltCreateRegKeyTest");
    EXPECT_EQ(UN(RtlCheckRegistryKey)(RTL_REGISTRY_USER, L"NtdlltCreateRegKeyTest"), ST_NOTFOUND);
}
TEST(rtl_check_portable_operating_system) {
    REQUIRE(UN(RtlCheckPortableOperatingSystem));
    BOOLEAN p = 2;
    NTSTATUS s = UN(RtlCheckPortableOperatingSystem)(&p);
    if (s == 0) { if (p) t_skip("this system is a portable (Windows To Go) installation"); else EXPECT_EQ(p, FALSE); }
    else { EXPECT_EQ(s, S(0xC0000225)); EXPECT_EQ(p, 2); }                            /* STATUS_NOT_FOUND: no PortableOperatingSystem value; output untouched */
}

/* ---------------- activation contexts ---------------- */
typedef VOID (NTAPI *ACT_NOTIFY)(ULONG, PVOID, PVOID, PVOID, PVOID, PBOOLEAN);
UDECL(NTSTATUS, RtlCreateActivationContext, (ULONG, PVOID, ULONG, ACT_NOTIFY, PVOID, PVOID *));
UDECL(VOID, RtlAddRefActivationContext, (PVOID));
UDECL(VOID, RtlReleaseActivationContext, (PVOID));
static volatile LONG g_act_calls; static volatile ULONG g_act_reason; static PVOID g_act_ctx_seen;
static VOID NTAPI act_notify(ULONG reason, PVOID actctx, PVOID data, PVOID ctx, PVOID p, PBOOLEAN disable) {
    g_act_calls++; g_act_reason = reason; g_act_ctx_seen = ctx;
}
static HANDLE make_actctx(void) {
    HANDLE (WINAPI *create)(PACTCTXW) = (void *)t_proc_in("kernel32.dll", "CreateActCtxW");
    if (!create) return INVALID_HANDLE_VALUE;
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "ntdllt.manifest");
    FILE *f = fopen(path, "wb");
    if (!f) return INVALID_HANDLE_VALUE;
    fputs("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
          "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n"
          "<assemblyIdentity type=\"win32\" name=\"Ntdllt.Test.App\" version=\"1.0.0.0\"/>\r\n"
          "</assembly>\r\n", f);
    fclose(f);
    WCHAR wp[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, path, -1, wp, MAX_PATH);
    ACTCTXW ac; memset(&ac, 0, sizeof ac); ac.cbSize = sizeof ac; ac.lpSource = wp;
    HANDLE h = create(&ac);
    DeleteFileA(path);                                          /* the context holds its own copy of the parsed data */
    return h;
}
TEST(rtl_activation_context_addref_create) {
    REQUIRE(UN(RtlCreateActivationContext)); REQUIRE(UN(RtlAddRefActivationContext)); REQUIRE(UN(RtlReleaseActivationContext));
    void (WINAPI *rel)(HANDLE) = (void *)t_proc_in("kernel32.dll", "ReleaseActCtx");
    HANDLE h = make_actctx();
    if (h == INVALID_HANDLE_VALUE || !rel) { t_skip("cannot create an activation context from a manifest here"); return; }
    volatile ULONG *rc = (volatile ULONG *)h;                   /* the reference count is the first field of the handle target */
    EXPECT_EQ(*rc, 1);
    UN(RtlAddRefActivationContext)(h); EXPECT_EQ(*rc, 2);
    UN(RtlAddRefActivationContext)(h); EXPECT_EQ(*rc, 3);
    UN(RtlReleaseActivationContext)(h); EXPECT_EQ(*rc, 2);
    UN(RtlReleaseActivationContext)(h); EXPECT_EQ(*rc, 1);
    /* null and pseudo handles are ignored */
    UN(RtlAddRefActivationContext)(NULL); UN(RtlAddRefActivationContext)((PVOID)(LONG_PTR)-1);
    EXPECT_EQ(*rc, 1);

    /* create a second context from the first one's validated data block */
    PVOID data = *(PVOID *)((BYTE *)h + 0x18);
    EXPECT_NE(data, NULL);
    PVOID h2 = (PVOID)1;
    g_act_calls = 0;
    NTSTATUS s = UN(RtlCreateActivationContext)(0, data, 0, act_notify, (PVOID)0x5151, &h2);
    EXPECT_EQ(s, 0); EXPECT_NE(h2, NULL); EXPECT_NE(h2, (PVOID)1); EXPECT_NE(h2, (PVOID)h);
    if (s == 0 && h2) {
        EXPECT_EQ(*(ULONG *)h2, 1);
        EXPECT_EQ(*(PVOID *)((BYTE *)h2 + 0x18), data);
        EXPECT_EQ(*(PVOID *)((BYTE *)h2 + 0x20), (PVOID)act_notify);
        EXPECT_EQ(*(PVOID *)((BYTE *)h2 + 0x28), (PVOID)0x5151);
        EXPECT_EQ(g_act_calls, 0);
        UN(RtlReleaseActivationContext)(h2);                     /* last reference: the notification fires */
        EXPECT_EQ(g_act_calls, 1);
        EXPECT_EQ(g_act_ctx_seen, (PVOID)0x5151);
        t_note("final-release notification reason %lu", (unsigned long)g_act_reason);
    }
    /* argument errors */
    h2 = (PVOID)1;
    EXPECT_EQ(UN(RtlCreateActivationContext)(1, data, 0, NULL, NULL, &h2), ST_INVPARAM); EXPECT_EQ(h2, NULL);
    EXPECT_EQ(UN(RtlCreateActivationContext)(0, NULL, 0, NULL, NULL, &h2), ST_INVPARAM);
    EXPECT_EQ(UN(RtlCreateActivationContext)(0, data, 0x10001, NULL, NULL, &h2), ST_INVPARAM);
    EXPECT_EQ(UN(RtlCreateActivationContext)(0, data, 0, NULL, NULL, NULL), ST_INVPARAM);
    BYTE junk[0x100]; memset(junk, 0, sizeof junk);
    h2 = (PVOID)1;
    s = UN(RtlCreateActivationContext)(0, junk, 0, NULL, NULL, &h2);
    EXPECT_EQ(s < 0, 1); EXPECT_EQ(h2, NULL);
    t_note("zeroed data block: 0x%08lx", (unsigned long)s);
    rel(h);
}

/* ---------------- debug buffer ---------------- */
UDECL(PVOID, RtlCreateQueryDebugBuffer, (ULONG, BOOLEAN));
UDECL(NTSTATUS, RtlDestroyQueryDebugBuffer, (PVOID));
UDECL(NTSTATUS, RtlQueryProcessDebugInformation, (ULONG, ULONG, PVOID));
TEST(rtl_create_query_debug_buffer) {
    REQUIRE(UN(RtlCreateQueryDebugBuffer)); REQUIRE(UN(RtlDestroyQueryDebugBuffer));
    BYTE *b = UN(RtlCreateQueryDebugBuffer)(0x10000, FALSE);
    EXPECT_NE(b, NULL);
    if (!b) return;
    EXPECT_EQ(*(PVOID *)(b + 8), (PVOID)b);                       /* ViewBaseClient points at the buffer itself */
    EXPECT_EQ(*(PVOID *)(b + 0x20), NULL);                        /* no event pair requested */
    ULONG_PTR off0 = *(ULONG_PTR *)(b + 0x48);
    EXPECT_EQ(off0 >= 0x80 && off0 <= 0x200, 1);                  /* OffsetFree: just past the header */
    if (UN(RtlQueryProcessDebugInformation)) {
        NTSTATUS s = UN(RtlQueryProcessDebugInformation)(GetCurrentProcessId(), 1 /* RTL_QUERY_PROCESS_MODULES */, b);
        EXPECT_EQ(s, 0);
        if (s == 0) EXPECT_EQ(*(ULONG_PTR *)(b + 0x48) > off0, 1);   /* module list appended */
    }
    EXPECT_EQ(UN(RtlDestroyQueryDebugBuffer)(b), 0);
    /* default size */
    b = UN(RtlCreateQueryDebugBuffer)(0, FALSE);
    EXPECT_NE(b, NULL);
    if (b) UN(RtlDestroyQueryDebugBuffer)(b);
}

/* ---------------- UMS objects ---------------- */
UDECL(NTSTATUS, RtlCreateUmsCompletionList, (PVOID *));
UDECL(NTSTATUS, RtlDeleteUmsCompletionList, (PVOID));
UDECL(NTSTATUS, RtlCreateUmsThreadContext, (PVOID *));
UDECL(NTSTATUS, RtlDeleteUmsThreadContext, (PVOID));
TEST(rtl_create_ums_objects) {
    REQUIRE(UN(RtlCreateUmsCompletionList)); REQUIRE(UN(RtlDeleteUmsCompletionList));
    REQUIRE(UN(RtlCreateUmsThreadContext)); REQUIRE(UN(RtlDeleteUmsThreadContext));
    PVOID l = NULL;
    NTSTATUS s = UN(RtlCreateUmsCompletionList)(&l);
    EXPECT_EQ(s, 0); EXPECT_NE(l, NULL);
    if (s == 0 && l) EXPECT_EQ(UN(RtlDeleteUmsCompletionList)(l), 0);
    PVOID c = NULL;
    s = UN(RtlCreateUmsThreadContext)(&c);
    EXPECT_EQ(s, 0); EXPECT_NE(c, NULL);
    if (s == 0 && c) EXPECT_EQ(UN(RtlDeleteUmsThreadContext)(c), 0);
}

/* ---------------- shadow stack / stubs ---------------- */
UDECL(NTSTATUS, RtlCreateUserFiberShadowStack, (ULONG_PTR, ULONG_PTR, PVOID *));
TEST(rtl_create_user_fiber_shadow_stack_args) {
    REQUIRE(UN(RtlCreateUserFiberShadowStack));
    PVOID out = (PVOID)1;
    /* the high byte of the second argument is a size-class selector; values above 0x40 are rejected before any system call */
    EXPECT_EQ(UN(RtlCreateUserFiberShadowStack)(0x10000, (ULONG_PTR)0x41 << 56, &out), ST_INVPARAM);
    EXPECT_EQ(UN(RtlCreateUserFiberShadowStack)(0x10000, (ULONG_PTR)0xFF << 56, &out), ST_INVPARAM);
    EXPECT_EQ(out, (PVOID)1);
}
UDECL(ULONG, RtlAddRefMemoryStream, (PVOID));
TEST(rtl_add_ref_memory_stream_stub) {
    REQUIRE(UN(RtlAddRefMemoryStream));
    /* a stub shared with several unrelated exports: returns 0 for any argument without touching it */
    EXPECT_EQ(UN(RtlAddRefMemoryStream)(NULL), 0);
    EXPECT_EQ(UN(RtlAddRefMemoryStream)((PVOID)(ULONG_PTR)0x1234), 0);
    EXPECT_EQ((ULONG_PTR)t_proc("RtlAddRefMemoryStream"), (ULONG_PTR)t_proc("RtlReleaseMemoryStream"));
}

/* ---------------- boot status data ---------------- */
UDECL(NTSTATUS, RtlCreateBootStatusDataFile, (PCWSTR));
UDECL(NTSTATUS, RtlCheckBootStatusIntegrity, (HANDLE, PBOOLEAN));
UDECL(NTSTATUS, RtlCheckSystemBootStatusIntegrity, (PBOOLEAN));
TEST(rtl_boot_status_data_file) {
    REQUIRE(UN(RtlCreateBootStatusDataFile)); REQUIRE(UN(RtlCheckBootStatusIntegrity));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "bootstat.dat");
    WCHAR nt[MAX_PATH + 8]; wcscpy(nt, L"\\??\\");
    MultiByteToWideChar(CP_ACP, 0, path, -1, nt + 4, MAX_PATH);
    NTSTATUS s = UN(RtlCreateBootStatusDataFile)(nt);
    EXPECT_EQ(s, 0);
    if (s < 0) return;
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    EXPECT_NE(f, INVALID_HANDLE_VALUE);
    if (f == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz; GetFileSizeEx(f, &sz);
    t_note("created boot status file size 0x%llx", (unsigned long long)sz.QuadPart);
    EXPECT_EQ(sz.QuadPart, 0x10800);
    BOOLEAN ok = 2;
    s = UN(RtlCheckBootStatusIntegrity)(f, &ok);
    EXPECT_EQ(s, 0); EXPECT_EQ(ok, TRUE);
    /* corrupt one payload byte: the checksum no longer matches */
    BYTE b; DWORD n;
    SetFilePointer(f, 0x20, NULL, FILE_BEGIN); ReadFile(f, &b, 1, &n, NULL);
    b ^= 0x5A; SetFilePointer(f, 0x20, NULL, FILE_BEGIN); WriteFile(f, &b, 1, &n, NULL); FlushFileBuffers(f);
    ok = 2; s = UN(RtlCheckBootStatusIntegrity)(f, &ok);
    EXPECT_EQ(s, 0); EXPECT_EQ(ok, FALSE);
    CloseHandle(f);
    DeleteFileA(path);
    /* nonexistent directory */
    EXPECT_EQ(UN(RtlCreateBootStatusDataFile)(L"\\??\\Z:\\NtdlltNoSuchDir\\bootstat.dat") < 0, 1);
}
TEST(rtl_check_system_boot_status_integrity) {
    REQUIRE(UN(RtlCheckSystemBootStatusIntegrity));
    EXPECT_EQ(UN(RtlCheckSystemBootStatusIntegrity)(NULL), ST_INVPARAM);
    BOOLEAN ok = 2;
    NTSTATUS s = UN(RtlCheckSystemBootStatusIntegrity)(&ok);
    t_note("system boot status integrity: status 0x%08lx value %d", (unsigned long)s, ok);
}

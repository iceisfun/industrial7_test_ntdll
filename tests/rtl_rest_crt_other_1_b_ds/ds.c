/* Data-structure and memory helpers: dynamic hash table growth and enumeration end, atom tables, handle
 * tables, memory zones, process parameters, query debug buffers, SLists, ACL free space, PE header
 * helpers, resource descriptor decoding, non-temporal / non-volatile fills, FLS and pointer encoding. */
#include "t.h"

#define ST_INVPARAM ((NTSTATUS)0xC000000D)
#define ST_INVHANDLE ((NTSTATUS)0xC0000008)

/* ---------------- memory zone / block lookaside ---------------- */
UDECL(NTSTATUS, RtlCreateMemoryZone, (PVOID *, SIZE_T, ULONG));
UDECL(NTSTATUS, RtlAllocateMemoryZone, (PVOID, SIZE_T, PVOID *));
UDECL(NTSTATUS, RtlDestroyMemoryZone, (PVOID));
UDECL(NTSTATUS, RtlCreateMemoryBlockLookaside, (PVOID *, ULONG, SIZE_T, SIZE_T, SIZE_T));
UDECL(NTSTATUS, RtlAllocateMemoryBlockLookaside, (PVOID, SIZE_T, PVOID *));
UDECL(NTSTATUS, RtlDestroyMemoryBlockLookaside, (PVOID));
TEST(rtl_rest_b_memory_zone_destroy) {
    REQUIRE(UN(RtlCreateMemoryZone)); REQUIRE(UN(RtlAllocateMemoryZone)); REQUIRE(UN(RtlDestroyMemoryZone));
    PVOID z = NULL, a = NULL; MEMORY_BASIC_INFORMATION mi;
    if (UN(RtlCreateMemoryZone)(&z, 0x4000, 0) < 0 || !z) { t_skip("zone creation failed"); return; }
    EXPECT_EQ(UN(RtlAllocateMemoryZone)(z, 64, &a), 0);
    CHECK(a != NULL);
    if (a) { CHECK(VirtualQuery(a, &mi, sizeof mi) == sizeof mi); EXPECT_EQ(mi.State, MEM_COMMIT); }
    EXPECT_EQ(UN(RtlDestroyMemoryZone)(z), 0);
    if (a) { CHECK(VirtualQuery(a, &mi, sizeof mi) == sizeof mi); EXPECT_EQ(mi.State, MEM_FREE); }   /* segments released */
}
TEST(rtl_rest_b_memory_lookaside_destroy) {
    REQUIRE(UN(RtlCreateMemoryBlockLookaside)); REQUIRE(UN(RtlAllocateMemoryBlockLookaside)); REQUIRE(UN(RtlDestroyMemoryBlockLookaside));
    PVOID la = NULL, a = NULL; MEMORY_BASIC_INFORMATION mi;
    NTSTATUS cs = UN(RtlCreateMemoryBlockLookaside)(&la, 0, 0x10000, 0x10, 0x100);
    if (cs < 0 || !la) { t_skip("lookaside creation failed 0x%lx", (unsigned long)cs); return; }
    EXPECT_EQ(UN(RtlAllocateMemoryBlockLookaside)(la, 0x40, &a), 0);
    CHECK(a != NULL);
    if (a) { CHECK(VirtualQuery(a, &mi, sizeof mi) == sizeof mi); EXPECT_EQ(mi.State, MEM_COMMIT); }
    EXPECT_EQ(UN(RtlDestroyMemoryBlockLookaside)(la), 0);
    if (a) { CHECK(VirtualQuery(a, &mi, sizeof mi) == sizeof mi); EXPECT_EQ(mi.State, MEM_FREE); }
}

/* ---------------- dynamic hash table ---------------- */
typedef struct HENT { LIST_ENTRY Linkage; ULONG_PTR Signature; } HENT;
typedef struct HTAB {
    ULONG Flags, Shift, TableSize, Pivot, DivisorMask, NumEntries, NonEmptyBuckets, NumEnumerators;
    PVOID Directory;
} HTAB;
typedef struct HENUM { HENT HashEntry; PLIST_ENTRY ChainHead; ULONG BucketIndex; } HENUM;
UDECL(BOOLEAN, RtlCreateHashTable, (HTAB **, ULONG, ULONG));
UDECL(VOID, RtlDeleteHashTable, (HTAB *));
UDECL(BOOLEAN, RtlInsertEntryHashTable, (HTAB *, HENT *, ULONG_PTR, PVOID));
UDECL(HENT *, RtlLookupEntryHashTable, (HTAB *, ULONG_PTR, PVOID));
UDECL(BOOLEAN, RtlExpandHashTable, (HTAB *));
UDECL(BOOLEAN, RtlInitEnumerationHashTable, (HTAB *, HENUM *));
UDECL(BOOLEAN, RtlInitWeakEnumerationHashTable, (HTAB *, HENUM *));
UDECL(BOOLEAN, RtlInitStrongEnumerationHashTable, (HTAB *, HENUM *));
UDECL(HENT *, RtlEnumerateEntryHashTable, (HTAB *, HENUM *));
UDECL(VOID, RtlEndEnumerationHashTable, (HTAB *, HENUM *));
UDECL(VOID, RtlEndWeakEnumerationHashTable, (HTAB *, HENUM *));
UDECL(VOID, RtlEndStrongEnumerationHashTable, (HTAB *, HENUM *));
UDECL(VOID, RtlDebugPrintTimes, (VOID));

#define NENT 300
static HENT g_ent[NENT];
TEST(rtl_rest_b_hash_expand) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlExpandHashTable)); REQUIRE(UN(RtlInsertEntryHashTable));
    REQUIRE(UN(RtlLookupEntryHashTable)); REQUIRE(UN(RtlDeleteHashTable));
    HTAB *t = NULL;
    if (!UN(RtlCreateHashTable)(&t, 0, 0) || !t) { t_skip("hash table creation failed"); return; }
    EXPECT_EQ(t->TableSize, 128); EXPECT_EQ(t->Pivot, 0); EXPECT_EQ(t->DivisorMask, 127);
    for (ULONG i = 0; i < NENT; i++) EXPECT_EQ(UN(RtlInsertEntryHashTable)(t, &g_ent[i], i * 7 + 3, NULL), TRUE);
    EXPECT_EQ(t->NumEntries, NENT);
    /* each expansion adds one bucket and advances the split pivot */
    for (ULONG i = 1; i <= 5; i++) {
        EXPECT_EQ(UN(RtlExpandHashTable)(t), TRUE);
        EXPECT_EQ(t->TableSize, 128 + i); EXPECT_EQ(t->Pivot, i); EXPECT_EQ(t->DivisorMask, 127);
    }
    EXPECT_EQ(t->NumEntries, NENT);                                  /* expansion neither adds nor drops entries */
    for (ULONG i = 0; i < NENT; i++) EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, i * 7 + 3, NULL), (ULONG_PTR)&g_ent[i]);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, 4, NULL), 0);
    /* a complete round of 128 splits doubles the table and widens the divisor mask */
    for (ULONG i = 6; i <= 128; i++) if (!UN(RtlExpandHashTable)(t)) { CHECKF(0, "expansion %lu failed", (unsigned long)i); break; }
    EXPECT_EQ(t->TableSize, 256); EXPECT_EQ(t->Pivot, 0); EXPECT_EQ(t->DivisorMask, 255);
    for (ULONG i = 0; i < NENT; i++) EXPECT_EQ((ULONG_PTR)UN(RtlLookupEntryHashTable)(t, i * 7 + 3, NULL), (ULONG_PTR)&g_ent[i]);
    UN(RtlDeleteHashTable)(t);
}
TEST(rtl_rest_b_hash_enumeration_end) {
    REQUIRE(UN(RtlCreateHashTable)); REQUIRE(UN(RtlExpandHashTable)); REQUIRE(UN(RtlInsertEntryHashTable));
    REQUIRE(UN(RtlInitEnumerationHashTable)); REQUIRE(UN(RtlEnumerateEntryHashTable)); REQUIRE(UN(RtlEndEnumerationHashTable));
    REQUIRE(UN(RtlDeleteHashTable));
    HTAB *t = NULL;
    if (!UN(RtlCreateHashTable)(&t, 0, 0) || !t) { t_skip("hash table creation failed"); return; }
    static HENT ent2[20];
    memset(ent2, 0, sizeof ent2);
    for (ULONG i = 0; i < 20; i++) UN(RtlInsertEntryHashTable)(t, &ent2[i], 100 + i * 37, NULL);
    HENUM en; memset(&en, 0, sizeof en);
    EXPECT_EQ(UN(RtlInitEnumerationHashTable)(t, &en), TRUE);
    EXPECT_EQ(t->NumEnumerators, 1);
    /* while an enumeration is active the table refuses to grow */
    EXPECT_EQ(UN(RtlExpandHashTable)(t), FALSE);
    EXPECT_EQ(t->TableSize, 128);
    ULONG seen = 0, mask = 0; HENT *e;
    while ((e = UN(RtlEnumerateEntryHashTable)(t, &en)) != NULL && seen < 100) { seen++; if (e >= ent2 && e < ent2 + 20) mask |= 1u << (e - ent2); }
    t_note("enumerated %lu entries, mask %05lx", (unsigned long)seen, (unsigned long)mask);
    EXPECT_EQ(seen, 20);
    UN(RtlEndEnumerationHashTable)(t, &en);
    EXPECT_EQ(t->NumEnumerators, 0);
    EXPECT_EQ(UN(RtlExpandHashTable)(t), TRUE); EXPECT_EQ(t->TableSize, 129);
    /* weak enumeration */
    if (UN(RtlInitWeakEnumerationHashTable) && UN(RtlEndWeakEnumerationHashTable)) {
        EXPECT_EQ(UN(RtlInitWeakEnumerationHashTable)(t, &en), TRUE);
        EXPECT_EQ(t->NumEnumerators, 1);
        seen = 0; mask = 0; while ((e = UN(RtlEnumerateEntryHashTable)(t, &en)) != NULL && seen < 100) { seen++; if (e >= ent2 && e < ent2 + 20) mask |= 1u << (e - ent2); }
        t_note("weak enumerated %lu entries, mask %05lx", (unsigned long)seen, (unsigned long)mask);
        EXPECT_EQ(seen, 20);
        UN(RtlEndWeakEnumerationHashTable)(t, &en);
        EXPECT_EQ(t->NumEnumerators, 0);
        /* ending part-way through also releases the enumerator */
        EXPECT_EQ(UN(RtlInitWeakEnumerationHashTable)(t, &en), TRUE);
        CHECK(UN(RtlEnumerateEntryHashTable)(t, &en) != NULL);
        EXPECT_EQ(t->NumEnumerators, 1);
        UN(RtlEndWeakEnumerationHashTable)(t, &en);
        EXPECT_EQ(t->NumEnumerators, 0);
    } else t_skip("weak enumeration exports missing");
    /* two concurrent enumerators */
    HENUM e2;
    EXPECT_EQ(UN(RtlInitEnumerationHashTable)(t, &en), TRUE);
    EXPECT_EQ(UN(RtlInitEnumerationHashTable)(t, &e2), TRUE);
    EXPECT_EQ(t->NumEnumerators, 2);
    UN(RtlEndEnumerationHashTable)(t, &e2); EXPECT_EQ(t->NumEnumerators, 1);
    UN(RtlEndEnumerationHashTable)(t, &en); EXPECT_EQ(t->NumEnumerators, 0);
    /* the strong-enumeration end export is an empty routine shared with other no-op exports */
    if (UN(RtlEndStrongEnumerationHashTable) && UN(RtlDebugPrintTimes)) {
        EXPECT_EQ((ULONG_PTR)UN(RtlEndStrongEnumerationHashTable), (ULONG_PTR)UN(RtlDebugPrintTimes));
        EXPECT_EQ(UN(RtlInitEnumerationHashTable)(t, &en), TRUE);
        UN(RtlEndStrongEnumerationHashTable)(t, &en);
        EXPECT_EQ(t->NumEnumerators, 1);                      /* nothing was released */
        UN(RtlEndEnumerationHashTable)(t, &en);
        EXPECT_EQ(t->NumEnumerators, 0);
        UN(RtlDebugPrintTimes)();                              /* returns without effect */
    } else t_skip("strong-enumeration end export missing");
    UN(RtlDeleteHashTable)(t);
}

/* ---------------- atom tables ---------------- */
typedef USHORT ATOMID;
UDECL(NTSTATUS, RtlCreateAtomTable, (ULONG, PVOID *));
UDECL(NTSTATUS, RtlDestroyAtomTable, (PVOID));
UDECL(NTSTATUS, RtlEmptyAtomTable, (PVOID, BOOLEAN));
UDECL(NTSTATUS, RtlAddAtomToAtomTable, (PVOID, PWSTR, ATOMID *));
UDECL(NTSTATUS, RtlLookupAtomInAtomTable, (PVOID, PWSTR, ATOMID *));
UDECL(NTSTATUS, RtlPinAtomInAtomTable, (PVOID, ATOMID));
TEST(rtl_rest_b_atom_table_empty_destroy) {
    REQUIRE(UN(RtlCreateAtomTable)); REQUIRE(UN(RtlDestroyAtomTable)); REQUIRE(UN(RtlEmptyAtomTable));
    REQUIRE(UN(RtlAddAtomToAtomTable)); REQUIRE(UN(RtlLookupAtomInAtomTable)); REQUIRE(UN(RtlPinAtomInAtomTable));
    PVOID t = NULL; ATOMID a = 0, b = 0, c = 0, r;
    if (UN(RtlCreateAtomTable)(37, &t) < 0 || !t) { t_skip("atom table creation failed"); return; }
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"loose", &a), 0);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"pinned", &b), 0);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"loose2", &c), 0);
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(t, b), 0);
    /* empty without pinned atoms: unpinned entries go, the pinned one stays */
    EXPECT_EQ(UN(RtlEmptyAtomTable)(t, FALSE), 0);
    r = 0; EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"loose", &r), (NTSTATUS)0xC0000034);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"loose2", &r), (NTSTATUS)0xC0000034);
    r = 0; EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"pinned", &r), 0); EXPECT_EQ(r, b);
    /* include pinned atoms */
    EXPECT_EQ(UN(RtlEmptyAtomTable)(t, TRUE), 0);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"pinned", &r), (NTSTATUS)0xC0000034);
    /* emptying an empty table is fine and the table stays usable */
    EXPECT_EQ(UN(RtlEmptyAtomTable)(t, TRUE), 0);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"again", &a), 0);
    CHECK(a >= 0xC000);
    r = 0; EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"again", &r), 0); EXPECT_EQ(r, a);
    EXPECT_EQ(UN(RtlDestroyAtomTable)(t), 0);
    /* destroying a table that still holds pinned atoms succeeds as well */
    t = NULL;
    if (UN(RtlCreateAtomTable)(11, &t) >= 0 && t) {
        UN(RtlAddAtomToAtomTable)(t, L"p", &a); UN(RtlPinAtomInAtomTable)(t, a);
        EXPECT_EQ(UN(RtlDestroyAtomTable)(t), 0);
    }
}

/* ---------------- handle table ---------------- */
typedef struct RHT { ULONG Max, EntrySize, Res[2]; PVOID Free, Committed, Uncommitted, MaxReserved; } RHT;
UDECL(VOID, RtlInitializeHandleTable, (ULONG, ULONG, RHT *));
UDECL(NTSTATUS, RtlDestroyHandleTable, (RHT *));
UDECL(PVOID, RtlAllocateHandle, (RHT *, PULONG));
UDECL(BOOLEAN, RtlFreeHandle, (RHT *, PVOID));
TEST(rtl_rest_b_handle_table_destroy) {
    REQUIRE(UN(RtlInitializeHandleTable)); REQUIRE(UN(RtlDestroyHandleTable)); REQUIRE(UN(RtlAllocateHandle));
    RHT t; memset(&t, 0xCD, sizeof t);
    UN(RtlInitializeHandleTable)(64, 32, &t);
    EXPECT_EQ(t.Max, 64); EXPECT_EQ(t.EntrySize, 32);
    EXPECT_EQ(UN(RtlDestroyHandleTable)(&t), 0);                       /* nothing committed yet */
    UN(RtlInitializeHandleTable)(64, 32, &t);
    ULONG idx = ~0u; PVOID h = UN(RtlAllocateHandle)(&t, &idx);
    CHECK(h != NULL); EXPECT_EQ(idx, 0);
    if (!h) return;
    PVOID base = t.Committed; CHECK(base != NULL);
    MEMORY_BASIC_INFORMATION mi;
    CHECK(VirtualQuery(base, &mi, sizeof mi) == sizeof mi);
    EXPECT_EQ(mi.State, MEM_COMMIT);
    EXPECT_EQ(UN(RtlDestroyHandleTable)(&t), 0);
    CHECK(VirtualQuery(base, &mi, sizeof mi) == sizeof mi);
    EXPECT_EQ(mi.State, MEM_FREE);                                      /* backing pages returned to the system */
}

/* ---------------- process parameters / debug buffer ---------------- */
UDECL(NTSTATUS, RtlCreateProcessParametersEx, (PVOID *, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG));
UDECL(NTSTATUS, RtlDestroyProcessParameters, (PVOID));
UDECL(NTSTATUS, RtlDestroyEnvironment, (PVOID));
UDECL(PVOID, RtlCreateQueryDebugBuffer, (ULONG, BOOLEAN));
UDECL(NTSTATUS, RtlDestroyQueryDebugBuffer, (PVOID));
TEST(rtl_rest_b_process_parameters_destroy) {
    REQUIRE(UN(RtlCreateProcessParametersEx)); REQUIRE(UN(RtlDestroyProcessParameters)); REQUIRE(U(RtlInitUnicodeString));
    UNICODE_STRING img, cmd; PVOID pp = NULL;
    U(RtlInitUnicodeString)(&img, L"\\??\\C:\\rtl_rest_b\\image.exe"); U(RtlInitUnicodeString)(&cmd, L"image.exe /x");
    NTSTATUS s = UN(RtlCreateProcessParametersEx)(&pp, &img, NULL, NULL, &cmd, NULL, NULL, NULL, NULL, NULL, 1);
    EXPECT_EQ(s, 0); CHECK(pp != NULL);
    if (s < 0 || !pp) return;
    HANDLE heap = GetProcessHeap();
    CHECK(HeapSize(heap, 0, pp) != (SIZE_T)-1);                          /* allocated from the process heap */
    EXPECT_EQ(UN(RtlDestroyProcessParameters)(pp), 0);
    CHECK(HeapValidate(heap, 0, NULL));
    /* second block, released through the environment-destroy alias, which shares the implementation */
    if (UN(RtlDestroyEnvironment)) {
        EXPECT_EQ((ULONG_PTR)UN(RtlDestroyEnvironment), (ULONG_PTR)UN(RtlDestroyProcessParameters));
        pp = NULL;
        EXPECT_EQ(UN(RtlCreateProcessParametersEx)(&pp, &img, NULL, NULL, &cmd, NULL, NULL, NULL, NULL, NULL, 1), 0);
        if (pp) EXPECT_EQ(UN(RtlDestroyEnvironment)(pp), 0);
    }
}
TEST(rtl_rest_b_query_debug_buffer_destroy) {
    REQUIRE(UN(RtlCreateQueryDebugBuffer)); REQUIRE(UN(RtlDestroyQueryDebugBuffer));
    PVOID b = UN(RtlCreateQueryDebugBuffer)(0x10000, FALSE);
    CHECK(b != NULL);
    if (!b) return;
    MEMORY_BASIC_INFORMATION mi;
    CHECK(VirtualQuery(b, &mi, sizeof mi) == sizeof mi);
    EXPECT_EQ(mi.State, MEM_COMMIT); EXPECT_EQ(mi.Type, MEM_MAPPED);     /* backed by a section view */
    PVOID base = mi.AllocationBase;
    EXPECT_EQ(UN(RtlDestroyQueryDebugBuffer)(b), 0);
    CHECK(VirtualQuery(base, &mi, sizeof mi) == sizeof mi);
    EXPECT_EQ(mi.State, MEM_FREE);                                        /* view unmapped */
}

/* ---------------- SList / ACL ---------------- */
UDECL(VOID, RtlInitializeSListHead, (PSLIST_HEADER));
UDECL(PSLIST_ENTRY, RtlInterlockedPushEntrySList, (PSLIST_HEADER, PSLIST_ENTRY));
UDECL(PSLIST_ENTRY, RtlInterlockedPopEntrySList, (PSLIST_HEADER));
UDECL(PSLIST_ENTRY, RtlFirstEntrySList, (const SLIST_HEADER *));
TEST(rtl_rest_b_slist_first_entry) {
    REQUIRE(UN(RtlFirstEntrySList)); REQUIRE(UN(RtlInitializeSListHead)); REQUIRE(UN(RtlInterlockedPushEntrySList));
    REQUIRE(UN(RtlInterlockedPopEntrySList));
    static SLIST_HEADER head __attribute__((aligned(16)));
    static SLIST_ENTRY ent[3] __attribute__((aligned(16)));
    UN(RtlInitializeSListHead)(&head);
    EXPECT_EQ(UN(RtlFirstEntrySList)(&head), 0);
    UN(RtlInterlockedPushEntrySList)(&head, &ent[0]);
    EXPECT_EQ((ULONG_PTR)UN(RtlFirstEntrySList)(&head), (ULONG_PTR)&ent[0]);
    UN(RtlInterlockedPushEntrySList)(&head, &ent[1]);
    EXPECT_EQ((ULONG_PTR)UN(RtlFirstEntrySList)(&head), (ULONG_PTR)&ent[1]);      /* LIFO: the head is the last push */
    UN(RtlInterlockedPushEntrySList)(&head, &ent[2]);
    EXPECT_EQ((ULONG_PTR)UN(RtlFirstEntrySList)(&head), (ULONG_PTR)&ent[2]);
    EXPECT_EQ(ent[2].Next, &ent[1]);
    EXPECT_EQ((ULONG_PTR)UN(RtlInterlockedPopEntrySList)(&head), (ULONG_PTR)&ent[2]);
    EXPECT_EQ((ULONG_PTR)UN(RtlFirstEntrySList)(&head), (ULONG_PTR)&ent[1]);           /* peeking does not pop */
    EXPECT_EQ((ULONG_PTR)UN(RtlFirstEntrySList)(&head), (ULONG_PTR)&ent[1]);
    UN(RtlInterlockedPopEntrySList)(&head); UN(RtlInterlockedPopEntrySList)(&head);
    EXPECT_EQ(UN(RtlFirstEntrySList)(&head), 0);
}

UDECL(NTSTATUS, RtlCreateAcl, (PACL, ULONG, ULONG));
UDECL(NTSTATUS, RtlAddAccessAllowedAce, (PACL, ULONG, ACCESS_MASK, PSID));
UDECL(BOOLEAN, RtlFirstFreeAce, (PACL, PVOID *));
TEST(rtl_rest_b_first_free_ace) {
    REQUIRE(UN(RtlFirstFreeAce)); REQUIRE(UN(RtlCreateAcl)); REQUIRE(UN(RtlAddAccessAllowedAce));
    static const UCHAR everyone[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };          /* S-1-1-0 */
    union { ACL a; UCHAR raw[256]; } u; memset(&u, 0, sizeof u);
    ACL *acl = &u.a; PVOID ff;
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 100, 2), 0);
    ff = (PVOID)1; EXPECT_EQ(UN(RtlFirstFreeAce)(acl, &ff), TRUE); EXPECT_EQ((ULONG_PTR)ff, (ULONG_PTR)acl + 8);
    EXPECT_EQ(UN(RtlAddAccessAllowedAce)(acl, 2, GENERIC_ALL, (PSID)everyone), 0);
    ff = NULL; EXPECT_EQ(UN(RtlFirstFreeAce)(acl, &ff), TRUE); EXPECT_EQ((ULONG_PTR)ff, (ULONG_PTR)acl + 8 + 20);
    EXPECT_EQ(UN(RtlAddAccessAllowedAce)(acl, 2, GENERIC_READ, (PSID)everyone), 0);
    ff = NULL; EXPECT_EQ(UN(RtlFirstFreeAce)(acl, &ff), TRUE); EXPECT_EQ((ULONG_PTR)ff, (ULONG_PTR)acl + 8 + 40);
    /* an ACL exactly filled by its entries: the free pointer is the end of the ACL */
    memset(&u, 0, sizeof u);
    EXPECT_EQ(UN(RtlCreateAcl)(acl, 8 + 20, 2), 0);
    EXPECT_EQ(UN(RtlAddAccessAllowedAce)(acl, 2, GENERIC_ALL, (PSID)everyone), 0);
    ff = NULL; EXPECT_EQ(UN(RtlFirstFreeAce)(acl, &ff), TRUE); EXPECT_EQ((ULONG_PTR)ff, (ULONG_PTR)acl + acl->AclSize);
    /* the count says there is another entry but there is no room for it */
    acl->AceCount = 2;
    ff = (PVOID)1; EXPECT_EQ(UN(RtlFirstFreeAce)(acl, &ff), FALSE); EXPECT_EQ(ff, NULL);
    /* an entry that overruns the ACL: reported as success with no free space */
    acl->AceCount = 1; ((ACE_HEADER *)((UCHAR *)acl + 8))->AceSize = 200;
    ff = (PVOID)1; EXPECT_EQ(UN(RtlFirstFreeAce)(acl, &ff), TRUE); EXPECT_EQ(ff, NULL);
}

/* ---------------- PE header helpers ---------------- */
UDECL(NTSTATUS, RtlImageNtHeaderEx, (ULONG, PVOID, ULONG64, PIMAGE_NT_HEADERS *));
UDECL(PIMAGE_SECTION_HEADER, RtlImageRvaToSection, (PIMAGE_NT_HEADERS, PVOID, ULONG));
#define ST_BADIMAGE ((NTSTATUS)0xC000007B)
TEST(rtl_rest_b_image_nt_header_ex) {
    REQUIRE(UN(RtlImageNtHeaderEx));
    HMODULE self = GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)self;
    IMAGE_NT_HEADERS *want = (IMAGE_NT_HEADERS *)((BYTE *)self + dos->e_lfanew);
    PIMAGE_NT_HEADERS out = (PIMAGE_NT_HEADERS)1;
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, self, want->OptionalHeader.SizeOfImage, &out), 0);
    EXPECT_EQ((ULONG_PTR)out, (ULONG_PTR)want);
    out = (PIMAGE_NT_HEADERS)1;
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(1, self, 0, &out), 0);              /* flag 1: size is not range-checked */
    EXPECT_EQ((ULONG_PTR)out, (ULONG_PTR)want);
    /* synthetic image */
    static UCHAR img[0x200] __attribute__((aligned(16)));
    memset(img, 0, sizeof img);
    ((IMAGE_DOS_HEADER *)img)->e_magic = 0x5A4D; ((IMAGE_DOS_HEADER *)img)->e_lfanew = 0x80;
    memcpy(img + 0x80, "PE\0\0", 4);
    out = (PIMAGE_NT_HEADERS)1;
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, img, sizeof img, &out), 0); EXPECT_EQ((ULONG_PTR)out, (ULONG_PTR)(img + 0x80));
    /* boundary: the header (0x18 bytes) must lie wholly inside the size */
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, img, 0x80 + 0x18, &out), ST_BADIMAGE); EXPECT_EQ(out, NULL);
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, img, 0x80 + 0x19, &out), 0); EXPECT_EQ((ULONG_PTR)out, (ULONG_PTR)(img + 0x80));
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, img, 0x80, &out), ST_BADIMAGE); EXPECT_EQ(out, NULL);
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, img, 0x3F, &out), ST_BADIMAGE); EXPECT_EQ(out, NULL);
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, img, 0, &out), ST_BADIMAGE); EXPECT_EQ(out, NULL);
    /* bad signatures */
    img[0] = 'X'; out = (PIMAGE_NT_HEADERS)1;
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, img, sizeof img, &out), ST_BADIMAGE); EXPECT_EQ(out, NULL);
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(1, img, 0, &out), ST_BADIMAGE);
    img[0] = 'M'; img[0x80] = 'Q'; out = (PIMAGE_NT_HEADERS)1;
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, img, sizeof img, &out), ST_BADIMAGE); EXPECT_EQ(out, NULL);
    img[0x80] = 'P';
    /* e_lfanew of 256 MiB or more is never accepted */
    ((IMAGE_DOS_HEADER *)img)->e_lfanew = 0x10000000;
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, img, 0xFFFFFFFFull, &out), ST_BADIMAGE); EXPECT_EQ(out, NULL);
    ((IMAGE_DOS_HEADER *)img)->e_lfanew = 0x80;
    /* argument validation */
    EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, img, sizeof img, NULL), ST_INVPARAM);
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, NULL, sizeof img, &out), ST_INVPARAM); EXPECT_EQ(out, NULL);
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(0, (PVOID)(ULONG_PTR)-1, sizeof img, &out), ST_INVPARAM); EXPECT_EQ(out, NULL);
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(4, img, sizeof img, &out), ST_INVPARAM); EXPECT_EQ(out, NULL);
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(2, img, sizeof img, &out), 0); EXPECT_EQ((ULONG_PTR)out, (ULONG_PTR)(img + 0x80));   /* bit 1 is accepted */
    out = (PIMAGE_NT_HEADERS)1; EXPECT_EQ(UN(RtlImageNtHeaderEx)(0x80000000, img, sizeof img, &out), ST_INVPARAM); EXPECT_EQ(out, NULL);
}
TEST(rtl_rest_b_image_rva_to_section) {
    REQUIRE(UN(RtlImageRvaToSection));
    /* synthetic NT headers followed by three section headers */
    static struct { IMAGE_NT_HEADERS64 nt; IMAGE_SECTION_HEADER sec[3]; } img;
    memset(&img, 0, sizeof img);
    img.nt.FileHeader.NumberOfSections = 3;
    img.nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    memcpy(img.sec[0].Name, ".a", 3); img.sec[0].VirtualAddress = 0x1000; img.sec[0].Misc.VirtualSize = 0x1000; img.sec[0].SizeOfRawData = 0x200;
    memcpy(img.sec[1].Name, ".c", 3); img.sec[1].VirtualAddress = 0x2000; img.sec[1].Misc.VirtualSize = 0x800;  img.sec[1].SizeOfRawData = 0;
    memcpy(img.sec[2].Name, ".b", 3); img.sec[2].VirtualAddress = 0x3000; img.sec[2].Misc.VirtualSize = 0x10;   img.sec[2].SizeOfRawData = 0x400;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)&img.nt;
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0x1000), (ULONG_PTR)&img.sec[0]);
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0x11FF), (ULONG_PTR)&img.sec[0]);
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0x1200), 0);        /* the raw size bounds the match, not the virtual size */
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0x1FFF), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0x2000), 0);        /* zero raw size matches nothing */
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0x3000), (ULONG_PTR)&img.sec[2]);
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0x33FF), (ULONG_PTR)&img.sec[2]);
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0x3400), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0xFFFFFFFF), 0);
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, (PVOID)0x1234, 0x1000), (ULONG_PTR)&img.sec[0]);   /* base is ignored */
    img.nt.FileHeader.NumberOfSections = 0;
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(nt, NULL, 0x1000), 0);
    /* this executable: entry point lies in the first section covering it */
    HMODULE self = GetModuleHandleW(NULL);
    PIMAGE_NT_HEADERS rn = (PIMAGE_NT_HEADERS)((BYTE *)self + ((IMAGE_DOS_HEADER *)self)->e_lfanew);
    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(rn), want = NULL;
    ULONG rva = rn->OptionalHeader.AddressOfEntryPoint;
    for (int i = 0; i < rn->FileHeader.NumberOfSections; i++)
        if (rva >= s[i].VirtualAddress && rva < s[i].VirtualAddress + s[i].SizeOfRawData) { want = &s[i]; break; }
    CHECK(want != NULL);
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(rn, self, rva), (ULONG_PTR)want);
    EXPECT_EQ((ULONG_PTR)UN(RtlImageRvaToSection)(rn, self, 0x10), 0);               /* header area belongs to no section */
}

/* ---------------- resource descriptor decoding ---------------- */
typedef struct { UCHAR Option, Type, Share, Spare1; USHORT Flags, Spare2; ULONG Length, Alignment; ULONGLONG Min, Max; } IORD;
UDECL(ULONGLONG, RtlIoDecodeMemIoResource, (IORD *, ULONGLONG *, ULONGLONG *, ULONGLONG *));
TEST(rtl_rest_b_io_decode_mem_io_resource) {
    REQUIRE(UN(RtlIoDecodeMemIoResource));
    CHECK(sizeof(IORD) == 32);
    IORD d; ULONGLONG al = 7, mn = 7, mx = 7, r;
    memset(&d, 0, sizeof d); d.Type = 1; d.Length = 0x100; d.Alignment = 0x10; d.Min = 0x1000; d.Max = 0x1FFF;
    r = UN(RtlIoDecodeMemIoResource)(&d, &al, &mn, &mx);
    EXPECT_EQ(r, 0x100); EXPECT_EQ(al, 0x10); EXPECT_EQ(mn, 0x1000); EXPECT_EQ(mx, 0x1FFF);
    d.Type = 3; d.Flags = 0x200 | 0x400 | 0x800;              /* memory descriptors are never scaled */
    al = mn = mx = 7; r = UN(RtlIoDecodeMemIoResource)(&d, &al, &mn, &mx);
    EXPECT_EQ(r, 0x100); EXPECT_EQ(al, 0x10); EXPECT_EQ(mn, 0x1000); EXPECT_EQ(mx, 0x1FFF);
    /* other descriptor kinds: length and alignment are scaled by the width flags */
    d.Type = 2; d.Flags = 0;
    al = mn = mx = 7; r = UN(RtlIoDecodeMemIoResource)(&d, &al, &mn, &mx);
    EXPECT_EQ(r, 0); EXPECT_EQ(al, 0); EXPECT_EQ(mn, 0x1000); EXPECT_EQ(mx, 0x1FFF);
    d.Flags = 0x200; r = UN(RtlIoDecodeMemIoResource)(&d, &al, NULL, NULL); EXPECT_EQ(r, 0x100 << 8); EXPECT_EQ(al, 0x10 << 8);
    d.Flags = 0x400; r = UN(RtlIoDecodeMemIoResource)(&d, &al, NULL, NULL); EXPECT_EQ(r, 0x100ull << 16); EXPECT_EQ(al, 0x10ull << 16);
    d.Flags = 0x800; r = UN(RtlIoDecodeMemIoResource)(&d, &al, NULL, NULL); EXPECT_EQ(r, 0x100ull << 32); EXPECT_EQ(al, 0x10ull << 32);
    d.Flags = 0xC00; r = UN(RtlIoDecodeMemIoResource)(&d, &al, NULL, NULL); EXPECT_EQ(r, 0x100ull << 16);   /* lowest set width flag wins */
    d.Flags = 0xE00; r = UN(RtlIoDecodeMemIoResource)(&d, &al, NULL, NULL); EXPECT_EQ(r, 0x100ull << 8);
    d.Flags = 0x1;   r = UN(RtlIoDecodeMemIoResource)(&d, &al, NULL, NULL); EXPECT_EQ(r, 0);
    d.Type = 1; d.Flags = 0x200; r = UN(RtlIoDecodeMemIoResource)(&d, NULL, NULL, NULL); EXPECT_EQ(r, 0x100);     /* port: unscaled, outputs optional */
    d.Type = 0xFF; d.Flags = 0x800; r = UN(RtlIoDecodeMemIoResource)(&d, &al, &mn, &mx); EXPECT_EQ(r, 0x100ull << 32);
}

/* ---------------- non-temporal fill and non-volatile helpers ---------------- */
UDECL(VOID, RtlFillMemoryNonTemporal, (PVOID, SIZE_T, UCHAR));
UDECL(NTSTATUS, RtlFillNonVolatileMemory, (PVOID, PVOID, SIZE_T, UCHAR, ULONG));
UDECL(NTSTATUS, RtlFlushNonVolatileMemory, (PVOID, PVOID, SIZE_T, ULONG));
UDECL(NTSTATUS, RtlFlushNonVolatileMemoryRanges, (PVOID, PVOID, SIZE_T, ULONG));
UDECL(NTSTATUS, RtlDrainNonVolatileFlush, (PVOID));
UDECL(NTSTATUS, RtlWriteNonVolatileMemory, (PVOID, PVOID, const VOID *, SIZE_T, ULONG));
UDECL(NTSTATUS, RtlGetNonVolatileToken, (PVOID, SIZE_T, PVOID *));
TEST(non_volatile_get_token_failure) {
    static const SIZE_T lengths[] = { 0, 1, 4096, ~(SIZE_T)0 };
    UCHAR *p;
    size_t i;
    REQUIRE(UN(RtlGetNonVolatileToken));
    p = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) { t_skip("no scratch memory"); return; }
    for (i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        PVOID token = (PVOID)(ULONG_PTR)0xdeadbeef;
        EXPECT_EQ(UN(RtlGetNonVolatileToken)(p, lengths[i], &token), ST_INVPARAM);
        EXPECT_EQ(token, (PVOID)(ULONG_PTR)0xdeadbeef);
        /* Failed queries must not access even an invalid output pointer. */
        EXPECT_EQ(UN(RtlGetNonVolatileToken)(p, lengths[i], NULL), ST_INVPARAM);
    }
    VirtualFree(p, 0, MEM_RELEASE);
}

TEST(non_volatile_write_fill_boundaries) {
    static const SIZE_T lengths[] = { 0, 1, 7, 8, 9, 63, 64, 65, 255 };
    static const ULONG flags[] = { 0, 1, 2, 3, 0x100, 0x101, 0x102, 0x103, 0x80000000 };
    static const ULONG_PTR tokens[] = { 1, 3, 5, 7, 0x100000001ULL, 0x100000003ULL };
    UCHAR src[320], dst[320], want[320], saved[320];
    size_t t, f, l, off, k;
    REQUIRE(UN(RtlWriteNonVolatileMemory)); REQUIRE(UN(RtlFillNonVolatileMemory));
    REQUIRE(UN(RtlDrainNonVolatileFlush));
    for (k = 0; k < sizeof src; k++) src[k] = (UCHAR)(k * 37 + 11);
    memcpy(saved, src, sizeof src);
    for (t = 0; t < sizeof tokens / sizeof tokens[0]; t++)
    for (f = 0; f < sizeof flags / sizeof flags[0]; f++)
    for (l = 0; l < sizeof lengths / sizeof lengths[0]; l++)
    for (off = 0; off < 2; off++) {
        SIZE_T n = lengths[l], start = 16 + off;
        PVOID token = (PVOID)tokens[t];
        EXPECT_EQ(UN(RtlDrainNonVolatileFlush)(token), 0);
        memset(dst, 0xee, sizeof dst); memset(want, 0xee, sizeof want);
        memcpy(want + start, src + 3, n);
        EXPECT_EQ(UN(RtlWriteNonVolatileMemory)(token, dst + start, src + 3, n, flags[f]), 0);
        CHECKF(!memcmp(dst, want, sizeof dst), "write token %p flags %lx length %zu offset %zu", token, flags[f], n, off);
        CHECK(!memcmp(src, saved, sizeof src));
        memset(dst, 0xee, sizeof dst); memset(want, 0xee, sizeof want);
        memset(want + start, 0xa7, n);
        EXPECT_EQ(UN(RtlFillNonVolatileMemory)(token, dst + start, n, 0xa7, flags[f]), 0);
        CHECKF(!memcmp(dst, want, sizeof dst), "fill token %p flags %lx length %zu offset %zu", token, flags[f], n, off);
    }
}

CHILD(non_volatile_no_access) {
    ULONG_PTR t;
    /* The parent requires these exports before launching this child. */
    for (t = 0; t <= 4; t += 2) {
        PVOID token = (PVOID)t;
        if (UN(RtlWriteNonVolatileMemory)(token, NULL, NULL, 4096, 1) != ST_INVPARAM ||
            UN(RtlFillNonVolatileMemory)(token, NULL, 4096, 0xff, 1) != ST_INVPARAM ||
            UN(RtlFlushNonVolatileMemory)(token, NULL, 4096, 0) != ST_INVPARAM ||
            UN(RtlFlushNonVolatileMemoryRanges)(token, NULL, 1, 0) != ST_INVPARAM ||
            UN(RtlDrainNonVolatileFlush)(token) != ST_INVPARAM) return 1;
    }
    /* Bit 1 clear bypasses all range and address accesses, even at nonzero size. */
    if (UN(RtlFlushNonVolatileMemory)((PVOID)5, NULL, 4096, 0) != 0 ||
        UN(RtlFlushNonVolatileMemoryRanges)((PVOID)5, NULL, 1, 0) != 0 ||
        UN(RtlFlushNonVolatileMemoryRanges)((PVOID)3, NULL, 0, 0) != 0) return 2;
    return 0;
}

TEST(non_volatile_reject_before_access) {
    REQUIRE(UN(RtlWriteNonVolatileMemory)); REQUIRE(UN(RtlFillNonVolatileMemory));
    REQUIRE(UN(RtlFlushNonVolatileMemory)); REQUIRE(UN(RtlFlushNonVolatileMemoryRanges));
    REQUIRE(UN(RtlDrainNonVolatileFlush));
    EXPECT_EQ(t_run_child("non_volatile_no_access", NULL, 10000), 0);
}
TEST(rtl_rest_b_fill_memory_non_temporal) {
    REQUIRE(UN(RtlFillMemoryNonTemporal));
    static const SIZE_T lens[] = { 0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 78, 79, 80, 81, 127, 128, 129, 255, 256, 1000, 4096 + 13 };
    static const UCHAR vals[] = { 0xA7, 0x00, 0xFF };
    UCHAR *blk = VirtualAlloc(NULL, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!blk) { t_skip("no scratch memory"); return; }
    int bad = 0;
    for (unsigned v = 0; v < 3 && !bad; v++)
    for (unsigned li = 0; li < sizeof lens / sizeof *lens && !bad; li++)
    for (SIZE_T off = 0; off < 17 && !bad; off += (off < 9 ? 1 : 8)) {
        SIZE_T n = lens[li], guard = 32;
        UCHAR bg = (UCHAR)~vals[v];
        memset(blk, bg, 0x4000);
        UN(RtlFillMemoryNonTemporal)(blk + guard + off, n, vals[v]);
        for (SIZE_T i = 0; i < 0x4000 && !bad; i++) {
            UCHAR want = (i >= guard + off && i < guard + off + n) ? vals[v] : bg;
            if (blk[i] != want) { CHECKF(0, "len %zu off %zu val %02x: byte %zu is %02x want %02x", n, off, vals[v], i, blk[i], want); bad = 1; }
        }
    }
    if (!bad) CHECK(1);
    VirtualFree(blk, 0, MEM_RELEASE);
}
TEST(rtl_rest_b_non_volatile_memory) {
    REQUIRE(UN(RtlFillNonVolatileMemory)); REQUIRE(UN(RtlFlushNonVolatileMemory));
    REQUIRE(UN(RtlFlushNonVolatileMemoryRanges)); REQUIRE(UN(RtlDrainNonVolatileFlush));
    static UCHAR buf[512];
    typedef struct { PVOID p; SIZE_T n; } RNG;
    /* the token must carry the "valid" bit */
    for (ULONG_PTR tok = 0; tok <= 2; tok += 2) {
        PVOID tk = (PVOID)tok;
        EXPECT_EQ(UN(RtlDrainNonVolatileFlush)(tk), ST_INVPARAM);
        EXPECT_EQ(UN(RtlFillNonVolatileMemory)(tk, buf, 16, 0x11, 0), ST_INVPARAM);
        EXPECT_EQ(UN(RtlFlushNonVolatileMemory)(tk, buf, 16, 0), ST_INVPARAM);
        EXPECT_EQ(UN(RtlFlushNonVolatileMemoryRanges)(tk, buf, 0, 0), ST_INVPARAM);
    }
    EXPECT_EQ(buf[0], 0);                                                    /* rejected calls write nothing */
    PVOID plain = (PVOID)1;     /* valid, no flush required */
    PVOID flush = (PVOID)3;     /* valid, cache lines must be flushed */
    EXPECT_EQ(UN(RtlDrainNonVolatileFlush)(plain), 0);
    EXPECT_EQ(UN(RtlDrainNonVolatileFlush)(flush), 0);
    static const ULONG fl[] = { 0, 1, 2, 3, 0x100, 0x101 };
    for (unsigned i = 0; i < sizeof fl / sizeof *fl; i++) {
        for (int t = 0; t < 2; t++) {
            memset(buf, 0xEE, sizeof buf);
            NTSTATUS s = UN(RtlFillNonVolatileMemory)(t ? flush : plain, buf + 5, 100, 0x5A, fl[i]);
            CHECKF(s == 0, "fill flags 0x%lx token %d -> 0x%lx", (unsigned long)fl[i], t, (unsigned long)s);
            int ok = buf[4] == 0xEE && buf[105] == 0xEE;
            for (int k = 5; k < 105; k++) ok &= buf[k] == 0x5A;
            CHECKF(ok, "fill flags 0x%lx token %d contents", (unsigned long)fl[i], t);
            memset(buf, 0xEE, sizeof buf);
            s = UN(RtlFillNonVolatileMemory)(t ? flush : plain, buf + 3, 5, 0x77, fl[i]);   /* short: below the non-temporal threshold */
            CHECKF(s == 0 && buf[3] == 0x77 && buf[7] == 0x77 && buf[2] == 0xEE && buf[8] == 0xEE, "short fill flags 0x%lx", (unsigned long)fl[i]);
        }
    }
    memset(buf, 0x33, sizeof buf);
    EXPECT_EQ(UN(RtlFlushNonVolatileMemory)(flush, buf, sizeof buf, 0), 0);
    EXPECT_EQ(UN(RtlFlushNonVolatileMemory)(flush, buf + 1, 1, 1), 0);
    EXPECT_EQ(UN(RtlFlushNonVolatileMemory)(flush, buf, 0, 0), 0);
    EXPECT_EQ(UN(RtlFlushNonVolatileMemory)(plain, buf, sizeof buf, 0), 0);
    EXPECT_EQ(buf[0], 0x33); EXPECT_EQ(buf[511], 0x33);                       /* flushing does not alter data */
    RNG r[3] = { { buf, 64 }, { buf + 100, 200 }, { buf + 400, 1 } };
    EXPECT_EQ(UN(RtlFlushNonVolatileMemoryRanges)(flush, r, 3, 0), 0);
    EXPECT_EQ(UN(RtlFlushNonVolatileMemoryRanges)(flush, r, 3, 1), 0);
    EXPECT_EQ(UN(RtlFlushNonVolatileMemoryRanges)(flush, r, 0, 0), 0);
    EXPECT_EQ(UN(RtlFlushNonVolatileMemoryRanges)(plain, r, 3, 0), 0);
    EXPECT_EQ(buf[0], 0x33);
}

/* ---------------- FLS ---------------- */
UDECL(NTSTATUS, RtlFlsAlloc, (PVOID, PULONG));
UDECL(NTSTATUS, RtlFlsFree, (ULONG));
UDECL(NTSTATUS, RtlFlsGetValue, (ULONG, PVOID *));
UDECL(NTSTATUS, RtlFlsSetValue, (ULONG, PVOID));
static volatile LONG g_fls_calls; static volatile PVOID g_fls_arg;
static VOID NTAPI fls_cb(PVOID p) { g_fls_arg = p; InterlockedIncrement(&g_fls_calls); }
TEST(rtl_rest_b_fls_lifecycle) {
    REQUIRE(UN(RtlFlsAlloc)); REQUIRE(UN(RtlFlsFree)); REQUIRE(UN(RtlFlsGetValue)); REQUIRE(UN(RtlFlsSetValue));
    ULONG idx = 0xFFFFFFFF; PVOID v = (PVOID)1;
    EXPECT_EQ(UN(RtlFlsAlloc)(NULL, &idx), 0);
    CHECK(idx >= 1 && idx < 0xFF0);
    if (idx < 1 || idx >= 0xFF0) return;
    EXPECT_EQ(UN(RtlFlsGetValue)(idx, &v), 0); EXPECT_EQ(v, NULL);              /* fresh slot reads zero */
    EXPECT_EQ(UN(RtlFlsSetValue)(idx, (PVOID)0x1234), 0);
    v = NULL; EXPECT_EQ(UN(RtlFlsGetValue)(idx, &v), 0); EXPECT_EQ(v, (PVOID)0x1234);
    EXPECT_EQ(UN(RtlFlsSetValue)(idx, (PVOID)0x5678), 0);
    EXPECT_EQ(UN(RtlFlsGetValue)(idx, &v), 0); EXPECT_EQ(v, (PVOID)0x5678);
    /* a second slot is independent */
    ULONG idx2 = 0;
    EXPECT_EQ(UN(RtlFlsAlloc)(NULL, &idx2), 0); EXPECT_NE(idx2, idx);
    EXPECT_EQ(UN(RtlFlsSetValue)(idx2, (PVOID)0x9999), 0);
    EXPECT_EQ(UN(RtlFlsGetValue)(idx, &v), 0); EXPECT_EQ(v, (PVOID)0x5678);
    EXPECT_EQ(UN(RtlFlsFree)(idx2), 0);
    EXPECT_EQ(UN(RtlFlsFree)(idx), 0);
    /* freed slots are invalid to free again; reading a free slot yields zero */
    EXPECT_EQ(UN(RtlFlsFree)(idx), ST_INVPARAM);
    v = (PVOID)1; EXPECT_EQ(UN(RtlFlsGetValue)(idx, &v), 0); EXPECT_EQ(v, NULL);
}
TEST(rtl_rest_b_fls_callback_and_errors) {
    REQUIRE(UN(RtlFlsAlloc)); REQUIRE(UN(RtlFlsFree)); REQUIRE(UN(RtlFlsGetValue)); REQUIRE(UN(RtlFlsSetValue));
    ULONG idx = 0; PVOID v = (PVOID)1;
    EXPECT_EQ(UN(RtlFlsAlloc)(fls_cb, &idx), 0);
    CHECK(idx >= 1 && idx < 0xFF0);
    if (idx < 1 || idx >= 0xFF0) return;
    g_fls_calls = 0; g_fls_arg = NULL;
    EXPECT_EQ(UN(RtlFlsSetValue)(idx, (PVOID)0xBEEF), 0);
    EXPECT_EQ(UN(RtlFlsFree)(idx), 0);
    EXPECT_EQ(g_fls_calls, 1);                                                   /* callback runs with the stored value */
    EXPECT_EQ(g_fls_arg, (PVOID)0xBEEF);
    /* no callback for a slot that holds NULL */
    EXPECT_EQ(UN(RtlFlsAlloc)(fls_cb, &idx), 0);
    g_fls_calls = 0;
    EXPECT_EQ(UN(RtlFlsFree)(idx), 0);
    EXPECT_EQ(g_fls_calls, 0);
    /* index validation */
    static const ULONG badidx[] = { 0, 0xFF0, 0x1000, 0xFFFFFFFF };       /* valid indices are 1..0xFEF */
    for (unsigned i = 0; i < sizeof badidx / sizeof *badidx; i++) {
        v = (PVOID)1;
        CHECKF(UN(RtlFlsGetValue)(badidx[i], &v) == ST_INVPARAM, "get %lx", (unsigned long)badidx[i]);
        EXPECT_EQ(v, (PVOID)1);
        CHECKF(UN(RtlFlsSetValue)(badidx[i], (PVOID)5) == ST_INVPARAM, "set %lx", (unsigned long)badidx[i]);
        CHECKF(UN(RtlFlsFree)(badidx[i]) == ST_INVPARAM, "free %lx", (unsigned long)badidx[i]);
    }
}

/* ---------------- pointer encoding ---------------- */
UDECL(PVOID, RtlEncodeSystemPointer, (PVOID));
UDECL(PVOID, RtlDecodeSystemPointer, (PVOID));
UDECL(NTSTATUS, RtlEncodeRemotePointer, (HANDLE, PVOID, PVOID *));
UDECL(NTSTATUS, RtlDecodeRemotePointer, (HANDLE, PVOID, PVOID *));
UDECL(PVOID, RtlEncodePointer, (PVOID));
UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
static ULONGLONG ror64(ULONGLONG v, unsigned n) { n &= 63; return n ? (v >> n) | (v << (64 - n)) : v; }
static ULONGLONG rol64(ULONGLONG v, unsigned n) { return ror64(v, 64 - (n & 63)); }
static const ULONGLONG ptrs[] = { 0, 1, 0x1234, 0x7FFE0000, 0x00007FFF12345678ull, 0xFFFFFFFFFFFFFFFFull, 0x8000000000000000ull, 0xDEADBEEFCAFEF00Dull };
TEST(rtl_rest_b_system_pointer_encoding) {
    REQUIRE(UN(RtlEncodeSystemPointer)); REQUIRE(UN(RtlDecodeSystemPointer));
    ULONG cookie = *(volatile ULONG *)0x7FFE0330;                      /* shared-data system cookie */
    CHECK(cookie != 0);
    for (unsigned i = 0; i < sizeof ptrs / sizeof *ptrs; i++) {
        ULONGLONG e = (ULONGLONG)(ULONG_PTR)UN(RtlEncodeSystemPointer)((PVOID)(ULONG_PTR)ptrs[i]);
        ULONGLONG want = ror64(ptrs[i] ^ cookie, cookie & 63);
        CHECKF(e == want, "encode %llx -> %llx want %llx", ptrs[i], e, want);
        ULONGLONG d = (ULONGLONG)(ULONG_PTR)UN(RtlDecodeSystemPointer)((PVOID)(ULONG_PTR)e);
        CHECKF(d == ptrs[i], "decode(encode(%llx)) = %llx", ptrs[i], d);
        ULONGLONG d2 = (ULONGLONG)(ULONG_PTR)UN(RtlDecodeSystemPointer)((PVOID)(ULONG_PTR)ptrs[i]);
        CHECKF(d2 == (rol64(ptrs[i], cookie & 63) ^ cookie), "decode raw %llx -> %llx", ptrs[i], d2);
    }
    CHECK((ULONG_PTR)UN(RtlEncodeSystemPointer)((PVOID)0x1234) != 0x1234);
}
TEST(rtl_rest_b_remote_pointer_encoding) {
    REQUIRE(UN(RtlEncodeRemotePointer)); REQUIRE(UN(RtlDecodeRemotePointer)); REQUIRE(UN(NtQueryInformationProcess));
    ULONG cookie = 0, rl = 0;
    EXPECT_EQ(UN(NtQueryInformationProcess)(GetCurrentProcess(), 36 /* ProcessCookie */, &cookie, 4, &rl), 0);
    CHECK(cookie != 0);
    for (unsigned i = 0; i < sizeof ptrs / sizeof *ptrs; i++) {
        PVOID e = (PVOID)1, d = (PVOID)1;
        EXPECT_EQ(UN(RtlEncodeRemotePointer)(GetCurrentProcess(), (PVOID)(ULONG_PTR)ptrs[i], &e), 0);
        ULONGLONG want = ror64(ptrs[i] ^ cookie, cookie & 63);
        CHECKF((ULONGLONG)(ULONG_PTR)e == want, "encode %llx -> %llx want %llx", ptrs[i], (ULONGLONG)(ULONG_PTR)e, want);
        EXPECT_EQ(UN(RtlDecodeRemotePointer)(GetCurrentProcess(), e, &d), 0);
        CHECKF((ULONGLONG)(ULONG_PTR)d == ptrs[i], "decode(encode(%llx)) = %llx", ptrs[i], (ULONGLONG)(ULONG_PTR)d);
        if (UN(RtlEncodePointer)) EXPECT_EQ((ULONG_PTR)UN(RtlEncodePointer)((PVOID)(ULONG_PTR)ptrs[i]), (ULONG_PTR)e);
    }
    /* a real handle works as well as the pseudo handle */
    HANDLE hp = NULL; PVOID e1 = NULL, e2 = NULL;
    if (DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &hp, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        EXPECT_EQ(UN(RtlEncodeRemotePointer)(hp, (PVOID)0x4242, &e1), 0);
        EXPECT_EQ(UN(RtlEncodeRemotePointer)(GetCurrentProcess(), (PVOID)0x4242, &e2), 0);
        EXPECT_EQ(e1, e2);
        CloseHandle(hp);
    } else t_skip("cannot duplicate a process handle");
    /* failures carry the failing status with bit 28 set and leave the output untouched */
    PVOID o = (PVOID)0x77;
    EXPECT_EQ(UN(RtlEncodeRemotePointer)((HANDLE)(ULONG_PTR)0x7FFC, (PVOID)1, &o), (NTSTATUS)(0xC0000008 | 0x10000000));
    EXPECT_EQ(o, (PVOID)0x77);
    EXPECT_EQ(UN(RtlDecodeRemotePointer)((HANDLE)(ULONG_PTR)0x7FFC, (PVOID)1, &o), (NTSTATUS)(0xC0000008 | 0x10000000));
    EXPECT_EQ(o, (PVOID)0x77);
    EXPECT_EQ(UN(RtlEncodeRemotePointer)(NULL, (PVOID)1, &o), (NTSTATUS)(0xC0000008 | 0x10000000));
    HANDLE hs = NULL;
    if (DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &hs, SYNCHRONIZE, FALSE, 0)) {
        EXPECT_EQ(UN(RtlEncodeRemotePointer)(hs, (PVOID)1, &o), (NTSTATUS)(0xC0000022 | 0x10000000));   /* no query access */
        EXPECT_EQ(UN(RtlDecodeRemotePointer)(hs, (PVOID)1, &o), (NTSTATUS)(0xC0000022 | 0x10000000));
        EXPECT_EQ(o, (PVOID)0x77);
        CloseHandle(hs);
    }
}

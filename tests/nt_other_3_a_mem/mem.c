/* Memory services: NtFlushVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory,
 * NtLockVirtualMemory, NtGetWriteWatch, NtMapViewOfSection(Ex), NtFlushInstructionCache,
 * NtFlushWriteBuffer, NtFlushProcessWriteBuffers. Private allocations and pagefile sections only. */
#include "t.h"

UDECL(NTSTATUS, NtAllocateVirtualMemory, (HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG));
UDECL(NTSTATUS, NtFreeVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtProtectVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryVirtualMemory, (HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtLockVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtUnlockVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtFlushVirtualMemory, (HANDLE, PVOID *, PSIZE_T, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtGetWriteWatch, (HANDLE, ULONG, PVOID, SIZE_T, PVOID *, PULONG_PTR, PULONG));
UDECL(NTSTATUS, NtResetWriteWatch, (HANDLE, PVOID, SIZE_T));
UDECL(NTSTATUS, NtCreateSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE));
UDECL(NTSTATUS, NtMapViewOfSection, (HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtMapViewOfSectionEx, (HANDLE, HANDLE, PVOID *, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtUnmapViewOfSection, (HANDLE, PVOID));
UDECL(NTSTATUS, NtFlushInstructionCache, (HANDLE, PVOID, SIZE_T));
UDECL(NTSTATUS, NtFlushWriteBuffer, (void));
UDECL(NTSTATUS, NtFlushProcessWriteBuffers, (void));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define XS(x) ((NTSTATUS)(x))
#define XOK(s) ((NTSTATUS)(s) >= 0)
#define SELF ((HANDLE)(LONG_PTR)-1)
#define N(f) UN(f)
typedef struct { PVOID base, alloc_base; ULONG alloc_prot, pad1; SIZE_T size; ULONG state, prot, type, pad2; } mbi_t;

static PVOID amem(SIZE_T size, ULONG type, ULONG prot)
{
    PVOID base = NULL; SIZE_T sz = size;
    if (!XOK(N(NtAllocateVirtualMemory)(SELF, &base, 0, &sz, type, prot))) return NULL;
    return base;
}
static void rel(PVOID b) { SIZE_T s = 0; N(NtFreeVirtualMemory)(SELF, &b, &s, MEM_RELEASE); }
static NTSTATUS qry(PVOID p, mbi_t *m) { SIZE_T r; memset(m, 0xcc, sizeof *m); return N(NtQueryVirtualMemory)(SELF, p, 0, m, sizeof *m, &r); }
static HANDLE mksec(ULONGLONG size)
{
    HANDLE h = NULL; LARGE_INTEGER li; li.QuadPart = size;
    if (!XOK(N(NtCreateSection)(&h, SECTION_ALL_ACCESS, NULL, &li, PAGE_READWRITE, SEC_COMMIT, NULL))) return NULL;
    return h;
}
#define NEED_VM() do { REQUIRE(N(NtAllocateVirtualMemory)); REQUIRE(N(NtFreeVirtualMemory)); REQUIRE(N(NtQueryVirtualMemory)); } while (0)

TEST(other3a_nt_zw_aliases)
{
    static const char *n[] = { "FlushInstructionCache", "FlushKey", "FlushProcessWriteBuffers", "FlushVirtualMemory",
        "FlushWriteBuffer", "FreeVirtualMemory", "GetWriteWatch", "LockVirtualMemory", "MapViewOfSection",
        "MapViewOfSectionEx", "ProtectVirtualMemory" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64]; FARPROC pa, pb;
        wsprintfA(a, "Nt%s", n[i]); wsprintfA(b, "Zw%s", n[i]);
        pa = t_proc(a); pb = t_proc(b);
        CHECKF(pa != NULL && pa == pb, "%s / %s", a, b);
    }
}

/* ---- NtFreeVirtualMemory ------------------------------------------------ */
TEST(other3a_free_release_and_zero_size)
{
    PVOID b; SIZE_T sz; mbi_t m; NEED_VM();
    b = amem(0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    sz = 0;
    EXPECT_EQ(N(NtFreeVirtualMemory)(SELF, &b, &sz, MEM_RELEASE), 0);
    EXPECT_EQ(sz, 0x3000);                                       /* size of the released region is returned */
    EXPECT_EQ(qry(b, &m), 0); EXPECT_EQ(m.state, MEM_FREE);
}
TEST(other3a_free_decommit_keeps_reservation_and_rezeroes)
{
    PVOID b, p; SIZE_T sz; mbi_t m; NEED_VM();
    b = amem(0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    ((BYTE *)b)[0x1000] = 0x5a;
    p = (BYTE *)b + 0x1000; sz = 0x1000;
    EXPECT_EQ(N(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_DECOMMIT), 0);
    EXPECT_EQ(p, (BYTE *)b + 0x1000); EXPECT_EQ(sz, 0x1000);
    EXPECT_EQ(qry((BYTE *)b + 0x1000, &m), 0); EXPECT_EQ(m.state, MEM_RESERVE); EXPECT_EQ(m.size, 0x1000);
    p = (BYTE *)b + 0x1000; sz = 0x1000;
    EXPECT_EQ(N(NtAllocateVirtualMemory)(SELF, &p, 0, &sz, MEM_COMMIT, PAGE_READWRITE), 0);
    EXPECT_EQ(((BYTE *)b)[0x1000], 0);                           /* recommitted pages are zero filled */
    rel(b);
}
TEST(other3a_free_decommit_unaligned_rounds_outward)
{
    PVOID b, p; SIZE_T sz; mbi_t m; NEED_VM();
    b = amem(0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    p = (BYTE *)b + 0x1800; sz = 0x1000;                          /* straddles pages 1 and 2 */
    EXPECT_EQ(N(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_DECOMMIT), 0);
    EXPECT_EQ(p, (BYTE *)b + 0x1000); EXPECT_EQ(sz, 0x2000);
    EXPECT_EQ(qry((BYTE *)b + 0x1000, &m), 0); EXPECT_EQ(m.state, MEM_RESERVE); EXPECT_EQ(m.size, 0x2000);
    EXPECT_EQ(qry(b, &m), 0); EXPECT_EQ(m.state, MEM_COMMIT); EXPECT_EQ(m.size, 0x1000);
    rel(b);
}
TEST(other3a_free_errors)
{
    PVOID b, p; SIZE_T sz; NEED_VM();
    b = amem(0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    p = b; sz = 0;
    EXPECT_EQ(N(NtFreeVirtualMemory)(SELF, &p, &sz, 0), XS(0xC00000F2));                    /* neither bit */
    p = b; sz = 0;
    EXPECT_EQ(N(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_RELEASE | MEM_DECOMMIT), XS(0xC00000F2));
    p = b; sz = 0;
    EXPECT_EQ(N(NtFreeVirtualMemory)(SELF, &p, &sz, 0x80000000u | MEM_RELEASE), XS(0xC00000F2));
    p = b; sz = 0;
    EXPECT_EQ(N(NtFreeVirtualMemory)((HANDLE)(LONG_PTR)-77, &p, &sz, MEM_RELEASE), XS(0xC0000008));
    p = (PVOID)0x10000; sz = 0;                                                               /* nothing allocated here */
    EXPECT_EQ(N(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_RELEASE), XS(0xC00000A0));          /* STATUS_MEMORY_NOT_ALLOCATED */
    rel(b);
}
TEST(other3a_free_release_with_size_releases_a_range)
{
    PVOID b, p; SIZE_T sz; mbi_t m; NEED_VM();
    b = amem(0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_RELEASE), 0);   /* native service, unlike VirtualFree, accepts a sub-range */
    EXPECT_EQ(sz, 0x1000);
    EXPECT_EQ(qry(b, &m), 0); EXPECT_EQ(m.state, MEM_FREE);
    EXPECT_EQ(qry((BYTE *)b + 0x1000, &m), 0); EXPECT_EQ(m.state, MEM_COMMIT); EXPECT_EQ(m.size, 0x2000);
    p = (BYTE *)b + 0x1000; sz = 0;
    EXPECT_EQ(N(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_RELEASE), 0);
    EXPECT_EQ(qry((BYTE *)b + 0x1000, &m), 0); EXPECT_EQ(m.state, MEM_FREE);
}

/* ---- NtProtectVirtualMemory -------------------------------------------- */
TEST(other3a_protect_basic_and_old_protection)
{
    PVOID b, p; SIZE_T sz; ULONG old; mbi_t m; NEED_VM(); REQUIRE(N(NtProtectVirtualMemory));
    b = amem(0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    p = (BYTE *)b + 0x1000; sz = 0x1000; old = 0xdead;
    EXPECT_EQ(N(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READONLY, &old), 0);
    EXPECT_EQ(old, PAGE_READWRITE); EXPECT_EQ(p, (BYTE *)b + 0x1000); EXPECT_EQ(sz, 0x1000);
    EXPECT_EQ(qry((BYTE *)b + 0x1000, &m), 0); EXPECT_EQ(m.prot, PAGE_READONLY); EXPECT_EQ(m.size, 0x1000); EXPECT_EQ(m.alloc_prot, PAGE_READWRITE);
    EXPECT_EQ(qry(b, &m), 0); EXPECT_EQ(m.prot, PAGE_READWRITE); EXPECT_EQ(m.size, 0x1000);
    p = (BYTE *)b + 0x1000; sz = 0x1000; old = 0;
    EXPECT_EQ(N(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READWRITE, &old), 0);
    EXPECT_EQ(old, PAGE_READONLY);
    rel(b);
}
TEST(other3a_protect_rounds_range_to_pages)
{
    PVOID b, p; SIZE_T sz; ULONG old; mbi_t m; NEED_VM(); REQUIRE(N(NtProtectVirtualMemory));
    b = amem(0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    p = (BYTE *)b + 0x1ff0; sz = 0x20;                           /* crosses the page 1/2 boundary */
    EXPECT_EQ(N(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READONLY, &old), 0);
    EXPECT_EQ(p, (BYTE *)b + 0x1000); EXPECT_EQ(sz, 0x2000);
    EXPECT_EQ(qry((BYTE *)b + 0x1000, &m), 0); EXPECT_EQ(m.prot, PAGE_READONLY); EXPECT_EQ(m.size, 0x2000);
    rel(b);
}
TEST(other3a_protect_guard_modifier_and_old_value)
{
    PVOID b, p; SIZE_T sz; ULONG old; mbi_t m; NEED_VM(); REQUIRE(N(NtProtectVirtualMemory));
    b = amem(0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READWRITE | PAGE_GUARD, &old), 0);
    EXPECT_EQ(old, PAGE_READWRITE);
    EXPECT_EQ(qry(b, &m), 0); EXPECT_EQ(m.prot, PAGE_READWRITE | PAGE_GUARD);
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_NOACCESS, &old), 0);
    EXPECT_EQ(old, PAGE_READWRITE | PAGE_GUARD);
    rel(b);
}
TEST(other3a_protect_errors)
{
    PVOID b, p; SIZE_T sz; ULONG old; NEED_VM(); REQUIRE(N(NtProtectVirtualMemory));
    b = amem(0x3000, MEM_RESERVE, PAGE_NOACCESS); CHECK(b != NULL); if (!b) return;
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtProtectVirtualMemory)(SELF, &p, &sz, 0x3, &old), XS(0xC0000045));          /* invalid protection value */
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtProtectVirtualMemory)(SELF, &p, &sz, 0, &old), XS(0xC0000045));
    p = b; sz = 0;
    EXPECT_EQ(N(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READWRITE, &old), XS(0xC00000F1)); /* zero size: invalid parameter 3 */
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtProtectVirtualMemory)((HANDLE)(LONG_PTR)-77, &p, &sz, PAGE_READWRITE, &old), XS(0xC0000008));
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READWRITE, &old), XS(0xC000002D));  /* STATUS_NOT_COMMITTED: range only reserved */
    rel(b);
}
TEST(other3a_protect_on_reserved_and_free_regions)
{
    PVOID b, p; SIZE_T sz; ULONG old = 0; NTSTATUS s; NEED_VM(); REQUIRE(N(NtProtectVirtualMemory));
    b = amem(0x2000, MEM_RESERVE, PAGE_NOACCESS); CHECK(b != NULL); if (!b) return;
    p = b; sz = 0x1000;
    s = N(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READWRITE, &old);
    EXPECT_EQ(s, XS(0xC000002D));
    rel(b);
    p = b; sz = 0x1000;
    s = N(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READWRITE, &old);
    EXPECT_EQ(s, XS(0xC0000018));                                 /* STATUS_CONFLICTING_ADDRESSES: range not allocated */
}

/* ---- NtFlushVirtualMemory ---------------------------------------------- */
TEST(other3a_flush_vm_private_and_section)
{
    PVOID b, p; SIZE_T sz; IO_STATUS_BLOCK io; NTSTATUS s; HANDLE sec; NEED_VM(); REQUIRE(N(NtFlushVirtualMemory));
    REQUIRE(N(NtCreateSection)); REQUIRE(N(NtMapViewOfSection)); REQUIRE(N(NtUnmapViewOfSection)); REQUIRE(N(NtClose));
    b = amem(0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    p = b; sz = 0x2000; memset(&io, 0xcc, sizeof io);
    s = N(NtFlushVirtualMemory)(SELF, &p, &sz, &io);
    EXPECT_EQ(s, XS(0xC0000019));                                /* STATUS_NOT_MAPPED_VIEW: private memory is not a view */
    rel(b);
    sec = mksec(0x2000); CHECK(sec != NULL); if (!sec) return;
    b = NULL; sz = 0;
    EXPECT_EQ(N(NtMapViewOfSection)(sec, SELF, &b, 0, 0, NULL, &sz, 1, 0, PAGE_READWRITE), 0);
    if (b) {
        ((BYTE *)b)[0] = 1;
        p = b; sz = 0x2000; memset(&io, 0xcc, sizeof io);
        s = N(NtFlushVirtualMemory)(SELF, &p, &sz, &io);
        EXPECT_EQ(s, XS(0xC0000088));                            /* STATUS_NOT_MAPPED_DATA: pagefile-backed view has no file */
        N(NtUnmapViewOfSection)(SELF, b);
    }
    N(NtClose)(sec);
}
TEST(other3a_flush_vm_errors)
{
    PVOID b, p; SIZE_T sz; IO_STATUS_BLOCK io; NEED_VM(); REQUIRE(N(NtFlushVirtualMemory));
    b = amem(0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtFlushVirtualMemory)((HANDLE)(LONG_PTR)-77, &p, &sz, &io), XS(0xC0000008));
    p = (PVOID)0x10000; sz = 0x1000;
    CHECK(N(NtFlushVirtualMemory)(SELF, &p, &sz, &io) < 0);
    rel(b);
}

/* ---- NtLockVirtualMemory ----------------------------------------------- */
TEST(other3a_lock_unlock_working_set)
{
    PVOID b, p; SIZE_T sz; NTSTATUS s; NEED_VM(); REQUIRE(N(NtLockVirtualMemory)); REQUIRE(N(NtUnlockVirtualMemory));
    b = amem(0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    p = b; sz = 0x2000;
    s = N(NtLockVirtualMemory)(SELF, &p, &sz, 1 /* MAP_PROCESS */);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(sz, 0x2000);
        p = b; sz = 0x2000;
        EXPECT_EQ(N(NtUnlockVirtualMemory)(SELF, &p, &sz, 1), 0);
        p = b; sz = 0x2000;
        EXPECT_EQ(N(NtUnlockVirtualMemory)(SELF, &p, &sz, 1), XS(0xC000002A));   /* STATUS_NOT_LOCKED */
    }
    rel(b);
}
TEST(other3a_lock_errors)
{
    PVOID b, p; SIZE_T sz; NEED_VM(); REQUIRE(N(NtLockVirtualMemory)); REQUIRE(N(NtUnlockVirtualMemory));
    b = amem(0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtLockVirtualMemory)(SELF, &p, &sz, 0), XS(0xC000000D));        /* no map type */
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtLockVirtualMemory)(SELF, &p, &sz, 4), XS(0xC000000D));
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtUnlockVirtualMemory)(SELF, &p, &sz, 0), XS(0xC000000D));
    p = b; sz = 0x1000;
    EXPECT_EQ(N(NtLockVirtualMemory)((HANDLE)(LONG_PTR)-77, &p, &sz, 1), XS(0xC0000008));
    p = b; sz = 0;
    EXPECT_EQ(N(NtLockVirtualMemory)(SELF, &p, &sz, 1), XS(0xC000000D));
    rel(b);
}

/* ---- NtGetWriteWatch ---------------------------------------------------- */
TEST(other3a_write_watch_reports_written_pages)
{
    PVOID b, addrs[16]; ULONG_PTR n; ULONG gran = 0; NTSTATUS s; NEED_VM(); REQUIRE(N(NtGetWriteWatch)); REQUIRE(N(NtResetWriteWatch));
    b = amem(0x8000, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    ((volatile BYTE *)b)[0x1000] = 1; ((volatile BYTE *)b)[0x5000] = 1; ((volatile BYTE *)b)[0x5008] = 2;
    n = 16; gran = 0;
    s = N(NtGetWriteWatch)(SELF, 0, b, 0x8000, addrs, &n, &gran);
    EXPECT_EQ(s, 0); EXPECT_EQ(n, 2); EXPECT_EQ(gran, 0x1000);
    if (n == 2) { EXPECT_EQ(addrs[0], (BYTE *)b + 0x1000); EXPECT_EQ(addrs[1], (BYTE *)b + 0x5000); }
    n = 16;                                                       /* no reset requested: same answer again */
    EXPECT_EQ(N(NtGetWriteWatch)(SELF, 1 /* RESET */, b, 0x8000, addrs, &n, &gran), 0); EXPECT_EQ(n, 2);
    n = 16;
    EXPECT_EQ(N(NtGetWriteWatch)(SELF, 0, b, 0x8000, addrs, &n, &gran), 0); EXPECT_EQ(n, 0);
    ((volatile BYTE *)b)[0x2000] = 1;
    EXPECT_EQ(N(NtResetWriteWatch)(SELF, b, 0x8000), 0);
    n = 16;
    EXPECT_EQ(N(NtGetWriteWatch)(SELF, 0, b, 0x8000, addrs, &n, &gran), 0); EXPECT_EQ(n, 0);
    rel(b);
}
TEST(other3a_write_watch_limited_array)
{
    PVOID b, addrs[2]; ULONG_PTR n; ULONG gran; NEED_VM(); REQUIRE(N(NtGetWriteWatch));
    b = amem(0x4000, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    for (int i = 0; i < 4; i++) ((volatile BYTE *)b)[i * 0x1000] = 1;
    n = 2;
    EXPECT_EQ(N(NtGetWriteWatch)(SELF, 0, b, 0x4000, addrs, &n, &gran), 0);
    EXPECT_EQ(n, 2);                                              /* array capacity limits the count */
    rel(b);
}
TEST(other3a_write_watch_errors)
{
    PVOID b, c, addrs[4]; ULONG_PTR n; ULONG gran; NTSTATUS s; NEED_VM(); REQUIRE(N(NtGetWriteWatch));
    b = amem(0x2000, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    c = amem(0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    n = 4;
    EXPECT_EQ(N(NtGetWriteWatch)(SELF, 2, b, 0x2000, addrs, &n, &gran), XS(0xC00000F0));     /* bad flags: invalid parameter 2 */
    n = 4;
    EXPECT_EQ(N(NtGetWriteWatch)(SELF, 0, b, 0, addrs, &n, &gran), XS(0xC00000F2));            /* zero size: invalid parameter 4 */
    n = 4;
    EXPECT_EQ(N(NtGetWriteWatch)((HANDLE)(LONG_PTR)-77, 0, b, 0x2000, addrs, &n, &gran), XS(0xC0000008));
    if (c) {
        n = 4;
        s = N(NtGetWriteWatch)(SELF, 0, c, 0x2000, addrs, &n, &gran);
        EXPECT_EQ(s, XS(0xC00000EF));                                                          /* region not write-watched (observed) */
        rel(c);
    }
    n = 0;
    s = N(NtGetWriteWatch)(SELF, 0, b, 0x2000, addrs, &n, &gran);
    EXPECT_EQ(s, XS(0xC00000F3));                                                              /* empty array: invalid parameter 5 */
    rel(b);
}

/* ---- NtMapViewOfSection / Ex -------------------------------------------- */
TEST(other3a_map_view_basic_and_unaligned_offset)
{
    HANDLE sec; PVOID b = NULL; SIZE_T vs = 0; LARGE_INTEGER off; mbi_t m; NEED_VM();
    REQUIRE(N(NtCreateSection)); REQUIRE(N(NtMapViewOfSection)); REQUIRE(N(NtUnmapViewOfSection)); REQUIRE(N(NtClose));
    sec = mksec(0x20000); CHECK(sec != NULL); if (!sec) return;
    EXPECT_EQ(N(NtMapViewOfSection)(sec, SELF, &b, 0, 0, NULL, &vs, 1, 0, PAGE_READWRITE), 0);
    EXPECT_EQ(vs, 0x20000); CHECK(b != NULL && ((ULONG_PTR)b & 0xffff) == 0);
    if (b) {
        EXPECT_EQ(qry(b, &m), 0); EXPECT_EQ(m.type, MEM_MAPPED); EXPECT_EQ(m.prot, PAGE_READWRITE); EXPECT_EQ(m.size, 0x20000);
        EXPECT_EQ(N(NtUnmapViewOfSection)(SELF, b), 0);
        EXPECT_EQ(N(NtUnmapViewOfSection)(SELF, b), XS(0xC0000019));         /* STATUS_NOT_MAPPED_VIEW */
    }
    b = NULL; vs = 0x1000; off.QuadPart = 0x1000;                              /* offset not 64K aligned */
    EXPECT_EQ(N(NtMapViewOfSection)(sec, SELF, &b, 0, 0, &off, &vs, 1, 0, PAGE_READWRITE), XS(0xC0000220));    /* STATUS_MAPPED_ALIGNMENT */
    b = NULL; vs = 0x1000; off.QuadPart = 0x10000;
    EXPECT_EQ(N(NtMapViewOfSection)(sec, SELF, &b, 0, 0, &off, &vs, 1, 0, PAGE_READWRITE), 0);
    EXPECT_EQ(vs, 0x1000);
    if (b) N(NtUnmapViewOfSection)(SELF, b);
    N(NtClose)(sec);
}
TEST(other3a_map_view_errors)
{
    HANDLE sec; PVOID b; SIZE_T vs; LARGE_INTEGER off; NEED_VM();
    REQUIRE(N(NtCreateSection)); REQUIRE(N(NtMapViewOfSection)); REQUIRE(N(NtUnmapViewOfSection)); REQUIRE(N(NtClose));
    sec = mksec(0x10000); CHECK(sec != NULL); if (!sec) return;
    b = NULL; vs = 0;
    EXPECT_EQ(N(NtMapViewOfSection)((HANDLE)(LONG_PTR)-77, SELF, &b, 0, 0, NULL, &vs, 1, 0, PAGE_READWRITE), XS(0xC0000008));
    b = NULL; vs = 0;
    EXPECT_EQ(N(NtMapViewOfSection)(sec, (HANDLE)(LONG_PTR)-77, &b, 0, 0, NULL, &vs, 1, 0, PAGE_READWRITE), XS(0xC0000008));
    b = NULL; vs = 0;
    EXPECT_EQ(N(NtMapViewOfSection)(sec, SELF, &b, 0, 0, NULL, &vs, 1, 0, 0x3), XS(0xC0000045));
    b = NULL; vs = 0x20000;                                                    /* larger than the section */
    EXPECT_EQ(N(NtMapViewOfSection)(sec, SELF, &b, 0, 0, NULL, &vs, 1, 0, PAGE_READWRITE), XS(0xC000001F));
    b = NULL; vs = 0; off.QuadPart = 0x20000;                                  /* offset beyond the section */
    EXPECT_EQ(N(NtMapViewOfSection)(sec, SELF, &b, 0, 0, &off, &vs, 1, 0, PAGE_READWRITE), XS(0xC000001F));  /* STATUS_INVALID_VIEW_SIZE */
    b = NULL; vs = 0;
    EXPECT_EQ(N(NtMapViewOfSection)(sec, SELF, &b, 0, 0, NULL, &vs, 1, 0, PAGE_EXECUTE_READWRITE), XS(0xC000004E));  /* STATUS_SECTION_PROTECTION */
    if (b) N(NtUnmapViewOfSection)(SELF, b);
    N(NtClose)(sec);
}
TEST(other3a_map_view_ex_basic)
{
    HANDLE sec; PVOID b = NULL; SIZE_T vs = 0; mbi_t m; NTSTATUS s; NEED_VM();
    REQUIRE(N(NtCreateSection)); REQUIRE(N(NtMapViewOfSectionEx)); REQUIRE(N(NtUnmapViewOfSection)); REQUIRE(N(NtClose));
    sec = mksec(0x4000); CHECK(sec != NULL); if (!sec) return;
    s = N(NtMapViewOfSectionEx)(sec, SELF, &b, NULL, &vs, 0, PAGE_READWRITE, NULL, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(vs, 0x4000);
    if (b) {
        EXPECT_EQ(qry(b, &m), 0); EXPECT_EQ(m.type, MEM_MAPPED); EXPECT_EQ(m.prot, PAGE_READWRITE);
        ((BYTE *)b)[0x3fff] = 3;
        EXPECT_EQ(N(NtUnmapViewOfSection)(SELF, b), 0);
    }
    b = NULL; vs = 0;
    EXPECT_EQ(N(NtMapViewOfSectionEx)((HANDLE)(LONG_PTR)-77, SELF, &b, NULL, &vs, 0, PAGE_READWRITE, NULL, 0), XS(0xC0000008));
    b = NULL; vs = 0;
    EXPECT_EQ(N(NtMapViewOfSectionEx)(sec, SELF, &b, NULL, &vs, 0, 0x3, NULL, 0), XS(0xC0000045));
    b = NULL; vs = 0;
    s = N(NtMapViewOfSectionEx)(sec, SELF, &b, NULL, &vs, 0, PAGE_READWRITE, NULL, 1);   /* count without array */
    EXPECT_EQ(s, XS(0xC000000D));
    if (b) N(NtUnmapViewOfSection)(SELF, b);
    N(NtClose)(sec);
}
TEST(other3a_map_view_two_views_share_data)
{
    HANDLE sec; PVOID a = NULL, b = NULL; SIZE_T va = 0, vb = 0; NEED_VM();
    REQUIRE(N(NtCreateSection)); REQUIRE(N(NtMapViewOfSection)); REQUIRE(N(NtMapViewOfSectionEx)); REQUIRE(N(NtUnmapViewOfSection)); REQUIRE(N(NtClose));
    sec = mksec(0x1000); CHECK(sec != NULL); if (!sec) return;
    EXPECT_EQ(N(NtMapViewOfSection)(sec, SELF, &a, 0, 0, NULL, &va, 1, 0, PAGE_READWRITE), 0);
    EXPECT_EQ(N(NtMapViewOfSectionEx)(sec, SELF, &b, NULL, &vb, 0, PAGE_READONLY, NULL, 0), 0);
    CHECK(a && b && a != b);
    if (a && b) { ((volatile BYTE *)a)[17] = 0x42; EXPECT_EQ(((volatile BYTE *)b)[17], 0x42); }
    if (a) N(NtUnmapViewOfSection)(SELF, a);
    if (b) N(NtUnmapViewOfSection)(SELF, b);
    N(NtClose)(sec);
}

/* ---- Flush services ----------------------------------------------------- */
TEST(other3a_flush_instruction_cache)
{
    PVOID b; NTSTATUS s; NEED_VM(); REQUIRE(N(NtFlushInstructionCache));
    b = amem(0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(b != NULL); if (!b) return;
    EXPECT_EQ(N(NtFlushInstructionCache)(SELF, b, 0x1000), 0);
    EXPECT_EQ(N(NtFlushInstructionCache)(SELF, NULL, 0), 0);                    /* whole-process form */
    EXPECT_EQ(N(NtFlushInstructionCache)((HANDLE)(LONG_PTR)-77, b, 0x10), 0);  /* handle is not validated (observed) */
    EXPECT_EQ(N(NtFlushInstructionCache)(SELF, (PVOID)0x10000, 0x10), 0);       /* unmapped range is not validated */
    rel(b);
}
TEST(other3a_flush_write_buffers)
{
    REQUIRE(N(NtFlushWriteBuffer)); REQUIRE(N(NtFlushProcessWriteBuffers));
    EXPECT_EQ(N(NtFlushWriteBuffer)(), 0);
    N(NtFlushProcessWriteBuffers)();                              /* returns no status; must simply return */
    CHECK(1);
}

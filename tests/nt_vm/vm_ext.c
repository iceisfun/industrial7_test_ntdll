/* Virtual memory services: reserve/commit/decommit/release transitions, protection changes,
 * region queries, section views and locking. Nothing here faults deliberately. */
#include "t.h"

UDECL(NTSTATUS, NtAllocateVirtualMemory, (HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG));
UDECL(NTSTATUS, NtFreeVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtProtectVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryVirtualMemory, (HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtLockVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtUnlockVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtFlushVirtualMemory, (HANDLE, PVOID *, PSIZE_T, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtCreateSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE));
UDECL(NTSTATUS, NtMapViewOfSection, (HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtUnmapViewOfSection, (HANDLE, PVOID));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define XS(x) ((NTSTATUS)(x))
#define XOK(s) ((NTSTATUS)(s) >= 0)
#define XV_NEED() do { REQUIRE(UN(NtAllocateVirtualMemory)); REQUIRE(UN(NtFreeVirtualMemory)); REQUIRE(UN(NtProtectVirtualMemory)); REQUIRE(UN(NtQueryVirtualMemory)); } while (0)
#define SELF ((HANDLE)(LONG_PTR)-1)
typedef struct { PVOID base, alloc_base; ULONG alloc_prot, pad1; SIZE_T size; ULONG state, prot, type, pad2; } xv_mbi;

static NTSTATUS xv_query(PVOID p, xv_mbi *m) { SIZE_T r = 0; memset(m, 0xcc, sizeof *m); return UN(NtQueryVirtualMemory)(SELF, p, 0, m, sizeof *m, &r); }
static PVOID xv_alloc(SIZE_T size, ULONG type, ULONG prot)
{
    PVOID base = NULL; SIZE_T sz = size;
    if (!XOK(UN(NtAllocateVirtualMemory)(SELF, &base, 0, &sz, type, prot))) return NULL;
    return base;
}
static void xv_release(PVOID base) { SIZE_T sz = 0; UN(NtFreeVirtualMemory)(SELF, &base, &sz, MEM_RELEASE); }

TEST(nt_vm_x_alloc_rounds_size_and_aligns_base)
{
    PVOID base = NULL; SIZE_T sz = 1; xv_mbi m; XV_NEED();
    EXPECT_EQ(UN(NtAllocateVirtualMemory)(SELF, &base, 0, &sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), 0);
    EXPECT_EQ(sz, 0x1000);
    CHECK(base != NULL && ((ULONG_PTR)base & 0xffff) == 0);       /* reservations start on the allocation granularity */
    EXPECT_EQ(xv_query(base, &m), 0);
    EXPECT_EQ(m.state, MEM_COMMIT); EXPECT_EQ(m.prot, PAGE_READWRITE); EXPECT_EQ(m.alloc_prot, PAGE_READWRITE);
    EXPECT_EQ(m.type, MEM_PRIVATE); EXPECT_EQ(m.size, 0x1000); EXPECT_EQ(m.alloc_base, base); EXPECT_EQ(m.base, base);
    ((volatile BYTE *)base)[0] = 7; ((volatile BYTE *)base)[0xfff] = 9;
    EXPECT_EQ(((volatile BYTE *)base)[0], 7);
    xv_release(base);
}
TEST(nt_vm_x_alloc_zero_filled)
{
    PVOID base = xv_alloc(0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); XV_NEED();
    CHECK(base != NULL); if (!base) return;
    for (int i = 0; i < 0x3000; i += 0x100) CHECK(((BYTE *)base)[i] == 0);
    xv_release(base);
}
TEST(nt_vm_x_reserve_then_commit_then_decommit)
{
    PVOID base, p; SIZE_T sz; xv_mbi m; XV_NEED();
    base = xv_alloc(0x10000, MEM_RESERVE, PAGE_NOACCESS); CHECK(base != NULL); if (!base) return;
    EXPECT_EQ(xv_query(base, &m), 0);
    EXPECT_EQ(m.state, MEM_RESERVE); EXPECT_EQ(m.prot, 0); EXPECT_EQ(m.size, 0x10000); EXPECT_EQ(m.type, MEM_PRIVATE);
    p = (BYTE *)base + 0x2000; sz = 0x2000;
    EXPECT_EQ(UN(NtAllocateVirtualMemory)(SELF, &p, 0, &sz, MEM_COMMIT, PAGE_READWRITE), 0);
    EXPECT_EQ(p, (BYTE *)base + 0x2000); EXPECT_EQ(sz, 0x2000);
    EXPECT_EQ(xv_query((BYTE *)base + 0x2000, &m), 0);
    EXPECT_EQ(m.state, MEM_COMMIT); EXPECT_EQ(m.size, 0x2000); EXPECT_EQ(m.alloc_base, base);
    EXPECT_EQ(m.alloc_prot, PAGE_NOACCESS);                        /* the reservation's own protection is remembered */
    EXPECT_EQ(xv_query(base, &m), 0); EXPECT_EQ(m.state, MEM_RESERVE); EXPECT_EQ(m.size, 0x2000);
    EXPECT_EQ(xv_query((BYTE *)base + 0x4000, &m), 0); EXPECT_EQ(m.state, MEM_RESERVE); EXPECT_EQ(m.size, 0xc000);
    p = (BYTE *)base + 0x2000; sz = 0x2000;
    EXPECT_EQ(UN(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_DECOMMIT), 0);
    EXPECT_EQ(xv_query((BYTE *)base + 0x2000, &m), 0); EXPECT_EQ(m.state, MEM_RESERVE);
    xv_release(base);
}
TEST(nt_vm_x_commit_rounds_unaligned_range)
{
    PVOID base, p; SIZE_T sz; xv_mbi m; XV_NEED();
    base = xv_alloc(0x10000, MEM_RESERVE, PAGE_NOACCESS); CHECK(base != NULL); if (!base) return;
    p = (BYTE *)base + 0x1801; sz = 0x1000;                       /* straddles two pages */
    EXPECT_EQ(UN(NtAllocateVirtualMemory)(SELF, &p, 0, &sz, MEM_COMMIT, PAGE_READWRITE), 0);
    EXPECT_EQ(p, (BYTE *)base + 0x1000); EXPECT_EQ(sz, 0x2000);
    EXPECT_EQ(xv_query((BYTE *)base + 0x1000, &m), 0); EXPECT_EQ(m.state, MEM_COMMIT); EXPECT_EQ(m.size, 0x2000);
    xv_release(base);
}
TEST(nt_vm_x_alloc_error_statuses)
{
    PVOID base; SIZE_T sz; NTSTATUS s; XV_NEED();
    base = NULL; sz = 0;
    s = UN(NtAllocateVirtualMemory)(SELF, &base, 0, &sz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(!XOK(s)); t_note("zero size status=%08lx", s);
    base = NULL; sz = 0x1000;
    s = UN(NtAllocateVirtualMemory)(SELF, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, 0x3);          /* not a protection value */
    EXPECT_EQ(s, XS(0xC0000045));
    base = NULL; sz = 0x1000;
    s = UN(NtAllocateVirtualMemory)(SELF, &base, 0, &sz, 0, PAGE_READWRITE);                     /* no allocation type */
    CHECK(!XOK(s)); t_note("no type status=%08lx", s);
    base = NULL; sz = 0x1000;
    s = UN(NtAllocateVirtualMemory)(SELF, &base, 0, &sz, MEM_RESERVE | MEM_DECOMMIT, PAGE_READWRITE);
    CHECK(!XOK(s)); t_note("reserve|decommit status=%08lx", s);
    base = NULL; sz = (SIZE_T)1 << 62;
    s = UN(NtAllocateVirtualMemory)(SELF, &base, 0, &sz, MEM_RESERVE, PAGE_READWRITE);
    CHECK(!XOK(s)); t_note("huge size status=%08lx", s);
    base = NULL; sz = 0x1000;
    EXPECT_EQ(UN(NtAllocateVirtualMemory)((HANDLE)(ULONG_PTR)0x7ffc, &base, 0, &sz, MEM_RESERVE, PAGE_READWRITE), XS(0xC0000008));
}
TEST(nt_vm_x_alloc_fixed_address_conflicts)
{
    PVOID base, again; SIZE_T sz = 0x1000; NTSTATUS s; XV_NEED();
    base = xv_alloc(0x10000, MEM_RESERVE, PAGE_NOACCESS); CHECK(base != NULL); if (!base) return;
    again = base; sz = 0x10000;
    s = UN(NtAllocateVirtualMemory)(SELF, &again, 0, &sz, MEM_RESERVE, PAGE_READWRITE);
    EXPECT_EQ(s, XS(0xC0000018));                                  /* STATUS_CONFLICTING_ADDRESSES */
    again = (BYTE *)base + 0x8000; sz = 0x20000;                   /* overlaps the tail */
    s = UN(NtAllocateVirtualMemory)(SELF, &again, 0, &sz, MEM_RESERVE, PAGE_READWRITE);
    EXPECT_EQ(s, XS(0xC0000018));
    again = (BYTE *)base + 0x20000; sz = 0x1000;                   /* commit with no reservation behind it */
    s = UN(NtAllocateVirtualMemory)(SELF, &again, 0, &sz, MEM_COMMIT, PAGE_READWRITE);
    t_note("commit outside any reservation status=%08lx", s);
    if (XOK(s)) xv_release(again);
    xv_release(base);
}
TEST(nt_vm_x_free_rules)
{
    PVOID base, p; SIZE_T sz; NTSTATUS s; XV_NEED();
    base = xv_alloc(0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(base != NULL); if (!base) return;
    p = (BYTE *)base + 0x1000; sz = 0;
    s = UN(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_RELEASE);
    EXPECT_EQ(s, XS(0xC000009F));                                  /* STATUS_FREE_VM_NOT_AT_BASE */
    p = base; sz = 0x1000;
    s = UN(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_RELEASE);       /* the size is ignored for MEM_RELEASE and the whole reservation is released */
    EXPECT_EQ(s, 0);
    if (XOK(s)) {
        xv_mbi m;
        EXPECT_EQ(xv_query(base, &m), 0); EXPECT_EQ(m.state, MEM_FREE);
        base = xv_alloc(0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(base != NULL); if (!base) return;
    }
    p = base; sz = 0;
    s = UN(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_RELEASE | MEM_DECOMMIT);
    CHECK(!XOK(s)); t_note("release|decommit status=%08lx", s);
    p = base; sz = 0;
    s = UN(NtFreeVirtualMemory)(SELF, &p, &sz, 0);
    CHECK(!XOK(s)); t_note("no free type status=%08lx", s);
    p = base; sz = 0;
    EXPECT_EQ(UN(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_RELEASE), 0);
    EXPECT_EQ(sz, 0x10000);                                        /* the size of the released region is reported */
    p = base; sz = 0;
    EXPECT_EQ(UN(NtFreeVirtualMemory)(SELF, &p, &sz, MEM_RELEASE), XS(0xC00000A0));   /* STATUS_MEMORY_NOT_ALLOCATED */
}
TEST(nt_vm_x_protect_transitions)
{
    PVOID base, p; SIZE_T sz; ULONG old; xv_mbi m; XV_NEED();
    base = xv_alloc(0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(base != NULL); if (!base) return;
    p = (BYTE *)base + 0x1000; sz = 0x1000; old = 0;
    EXPECT_EQ(UN(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READONLY, &old), 0);
    EXPECT_EQ(old, PAGE_READWRITE);
    EXPECT_EQ(xv_query((BYTE *)base + 0x1000, &m), 0); EXPECT_EQ(m.prot, PAGE_READONLY); EXPECT_EQ(m.size, 0x1000);
    EXPECT_EQ(xv_query(base, &m), 0); EXPECT_EQ(m.prot, PAGE_READWRITE); EXPECT_EQ(m.size, 0x1000);
    EXPECT_EQ(m.alloc_prot, PAGE_READWRITE);
    p = (BYTE *)base + 0x1000; sz = 0x1000;
    EXPECT_EQ(UN(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_EXECUTE_READ, &old), 0); EXPECT_EQ(old, PAGE_READONLY);
    p = (BYTE *)base + 0x1000; sz = 0x1000;
    EXPECT_EQ(UN(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_NOACCESS, &old), 0);
    p = (BYTE *)base + 0x1000; sz = 0x1000;
    EXPECT_EQ(UN(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READWRITE | PAGE_GUARD, &old), 0); EXPECT_EQ(old, PAGE_NOACCESS);
    EXPECT_EQ(xv_query((BYTE *)base + 0x1000, &m), 0); EXPECT_EQ(m.prot, PAGE_READWRITE | PAGE_GUARD);
    xv_release(base);
}
TEST(nt_vm_x_protect_rounds_range_and_old_protect)
{
    PVOID base, p; SIZE_T sz; ULONG old; xv_mbi m; XV_NEED();
    base = xv_alloc(0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(base != NULL); if (!base) return;
    p = (BYTE *)base + 0x1ff0; sz = 0x20; old = 0;                 /* crosses a page boundary */
    EXPECT_EQ(UN(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READONLY, &old), 0);
    EXPECT_EQ(p, (BYTE *)base + 0x1000); EXPECT_EQ(sz, 0x2000);
    EXPECT_EQ(xv_query((BYTE *)base + 0x1000, &m), 0); EXPECT_EQ(m.prot, PAGE_READONLY); EXPECT_EQ(m.size, 0x2000);
    xv_release(base);
}
TEST(nt_vm_x_protect_error_statuses)
{
    PVOID base, p; SIZE_T sz; ULONG old; NTSTATUS s; XV_NEED();
    base = xv_alloc(0x10000, MEM_RESERVE, PAGE_NOACCESS); CHECK(base != NULL); if (!base) return;
    p = base; sz = 0x1000;
    s = UN(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READWRITE, &old);
    EXPECT_EQ(s, XS(0xC000002D));                                  /* reserved but not committed */
    xv_release(base);
    base = xv_alloc(0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(base != NULL); if (!base) return;
    p = base; sz = 0x1000;
    EXPECT_EQ(UN(NtProtectVirtualMemory)(SELF, &p, &sz, 0x3, &old), XS(0xC0000045));
    p = base; sz = 0x1000;
    EXPECT_EQ(UN(NtProtectVirtualMemory)(SELF, &p, &sz, 0, &old), XS(0xC0000045));
    p = base; sz = 0x1000;
    EXPECT_EQ(UN(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READWRITE | PAGE_NOCACHE | PAGE_WRITECOMBINE, &old), XS(0xC0000045));  /* mutually exclusive modifiers */
    xv_release(base);
    p = (PVOID)0x7ff000000000; sz = 0x1000;                        /* an address nothing occupies */
    s = UN(NtProtectVirtualMemory)(SELF, &p, &sz, PAGE_READWRITE, &old);
    EXPECT_EQ(s, XS(0xC0000018));
    base = xv_alloc(0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (base) { p = base; sz = 0x1000; EXPECT_EQ(UN(NtProtectVirtualMemory)((HANDLE)(ULONG_PTR)0x7ffc, &p, &sz, PAGE_READONLY, &old), XS(0xC0000008)); xv_release(base); }
}
TEST(nt_vm_x_query_free_and_null_page_regions)
{
    xv_mbi m; PVOID base; XV_NEED();
    EXPECT_EQ(xv_query((PVOID)0, &m), 0);
    /* The free region at address zero runs up to the next allocation; the shared user data page sits at 0x7ffe0000. */
    EXPECT_EQ(m.state, MEM_FREE); EXPECT_EQ(m.prot, PAGE_NOACCESS); CHECK(m.size >= 0x10000 && m.size <= 0x7ffe0000); EXPECT_EQ(m.alloc_base, NULL); EXPECT_EQ(m.type, 0);
    EXPECT_EQ(xv_query((PVOID)0x1234, &m), 0);
    EXPECT_EQ(m.base, (PVOID)0x1000); CHECK(m.size >= 0xF000 && (ULONG_PTR)m.base + m.size <= 0x7ffe0000);   /* base is rounded down to the page */
    base = xv_alloc(0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (base) { EXPECT_EQ(xv_query((BYTE *)base + 0x123, &m), 0); EXPECT_EQ(m.base, base); xv_release(base); }
}
TEST(nt_vm_x_query_argument_errors)
{
    xv_mbi m; SIZE_T r = 0; NTSTATUS s; XV_NEED();
    s = UN(NtQueryVirtualMemory)(SELF, (PVOID)0x10000, 0, &m, sizeof m - 1, &r);
    EXPECT_EQ(s, XS(0xC0000004));
    s = UN(NtQueryVirtualMemory)(SELF, (PVOID)0x10000, 0, &m, 0, &r);
    EXPECT_EQ(s, XS(0xC0000004));
    s = UN(NtQueryVirtualMemory)(SELF, (PVOID)0x10000, 0x7fff, &m, sizeof m, &r);
    EXPECT_EQ(s, XS(0xC0000003));
    s = UN(NtQueryVirtualMemory)(SELF, (PVOID)0x7fffffff0000ULL, 0, &m, sizeof m, &r);   /* beyond the user address range */
    EXPECT_EQ(s, XS(0xC000000D));
    s = UN(NtQueryVirtualMemory)((HANDLE)(ULONG_PTR)0x7ffc, (PVOID)0x10000, 0, &m, sizeof m, &r);
    EXPECT_EQ(s, XS(0xC0000008));
    s = UN(NtQueryVirtualMemory)(SELF, (PVOID)0x10000, 0, &m, sizeof m, NULL);              /* return length is optional */
    CHECK(XOK(s));
}
TEST(nt_vm_x_query_reports_return_length)
{
    xv_mbi m; SIZE_T r = 0; XV_NEED();
    EXPECT_EQ(UN(NtQueryVirtualMemory)(SELF, (PVOID)0x10000, 0, &m, sizeof m, &r), 0);
    EXPECT_EQ(r, 48);
    CHECK(sizeof m == 48);
}

/* ---- sections --------------------------------------------------------------------- */
#define XV_SEC_NEED() do { XV_NEED(); REQUIRE(UN(NtCreateSection)); REQUIRE(UN(NtMapViewOfSection)); REQUIRE(UN(NtUnmapViewOfSection)); REQUIRE(UN(NtClose)); } while (0)
static HANDLE xv_section(LONGLONG size, ULONG prot)
{
    HANDLE h = NULL; LARGE_INTEGER sz; sz.QuadPart = size;
    if (!XOK(UN(NtCreateSection)(&h, SECTION_ALL_ACCESS, NULL, &sz, prot, SEC_COMMIT, NULL))) return NULL;
    return h;
}
TEST(nt_vm_x_section_views_share_memory)
{
    HANDLE sec; PVOID v1 = NULL, v2 = NULL; SIZE_T s1 = 0, s2 = 0; xv_mbi m; XV_SEC_NEED();
    sec = xv_section(0x10000, PAGE_READWRITE); CHECK(sec != NULL); if (!sec) return;
    EXPECT_EQ(UN(NtMapViewOfSection)(sec, SELF, &v1, 0, 0, NULL, &s1, 2 /* ViewUnmap */, 0, PAGE_READWRITE), 0);
    EXPECT_EQ(UN(NtMapViewOfSection)(sec, SELF, &v2, 0, 0, NULL, &s2, 2, 0, PAGE_READWRITE), 0);
    CHECK(v1 != NULL && v2 != NULL && v1 != v2);
    EXPECT_EQ(s1, 0x10000); EXPECT_EQ(s2, 0x10000);
    if (v1 && v2) {
        ((volatile ULONG *)v1)[3] = 0xdeadbeef;
        EXPECT_EQ(((volatile ULONG *)v2)[3], 0xdeadbeef);         /* both views alias the same pages */
        EXPECT_EQ(xv_query(v1, &m), 0); EXPECT_EQ(m.type, MEM_MAPPED); EXPECT_EQ(m.state, MEM_COMMIT); EXPECT_EQ(m.size, 0x10000); EXPECT_EQ(m.prot, PAGE_READWRITE);
    }
    if (v1) EXPECT_EQ(UN(NtUnmapViewOfSection)(SELF, v1), 0);
    if (v2) EXPECT_EQ(UN(NtUnmapViewOfSection)(SELF, v2), 0);
    if (v1) EXPECT_EQ(UN(NtUnmapViewOfSection)(SELF, v1), XS(0xC0000019));          /* STATUS_NOT_MAPPED_VIEW */
    UN(NtClose)(sec);
}
TEST(nt_vm_x_section_view_survives_section_close)
{
    HANDLE sec; PVOID v = NULL; SIZE_T s = 0; XV_SEC_NEED();
    sec = xv_section(0x2000, PAGE_READWRITE); CHECK(sec != NULL); if (!sec) return;
    EXPECT_EQ(UN(NtMapViewOfSection)(sec, SELF, &v, 0, 0, NULL, &s, 2, 0, PAGE_READWRITE), 0);
    EXPECT_EQ(UN(NtClose)(sec), 0);
    if (v) { ((volatile ULONG *)v)[0] = 5; EXPECT_EQ(((volatile ULONG *)v)[0], 5); EXPECT_EQ(UN(NtUnmapViewOfSection)(SELF, v), 0); }
}
TEST(nt_vm_x_section_partial_view_and_offset)
{
    HANDLE sec; PVOID v1 = NULL, v2 = NULL; SIZE_T s1 = 0x1000, s2 = 0x1000; LARGE_INTEGER off; NTSTATUS st; XV_SEC_NEED();
    sec = xv_section(0x20000, PAGE_READWRITE); CHECK(sec != NULL); if (!sec) return;
    v1 = NULL; s1 = 0x1000; off.QuadPart = 0;
    EXPECT_EQ(UN(NtMapViewOfSection)(sec, SELF, &v1, 0, 0, &off, &s1, 2, 0, PAGE_READWRITE), 0);
    EXPECT_EQ(s1, 0x1000);
    off.QuadPart = 0x10000;
    EXPECT_EQ(UN(NtMapViewOfSection)(sec, SELF, &v2, 0, 0, &off, &s2, 2, 0, PAGE_READWRITE), 0);
    if (v1 && v2) { ((volatile ULONG *)v1)[0] = 1; ((volatile ULONG *)v2)[0] = 2; EXPECT_EQ(((volatile ULONG *)v1)[0], 1); }
    if (v1) UN(NtUnmapViewOfSection)(SELF, v1);
    if (v2) UN(NtUnmapViewOfSection)(SELF, v2);
    { PVOID v3 = NULL; SIZE_T s3 = 0x1000; off.QuadPart = 0x1000;
      st = UN(NtMapViewOfSection)(sec, SELF, &v3, 0, 0, &off, &s3, 2, 0, PAGE_READWRITE);
      EXPECT_EQ(st, XS(0xC0000220));                                 /* offset must be a multiple of the allocation granularity */
      if (XOK(st) && v3) UN(NtUnmapViewOfSection)(SELF, v3); }
    UN(NtClose)(sec);
}
TEST(nt_vm_x_section_view_size_errors)
{
    HANDLE sec; PVOID v = NULL; SIZE_T s; LARGE_INTEGER off; NTSTATUS st; XV_SEC_NEED();
    sec = xv_section(0x10000, PAGE_READWRITE); CHECK(sec != NULL); if (!sec) return;
    s = 0x20000; off.QuadPart = 0;
    st = UN(NtMapViewOfSection)(sec, SELF, &v, 0, 0, &off, &s, 2, 0, PAGE_READWRITE);
    EXPECT_EQ(st, XS(0xC000001F));                                   /* STATUS_INVALID_VIEW_SIZE */
    if (XOK(st) && v) UN(NtUnmapViewOfSection)(SELF, v);
    v = NULL; s = 0x1000; off.QuadPart = 0x20000;
    st = UN(NtMapViewOfSection)(sec, SELF, &v, 0, 0, &off, &s, 2, 0, PAGE_READWRITE);
    CHECK(!XOK(st)); t_note("offset past the end status=%08lx", st);
    if (XOK(st) && v) UN(NtUnmapViewOfSection)(SELF, v);
    UN(NtClose)(sec);
}
TEST(nt_vm_x_section_protection_limits)
{
    HANDLE sec; PVOID v = NULL; SIZE_T s = 0; NTSTATUS st; XV_SEC_NEED();
    sec = xv_section(0x4000, PAGE_READONLY); CHECK(sec != NULL); if (!sec) return;
    st = UN(NtMapViewOfSection)(sec, SELF, &v, 0, 0, NULL, &s, 2, 0, PAGE_READWRITE);
    EXPECT_EQ(st, XS(0xC000004E));                                   /* STATUS_SECTION_PROTECTION */
    if (XOK(st) && v) UN(NtUnmapViewOfSection)(SELF, v);
    v = NULL; s = 0;
    st = UN(NtMapViewOfSection)(sec, SELF, &v, 0, 0, NULL, &s, 2, 0, PAGE_READONLY);
    EXPECT_EQ(st, 0);
    if (v) { xv_mbi m; EXPECT_EQ(xv_query(v, &m), 0); EXPECT_EQ(m.prot, PAGE_READONLY); UN(NtUnmapViewOfSection)(SELF, v); }
    UN(NtClose)(sec);
}
TEST(nt_vm_x_section_create_errors)
{
    HANDLE h = NULL; LARGE_INTEGER sz; NTSTATUS s; XV_SEC_NEED();
    sz.QuadPart = 0;
    s = UN(NtCreateSection)(&h, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT, NULL);
    CHECK(!XOK(s)); t_note("zero-size anonymous section status=%08lx", s); if (h) { UN(NtClose)(h); h = NULL; }
    s = UN(NtCreateSection)(&h, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READWRITE, SEC_COMMIT, NULL);
    CHECK(!XOK(s)); t_note("anonymous section without a size status=%08lx", s); if (h) { UN(NtClose)(h); h = NULL; }
    sz.QuadPart = 0x1000;
    s = UN(NtCreateSection)(&h, SECTION_ALL_ACCESS, NULL, &sz, 0x3, SEC_COMMIT, NULL);
    EXPECT_EQ(s, XS(0xC0000045)); if (h) { UN(NtClose)(h); h = NULL; }
    s = UN(NtCreateSection)(&h, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, 0, NULL);
    CHECK(!XOK(s)); t_note("no allocation attributes status=%08lx", s); if (h) { UN(NtClose)(h); h = NULL; }
    sz.QuadPart = -1;
    s = UN(NtCreateSection)(&h, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT, NULL);
    CHECK(!XOK(s)); t_note("negative size status=%08lx", s); if (h) { UN(NtClose)(h); h = NULL; }
}
TEST(nt_vm_x_unmap_non_view_addresses)
{
    PVOID base; XV_SEC_NEED();
    EXPECT_EQ(UN(NtUnmapViewOfSection)(SELF, (PVOID)0x10000), XS(0xC0000019));
    base = xv_alloc(0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (base) { EXPECT_EQ(UN(NtUnmapViewOfSection)(SELF, base), XS(0xC0000019)); xv_release(base); }   /* private memory is not a view */
    EXPECT_EQ(UN(NtUnmapViewOfSection)((HANDLE)(ULONG_PTR)0x7ffc, (PVOID)0x10000), XS(0xC0000008));
}

/* ---- locking and flushing ---------------------------------------------------------- */
TEST(nt_vm_x_lock_and_unlock_pages)
{
    PVOID base, p; SIZE_T sz; NTSTATUS s; XV_NEED(); REQUIRE(UN(NtLockVirtualMemory)); REQUIRE(UN(NtUnlockVirtualMemory));
    base = xv_alloc(0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); CHECK(base != NULL); if (!base) return;
    p = base; sz = 0x1000;
    s = UN(NtLockVirtualMemory)(SELF, &p, &sz, 1 /* MAP_PROCESS */);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        p = base; sz = 0x1000;
        EXPECT_EQ(UN(NtUnlockVirtualMemory)(SELF, &p, &sz, 1), 0);
        p = base; sz = 0x1000;
        EXPECT_EQ(UN(NtUnlockVirtualMemory)(SELF, &p, &sz, 1), XS(0xC000002A));      /* STATUS_NOT_LOCKED */
    }
    p = (BYTE *)base + 0x1000; sz = 0x1000;
    EXPECT_EQ(UN(NtUnlockVirtualMemory)(SELF, &p, &sz, 1), XS(0xC000002A));
    p = base; sz = 0x1000;
    s = UN(NtUnlockVirtualMemory)(SELF, &p, &sz, 0);                                  /* no map type */
    CHECK(!XOK(s)); t_note("unlock without a map type status=%08lx", s);
    xv_release(base);
}
TEST(nt_vm_x_flush_private_and_mapped)
{
    HANDLE sec; PVOID v = NULL, p; SIZE_T s = 0, sz; IO_STATUS_BLOCK io; NTSTATUS st; XV_SEC_NEED(); REQUIRE(UN(NtFlushVirtualMemory));
    sec = xv_section(0x2000, PAGE_READWRITE); CHECK(sec != NULL); if (!sec) return;
    EXPECT_EQ(UN(NtMapViewOfSection)(sec, SELF, &v, 0, 0, NULL, &s, 2, 0, PAGE_READWRITE), 0);
    if (v) {
        ((volatile ULONG *)v)[0] = 1;
        p = v; sz = 0x1000; memset(&io, 0xcc, sizeof io);
        st = UN(NtFlushVirtualMemory)(SELF, &p, &sz, &io);
        EXPECT_EQ(st, XS(0xC0000088));   /* STATUS_NOT_MAPPED_DATA: a pagefile-backed view has no file to flush to */
        UN(NtUnmapViewOfSection)(SELF, v);
    }
    p = (PVOID)0x10000; sz = 0x1000;
    st = UN(NtFlushVirtualMemory)(SELF, &p, &sz, &io);
    CHECK(!XOK(st)); t_note("flush of unallocated memory status=%08lx", st);
    UN(NtClose)(sec);
}

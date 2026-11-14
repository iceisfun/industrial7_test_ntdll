/* Memory-related natives: NtFlushInstructionCache, NtFlushVirtualMemory, NtFlushProcessWriteBuffers,
 * NtFlushWriteBuffer, NtLockVirtualMemory, NtGetWriteWatch, NtMapViewOfSectionEx. */
#include "t.h"

UDECL(NTSTATUS, NtFlushInstructionCache, (HANDLE, PVOID, SIZE_T));
UDECL(NTSTATUS, NtFlushVirtualMemory, (HANDLE, PVOID *, PSIZE_T, PIO_STATUS_BLOCK));
UDECL(VOID, NtFlushProcessWriteBuffers, (VOID));
UDECL(NTSTATUS, NtFlushWriteBuffer, (VOID));
UDECL(NTSTATUS, NtLockVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtUnlockVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtGetWriteWatch, (HANDLE, ULONG, PVOID, SIZE_T, PVOID *, PULONG_PTR, PULONG));
UDECL(NTSTATUS, NtResetWriteWatch, (HANDLE, PVOID, SIZE_T));
UDECL(NTSTATUS, NtMapViewOfSectionEx, (HANDLE, HANDLE, PVOID *, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtUnmapViewOfSection, (HANDLE, PVOID));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define XS(x) ((NTSTATUS)(x))
#define PSEUDO_PROC ((HANDLE)(LONG_PTR)-1)

TEST(alias_pairs)
{
    const char *n[] = { "FlushInstructionCache", "FlushVirtualMemory", "FlushProcessWriteBuffers", "FlushWriteBuffer",
        "LockVirtualMemory", "GetWriteWatch", "MapViewOfSectionEx" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64]; wsprintfA(a, "Nt%s", n[i]); wsprintfA(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a), pb = t_proc(b);
        if (!pa || !pb) { t_skip("missing %s", pa ? b : a); return; }
        CHECKF(pa == pb, "%s and %s differ", a, b);
    }
}

TEST(flush_instruction_cache)
{
    REQUIRE(UN(NtFlushInstructionCache));
    BYTE *p = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    CHECK(p != NULL); if (!p) return;
    p[0] = 0xc3;
    EXPECT_EQ(UN(NtFlushInstructionCache)(PSEUDO_PROC, p, 1), 0);
    EXPECT_EQ(UN(NtFlushInstructionCache)(PSEUDO_PROC, p, 4096), 0);
    EXPECT_EQ(UN(NtFlushInstructionCache)(GetCurrentProcess(), p, 16), 0);
    /* NULL base / zero length means "flush everything" */
    EXPECT_EQ(UN(NtFlushInstructionCache)(PSEUDO_PROC, NULL, 0), 0);
    ((void (*)(void))p)();
    /* the process handle is not validated on Windows 10: invalid handles succeed (observed) */
    EXPECT_EQ(UN(NtFlushInstructionCache)((HANDLE)(LONG_PTR)0x7777c, p, 1), 0);
    EXPECT_EQ(UN(NtFlushInstructionCache)(NULL, p, 1), 0);
    VirtualFree(p, 0, MEM_RELEASE);
}

TEST(flush_write_buffers)
{
    REQUIRE(UN(NtFlushProcessWriteBuffers));
    REQUIRE(UN(NtFlushWriteBuffer));
    UN(NtFlushProcessWriteBuffers)();
    UN(NtFlushProcessWriteBuffers)();
    EXPECT_EQ(UN(NtFlushWriteBuffer)(), 0);
    EXPECT_EQ(UN(NtFlushWriteBuffer)(), 0);
}

TEST(flush_virtual_memory)
{
    REQUIRE(UN(NtFlushVirtualMemory));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "fvm.bin");
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(f != INVALID_HANDLE_VALUE); if (f == INVALID_HANDLE_VALUE) return;
    HANDLE m = CreateFileMappingA(f, NULL, PAGE_READWRITE, 0, 8192, NULL);
    BYTE *v = m ? MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    CHECK(v != NULL);
    if (v) {
        IO_STATUS_BLOCK io; PVOID base; SIZE_T sz;
        v[0] = 0x5a; v[4096] = 0xa5;
        memset(&io, 0xcc, sizeof io); base = v; sz = 8192;
        EXPECT_EQ(UN(NtFlushVirtualMemory)(PSEUDO_PROC, &base, &sz, &io), 0);
        EXPECT_EQ(io.Status, 0);
        EXPECT_EQ((ULONG_PTR)base, (ULONG_PTR)v);
        EXPECT_EQ(sz, 8192);
        /* unaligned request is rounded out to page boundaries */
        memset(&io, 0xcc, sizeof io); base = v + 10; sz = 20;
        EXPECT_EQ(UN(NtFlushVirtualMemory)(PSEUDO_PROC, &base, &sz, &io), 0);
        EXPECT_EQ((ULONG_PTR)base, (ULONG_PTR)v);
        EXPECT_EQ(sz, 4096);
        /* bad handle */
        base = v; sz = 4096;
        EXPECT_EQ(UN(NtFlushVirtualMemory)((HANDLE)(LONG_PTR)0x7777c, &base, &sz, &io), XS(0xC0000008));
        UnmapViewOfFile(v);
        /* the flushed data reached the file */
        BYTE rb[2]; DWORD n = 0;
        SetFilePointer(f, 0, NULL, FILE_BEGIN);
        CHECK(ReadFile(f, rb, 1, &n, NULL) && n == 1);
        EXPECT_EQ(rb[0], 0x5a);
    }
    /* unallocated memory */
    {
        BYTE *r = VirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_NOACCESS);
        IO_STATUS_BLOCK io; PVOID base = r; SIZE_T sz = 4096;
        NTSTATUS s = UN(NtFlushVirtualMemory)(PSEUDO_PROC, &base, &sz, &io);
        EXPECT_EQ(s, XS(0xC0000019)); /* STATUS_NOT_MAPPED_DATA */
        if (r) VirtualFree(r, 0, MEM_RELEASE);
    }
    if (m) CloseHandle(m);
    CloseHandle(f);
}

TEST(lock_virtual_memory)
{
    REQUIRE(UN(NtLockVirtualMemory)); REQUIRE(UN(NtUnlockVirtualMemory));
    BYTE *p = VirtualAlloc(NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(p != NULL); if (!p) return;
    PVOID base = p; SIZE_T sz = 100;
    NTSTATUS s = UN(NtLockVirtualMemory)(PSEUDO_PROC, &base, &sz, 1 /* MAP_PROCESS */);
    EXPECT_EQ(s, 0);
    EXPECT_EQ((ULONG_PTR)base, (ULONG_PTR)p);
    EXPECT_EQ(sz, 4096);
    if (s == 0) {
        /* second lock of the same page succeeds as well, each needs its own unlock */
        base = p; sz = 4096;
        s = UN(NtLockVirtualMemory)(PSEUDO_PROC, &base, &sz, 1);
        EXPECT_EQ(s, XS(0x40000019)); /* STATUS_WAS_LOCKED */
        base = p; sz = 4096;
        EXPECT_EQ(UN(NtUnlockVirtualMemory)(PSEUDO_PROC, &base, &sz, 1), 0);
        if (s >= 0) { base = p; sz = 4096; UN(NtUnlockVirtualMemory)(PSEUDO_PROC, &base, &sz, 1); }
    }
    /* invalid map type */
    base = p; sz = 4096;
    EXPECT_EQ(UN(NtLockVirtualMemory)(PSEUDO_PROC, &base, &sz, 0), XS(0xC000000D));
    base = p; sz = 4096;
    EXPECT_EQ(UN(NtLockVirtualMemory)(PSEUDO_PROC, &base, &sz, 4), XS(0xC000000D));
    base = p; sz = 4096;
    EXPECT_EQ(UN(NtLockVirtualMemory)((HANDLE)(LONG_PTR)0x7777c, &base, &sz, 1), XS(0xC0000008));
    /* unaligned within second page, size spans */
    base = p + 4090; sz = 20;
    s = UN(NtLockVirtualMemory)(PSEUDO_PROC, &base, &sz, 1);
    EXPECT_EQ(s, 0);
    EXPECT_EQ((ULONG_PTR)base, (ULONG_PTR)p);
    EXPECT_EQ(sz, 8192);
    if (s == 0) { base = p; sz = 8192; UN(NtUnlockVirtualMemory)(PSEUDO_PROC, &base, &sz, 1); }
    VirtualFree(p, 0, MEM_RELEASE);
}

TEST(write_watch)
{
    REQUIRE(UN(NtGetWriteWatch));
    const SIZE_T pg = 4096, n = 8;
    BYTE *p = VirtualAlloc(NULL, n * pg, MEM_COMMIT | MEM_RESERVE | MEM_WRITE_WATCH, PAGE_READWRITE);
    CHECK(p != NULL); if (!p) return;
    PVOID addrs[16]; ULONG_PTR cnt; ULONG gran = 0; NTSTATUS s;
    /* nothing written yet */
    cnt = 16; s = UN(NtGetWriteWatch)(PSEUDO_PROC, 0, p, n * pg, addrs, &cnt, &gran);
    EXPECT_EQ(s, 0); EXPECT_EQ(cnt, 0); EXPECT_EQ(gran, 4096);
    p[pg * 1] = 1; p[pg * 5 + 7] = 2;
    cnt = 16; gran = 0;
    s = UN(NtGetWriteWatch)(PSEUDO_PROC, 0, p, n * pg, addrs, &cnt, &gran);
    EXPECT_EQ(s, 0); EXPECT_EQ(cnt, 2); EXPECT_EQ(gran, 4096);
    if (cnt == 2) { EXPECT_EQ((ULONG_PTR)addrs[0], (ULONG_PTR)(p + pg)); EXPECT_EQ((ULONG_PTR)addrs[1], (ULONG_PTR)(p + 5 * pg)); }
    /* small output array: count is clamped to the array size */
    cnt = 1; s = UN(NtGetWriteWatch)(PSEUDO_PROC, 0, p, n * pg, addrs, &cnt, &gran);
    EXPECT_EQ(s, 0); EXPECT_EQ(cnt, 1);
    /* reset flag (1) returns the hits and clears them */
    cnt = 16; s = UN(NtGetWriteWatch)(PSEUDO_PROC, 1, p, n * pg, addrs, &cnt, &gran);
    EXPECT_EQ(s, 0); EXPECT_EQ(cnt, 2);
    cnt = 16; s = UN(NtGetWriteWatch)(PSEUDO_PROC, 0, p, n * pg, addrs, &cnt, &gran);
    EXPECT_EQ(s, 0); EXPECT_EQ(cnt, 0);
    /* NtResetWriteWatch */
    if (UN(NtResetWriteWatch)) {
        p[pg * 3] = 9;
        EXPECT_EQ(UN(NtResetWriteWatch)(PSEUDO_PROC, p, n * pg), 0);
        cnt = 16; s = UN(NtGetWriteWatch)(PSEUDO_PROC, 0, p, n * pg, addrs, &cnt, &gran);
        EXPECT_EQ(cnt, 0);
    }
    /* errors */
    cnt = 16; EXPECT_EQ(UN(NtGetWriteWatch)(PSEUDO_PROC, 2, p, n * pg, addrs, &cnt, &gran), XS(0xC00000F0));
    cnt = 16; EXPECT_EQ(UN(NtGetWriteWatch)(PSEUDO_PROC, 0, p, 0, addrs, &cnt, &gran), XS(0xC00000F2));
    cnt = 16; EXPECT_EQ(UN(NtGetWriteWatch)(PSEUDO_PROC, 0, p + 1, pg, addrs, &cnt, &gran), 0); /* unaligned base is rounded */
    cnt = 16; EXPECT_EQ(UN(NtGetWriteWatch)((HANDLE)(LONG_PTR)0x7777c, 0, p, pg, addrs, &cnt, &gran), XS(0xC0000008));
    {   /* region not allocated with MEM_WRITE_WATCH */
        BYTE *q = VirtualAlloc(NULL, pg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        cnt = 16; EXPECT_EQ(UN(NtGetWriteWatch)(PSEUDO_PROC, 0, q, pg, addrs, &cnt, &gran), XS(0xC00000EF));
        if (q) VirtualFree(q, 0, MEM_RELEASE);
    }
    VirtualFree(p, 0, MEM_RELEASE);
}

TEST(map_view_of_section_ex)
{
    REQUIRE(UN(NtMapViewOfSectionEx)); REQUIRE(UN(NtUnmapViewOfSection));
    HANDLE m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 65536, NULL);
    CHECK(m != NULL); if (!m) return;
    BYTE *a = MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, 0);
    CHECK(a != NULL); if (!a) { CloseHandle(m); return; }
    memcpy(a + 5000, "section-ex", 11);
    PVOID base = NULL; SIZE_T vs = 0; LARGE_INTEGER off; NTSTATUS s;
    off.QuadPart = 0;
    s = UN(NtMapViewOfSectionEx)(m, PSEUDO_PROC, &base, &off, &vs, 0, PAGE_READWRITE, NULL, 0);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(vs, 65536);
    if (s == 0) {
        CHECK(base != NULL && base != (PVOID)a);
        CHECK(!memcmp((BYTE *)base + 5000, "section-ex", 11));
        ((BYTE *)base)[0] = 0x77;
        EXPECT_EQ(a[0], 0x77);
        EXPECT_EQ(UN(NtUnmapViewOfSection)(PSEUDO_PROC, base), 0);
    }
    /* section offset 64 KiB granularity: nonzero unaligned offset is rejected */
    base = NULL; vs = 0; off.QuadPart = 4096;
    s = UN(NtMapViewOfSectionEx)(m, PSEUDO_PROC, &base, &off, &vs, 0, PAGE_READWRITE, NULL, 0);
    EXPECT_EQ(s, XS(0xC0000220)); /* STATUS_MAPPED_ALIGNMENT */
    if (s >= 0) UN(NtUnmapViewOfSection)(PSEUDO_PROC, base);
    /* partial view with a size */
    base = NULL; vs = 4096; off.QuadPart = 0;
    s = UN(NtMapViewOfSectionEx)(m, PSEUDO_PROC, &base, &off, &vs, 0, PAGE_READONLY, NULL, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(vs, 4096);
    if (s == 0) {
        MEMORY_BASIC_INFORMATION mbi;
        CHECK(VirtualQuery(base, &mbi, sizeof mbi) == sizeof mbi);
        EXPECT_EQ(mbi.Protect, PAGE_READONLY);
        EXPECT_EQ(mbi.Type, MEM_MAPPED);
        UN(NtUnmapViewOfSection)(PSEUDO_PROC, base);
    }
    /* bad handles */
    base = NULL; vs = 0; off.QuadPart = 0;
    EXPECT_EQ(UN(NtMapViewOfSectionEx)((HANDLE)(LONG_PTR)0x7777c, PSEUDO_PROC, &base, &off, &vs, 0, PAGE_READWRITE, NULL, 0), XS(0xC0000008));
    base = NULL; vs = 0;
    EXPECT_EQ(UN(NtMapViewOfSectionEx)(m, (HANDLE)(LONG_PTR)0x7777c, &base, &off, &vs, 0, PAGE_READWRITE, NULL, 0), XS(0xC0000008));
    UnmapViewOfFile(a);
    CloseHandle(m);
}

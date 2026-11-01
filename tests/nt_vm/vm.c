#include "t.h"

UDECL(NTSTATUS, NtAllocateVirtualMemory, (HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG));
UDECL(NTSTATUS, NtFreeVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG));
UDECL(NTSTATUS, NtProtectVirtualMemory, (HANDLE, PVOID *, PSIZE_T, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryVirtualMemory, (HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtReadVirtualMemory, (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtWriteVirtualMemory, (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtCreateSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE));
UDECL(NTSTATUS, NtMapViewOfSection, (HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtUnmapViewOfSection, (HANDLE, PVOID));
UDECL(NTSTATUS, NtQuerySection, (HANDLE, ULONG, PVOID, SIZE_T, PSIZE_T));

#define SELF ((HANDLE)(LONG_PTR)-1)
#define ST(x) ((NTSTATUS)(x))
#define VM_APIS() do { REQUIRE(UN(NtAllocateVirtualMemory)); REQUIRE(UN(NtFreeVirtualMemory)); } while (0)

static SIZE_T page_size(void) { SYSTEM_INFO s; GetSystemInfo(&s); return s.dwPageSize; }
static SIZE_T rounded(SIZE_T n) { SIZE_T p = page_size(); return (n + p - 1) & ~(p - 1); }
static void release_vm(PVOID p) {
    SIZE_T n = 0;
    if (p) EXPECT_EQ(UN(NtFreeVirtualMemory)(SELF, &p, &n, MEM_RELEASE), 0);
}
static PVOID allocate_vm(SIZE_T bytes, ULONG flags, ULONG protect, SIZE_T *actual) {
    PVOID p = NULL; SIZE_T n = bytes;
    NTSTATUS s = UN(NtAllocateVirtualMemory)(SELF, &p, 0, &n, flags, protect);
    EXPECT_EQ(s, 0);
    if (s < 0 || !p) { if (s >= 0) CHECK(p != NULL); return NULL; }
    if (actual) *actual = n;
    return p;
}
static int query_vm(PVOID p, MEMORY_BASIC_INFORMATION *m) {
    SIZE_T n = 0;
    NTSTATUS s = UN(NtQueryVirtualMemory)(SELF, p, 0, m, sizeof *m, &n);
    EXPECT_EQ(s, 0);
    if (s < 0) return 0;
    EXPECT_EQ(n, sizeof *m);
    return 1;
}
static void allocation_case(SIZE_T bytes, ULONG protect, int what) {
    VM_APIS(); REQUIRE(UN(NtQueryVirtualMemory));
    SIZE_T n = 0; PVOID p = allocate_vm(bytes, MEM_RESERVE | MEM_COMMIT, protect, &n);
    if (!p) return;
    MEMORY_BASIC_INFORMATION m;
    EXPECT_EQ(n, rounded(bytes));
    EXPECT_EQ((ULONG_PTR)p % page_size(), 0);
    if (query_vm(p, &m)) {
        EXPECT_EQ(m.BaseAddress, p); EXPECT_EQ(m.AllocationBase, p);
        EXPECT_EQ(m.State, MEM_COMMIT); EXPECT_EQ(m.Type, MEM_PRIVATE);
        EXPECT_EQ(m.Protect, protect); EXPECT_EQ(m.AllocationProtect, protect);
        CHECK(m.RegionSize >= n);
    }
    if (what && protect != PAGE_NOACCESS) {
        SIZE_T i; int zero = 1;
        for (i = 0; i < n; ++i) if (((BYTE *)p)[i]) { zero = 0; break; }
        CHECK(zero);
    }
    release_vm(p);
}
TEST(nt_vm_allocate_one_byte) { allocation_case(1, PAGE_READWRITE, 0); }
TEST(nt_vm_allocate_page_minus_one) { allocation_case(page_size()-1, PAGE_READWRITE, 0); }
TEST(nt_vm_allocate_one_page) { allocation_case(page_size(), PAGE_READWRITE, 0); }
TEST(nt_vm_allocate_page_plus_one) { allocation_case(page_size()+1, PAGE_READWRITE, 0); }
TEST(nt_vm_allocate_three_pages) { allocation_case(page_size()*3, PAGE_READWRITE, 0); }
TEST(nt_vm_allocate_readonly) { allocation_case(1, PAGE_READONLY, 0); }
TEST(nt_vm_allocate_noaccess) { allocation_case(1, PAGE_NOACCESS, 0); }
TEST(nt_vm_zero_fill_small) { allocation_case(1, PAGE_READWRITE, 1); }
TEST(nt_vm_zero_fill_rounded_tail) { allocation_case(page_size()+7, PAGE_READWRITE, 1); }
TEST(nt_vm_zero_fill_readonly) { allocation_case(page_size(), PAGE_READONLY, 1); }

static void reserve_case(int mode) {
    VM_APIS(); REQUIRE(UN(NtQueryVirtualMemory));
    SIZE_T n = page_size()*3; PVOID p = allocate_vm(n, MEM_RESERVE, PAGE_READWRITE, NULL);
    if (!p) return;
    MEMORY_BASIC_INFORMATION m;
    if (query_vm(p, &m)) { EXPECT_EQ(m.State, MEM_RESERVE); EXPECT_EQ(m.AllocationBase, p); }
    if (mode) {
        PVOID q = (BYTE *)p + (mode == 2 ? page_size() : 0); SIZE_T z = 1;
        NTSTATUS s = UN(NtAllocateVirtualMemory)(SELF, &q, 0, &z, MEM_COMMIT, PAGE_READWRITE);
        EXPECT_EQ(s, 0);
        if (s >= 0 && q) {
            EXPECT_EQ(z, page_size());
            if (query_vm(q, &m)) { EXPECT_EQ(m.State, MEM_COMMIT); EXPECT_EQ(m.AllocationBase, p); }
            CHECK(((BYTE *)q)[0] == 0); CHECK(((BYTE *)q)[z-1] == 0);
        }
    }
    release_vm(p);
}
TEST(nt_vm_reserve_only) { reserve_case(0); }
TEST(nt_vm_commit_reserved_first_page) { reserve_case(1); }
TEST(nt_vm_commit_reserved_middle_page) { reserve_case(2); }

static void alloc_failure(ULONG flags, ULONG protect, SIZE_T size) {
    VM_APIS(); PVOID p = NULL; SIZE_T n = size;
    NTSTATUS s = UN(NtAllocateVirtualMemory)(SELF, &p, 0, &n, flags, protect);
    CHECK(s < 0);
    if (s < 0) { EXPECT_EQ(p, NULL); EXPECT_EQ(n, size); }
    else release_vm(p);
    t_note("allocation validation status=%08lx", (ULONG)s);
}
TEST(nt_vm_allocate_zero_size_rejected) { alloc_failure(MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE, 0); }
TEST(nt_vm_allocate_missing_type_rejected) { alloc_failure(0, PAGE_READWRITE, 1); }
TEST(nt_vm_allocate_release_flag_rejected) { alloc_failure(MEM_RELEASE, PAGE_READWRITE, 1); }
TEST(nt_vm_allocate_invalid_protection_rejected) { alloc_failure(MEM_RESERVE|MEM_COMMIT, 0, 1); }

static void query_failure(SIZE_T bytes, ULONG cls) {
    VM_APIS(); REQUIRE(UN(NtQueryVirtualMemory));
    PVOID p=allocate_vm(1,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE,NULL);
    if(!p) return;
    MEMORY_BASIC_INFORMATION out; SIZE_T n=0;
    NTSTATUS s=UN(NtQueryVirtualMemory)(SELF,p,cls,&out,bytes,&n);
    EXPECT_EQ(s,cls==0 ? ST(0xc0000004) : ST(0xc0000003));
    release_vm(p);
}
TEST(nt_vm_query_zero_length) { query_failure(0,0); }
TEST(nt_vm_query_short_length) { query_failure(sizeof(MEMORY_BASIC_INFORMATION)-1,0); }
TEST(nt_vm_query_invalid_class) { query_failure(sizeof(MEMORY_BASIC_INFORMATION),0xffffffff); }

static void protect_case(ULONG protection, int unaligned, int restore) {
    VM_APIS(); REQUIRE(UN(NtProtectVirtualMemory)); REQUIRE(UN(NtQueryVirtualMemory));
    PVOID p = allocate_vm(page_size()*2, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE, NULL);
    if (!p) return;
    PVOID q = (BYTE *)p + (unaligned ? 7 : 0); SIZE_T n = 1; ULONG old = 0;
    NTSTATUS s = UN(NtProtectVirtualMemory)(SELF, &q, &n, protection, &old);
    EXPECT_EQ(s, 0);
    if (s >= 0) {
        EXPECT_EQ(q, p); EXPECT_EQ(n, page_size()); EXPECT_EQ(old, PAGE_READWRITE);
        MEMORY_BASIC_INFORMATION m;
        if (query_vm(p, &m)) EXPECT_EQ(m.Protect, protection);
        if (query_vm((BYTE *)p + page_size(), &m)) EXPECT_EQ(m.Protect, PAGE_READWRITE);
        if (restore) {
            s = UN(NtProtectVirtualMemory)(SELF, &q, &n, PAGE_READWRITE, &old);
            EXPECT_EQ(s, 0);
            if (s >= 0) EXPECT_EQ(old, protection);
        }
    }
    release_vm(p);
}
TEST(nt_vm_protect_readonly) { protect_case(PAGE_READONLY, 0, 0); }
TEST(nt_vm_protect_noaccess) { protect_case(PAGE_NOACCESS, 0, 0); }
TEST(nt_vm_protect_same_protection) { protect_case(PAGE_READWRITE, 0, 0); }
TEST(nt_vm_protect_unaligned_rounds) { protect_case(PAGE_READONLY, 1, 0); }
TEST(nt_vm_protect_restore_readonly) { protect_case(PAGE_READONLY, 0, 1); }
TEST(nt_vm_protect_restore_noaccess) { protect_case(PAGE_NOACCESS, 0, 1); }
static void protect_failure(int zero) {
    VM_APIS(); REQUIRE(UN(NtProtectVirtualMemory));
    PVOID p = allocate_vm(page_size(), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE, NULL);
    if (!p) return;
    PVOID q = p; SIZE_T n = zero ? 0 : page_size(); ULONG old = 0;
    NTSTATUS s = UN(NtProtectVirtualMemory)(SELF, &q, &n, zero ? PAGE_READONLY : 0, &old);
    EXPECT_EQ(s, zero ? ST(0xc00000f1) : ST(0xc0000045));
    release_vm(p);
}
TEST(nt_vm_protect_zero_size_status) { protect_failure(1); }
TEST(nt_vm_protect_invalid_protection_status) { protect_failure(0); }

static void transfer_case(int write, SIZE_T length, SIZE_T offset, int optional) {
    VM_APIS(); REQUIRE(UN(NtReadVirtualMemory)); REQUIRE(UN(NtWriteVirtualMemory));
    SIZE_T n = page_size()*2;
    PVOID p = allocate_vm(n, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE, NULL);
    if (!p) return;
    BYTE buffer[8192];
    if (length > sizeof buffer || offset > n || length > n-offset) { release_vm(p); t_skip("page size exceeds bounded fixture"); return; }
    for (SIZE_T i = 0; i < n; ++i) ((BYTE *)p)[i] = (BYTE)(i*17+3);
    for (SIZE_T i = 0; i < sizeof buffer; ++i) buffer[i] = (BYTE)(i*7+11);
    SIZE_T done = ~(SIZE_T)0;
    NTSTATUS s = write ? UN(NtWriteVirtualMemory)(SELF, (BYTE *)p+offset, buffer, length, optional ? NULL : &done)
                       : UN(NtReadVirtualMemory)(SELF, (BYTE *)p+offset, buffer, length, optional ? NULL : &done);
    EXPECT_EQ(s, 0);
    if (s >= 0) {
        if (!optional) EXPECT_EQ(done, length);
        CHECK(!memcmp((BYTE *)p+offset, buffer, length));
        if (write && offset) EXPECT_EQ(((BYTE *)p)[offset-1], (BYTE)((offset-1)*17+3));
        if (write && offset+length<n) EXPECT_EQ(((BYTE *)p)[offset+length], (BYTE)((offset+length)*17+3));
    }
    release_vm(p);
}
TEST(nt_vm_read_zero_bytes) { transfer_case(0, 0, 0, 0); }
TEST(nt_vm_read_one_byte) { transfer_case(0, 1, 0, 0); }
TEST(nt_vm_read_unaligned) { transfer_case(0, 31, 7, 0); }
TEST(nt_vm_read_page_boundary) { transfer_case(0, 32, page_size()-16, 0); }
TEST(nt_vm_read_optional_count) { transfer_case(0, 32, 0, 1); }
TEST(nt_vm_write_zero_bytes) { transfer_case(1, 0, 0, 0); }
TEST(nt_vm_write_one_byte) { transfer_case(1, 1, 0, 0); }
TEST(nt_vm_write_unaligned) { transfer_case(1, 31, 7, 0); }
TEST(nt_vm_write_page_boundary) { transfer_case(1, 32, page_size()-16, 0); }
TEST(nt_vm_write_optional_count) { transfer_case(1, 32, 0, 1); }

static void decommit_case(int recommit) {
    VM_APIS(); REQUIRE(UN(NtQueryVirtualMemory));
    PVOID p = allocate_vm(page_size()*2, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE, NULL);
    if (!p) return;
    memset(p, 0x5a, page_size()); PVOID q = p; SIZE_T n = 1;
    NTSTATUS s = UN(NtFreeVirtualMemory)(SELF, &q, &n, MEM_DECOMMIT);
    EXPECT_EQ(s, 0);
    if (s >= 0) {
        EXPECT_EQ(q, p); EXPECT_EQ(n, page_size());
        MEMORY_BASIC_INFORMATION m;
        if (query_vm(p, &m)) EXPECT_EQ(m.State, MEM_RESERVE);
        if (query_vm((BYTE *)p+page_size(), &m)) EXPECT_EQ(m.State, MEM_COMMIT);
        if (recommit) {
            s = UN(NtAllocateVirtualMemory)(SELF, &q, 0, &n, MEM_COMMIT, PAGE_READWRITE);
            EXPECT_EQ(s, 0);
            if (s >= 0) { int zero = 1; for (SIZE_T i=0;i<n;++i) if (((BYTE *)q)[i]) zero=0; CHECK(zero); }
        }
    }
    release_vm(p);
}
TEST(nt_vm_decommit_rounding) { decommit_case(0); }
TEST(nt_vm_recommit_zero_fills) { decommit_case(1); }
TEST(nt_vm_free_conflicting_types_rejected) {
    VM_APIS(); PVOID p = allocate_vm(1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE, NULL);
    if (!p) return;
    PVOID q=p; SIZE_T n=page_size(); NTSTATUS s=UN(NtFreeVirtualMemory)(SELF,&q,&n,MEM_RELEASE|MEM_DECOMMIT);
    EXPECT_EQ(s,ST(0xc00000f2));
    if (s<0) release_vm(p);
}

typedef struct { PVOID BaseAddress; ULONG AllocationAttributes; LARGE_INTEGER MaximumSize; } VM_SECTION_BASIC;
#define SECTION_APIS() do { REQUIRE(UN(NtCreateSection)); REQUIRE(UN(NtMapViewOfSection)); REQUIRE(UN(NtUnmapViewOfSection)); REQUIRE(UN(NtQuerySection)); } while (0)
static void section_case(SIZE_T bytes, SIZE_T requested, ULONG protection, int mode) {
    SECTION_APIS();
    LARGE_INTEGER max; max.QuadPart=bytes; HANDLE h=NULL;
    NTSTATUS s=UN(NtCreateSection)(&h, SECTION_QUERY|SECTION_MAP_READ|SECTION_MAP_WRITE, NULL, &max, PAGE_READWRITE, SEC_COMMIT, NULL);
    EXPECT_EQ(s,0); if(s<0 || !h) { if(s>=0) CHECK(h!=NULL); return; }
    VM_SECTION_BASIC info; SIZE_T got=0;
    s=UN(NtQuerySection)(h,0,&info,sizeof info,&got); EXPECT_EQ(s,0);
    if(s>=0) { EXPECT_EQ(got,sizeof info); EXPECT_EQ(info.MaximumSize.QuadPart,rounded(bytes)); CHECK(info.AllocationAttributes & SEC_COMMIT); }
    PVOID p=NULL; SIZE_T n=requested;
    s=UN(NtMapViewOfSection)(h,SELF,&p,0,0,NULL,&n,2,0,protection); EXPECT_EQ(s,0);
    if(s>=0 && p) {
        EXPECT_EQ(n, requested ? rounded(requested) : rounded(bytes));
        int zero=1; for(SIZE_T i=0;i<n;++i) if(((BYTE *)p)[i]) zero=0; CHECK(zero);
        if(mode==1) {
            PVOID q=NULL; SIZE_T z=0;
            s=UN(NtMapViewOfSection)(h,SELF,&q,0,0,NULL,&z,2,0,PAGE_READWRITE); EXPECT_EQ(s,0);
            if(s>=0 && q) { ((BYTE *)p)[0]=0x67; EXPECT_EQ(((BYTE *)q)[0],0x67); ((BYTE *)q)[z-1]=0x39; EXPECT_EQ(((BYTE *)p)[z-1],0x39); EXPECT_EQ(UN(NtUnmapViewOfSection)(SELF,q),0); }
        }
        if(mode==2) { CHECK(CloseHandle(h)); h=NULL; EXPECT_EQ(((BYTE *)p)[0],0); }
        EXPECT_EQ(UN(NtUnmapViewOfSection)(SELF,mode==3 ? (BYTE *)p+7 : p),0);
    } else if(s>=0) CHECK(p!=NULL);
    if(h) CHECK(CloseHandle(h));
}
TEST(nt_vm_section_one_byte) { section_case(1,0,PAGE_READWRITE,0); }
TEST(nt_vm_section_page_plus_one) { section_case(page_size()+1,0,PAGE_READWRITE,0); }
TEST(nt_vm_section_partial_view_rounding) { section_case(page_size()*2,1,PAGE_READWRITE,0); }
TEST(nt_vm_section_readonly_view) { section_case(page_size(),0,PAGE_READONLY,0); }
TEST(nt_vm_section_shared_views) { section_case(page_size(),0,PAGE_READWRITE,1); }
TEST(nt_vm_section_view_survives_handle) { section_case(page_size(),0,PAGE_READWRITE,2); }
TEST(nt_vm_section_unmap_interior_address) { section_case(page_size(),0,PAGE_READWRITE,3); }

static void section_query_failure(SIZE_T length, ULONG cls) {
    SECTION_APIS(); HANDLE h=NULL; LARGE_INTEGER max; max.QuadPart=page_size();
    NTSTATUS s=UN(NtCreateSection)(&h,SECTION_QUERY,NULL,&max,PAGE_READWRITE,SEC_COMMIT,NULL);
    EXPECT_EQ(s,0); if(s<0 || !h) return;
    VM_SECTION_BASIC info; SIZE_T got=0;
    s=UN(NtQuerySection)(h,cls,&info,length,&got);
    EXPECT_EQ(s,cls==0 ? ST(0xc0000004) : ST(0xc0000003));
    CHECK(CloseHandle(h));
}
TEST(nt_vm_section_query_zero_length) { section_query_failure(0,0); }
TEST(nt_vm_section_query_short_length) { section_query_failure(sizeof(VM_SECTION_BASIC)-1,0); }
TEST(nt_vm_section_query_invalid_class) { section_query_failure(sizeof(VM_SECTION_BASIC),0xffffffff); }

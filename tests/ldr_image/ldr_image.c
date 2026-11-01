#include "t.h"

UDECL(NTSTATUS, LdrGetDllHandle, (PWSTR, PULONG, PUNICODE_STRING, PVOID *));
UDECL(NTSTATUS, LdrGetProcedureAddress, (PVOID, PANSI_STRING, ULONG, PVOID *));
UDECL(NTSTATUS, LdrLoadDll, (PWSTR, PULONG, PUNICODE_STRING, PVOID *));
UDECL(NTSTATUS, LdrUnloadDll, (PVOID));
UDECL(PIMAGE_NT_HEADERS, RtlImageNtHeader, (PVOID));
UDECL(PVOID, RtlImageDirectoryEntryToData, (PVOID, BOOLEAN, USHORT, PULONG));
UDECL(PVOID, RtlImageRvaToVa, (PIMAGE_NT_HEADERS, PVOID, ULONG, PIMAGE_SECTION_HEADER *));

static UNICODE_STRING ldr_image_us(const WCHAR *s)
{
    UNICODE_STRING u;
    u.Buffer = (PWSTR)s; u.Length = lstrlenW(s) * 2; u.MaximumLength = u.Length + 2;
    return u;
}

static void ldr_image_handle(const WCHAR *name, const char *module)
{
    UNICODE_STRING u = ldr_image_us(name);
    PVOID h = NULL;
    REQUIRE(UN(LdrGetDllHandle));
    EXPECT_EQ(UN(LdrGetDllHandle)(NULL, NULL, &u, &h), 0);
    EXPECT_EQ(h, GetModuleHandleA(module));
    CHECK(h != NULL);
}
#define HANDLE_CASE(n,s,m) TEST(ldr_image_handle_##n) { ldr_image_handle(s,m); }
HANDLE_CASE(ntdll, L"ntdll.dll", "ntdll.dll")
HANDLE_CASE(ntdll_upper, L"NTDLL.DLL", "ntdll.dll")
HANDLE_CASE(ntdll_noext, L"ntdll", "ntdll.dll")
HANDLE_CASE(kernel32, L"kernel32.dll", "kernel32.dll")
HANDLE_CASE(kernel32_upper, L"KERNEL32.DLL", "kernel32.dll")
HANDLE_CASE(kernel32_noext, L"kernel32", "kernel32.dll")

static void ldr_image_proc(const char *name, int missing, int counted)
{
    char text[160];
    ANSI_STRING a;
    PVOID out = NULL;
    NTSTATUS s;
    REQUIRE(UN(LdrGetProcedureAddress));
    memset(text, 0, sizeof(text));
    strcpy(text, name);
    a.Buffer = text; a.Length = strlen(name); a.MaximumLength = a.Length + 1;
    if (counted) { text[a.Length] = '!'; a.MaximumLength = a.Length; }
    s = UN(LdrGetProcedureAddress)(GetModuleHandleA("ntdll.dll"), &a, 0, &out);
    if (missing) {
        EXPECT_EQ(s, (NTSTATUS)0xc000007a);
        t_note("missing export output=%p", out);
    } else {
        EXPECT_EQ(s, 0);
        EXPECT_EQ(out, t_proc_in("ntdll.dll", name));
        CHECK(out != NULL);
    }
    if (counted) EXPECT_EQ(text[a.Length], '!');
}
#define PROC_CASE(n,s,m,c) TEST(ldr_image_proc_##n) { ldr_image_proc(s,m,c); }
PROC_CASE(close, "NtClose", 0, 0)
PROC_CASE(init, "RtlInitUnicodeString", 0, 0)
PROC_CASE(header, "RtlImageNtHeader", 0, 0)
PROC_CASE(load, "LdrLoadDll", 0, 0)
PROC_CASE(counted_close, "NtClose", 0, 1)
PROC_CASE(counted_header, "RtlImageNtHeader", 0, 1)
PROC_CASE(missing, "no_such_export_73f42", 1, 0)
PROC_CASE(wrong_case, "ntclose", 1, 0)

static void ldr_image_load(const WCHAR *name, unsigned count)
{
    UNICODE_STRING u = ldr_image_us(name);
    PVOID h[2] = {NULL, NULL};
    unsigned acquired = 0, i;
    REQUIRE(UN(LdrLoadDll)); REQUIRE(UN(LdrUnloadDll));
    for (i = 0; i < count; ++i) {
        NTSTATUS s = UN(LdrLoadDll)(NULL, NULL, &u, &h[i]);
        EXPECT_EQ(s, 0);
        CHECK(h[i] != NULL);
        if (s < 0 || !h[i]) break;
        ++acquired;
    }
    if (acquired == 2) EXPECT_EQ(h[0], h[1]);
    while (acquired) EXPECT_EQ(UN(LdrUnloadDll)(h[--acquired]), 0);
}
TEST(ldr_image_load_ntdll) { ldr_image_load(L"ntdll.dll", 1); }
TEST(ldr_image_load_kernel32) { ldr_image_load(L"kernel32.dll", 1); }
TEST(ldr_image_load_ntdll_twice) { ldr_image_load(L"ntdll.dll", 2); }
TEST(ldr_image_load_kernel32_twice) { ldr_image_load(L"kernel32.dll", 2); }

/* The allocation contains both raw and mapped views; no parser may escape it. */
typedef union { ULONGLONG alignment; BYTE b[0x4000]; } ldr_image_fixture;
static PIMAGE_NT_HEADERS ldr_image_make(ldr_image_fixture *f)
{
    PIMAGE_DOS_HEADER d;
    PIMAGE_NT_HEADERS n;
    PIMAGE_SECTION_HEADER s;
    memset(f, 0, sizeof(*f));
    d = (PIMAGE_DOS_HEADER)f->b; d->e_magic = IMAGE_DOS_SIGNATURE; d->e_lfanew = 0x80;
    n = (PIMAGE_NT_HEADERS)(f->b + 0x80); n->Signature = IMAGE_NT_SIGNATURE;
    n->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    n->FileHeader.NumberOfSections = 2;
    n->FileHeader.SizeOfOptionalHeader = sizeof(n->OptionalHeader);
    n->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    n->OptionalHeader.SizeOfHeaders = 0x400;
    n->OptionalHeader.SizeOfImage = sizeof(f->b);
    n->OptionalHeader.SectionAlignment = 0x1000;
    n->OptionalHeader.FileAlignment = 0x200;
    n->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    s = IMAGE_FIRST_SECTION(n);
    s[0].VirtualAddress = 0x1000; s[0].SizeOfRawData = 0x200;
    s[0].Misc.VirtualSize = 0x300; s[0].PointerToRawData = 0x400;
    s[1].VirtualAddress = 0x2000; s[1].SizeOfRawData = 0x400;
    s[1].Misc.VirtualSize = 0x400; s[1].PointerToRawData = 0x600;
    return n;
}

static void ldr_image_header(unsigned mode)
{
    ldr_image_fixture f;
    PIMAGE_NT_HEADERS n = ldr_image_make(&f), expected = n;
    REQUIRE(UN(RtlImageNtHeader));
    if (mode == 1) { ((PIMAGE_DOS_HEADER)f.b)->e_magic = 0; expected = NULL; }
    if (mode == 2) { n->Signature = 0; expected = NULL; }
    if (mode == 3) {
        memmove(f.b + 0x180, n, sizeof(*n));
        ((PIMAGE_DOS_HEADER)f.b)->e_lfanew = 0x180;
        expected = (PIMAGE_NT_HEADERS)(f.b + 0x180);
    }
    EXPECT_EQ(UN(RtlImageNtHeader)(f.b), expected);
}
TEST(ldr_image_header_valid) { ldr_image_header(0); }
TEST(ldr_image_header_bad_dos) { ldr_image_header(1); }
TEST(ldr_image_header_bad_nt) { ldr_image_header(2); }
TEST(ldr_image_header_relocated) { ldr_image_header(3); }
TEST(ldr_image_header_loaded) {
    PVOID base = GetModuleHandleA("ntdll.dll");
    REQUIRE(UN(RtlImageNtHeader));
    CHECK(base != NULL); if (!base) return;
    EXPECT_EQ(UN(RtlImageNtHeader)(base), (BYTE *)base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
}

static void ldr_image_directory(ULONG rva, BOOLEAN mapped, USHORT index, ULONG count, LONG offset, int tagged)
{
    ldr_image_fixture f;
    PIMAGE_NT_HEADERS n = ldr_image_make(&f);
    ULONG size = 0xdeadbeef;
    PVOID p;
    REQUIRE(UN(RtlImageDirectoryEntryToData));
    n->OptionalHeader.DataDirectory[0].VirtualAddress = rva;
    n->OptionalHeader.DataDirectory[0].Size = 0x31;
    n->OptionalHeader.NumberOfRvaAndSizes = count;
    p = UN(RtlImageDirectoryEntryToData)((PVOID)((ULONG_PTR)f.b | tagged), mapped, index, &size);
    EXPECT_EQ(p, offset < 0 ? NULL : f.b + offset);
    EXPECT_EQ(size, index >= count || !rva ? 0xdeadbeef : 0x31);
}
#define DIR_CASE(n,r,m,i,c,o) TEST(ldr_image_dir_##n) { ldr_image_directory(r,m,i,c,o,0); }
DIR_CASE(mapped_section, 0x1020, TRUE, 0, 16, 0x1020)
DIR_CASE(raw_section, 0x1020, FALSE, 0, 16, 0x420)
DIR_CASE(mapped_header, 0x300, TRUE, 0, 16, 0x300)
DIR_CASE(raw_header, 0x300, FALSE, 0, 16, 0x300)
DIR_CASE(absent, 0, TRUE, 0, 16, -1)
DIR_CASE(out_of_count, 0x1020, TRUE, 0, 0, -1)
DIR_CASE(invalid_index, 0x1020, TRUE, 16, 16, -1)
DIR_CASE(raw_gap, 0x1800, FALSE, 0, 16, -1)
TEST(ldr_image_dir_tagged_section) { ldr_image_directory(0x1020, TRUE, 0, 16, 0x420, 1); }
TEST(ldr_image_dir_tagged_header) { ldr_image_directory(0x300, TRUE, 0, 16, 0x300, 1); }

static void ldr_image_rva(ULONG rva, LONG offset, int cache)
{
    ldr_image_fixture f;
    PIMAGE_NT_HEADERS n = ldr_image_make(&f);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(n);
    PIMAGE_SECTION_HEADER last = cache == 2 ? section + 1 : cache == 3 ? section : NULL;
    PVOID p;
    REQUIRE(UN(RtlImageRvaToVa));
    p = UN(RtlImageRvaToVa)(n, f.b, rva, cache ? &last : NULL);
    EXPECT_EQ(p, offset < 0 ? NULL : f.b + offset);
    if (cache && p) EXPECT_EQ(last, section + (rva >= 0x2000));
}
#define RVA_CASE(n,r,o,c) TEST(ldr_image_rva_##n) { ldr_image_rva(r,o,c); }
RVA_CASE(first, 0x1000, 0x400, 0)
RVA_CASE(first_last, 0x11ff, 0x5ff, 0)
RVA_CASE(exclusive_end, 0x1200, -1, 0)
RVA_CASE(virtual_tail, 0x1250, -1, 0)
RVA_CASE(gap, 0x1800, -1, 0)
RVA_CASE(second, 0x2020, 0x620, 1)
RVA_CASE(second_end, 0x2400, -1, 0)
RVA_CASE(cache_empty, 0x1010, 0x410, 1)
RVA_CASE(cache_miss, 0x1010, 0x410, 2)
RVA_CASE(cache_hit, 0x1010, 0x410, 3)
RVA_CASE(header_not_section, 0x300, -1, 0)

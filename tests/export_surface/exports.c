#include "t.h"
#include <stdlib.h>
#include "reference.inc"

static PIMAGE_EXPORT_DIRECTORY export_directory(HMODULE module, BYTE **base_out) {
    BYTE *base = (BYTE *)module;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    CHECK(dos->e_magic == IMAGE_DOS_SIGNATURE);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    CHECK(nt->Signature == IMAGE_NT_SIGNATURE);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    CHECK(rva != 0);
    if (!rva) return NULL;
    *base_out = base;
    return (PIMAGE_EXPORT_DIRECTORY)(base + rva);
}

TEST(export_surface_pe_headers) {
    HMODULE module = t_module("ntdll.dll");
    REQUIRE(module);
    BYTE *base;
    PIMAGE_EXPORT_DIRECTORY exports = export_directory(module, &base);
    if (!exports) return;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    EXPECT_EQ(nt->FileHeader.Machine, IMAGE_FILE_MACHINE_AMD64);
    CHECK(nt->FileHeader.Characteristics & IMAGE_FILE_DLL);
    EXPECT_EQ(nt->OptionalHeader.Magic, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    CHECK(exports->NumberOfNames > 0);
    CHECK(exports->NumberOfFunctions >= exports->NumberOfNames);
    EXPECT_STR((char *)base + exports->Name, "ntdll.dll");
}

TEST(export_surface_host_name_ordinal_consistency) {
    HMODULE module = t_module("ntdll.dll");
    REQUIRE(module);
    BYTE *base;
    PIMAGE_EXPORT_DIRECTORY exports = export_directory(module, &base);
    if (!exports) return;
    DWORD *names = (DWORD *)(base + exports->AddressOfNames);
    WORD *ordinals = (WORD *)(base + exports->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        CHECKF(ordinals[i] < exports->NumberOfFunctions, "%s ordinal index %u", name, ordinals[i]);
        if (ordinals[i] >= exports->NumberOfFunctions) continue;
        FARPROC named = t_proc_in("ntdll.dll", name);
        FARPROC ordinal = t_proc_ord("ntdll.dll", exports->Base + ordinals[i]);
        CHECKF(named != NULL, "%s must resolve from the loaded image's export table", name);
        EXPECT_EQ(named, ordinal);
        if (i) CHECK(strcmp((char *)base + names[i - 1], name) < 0);
    }
    t_note("host table: %lu names, %lu slots, ordinal base %lu", exports->NumberOfNames,
           exports->NumberOfFunctions, exports->Base);
}

TEST(export_surface_reference_resolution) {
    const char *option = getenv("NTDLL_STRICT_EXPORTS");
    int strict = option && !strcmp(option, "1");
    unsigned found = 0, missing = 0;
    for (unsigned i = 0; i < sizeof reference_exports / sizeof reference_exports[0]; i++) {
        const char *name = reference_exports[i].name;
        FARPROC p = name ? t_proc_in("ntdll.dll", name) : t_proc_ord("ntdll.dll", reference_exports[i].ordinal);
        if (p) found++; else missing++;
        if (strict) {
            CHECKF(p != NULL, "reference export %s ordinal %u", name ? name : "<ordinal-only>", reference_exports[i].ordinal);
            if (name && p) EXPECT_EQ(p, t_proc_ord("ntdll.dll", reference_exports[i].ordinal));
        } else if (!p) {
            t_note("reference export absent on this host: %s ordinal %u", name ? name : "<ordinal-only>", reference_exports[i].ordinal);
        }
    }
    CHECK(found > 0);
    t_note("reference resolve-only coverage: found=%u absent=%u strict=%d; no signature inferred", found, missing, strict);
}

TEST(export_surface_nt_zw_reference_aliases) {
    unsigned pairs = 0;
    for (unsigned i = 0; i < sizeof reference_exports / sizeof reference_exports[0]; i++) {
        const char *name = reference_exports[i].name;
        if (!name || strncmp(name, "Nt", 2)) continue;
        char twin[256];
        snprintf(twin, sizeof twin, "Zw%s", name + 2);
        for (unsigned j = 0; j < sizeof reference_exports / sizeof reference_exports[0]; j++) {
            if (!reference_exports[j].name || strcmp(twin, reference_exports[j].name) ||
                reference_exports[i].rva != reference_exports[j].rva) continue;
            FARPROC nt = t_proc_in("ntdll.dll", name), zw = t_proc_in("ntdll.dll", twin);
            if (!nt || !zw) { t_note("alias pair unavailable: %s/%s", name, twin); continue; }
            CHECKF(nt == zw, "%s/%s share an entry RVA in the Win10 reference", name, twin);
            pairs++;
            break;
        }
    }
    CHECK(pairs > 0);
    t_note("checked %u Nt/Zw aliases; aliases are not behavioural coverage", pairs);
}

TEST(export_surface_core_entrypoints) {
    const char *names[] = {"NtClose", "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtQueryInformationProcess",
        "NtCreateFile", "NtCreateEvent", "LdrLoadDll", "LdrGetProcedureAddress", "RtlGetVersion",
        "RtlInitUnicodeString", "RtlAllocateHeap", "RtlFreeHeap", "RtlNtStatusToDosError"};
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++)
        CHECKF(t_proc_in("ntdll.dll", names[i]) != NULL, "core entrypoint %s", names[i]);
}

/* Loader resource APIs against a synthetic code-free DLL with a known resource tree (see pebuild.h):
 * LdrFindResource_U, LdrFindResourceEx_U, LdrFindResourceDirectory_U, LdrAccessResource, LdrEnumResources,
 * and the mapped-file (MUI style) family LdrResFindResource, LdrResFindResourceDirectory, LdrResSearchResource,
 * LdrResGetRCConfig, LdrRscIsTypeExist, LdrResRelease, LdrpResGetMappingSize, plus the load-as-data table.
 * Every status below is documented in EVIDENCE.md. */
#include "t.h"
#include "pebuild.h"

UDECL(NTSTATUS, LdrFindResource_U, (PVOID, ULONG_PTR *, ULONG, PVOID *));
UDECL(NTSTATUS, LdrFindResourceEx_U, (ULONG, PVOID, ULONG_PTR *, ULONG, PVOID *));
UDECL(NTSTATUS, LdrFindResourceDirectory_U, (PVOID, ULONG_PTR *, ULONG, PVOID *));
UDECL(NTSTATUS, LdrAccessResource, (PVOID, PVOID, PVOID *, PULONG));
UDECL(NTSTATUS, LdrEnumResources, (PVOID, ULONG_PTR *, ULONG, PULONG, PVOID));
UDECL(NTSTATUS, LdrResFindResource, (PVOID, ULONG_PTR, ULONG_PTR, ULONG_PTR, PVOID *, PULONG_PTR, PVOID, PULONG, ULONG));
UDECL(NTSTATUS, LdrResFindResourceDirectory, (PVOID, ULONG_PTR, ULONG_PTR, PVOID *, PVOID, PULONG, ULONG));
UDECL(NTSTATUS, LdrResSearchResource, (PVOID, ULONG_PTR *, ULONG, ULONG, PVOID *, PULONG_PTR, PVOID, PULONG));
UDECL(NTSTATUS, LdrResGetRCConfig, (PVOID, PVOID, PVOID *, ULONG, BOOLEAN));
UDECL(NTSTATUS, LdrRscIsTypeExist, (PVOID, PCWSTR, ULONG, PULONG));
UDECL(NTSTATUS, LdrResRelease, (PVOID, PVOID, ULONG, ULONG));
UDECL(NTSTATUS, LdrpResGetMappingSize, (PVOID, PSIZE_T, ULONG, BOOLEAN));
UDECL(NTSTATUS, LdrAddLoadAsDataTable, (PVOID, PCWSTR, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, LdrRemoveLoadAsDataTable, (PVOID, PVOID *, PVOID *, ULONG));
UDECL(NTSTATUS, LdrGetFileNameFromLoadAsDataTable, (PVOID, PVOID *));

#define S(x) ((NTSTATUS)(x))
#define ST_BAD_PARAM     S(0xC000000D)
#define ST_LEN_MISMATCH  S(0xC0000004)
#define ST_PARAM3        S(0xC00000F1)
#define ST_TYPE_NOTFOUND S(0xC000008A)
#define ST_NAME_NOTFOUND S(0xC000008B)
#define ST_LANG_NOTFOUND S(0xC0000204)
#define ST_DATA_NOTFOUND S(0xC0000089)
#define ST_UNSUCCESSFUL  S(0xC0000001)
#define ST_NOT_FOUND_139 S(0xC0000139)

#define NEED_RES() do { REQUIRE(UN(LdrFindResource_U)); REQUIRE(UN(LdrAccessResource)); REQUIRE(UN(LdrFindResourceDirectory_U)); REQUIRE(UN(LdrEnumResources)); } while (0)

enum { M_IMAGE, M_DATAFILE, M_IMGRES };
static const char *const mode_name[] = {"image", "datafile", "image-resource"};

/* Writes the fixture DLL into the scratch dir and maps it in the requested way; NULL on failure. */
static HMODULE map_fixture(int mode, char *path, size_t cap, int *skip)
{
    static int seq;
    char leaf[32];
    wsprintfA(leaf, "res%d.dll", ++seq);
    t_tmpfile(path, cap, leaf);
    if (!peb_write(path, 1, NULL)) { t_skip("cannot write fixture dll (err %lu)", GetLastError()); *skip = 1; return NULL; }
    HMODULE h = mode == M_IMAGE ? LoadLibraryA(path)
              : LoadLibraryExA(path, NULL, mode == M_DATAFILE ? LOAD_LIBRARY_AS_DATAFILE : LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!h) { t_skip("fixture dll cannot be loaded as %s (err %lu)", mode_name[mode], GetLastError()); *skip = 1; }
    return h;
}

static const BYTE *res_text(PVOID base, PVOID entry, ULONG *size)
{
    PVOID a = NULL; ULONG sz = 0;
    NTSTATUS s = UN(LdrAccessResource)(base, entry, &a, &sz);
    EXPECT_EQ(s, 0);
    if (size) *size = sz;
    return s == 0 ? (const BYTE *)a : NULL;
}
static void expect_data(PVOID base, ULONG_PTR *info, const char *want)
{
    PVOID e = NULL; ULONG sz = 0;
    NTSTATUS s = UN(LdrFindResource_U)(base, info, 3, &e);
    EXPECT_EQ(s, 0);
    if (s) return;
    const BYTE *d = res_text(base, e, &sz);
    EXPECT_EQ(sz, strlen(want) + 1);
    CHECKF(d && !memcmp(d, want, strlen(want) + 1), "resource data mismatch (want %s)", want);
}

static void find_access(int mode)
{
    char path[MAX_PATH]; int skip = 0;
    HMODULE h = map_fixture(mode, path, sizeof path, &skip);
    if (!h) return;
    NEED_RES();
    PVOID base = (PVOID)h, e = NULL;
    ULONG_PTR info[3] = {10, 1, 0x409};
    expect_data(base, info, "data-1-409");
    info[2] = 0x407; expect_data(base, info, "data-1-407");
    /* the data entry itself: size and code page as stored in the tree */
    info[2] = 0x409;
    NTSTATUS s = UN(LdrFindResource_U)(base, info, 3, &e);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        PIMAGE_RESOURCE_DATA_ENTRY de = (PIMAGE_RESOURCE_DATA_ENTRY)e;
        EXPECT_EQ(de->Size, 11);
        EXPECT_EQ(de->CodePage, 1252);
    }
    /* a name that has only the neutral language still resolves for a specific language request and for 0 */
    info[0] = 10; info[1] = 2; info[2] = 0x409; expect_data(base, info, "data-2-neutral");
    info[2] = 0;                                 expect_data(base, info, "data-2-neutral");
    info[0] = 23; info[1] = 7; info[2] = 0x409;  expect_data(base, info, "<html/>");
    /* lang 0 on a name with several languages picks one of them */
    info[0] = 10; info[1] = 1; info[2] = 0;
    s = UN(LdrFindResource_U)(base, info, 3, &e);
    EXPECT_EQ(s, 0);
    if (s == 0) { ULONG sz; const BYTE *d = res_text(base, e, &sz); CHECK(d && (!memcmp(d, "data-1-407", 11) || !memcmp(d, "data-1-409", 11))); }
    /* named type and name (names are matched as stored: upper case) */
    WCHAR cu[] = L"CUSTOM", my[] = L"MYRES";
    ULONG_PTR ni[3] = {(ULONG_PTR)cu, (ULONG_PTR)my, 0x409};
    expect_data(base, ni, "named-res");
    /* misses */
    info[0] = 10; info[1] = 1; info[2] = 0x809; EXPECT_EQ(UN(LdrFindResource_U)(base, info, 3, &e), ST_LANG_NOTFOUND);
    info[2] = 0x009;                            EXPECT_EQ(UN(LdrFindResource_U)(base, info, 3, &e), ST_LANG_NOTFOUND);
    info[1] = 99; info[2] = 0x409;              EXPECT_EQ(UN(LdrFindResource_U)(base, info, 3, &e), ST_NAME_NOTFOUND);
    info[0] = 99; info[1] = 1;                  EXPECT_EQ(UN(LdrFindResource_U)(base, info, 3, &e), ST_TYPE_NOTFOUND);
    ULONG_PTR nn[3] = {(ULONG_PTR)L"NOPE", (ULONG_PTR)my, 0x409};
    EXPECT_EQ(UN(LdrFindResource_U)(base, nn, 3, &e), ST_TYPE_NOTFOUND);
    /* levels other than 3 are rejected as invalid parameter 3 */
    info[0] = 10; info[1] = 1; info[2] = 0x409;
    for (ULONG lvl = 0; lvl <= 4; lvl++) {
        if (lvl == 3) continue;
        EXPECT_EQ(UN(LdrFindResource_U)(base, info, lvl, &e), ST_PARAM3);
    }
    /* Ex form: flags 0 is the same lookup */
    if (UN(LdrFindResourceEx_U)) {
        PVOID e2 = NULL;
        EXPECT_EQ(UN(LdrFindResource_U)(base, info, 3, &e), 0);
        EXPECT_EQ(UN(LdrFindResourceEx_U)(0, base, info, 3, &e2), 0);
        EXPECT_EQ(e2, e);
        info[2] = 0x809; EXPECT_EQ(UN(LdrFindResourceEx_U)(0, base, info, 3, &e2), ST_LANG_NOTFOUND);
        info[2] = 0x409; info[1] = 99; EXPECT_EQ(UN(LdrFindResourceEx_U)(0, base, info, 3, &e2), ST_NAME_NOTFOUND);
        EXPECT_EQ(UN(LdrFindResourceEx_U)(0, base, info, 1, &e2), ST_PARAM3);
    }
    EXPECT_EQ(UN(LdrFindResource_U)(NULL, info, 3, &e), ST_DATA_NOTFOUND);
    FreeLibrary(h);
}
TEST(ldr_res_find_access_image)    { find_access(M_IMAGE); }
TEST(ldr_res_find_access_datafile) { find_access(M_DATAFILE); }
TEST(ldr_res_find_access_imgres)   { find_access(M_IMGRES); }

static void dir_enum(int mode)
{
    char path[MAX_PATH]; int skip = 0;
    HMODULE h = map_fixture(mode, path, sizeof path, &skip);
    if (!h) return;
    NEED_RES();
    PVOID base = (PVOID)h, d = NULL;
    ULONG_PTR info[3] = {10, 1, 0};
    /* directory at each level: counts of named/id entries come from the fixture tree */
    EXPECT_EQ(UN(LdrFindResourceDirectory_U)(base, info, 0, &d), 0);
    PIMAGE_RESOURCE_DIRECTORY root = (PIMAGE_RESOURCE_DIRECTORY)d;
    if (root) { EXPECT_EQ(root->NumberOfNamedEntries, 2); EXPECT_EQ(root->NumberOfIdEntries, 2); }
    d = NULL;
    EXPECT_EQ(UN(LdrFindResourceDirectory_U)(base, info, 1, &d), 0);
    PIMAGE_RESOURCE_DIRECTORY tdir = (PIMAGE_RESOURCE_DIRECTORY)d;
    if (tdir) { EXPECT_EQ(tdir->NumberOfNamedEntries, 0); EXPECT_EQ(tdir->NumberOfIdEntries, 2); }
    CHECK(root && tdir && (BYTE *)tdir > (BYTE *)root);
    d = NULL;
    EXPECT_EQ(UN(LdrFindResourceDirectory_U)(base, info, 2, &d), 0);
    PIMAGE_RESOURCE_DIRECTORY ndir = (PIMAGE_RESOURCE_DIRECTORY)d;
    if (ndir) { EXPECT_EQ(ndir->NumberOfNamedEntries, 0); EXPECT_EQ(ndir->NumberOfIdEntries, 2); }
    CHECK(tdir && ndir && (BYTE *)ndir > (BYTE *)tdir);
    info[0] = 99;
    EXPECT_EQ(UN(LdrFindResourceDirectory_U)(base, info, 1, &d), ST_TYPE_NOTFOUND);
    info[0] = 10; info[1] = 99;
    EXPECT_EQ(UN(LdrFindResourceDirectory_U)(base, info, 2, &d), ST_NAME_NOTFOUND);

    /* enumeration: capacity in / count out, entries are {type, name, lang, data, size, reserved} */
    typedef struct { ULONG_PTR path[3]; PVOID data; ULONG size, reserved; } ENUM_ENTRY;
    ENUM_ENTRY ent[16];
    ULONG cnt = 0;
    info[0] = 10; info[1] = 1; info[2] = 0x409;
    EXPECT_EQ(UN(LdrEnumResources)(base, info, 0, &cnt, NULL), ST_LEN_MISMATCH);
    EXPECT_EQ(cnt, 6);
    cnt = 1;
    EXPECT_EQ(UN(LdrEnumResources)(base, info, 0, &cnt, ent), ST_LEN_MISMATCH);
    EXPECT_EQ(cnt, 6);
    memset(ent, 0, sizeof ent); cnt = 16;
    EXPECT_EQ(UN(LdrEnumResources)(base, info, 0, &cnt, ent), 0);
    EXPECT_EQ(cnt, 6);
    if (cnt == 6) {
        /* named entries first: CUSTOM/MYRES/0x409, then MUI/1/0, then ids ascending */
        PUSHORT t0 = (PUSHORT)ent[0].path[0], n0 = (PUSHORT)ent[0].path[1];
        CHECK(t0 && t0[0] == 6 && !memcmp(t0 + 1, L"CUSTOM", 12));
        CHECK(n0 && n0[0] == 5 && !memcmp(n0 + 1, L"MYRES", 10));
        EXPECT_EQ(ent[0].path[2], 0x409);
        EXPECT_EQ(ent[0].size, 10);
        PUSHORT t1 = (PUSHORT)ent[1].path[0];
        CHECK(t1 && t1[0] == 3 && !memcmp(t1 + 1, L"MUI", 6));
        EXPECT_EQ(ent[1].path[1], 1); EXPECT_EQ(ent[1].path[2], 0); EXPECT_EQ(ent[1].size, PEB_MUI_SIZE);
        EXPECT_EQ(ent[2].path[0], 10); EXPECT_EQ(ent[2].path[1], 1); EXPECT_EQ(ent[2].path[2], 0x407);
        EXPECT_EQ(ent[3].path[0], 10); EXPECT_EQ(ent[3].path[1], 1); EXPECT_EQ(ent[3].path[2], 0x409);
        EXPECT_EQ(ent[4].path[0], 10); EXPECT_EQ(ent[4].path[1], 2); EXPECT_EQ(ent[4].path[2], 0);
        EXPECT_EQ(ent[5].path[0], 23); EXPECT_EQ(ent[5].path[1], 7); EXPECT_EQ(ent[5].path[2], 0x409);
        EXPECT_EQ(ent[2].size, 11); EXPECT_EQ(ent[4].size, 15); EXPECT_EQ(ent[5].size, 8);
        if (mode == M_IMAGE) {   /* only a loaded image makes the reported data addresses directly readable */
            CHECK(!memcmp(ent[0].data, "named-res", 10));
            CHECK(!memcmp(ent[2].data, "data-1-407", 11));
            CHECK(!memcmp(ent[3].data, "data-1-409", 11));
            CHECK(!memcmp(ent[4].data, "data-2-neutral", 15));
            CHECK(!memcmp(ent[5].data, "<html/>", 8));
        }
        /* data pointers agree with LdrAccessResource for the same resource */
        PVOID e = NULL; ULONG_PTR key[3] = {10, 1, 0x409};
        if (UN(LdrFindResource_U)(base, key, 3, &e) == 0) {
            PVOID a = NULL; ULONG sz = 0;
            if (UN(LdrAccessResource)(base, e, &a, &sz) == 0) { if (mode == M_IMAGE) EXPECT_EQ(ent[3].data, a); EXPECT_EQ(ent[3].size, sz); }
        }
    }
    /* filtered levels: 1 = type, 2 = type+name, 3 = type+name+language */
    info[0] = 10; info[1] = 1; info[2] = 0x409;
    cnt = 16; EXPECT_EQ(UN(LdrEnumResources)(base, info, 1, &cnt, ent), 0); EXPECT_EQ(cnt, 3);
    cnt = 16; EXPECT_EQ(UN(LdrEnumResources)(base, info, 2, &cnt, ent), 0); EXPECT_EQ(cnt, 2);
    cnt = 16; EXPECT_EQ(UN(LdrEnumResources)(base, info, 3, &cnt, ent), 0); EXPECT_EQ(cnt, 1);
    if (cnt == 1) { EXPECT_EQ(ent[0].path[2], 0x409); EXPECT_EQ(ent[0].size, 11); }
    info[0] = 99;
    cnt = 16; EXPECT_EQ(UN(LdrEnumResources)(base, info, 1, &cnt, ent), 0); EXPECT_EQ(cnt, 0);
    FreeLibrary(h);
}
TEST(ldr_res_dir_enum_image)    { dir_enum(M_IMAGE); }
TEST(ldr_res_dir_enum_datafile) { dir_enum(M_DATAFILE); }
TEST(ldr_res_dir_enum_imgres)   { dir_enum(M_IMGRES); }

/* A module without a resource directory (a headers-only image has none): ntdll has one, so use a
 * mapping of the fixture with the resource data-directory entry cleared. */
static void clear_rsrc_dir(BYTE *b)
{
    BYTE *nt = b + *(ULONG *)(b + 0x3c);
    BYTE *oh = nt + 24;
    *(ULONG *)(oh + 112 + 16) = 0; *(ULONG *)(oh + 112 + 20) = 0;
}
TEST(ldr_res_no_resource_directory)
{
    char path[MAX_PATH];
    t_tmpfile(path, sizeof path, "nores.dll");
    if (!peb_write(path, 0, clear_rsrc_dir)) { t_skip("cannot write fixture"); return; }
    HMODULE h = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!h) { t_skip("fixture cannot be loaded (err %lu)", GetLastError()); return; }
    NEED_RES();
    PVOID e = NULL, d = NULL; ULONG_PTR info[3] = {10, 1, 0x409}; ULONG cnt = 4;
    EXPECT_EQ(UN(LdrFindResource_U)((PVOID)h, info, 3, &e), ST_DATA_NOTFOUND);
    EXPECT_EQ(UN(LdrFindResourceDirectory_U)((PVOID)h, info, 0, &d), ST_DATA_NOTFOUND);
    EXPECT_EQ(UN(LdrEnumResources)((PVOID)h, info, 0, &cnt, NULL), ST_DATA_NOTFOUND);
    EXPECT_EQ(cnt, 0);
    FreeLibrary(h);
}

/* ---- mapped-file family -------------------------------------------------------------------- */
#define RF_IMAGE_DEFAULT 0x1100   /* default: resources of a mapped data file, parsed as an image layout */
TEST(ldr_res_res_find_resource)
{
    char path[MAX_PATH]; int skip = 0;
    HMODULE h = map_fixture(M_DATAFILE, path, sizeof path, &skip);
    if (!h) return;
    REQUIRE(UN(LdrResFindResource)); REQUIRE(UN(LdrFindResource_U)); REQUIRE(UN(LdrAccessResource));
    PVOID out = NULL; ULONG_PTR sz = 0;
    /* the first lookup validates the module's MUI config block (valid here) and must succeed */
    NTSTATUS s = UN(LdrResFindResource)(h, 10, 1, 0x409, &out, &sz, NULL, NULL, 0);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(sz, 11);
    if (s == 0) {
        CHECK(out && !memcmp(out, "data-1-409", 11));
        PVOID e = NULL, a = NULL; ULONG asz = 0; ULONG_PTR key[3] = {10, 1, 0x409};
        if (UN(LdrFindResource_U)(h, key, 3, &e) == 0 && UN(LdrAccessResource)(h, e, &a, &asz) == 0) EXPECT_EQ(out, a);
    }
    out = NULL; sz = 0;
    EXPECT_EQ(UN(LdrResFindResource)(h, 10, 1, 0x407, &out, &sz, NULL, NULL, 0), 0);
    CHECK(out && !memcmp(out, "data-1-407", 11));
    EXPECT_EQ(UN(LdrResFindResource)(h, 10, 1, 0x409, &out, &sz, NULL, NULL, RF_IMAGE_DEFAULT), 0);
    EXPECT_EQ(UN(LdrResFindResource)(h, 10, 99, 0x409, &out, &sz, NULL, NULL, 0), ST_NAME_NOTFOUND);
    EXPECT_EQ(UN(LdrResFindResource)(h, 99, 1, 0x409, &out, &sz, NULL, NULL, 0), ST_TYPE_NOTFOUND);
    EXPECT_EQ(UN(LdrResFindResource)(h, 10, 1, 0x411, &out, &sz, NULL, NULL, 0), ST_LANG_NOTFOUND);
    EXPECT_EQ(UN(LdrResFindResource)(h, 10, 1, 0, &out, &sz, NULL, NULL, 0), 0);
    /* flag validation */
    EXPECT_EQ(UN(LdrResFindResource)(NULL, 10, 1, 0x409, &out, &sz, NULL, NULL, 0), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrResFindResource)(h, 10, 1, 0x409, &out, &sz, NULL, NULL, 0x2), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrResFindResource)(h, 10, 1, 0x409, &out, &sz, NULL, NULL, 0x400), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrResFindResource)(h, 10, 1, 0x409, &out, &sz, NULL, NULL, 0x800), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrResFindResource)(h, 10, 1, 0x409, &out, &sz, &out, NULL, 0), ST_BAD_PARAM);
    FreeLibrary(h);
}

TEST(ldr_res_res_find_directory)
{
    char path[MAX_PATH]; int skip = 0;
    HMODULE h = map_fixture(M_DATAFILE, path, sizeof path, &skip);
    if (!h) return;
    REQUIRE(UN(LdrResFindResourceDirectory));
    PVOID dir = NULL;
    NTSTATUS s = UN(LdrResFindResourceDirectory)(h, 10, 0, &dir, NULL, NULL, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        PIMAGE_RESOURCE_DIRECTORY rd = (PIMAGE_RESOURCE_DIRECTORY)dir;
        CHECK(rd != NULL);
        if (rd) { EXPECT_EQ(rd->NumberOfNamedEntries, 0); EXPECT_EQ(rd->NumberOfIdEntries, 2); }   /* the RT_RCDATA(10) directory */
    }
    dir = NULL;
    EXPECT_EQ(UN(LdrResFindResourceDirectory)(h, 10, 1, &dir, NULL, NULL, 0), 0);
    if (dir) { PIMAGE_RESOURCE_DIRECTORY rd = (PIMAGE_RESOURCE_DIRECTORY)dir; EXPECT_EQ(rd->NumberOfIdEntries, 2); }   /* languages of name 1 */
    EXPECT_EQ(UN(LdrResFindResourceDirectory)(h, 99, 0, &dir, NULL, NULL, 0), ST_TYPE_NOTFOUND);
    /* neither type nor name: nothing to locate */
    EXPECT_EQ(UN(LdrResFindResourceDirectory)(h, 0, 0, &dir, NULL, NULL, 0), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrResFindResourceDirectory)(h, 10, 0, &dir, NULL, NULL, 0x400), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrResFindResourceDirectory)(h, 10, 0, &dir, NULL, NULL, 0x800), ST_BAD_PARAM);
    FreeLibrary(h);
}

TEST(ldr_res_res_search_resource)
{
    char path[MAX_PATH]; int skip = 0;
    HMODULE h = map_fixture(M_DATAFILE, path, sizeof path, &skip);
    if (!h) return;
    REQUIRE(UN(LdrResSearchResource));
    PVOID out = NULL; ULONG_PTR sz = 0; ULONG_PTR info[3] = {10, 1, 0x409};
    EXPECT_EQ(UN(LdrResSearchResource)(h, info, 3, 0, &out, &sz, NULL, NULL), 0);
    EXPECT_EQ(sz, 11);
    CHECK(out && !memcmp(out, "data-1-409", 11));
    info[1] = 99;
    EXPECT_EQ(UN(LdrResSearchResource)(h, info, 3, 0, &out, &sz, NULL, NULL), ST_NAME_NOTFOUND);
    info[1] = 1;
    EXPECT_EQ(UN(LdrResSearchResource)(NULL, info, 3, 0, &out, &sz, NULL, NULL), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrResSearchResource)(h, NULL, 3, 0, &out, &sz, NULL, NULL), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrResSearchResource)(h, info, 9, 0, &out, &sz, NULL, NULL), ST_PARAM3);
    EXPECT_EQ(UN(LdrResSearchResource)(h, info, 3, 0, &out, &sz, &out, NULL), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrResSearchResource)(h, info, 1, 0, &out, &sz, NULL, NULL), ST_PARAM3);
    EXPECT_EQ(UN(LdrResSearchResource)(h, info, 3, 0xFFF80000u, &out, &sz, NULL, NULL), S(0xC00000F2));
    FreeLibrary(h);
}

TEST(ldr_res_rc_config)
{
    char path[MAX_PATH]; int skip = 0;
    HMODULE h = map_fixture(M_DATAFILE, path, sizeof path, &skip);
    if (!h) return;
    REQUIRE(UN(LdrResGetRCConfig));
    PVOID cfg = NULL;
    EXPECT_EQ(UN(LdrResGetRCConfig)(NULL, NULL, &cfg, 0, 0), ST_BAD_PARAM);
    /* flag 0x2000 returns the "MUI" resource without validating the block */
    NTSTATUS s = UN(LdrResGetRCConfig)(h, NULL, &cfg, 0x2000, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        CHECK(cfg != NULL);
        if (cfg) {
            EXPECT_EQ(*(ULONG *)cfg, 0xFECDFECDu);
            EXPECT_EQ(*((ULONG *)cfg + 1), PEB_MUI_SIZE);
            EXPECT_EQ(*((ULONG *)cfg + 2), 0x10000);
        }
    }
    cfg = NULL;
    s = UN(LdrResGetRCConfig)(h, NULL, &cfg, 0, 0);
    EXPECT_EQ(s, 0);                                   /* validated: the fixture's block satisfies every check */
    CHECK(cfg != NULL);
    if (cfg) EXPECT_EQ(*(ULONG *)cfg, 0xFECDFECDu);
    FreeLibrary(h);
}

TEST(ldr_res_type_exist_lists)
{
    REQUIRE(UN(LdrRscIsTypeExist));
    BYTE c[0x200]; memset(c, 0, sizeof c);
    ULONG *u = (ULONG *)c;
    u[0x5c / 4] = 0x80; u[0x60 / 4] = 8;  ((ULONG *)(c + 0x80))[0] = 16; ((ULONG *)(c + 0x80))[1] = 24;   /* main ids {16,24} */
    u[0x6c / 4] = 0x90; u[0x70 / 4] = 4;  ((ULONG *)(c + 0x90))[0] = 6;                                   /* mui ids {6} */
    ULONG fl;
    /* bit 0x40000 is set when the type is missing from the main list, 0x20000 when missing from the mui list */
    fl = 0; EXPECT_EQ(UN(LdrRscIsTypeExist)(c, (PCWSTR)16, 0, &fl), 0); EXPECT_EQ(fl, 0x20000);
    fl = 0; EXPECT_EQ(UN(LdrRscIsTypeExist)(c, (PCWSTR)24, 0, &fl), 0); EXPECT_EQ(fl, 0x20000);
    fl = 0; EXPECT_EQ(UN(LdrRscIsTypeExist)(c, (PCWSTR)6, 0, &fl), 0);  EXPECT_EQ(fl, 0x40000);
    fl = 0; EXPECT_EQ(UN(LdrRscIsTypeExist)(c, (PCWSTR)99, 0, &fl), 0); EXPECT_EQ(fl, 0x60000);
    fl = 1; EXPECT_EQ(UN(LdrRscIsTypeExist)(c, (PCWSTR)99, 0, &fl), 0); EXPECT_EQ(fl, 0x60001);
    fl = 0; EXPECT_EQ(UN(LdrRscIsTypeExist)(NULL, (PCWSTR)99, 0, &fl), ST_BAD_PARAM); EXPECT_EQ(fl, 0);
    EXPECT_EQ(UN(LdrRscIsTypeExist)(c, (PCWSTR)99, 0, NULL), ST_BAD_PARAM);
    /* names: multi-string lists, compared case-insensitively */
    u[0x54 / 4] = 0xA0; u[0x58 / 4] = 16; memcpy(c + 0xA0, L"CUSTOM\0X\0\0\0\0\0\0", 16);
    u[0x64 / 4] = 0xC0; u[0x68 / 4] = 8;  memcpy(c + 0xC0, L"HTML\0\0\0\0", 8);
    fl = 0; EXPECT_EQ(UN(LdrRscIsTypeExist)(c, L"custom", 0, &fl), 0); EXPECT_EQ(fl, 0x20000);
    fl = 0; EXPECT_EQ(UN(LdrRscIsTypeExist)(c, L"HTML", 0, &fl), 0);   EXPECT_EQ(fl, 0x40000);
    fl = 0; EXPECT_EQ(UN(LdrRscIsTypeExist)(c, L"NOSUCH", 0, &fl), 0); EXPECT_EQ(fl, 0x60000);
}

TEST(ldr_res_release_and_mapping_size)
{
    REQUIRE(UN(LdrResRelease)); REQUIRE(UN(LdrpResGetMappingSize));
    EXPECT_EQ(UN(LdrResRelease)(NULL, NULL, 0, 0), ST_BAD_PARAM);
    char path[MAX_PATH]; int skip = 0;
    HMODULE h = map_fixture(M_DATAFILE, path, sizeof path, &skip);
    if (h) { EXPECT_EQ(UN(LdrResRelease)(h, NULL, 0, 0), 0); FreeLibrary(h); }
    /* mapping size of a loaded image is its SizeOfImage */
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)((BYTE *)nt + ((PIMAGE_DOS_HEADER)nt)->e_lfanew);
    SIZE_T sz = 0;
    EXPECT_EQ(UN(LdrpResGetMappingSize)(nt, &sz, 0, 0), 0);
    EXPECT_EQ(sz, nth->OptionalHeader.SizeOfImage);
    EXPECT_EQ(UN(LdrpResGetMappingSize)(NULL, &sz, 0, 0), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrpResGetMappingSize)(nt, NULL, 0, 0), ST_BAD_PARAM);
}

/* ---- load-as-data table ------------------------------------------------------------------- */
TEST(ldr_res_load_as_data_table)
{
    REQUIRE(UN(LdrAddLoadAsDataTable)); REQUIRE(UN(LdrRemoveLoadAsDataTable)); REQUIRE(UN(LdrGetFileNameFromLoadAsDataTable));
    char path[MAX_PATH]; int skip = 0;
    HMODULE h = map_fixture(M_DATAFILE, path, sizeof path, &skip);
    if (!h) return;
    /* LoadLibraryEx(AS_DATAFILE) registers the mapping with its file name */
    PVOID name = NULL;
    EXPECT_EQ(UN(LdrGetFileNameFromLoadAsDataTable)(h, &name), 0);
    if (name) {
        WCHAR wpath[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
        CHECK(!lstrcmpiW((const WCHAR *)name, wpath));
    }
    EXPECT_EQ(UN(LdrGetFileNameFromLoadAsDataTable)(NULL, &name), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrGetFileNameFromLoadAsDataTable)(h, NULL), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrGetFileNameFromLoadAsDataTable)((PVOID)0x1234, &name), ST_UNSUCCESSFUL);
    EXPECT_EQ(UN(LdrGetFileNameFromLoadAsDataTable)((PVOID)((ULONG_PTR)h & ~(ULONG_PTR)1), &name), ST_UNSUCCESSFUL);
    /* remove, then the entry is gone; removing again reports not found */
    EXPECT_EQ(UN(LdrRemoveLoadAsDataTable)(h, NULL, NULL, 0), 0);
    EXPECT_EQ(UN(LdrGetFileNameFromLoadAsDataTable)(h, &name), ST_UNSUCCESSFUL);
    EXPECT_EQ(UN(LdrRemoveLoadAsDataTable)(h, NULL, NULL, 0), ST_NOT_FOUND_139);
    EXPECT_EQ(UN(LdrRemoveLoadAsDataTable)(NULL, NULL, NULL, 0), ST_BAD_PARAM);
    /* add an entry with a chosen name; the table stores its own copy of the string */
    WCHAR nm[] = L"C:\\corpus_fake_data_file.dll";
    EXPECT_EQ(UN(LdrAddLoadAsDataTable)(h, nm, NULL, NULL, NULL), 0);
    name = NULL;
    EXPECT_EQ(UN(LdrGetFileNameFromLoadAsDataTable)(h, &name), 0);
    CHECK(name != NULL && name != (PVOID)nm && !lstrcmpW((const WCHAR *)name, L"C:\\corpus_fake_data_file.dll"));
    EXPECT_EQ(UN(LdrAddLoadAsDataTable)(NULL, nm, NULL, NULL, NULL), ST_BAD_PARAM);
    EXPECT_EQ(UN(LdrRemoveLoadAsDataTable)(h, NULL, NULL, 0), 0);
    FreeLibrary(h);
}

/* Registry key rename, save, restore, merge, replace and hive unload.
 * Everything happens below the current user's HKCU root in uniquely named throwaway keys and in a hive
 * file under the scratch directory loaded as a temporary hive; privilege-gated calls first assert the
 * denial with the privilege disabled, then (when it can be enabled) the success path.
 * Expected values: see EVIDENCE.md. */
#include "t.h"

#define S(x) ((NTSTATUS)(x))
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_INV_PARAM    S(0xC000000D)
#define ST_NAME_NOT_FOUND S(0xC0000034)
#define ST_NAME_COLLISION S(0xC0000035)
#define ST_PRIV_NOT_HELD S(0xC0000061)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_DENIED       S(0xC0000022)
#define BOGUS ((HANDLE)(ULONG_PTR)0x7ffffff4)
#define KEY_ALL 0xF003F

UDECL(NTSTATUS, NtRenameKey, (HANDLE, PUNICODE_STRING));
UDECL(NTSTATUS, NtSaveKey, (HANDLE, HANDLE));
UDECL(NTSTATUS, NtSaveKeyEx, (HANDLE, HANDLE, ULONG));
UDECL(NTSTATUS, NtSaveMergedKeys, (HANDLE, HANDLE, HANDLE));
UDECL(NTSTATUS, NtRestoreKey, (HANDLE, HANDLE, ULONG));
UDECL(NTSTATUS, NtReplaceKey, (POBJECT_ATTRIBUTES, HANDLE, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtUnloadKey, (POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtUnloadKey2, (POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtUnloadKeyEx, (POBJECT_ATTRIBUTES, HANDLE));
UDECL(NTSTATUS, NtLoadKey, (POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryValueKey, (HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, RtlOpenCurrentUser, (ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));
UDECL(BOOLEAN, RtlDosPathNameToNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, PVOID));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));

#define EXPECT_ST(call, want) do { NTSTATUS st_ = (call); t_check(st_ == (NTSTATUS)(want), __FILE__, __LINE__, #call " == " #want, "got 0x%lx want 0x%lx", (unsigned long)st_, (unsigned long)(NTSTATUS)(want)); } while (0)

static void mkoa(OBJECT_ATTRIBUTES *oa, UNICODE_STRING *us, HANDLE root, PCWSTR name)
{
    UN(RtlInitUnicodeString)(us, name);
    memset(oa, 0, sizeof *oa); oa->Length = sizeof *oa; oa->RootDirectory = root; oa->ObjectName = us; oa->Attributes = 0x40; /* OBJ_CASE_INSENSITIVE */
}
static NTSTATUS mkkey(HANDLE parent, PCWSTR name, HANDLE *h)
{
    OBJECT_ATTRIBUTES oa; UNICODE_STRING us; ULONG disp;
    mkoa(&oa, &us, parent, name);
    return UN(NtCreateKey)(h, KEY_ALL, &oa, 0, NULL, 0, &disp);
}
static NTSTATUS openkey(HANDLE parent, PCWSTR name, HANDLE *h)
{
    OBJECT_ATTRIBUTES oa; UNICODE_STRING us;
    mkoa(&oa, &us, parent, name);
    return UN(NtOpenKey)(h, KEY_ALL, &oa);
}
static void rmkey(HANDLE parent, PCWSTR name)
{
    HANDLE h;
    if (openkey(parent, name, &h) == 0) { UN(NtDeleteKey)(h); UN(NtClose)(h); }
}
static NTSTATUS setdw(HANDLE k, PCWSTR name, DWORD v)
{
    UNICODE_STRING us; UN(RtlInitUnicodeString)(&us, name);
    return UN(NtSetValueKey)(k, &us, 0, REG_DWORD, &v, sizeof v);
}
static NTSTATUS getdw(HANDLE k, PCWSTR name, DWORD *v)
{
    UNICODE_STRING us; UN(RtlInitUnicodeString)(&us, name);
    BYTE buf[64]; ULONG ret = 0;
    NTSTATUS st = UN(NtQueryValueKey)(k, &us, 2 /*KeyValuePartialInformation*/, buf, sizeof buf, &ret);
    if (st == 0) *v = *(DWORD *)(buf + 12);     /* KEY_VALUE_PARTIAL_INFORMATION.Data */
    return st;
}
#define NEED() do { REQUIRE(UN(NtCreateKey)); REQUIRE(UN(NtOpenKey)); REQUIRE(UN(NtDeleteKey)); REQUIRE(UN(RtlOpenCurrentUser)); REQUIRE(UN(RtlInitUnicodeString)); } while (0)

static HANDLE open_hkcu(void)
{
    HANDLE h = NULL;
    if (UN(RtlOpenCurrentUser)(KEY_ALL, &h) != 0) UN(RtlOpenCurrentUser)(0x2000000, &h);
    return h;
}
static HANDLE new_file(const char *leaf, char *pathout)
{
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, leaf);
    if (pathout) strcpy(pathout, p);
    return CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
}
static int has_regf(const char *path)
{
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    char sig[4] = {0}; DWORD n = 0;
    if (f == INVALID_HANDLE_VALUE) return 0;
    ReadFile(f, sig, 4, &n, NULL); CloseHandle(f);
    return n == 4 && !memcmp(sig, "regf", 4);
}

TEST(rename_key)
{
    NEED(); REQUIRE(UN(NtRenameKey));
    HANDLE root = open_hkcu(); REQUIRE(root);
    WCHAR a[64], b[64], c[64];
    wsprintfW(a, L"NtOther2aRen_%lu_a", GetCurrentProcessId());
    wsprintfW(b, L"NtOther2aRen_%lu_b", GetCurrentProcessId());
    wsprintfW(c, L"NtOther2aRen_%lu_c", GetCurrentProcessId());
    rmkey(root, a); rmkey(root, b); rmkey(root, c);
    HANDLE ka = NULL, kc = NULL;
    EXPECT_ST(mkkey(root, a, &ka), 0); REQUIRE(ka);
    EXPECT_ST(mkkey(root, c, &kc), 0);
    EXPECT_ST(setdw(ka, L"Marker", 0x1234), 0);
    UNICODE_STRING nb, nc, bad;
    UN(RtlInitUnicodeString)(&nb, b); UN(RtlInitUnicodeString)(&nc, c);
    UN(RtlInitUnicodeString)(&bad, L"x\\y");
    EXPECT_ST(UN(NtRenameKey)(BOGUS, &nb), ST_INV_HANDLE);
    EXPECT_ST(UN(NtRenameKey)(ka, &nc), S(0xC0000121));              /* sibling exists: STATUS_CANNOT_DELETE */
    EXPECT_ST(UN(NtRenameKey)(ka, &bad), ST_INV_PARAM);               /* a key name cannot contain a separator */
    EXPECT_ST(UN(NtRenameKey)(ka, &nb), 0);
    HANDLE h = NULL;
    EXPECT_ST(openkey(root, a, &h), ST_NAME_NOT_FOUND);
    EXPECT_ST(openkey(root, b, &h), 0);
    DWORD v = 0; if (h) { EXPECT_ST(getdw(h, L"Marker", &v), 0); EXPECT_EQ(v, 0x1234); UN(NtClose)(h); }
    v = 0; EXPECT_ST(getdw(ka, L"Marker", &v), 0); EXPECT_EQ(v, 0x1234);   /* the renamed handle stays valid */
    /* a handle with only read access cannot rename */
    HANDLE ro = NULL; OBJECT_ATTRIBUTES oa; UNICODE_STRING us;
    mkoa(&oa, &us, root, b);
    if (UN(NtOpenKey)(&ro, KEY_READ, &oa) == 0) { EXPECT_ST(UN(NtRenameKey)(ro, &nc), ST_DENIED); UN(NtClose)(ro); }
    UN(NtDeleteKey)(ka); UN(NtClose)(ka);
    UN(NtDeleteKey)(kc); UN(NtClose)(kc);
    rmkey(root, a); rmkey(root, b); rmkey(root, c);
    UN(NtClose)(root);
    CHECK(t_proc("NtRenameKey") == t_proc("ZwRenameKey"));
}

/* enable a privilege: 0 on success, else the status that RtlAdjustPrivilege reports */
static NTSTATUS enable_priv(ULONG p) { BOOLEAN old; return UN(RtlAdjustPrivilege)(p, TRUE, FALSE, &old); }
static void disable_priv(ULONG p) { BOOLEAN old; UN(RtlAdjustPrivilege)(p, FALSE, FALSE, &old); }
#define SE_RESTORE 18
#define SE_BACKUP 17

TEST(save_key_and_ex)
{
    NEED(); REQUIRE(UN(NtSaveKey)); REQUIRE(UN(NtSaveKeyEx)); REQUIRE(UN(RtlAdjustPrivilege));
    disable_priv(SE_BACKUP); disable_priv(SE_RESTORE);
    HANDLE root = open_hkcu(); REQUIRE(root);
    WCHAR nm[64]; wsprintfW(nm, L"NtOther2aSave_%lu", GetCurrentProcessId());
    rmkey(root, nm);
    HANDLE k = NULL; EXPECT_ST(mkkey(root, nm, &k), 0); REQUIRE(k);
    setdw(k, L"Value", 77);
    HANDLE sub = NULL; mkkey(k, L"Sub", &sub); if (sub) { setdw(sub, L"Inner", 5); UN(NtClose)(sub); }
    char p1[MAX_PATH]; HANDLE f = new_file("save_a.hiv", p1);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    /* privilege not yet enabled */
    EXPECT_ST(UN(NtSaveKey)(k, f), ST_PRIV_NOT_HELD);
    EXPECT_ST(UN(NtSaveKeyEx)(k, f, 1), ST_PRIV_NOT_HELD);
    NTSTATUS pst = enable_priv(SE_BACKUP);
    if (pst) {
        EXPECT_ST(pst, ST_PRIV_NOT_HELD);
        CloseHandle(f); UN(NtDeleteKey)(k); UN(NtClose)(k); UN(NtClose)(root);
        t_skip("SeBackupPrivilege not held by this token (RtlAdjustPrivilege status 0x%lx); success paths skipped", (unsigned long)pst);
        return;
    }
    EXPECT_ST(UN(NtSaveKey)(BOGUS, f), ST_INV_HANDLE);
    EXPECT_ST(UN(NtSaveKey)(k, BOGUS), ST_INV_HANDLE);
    EXPECT_ST(UN(NtSaveKey)(k, f), 0);
    CHECK(GetFileSize(f, NULL) >= 4096);
    CloseHandle(f);
    CHECK(has_regf(p1));
    NTSTATUS st;
    /* the Ex variant and its formats */
    static const ULONG fmts[] = { 1, 2 };
    for (int i = 0; i < 2; i++) {
        char pe[MAX_PATH]; char leaf[32]; snprintf(leaf, sizeof leaf, "save_ex%d.hiv", i);
        f = new_file(leaf, pe); REQUIRE(f != INVALID_HANDLE_VALUE);
        st = UN(NtSaveKeyEx)(k, f, fmts[i]);
        t_note("NtSaveKeyEx(format %lu) -> 0x%lx", fmts[i], (unsigned long)st);
        EXPECT_ST(st, 0);
        CHECK(GetFileSize(f, NULL) >= 4096);
        CloseHandle(f);
        CHECK(has_regf(pe));
    }
    f = new_file("save_bad.hiv", NULL); REQUIRE(f != INVALID_HANDLE_VALUE);
    EXPECT_ST(UN(NtSaveKeyEx)(k, f, 4), ST_INV_PARAM);      /* only formats 1 and 2 exist */
    EXPECT_ST(UN(NtSaveKeyEx)(k, f, 5), ST_INV_PARAM);
    EXPECT_ST(UN(NtSaveKeyEx)(k, f, 6), ST_INV_PARAM);
    EXPECT_ST(UN(NtSaveKeyEx)(k, f, 0), ST_INV_PARAM);
    EXPECT_ST(UN(NtSaveKeyEx)(k, f, 99), ST_INV_PARAM);
    EXPECT_ST(UN(NtSaveKeyEx)(BOGUS, f, 1), ST_INV_HANDLE);
    CloseHandle(f);
    UN(NtDeleteKey)(k); UN(NtClose)(k); UN(NtClose)(root);
    CHECK(t_proc("NtSaveKey") == t_proc("ZwSaveKey"));
    CHECK(t_proc("NtSaveKeyEx") == t_proc("ZwSaveKeyEx"));
}

TEST(restore_and_merge_keys)
{
    NEED(); REQUIRE(UN(NtSaveKey)); REQUIRE(UN(NtRestoreKey)); REQUIRE(UN(NtSaveMergedKeys)); REQUIRE(UN(RtlAdjustPrivilege));
    disable_priv(SE_BACKUP); disable_priv(SE_RESTORE);
    HANDLE root = open_hkcu(); REQUIRE(root);
    WCHAR n1[64], n2[64], n3[64];
    wsprintfW(n1, L"NtOther2aRst_%lu_src", GetCurrentProcessId());
    wsprintfW(n2, L"NtOther2aRst_%lu_dst", GetCurrentProcessId());
    wsprintfW(n3, L"NtOther2aRst_%lu_low", GetCurrentProcessId());
    rmkey(root, n1); rmkey(root, n2); rmkey(root, n3);
    HANDLE src = NULL, dst = NULL, low = NULL;
    EXPECT_ST(mkkey(root, n1, &src), 0); EXPECT_ST(mkkey(root, n2, &dst), 0); EXPECT_ST(mkkey(root, n3, &low), 0);
    REQUIRE(src && dst && low);
    setdw(src, L"FromSrc", 1234);
    setdw(low, L"FromLow", 55); setdw(low, L"FromSrc", 99);
    char ps[MAX_PATH]; HANDLE f = new_file("rst_src.hiv", ps); REQUIRE(f != INVALID_HANDLE_VALUE);
    HANDLE empty = new_file("rst_empty.hiv", NULL);
    NTSTATUS st = UN(NtRestoreKey)(dst, f, 0);
    EXPECT_ST(st, ST_PRIV_NOT_HELD);
    NTSTATUS pb = enable_priv(SE_BACKUP), pr = enable_priv(SE_RESTORE);
    if (pb || pr) {
        CloseHandle(f); CloseHandle(empty);
        UN(NtDeleteKey)(src); UN(NtDeleteKey)(dst); UN(NtDeleteKey)(low);
        UN(NtClose)(src); UN(NtClose)(dst); UN(NtClose)(low); UN(NtClose)(root);
        t_skip("backup/restore privileges not held (0x%lx / 0x%lx); success paths skipped", (unsigned long)pb, (unsigned long)pr);
        return;
    }
    EXPECT_ST(UN(NtSaveKey)(src, f), 0);
    /* restore into the empty destination key */
    EXPECT_ST(UN(NtRestoreKey)(BOGUS, f, 0), ST_INV_HANDLE);
    EXPECT_ST(UN(NtRestoreKey)(dst, BOGUS, 0), ST_INV_HANDLE);
    SetFilePointer(f, 0, NULL, FILE_BEGIN);
    st = UN(NtRestoreKey)(dst, f, 0);
    t_note("NtRestoreKey(flags 0) -> 0x%lx", (unsigned long)st);
    EXPECT_ST(st, 0);
    DWORD v = 0;
    EXPECT_ST(getdw(dst, L"FromSrc", &v), 0); EXPECT_EQ(v, 1234);
    /* merged save of high-precedence src over low: union of values, high wins */
    EXPECT_ST(UN(NtSaveMergedKeys)(BOGUS, low, empty), ST_INV_HANDLE);
    EXPECT_ST(UN(NtSaveMergedKeys)(src, BOGUS, empty), ST_INV_HANDLE);
    EXPECT_ST(UN(NtSaveMergedKeys)(src, low, BOGUS), ST_INV_HANDLE);
    /* both keys must be hive roots; ordinary subkeys are refused */
    st = UN(NtSaveMergedKeys)(src, low, empty);
    EXPECT_ST(st, ST_INV_PARAM);
    CloseHandle(f); CloseHandle(empty);
    UN(NtDeleteKey)(src); UN(NtDeleteKey)(dst); UN(NtDeleteKey)(low);
    UN(NtClose)(src); UN(NtClose)(dst); UN(NtClose)(low); UN(NtClose)(root);
    CHECK(t_proc("NtRestoreKey") == t_proc("ZwRestoreKey"));
    CHECK(t_proc("NtSaveMergedKeys") == t_proc("ZwSaveMergedKeys"));
}

TEST(replace_key_rejects_non_hive)
{
    NEED(); REQUIRE(UN(NtReplaceKey)); REQUIRE(UN(RtlAdjustPrivilege));
    HANDLE root = open_hkcu(); REQUIRE(root);
    WCHAR nm[64]; wsprintfW(nm, L"NtOther2aRpl_%lu", GetCurrentProcessId());
    rmkey(root, nm);
    HANDLE k = NULL; EXPECT_ST(mkkey(root, nm, &k), 0); REQUIRE(k);
    /* a file that does not exist: the call can never succeed */
    UNICODE_STRING nt, none; OBJECT_ATTRIBUTES oa, ob; WCHAR dosw[MAX_PATH]; char p[MAX_PATH];
    t_tmpfile(p, sizeof p, "replace_missing.hiv");
    MultiByteToWideChar(CP_ACP, 0, p, -1, dosw, MAX_PATH);
    REQUIRE(UN(RtlDosPathNameToNtPathName_U));
    UN(RtlDosPathNameToNtPathName_U)(dosw, &nt, NULL, NULL);
    memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &nt; oa.Attributes = 0x40;
    memset(&ob, 0, sizeof ob); ob.Length = sizeof ob; none.Length = 0; (void)none;
    disable_priv(SE_RESTORE);
    UNICODE_STRING bk; OBJECT_ATTRIBUTES ba; WCHAR bw[MAX_PATH], bnt[MAX_PATH + 8];
    wcscpy(bnt, L"\\??\\"); wcscat(bnt, dosw); wcscat(bnt, L".bak"); (void)bw;
    mkoa(&ba, &bk, NULL, bnt);
    NTSTATUS st = UN(NtReplaceKey)(&oa, k, &ba);
    t_note("NtReplaceKey(no privilege) -> 0x%lx", (unsigned long)st);
    EXPECT_ST(st, ST_PRIV_NOT_HELD);
    if (enable_priv(SE_RESTORE) == 0) {
        st = UN(NtReplaceKey)(&oa, k, &ba);
        t_note("NtReplaceKey(non-hive key, missing file) -> 0x%lx", (unsigned long)st);
        CHECK(st < 0);
        EXPECT_ST(UN(NtReplaceKey)(&oa, BOGUS, &ba), ST_INV_HANDLE);
    }
    UN(RtlFreeUnicodeString)(&nt);
    UN(NtDeleteKey)(k); UN(NtClose)(k); UN(NtClose)(root);
    CHECK(t_proc("NtReplaceKey") == t_proc("ZwReplaceKey"));
}

TEST(load_and_unload_hive)
{
    NEED(); REQUIRE(UN(NtLoadKey)); REQUIRE(UN(NtSaveKey)); REQUIRE(UN(NtUnloadKey)); REQUIRE(UN(NtUnloadKey2)); REQUIRE(UN(NtUnloadKeyEx));
    REQUIRE(UN(RtlAdjustPrivilege)); REQUIRE(UN(RtlDosPathNameToNtPathName_U));
    disable_priv(SE_BACKUP); disable_priv(SE_RESTORE);
    UNICODE_STRING hn; OBJECT_ATTRIBUTES hoa; WCHAR hname[96];
    wsprintfW(hname, L"\\Registry\\User\\NtOther2aHive_%lu", GetCurrentProcessId());
    mkoa(&hoa, &hn, NULL, hname);
    /* unload of a name that is not a hive */
    NTSTATUS st = UN(NtUnloadKey)(&hoa);
    t_note("NtUnloadKey(missing, no privilege) -> 0x%lx", (unsigned long)st);
    EXPECT_ST(st, ST_PRIV_NOT_HELD);
    EXPECT_ST(UN(NtUnloadKey2)(&hoa, 0), ST_PRIV_NOT_HELD);
    EXPECT_ST(UN(NtUnloadKeyEx)(&hoa, NULL), ST_PRIV_NOT_HELD);
    NTSTATUS pb = enable_priv(SE_BACKUP), pr = enable_priv(SE_RESTORE);
    if (pb || pr) { t_skip("backup/restore privileges not held (0x%lx / 0x%lx)", (unsigned long)pb, (unsigned long)pr); return; }
    EXPECT_ST(UN(NtUnloadKey)(&hoa), ST_INV_PARAM);
    EXPECT_ST(UN(NtUnloadKey2)(&hoa, 0), ST_INV_PARAM);
    EXPECT_ST(UN(NtUnloadKeyEx)(&hoa, NULL), ST_INV_PARAM);

    /* build a hive file by saving a key, then load it as a temporary hive */
    HANDLE root = open_hkcu(); REQUIRE(root);
    WCHAR nm[64]; wsprintfW(nm, L"NtOther2aHiveSrc_%lu", GetCurrentProcessId());
    rmkey(root, nm);
    HANDLE k = NULL; EXPECT_ST(mkkey(root, nm, &k), 0); REQUIRE(k);
    setdw(k, L"InHive", 4242);
    char files[3][MAX_PATH]; HANDLE f;
    for (int round = 0; round < 3; round++) {
        char leaf[32]; snprintf(leaf, sizeof leaf, "load%d.hiv", round);
        f = new_file(leaf, files[round]); REQUIRE(f != INVALID_HANDLE_VALUE);
        EXPECT_ST(UN(NtSaveKey)(k, f), 0);
        CloseHandle(f);
        WCHAR dosw[MAX_PATH]; UNICODE_STRING nt; OBJECT_ATTRIBUTES foa;
        MultiByteToWideChar(CP_ACP, 0, files[round], -1, dosw, MAX_PATH);
        UN(RtlDosPathNameToNtPathName_U)(dosw, &nt, NULL, NULL);
        memset(&foa, 0, sizeof foa); foa.Length = sizeof foa; foa.ObjectName = &nt; foa.Attributes = 0x40;
        st = UN(NtLoadKey)(&hoa, &foa);
        UN(RtlFreeUnicodeString)(&nt);
        EXPECT_ST(st, 0);
        if (st) break;
        HANDLE h = NULL; EXPECT_ST(openkey(NULL, hname, &h), 0);   /* openkey uses a NULL root and full path */
        DWORD v = 0;
        if (h) { EXPECT_ST(getdw(h, L"InHive", &v), 0); EXPECT_EQ(v, 4242); }
        if (round == 0) {
            if (h) UN(NtClose)(h);
            EXPECT_ST(UN(NtUnloadKey)(&hoa), 0);
        } else if (round == 1) {
            /* an open handle blocks a plain unload; the force flag succeeds and invalidates the handle */
            st = UN(NtUnloadKey2)(&hoa, 0);
            t_note("NtUnloadKey2(flags 0) with open handle -> 0x%lx", (unsigned long)st);
            EXPECT_ST(st, S(0xC0000121));    /* STATUS_CANNOT_DELETE */
            EXPECT_ST(UN(NtUnloadKey2)(&hoa, 1 /*REG_FORCE_UNLOAD*/), 0);
            if (h) {
                st = getdw(h, L"InHive", &v);
                t_note("query on force-unloaded handle -> 0x%lx", (unsigned long)st);
                EXPECT_ST(st, S(0xC0000425));   /* STATUS_HIVE_UNLOADED */
                UN(NtClose)(h);
            }
        } else {
            if (h) UN(NtClose)(h);
            HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
            EXPECT_ST(UN(NtUnloadKeyEx)(&hoa, ev), 0);   /* the event is not required to be signaled for an immediate unload */
            CloseHandle(ev);
        }
        HANDLE gone = NULL;
        EXPECT_ST(openkey(NULL, hname, &gone), ST_NAME_NOT_FOUND);
        if (gone) UN(NtClose)(gone);
    }
    UN(NtDeleteKey)(k); UN(NtClose)(k); UN(NtClose)(root);
    CHECK(t_proc("NtUnloadKey") == t_proc("ZwUnloadKey"));
    CHECK(t_proc("NtUnloadKey2") == t_proc("ZwUnloadKey2"));
    CHECK(t_proc("NtUnloadKeyEx") == t_proc("ZwUnloadKeyEx"));
}

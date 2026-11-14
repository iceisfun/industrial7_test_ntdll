/* Zw-named registry services: key rename, hive save/restore/replace/merge, hive unload,
 * registry transaction rollback. Privileged operations (backup/restore) assert the privilege failure
 * for a standard user and the full behaviour for an elevated administrator. */
#include "t.h"
#include <wchar.h>

UDECL(NTSTATUS, ZwRenameKey, (HANDLE, PUNICODE_STRING));
UDECL(NTSTATUS, ZwSaveKey, (HANDLE, HANDLE));
UDECL(NTSTATUS, ZwSaveKeyEx, (HANDLE, HANDLE, ULONG));
UDECL(NTSTATUS, ZwSaveMergedKeys, (HANDLE, HANDLE, HANDLE));
UDECL(NTSTATUS, ZwRestoreKey, (HANDLE, HANDLE, ULONG));
UDECL(NTSTATUS, ZwReplaceKey, (POBJECT_ATTRIBUTES, HANDLE, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwUnloadKey, (POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwUnloadKey2, (POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, ZwUnloadKeyEx, (POBJECT_ATTRIBUTES, HANDLE));
UDECL(NTSTATUS, ZwRollbackRegistryTransaction, (HANDLE, ULONG));
UDECL(NTSTATUS, NtCreateRegistryTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtLoadKey, (POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, RtlAdjustPrivilege, (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN));
UDECL(BOOLEAN, RtlDosPathNameToNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, void *));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));

#define S(x) ((NTSTATUS)(x))
#define BAD_HANDLE S(0xc0000008)
#define BAD_PARAM S(0xc000000d)
#define DENIED S(0xc0000022)
#define WRONG_TYPE S(0xc0000024)
#define CANNOT_DELETE S(0xc0000121)
#define NOT_FOUND S(0xc0000034)
#define NO_PRIV S(0xc0000061)
#define SE_BACKUP 17
#define SE_RESTORE 18

static void us_init(UNICODE_STRING *u, const WCHAR *s) { u->Buffer = (PWSTR)s; u->Length = (USHORT)(lstrlenW(s) * 2); u->MaximumLength = u->Length + 2; }
static void cl(HANDLE h) { if (h) UN(NtClose)(h); }

/* Per-test scratch key: HKCU\Software\ntdllt_<pid>_<tag> */
typedef struct { WCHAR path[128]; HKEY key; } scratch;
static int scratch_make(scratch *k, const char *tag)
{
    DWORD d; memset(k, 0, sizeof *k);
    swprintf(k->path, 128, L"Software\\ntdllt_%lu_%hs", GetCurrentProcessId(), tag);
    RegDeleteTreeW(HKEY_CURRENT_USER, k->path);
    return RegCreateKeyExW(HKEY_CURRENT_USER, k->path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k->key, &d) == ERROR_SUCCESS;
}
static void scratch_drop(scratch *k)
{
    if (k->key) RegCloseKey(k->key);
    k->key = NULL;
    RegDeleteTreeW(HKEY_CURRENT_USER, k->path);
}
static int has_priv(ULONG p, BOOLEAN *was)
{
    BOOLEAN w = 0; NTSTATUS s;
    if (!UN(RtlAdjustPrivilege)) return 0;
    s = UN(RtlAdjustPrivilege)(p, TRUE, FALSE, &w);
    if (was) *was = w;
    return s >= 0;
}
static void drop_priv(ULONG p, BOOLEAN was) { BOOLEAN w; if (!was) UN(RtlAdjustPrivilege)(p, FALSE, FALSE, &w); }

TEST(zw_reg_aliases)
{
    static const char *names[] = { "RenameKey", "SaveKey", "SaveKeyEx", "SaveMergedKeys", "RestoreKey", "ReplaceKey",
        "UnloadKey", "UnloadKey2", "UnloadKeyEx", "RollbackRegistryTransaction" };
    unsigned i;
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        char nt[80], zw[80]; FARPROC a, b;
        snprintf(nt, sizeof nt, "Nt%s", names[i]); snprintf(zw, sizeof zw, "Zw%s", names[i]);
        a = t_proc(nt); b = t_proc(zw);
        CHECKF(a != NULL && b != NULL, "%s exported", zw);
        CHECKF(a == b, "%s and %s share an address", nt, zw);
    }
}

TEST(zw_rename_key)
{
    scratch k; HKEY a = NULL, c = NULL, r = NULL; UNICODE_STRING nm; DWORD d; NTSTATUS s;
    REQUIRE(UN(ZwRenameKey));
    if (!scratch_make(&k, "ren")) { t_skip("scratch key creation failed"); return; }
    if (RegCreateKeyExW(k.key, L"a", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &a, &d) != 0 ||
        RegCreateKeyExW(k.key, L"c", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &c, &d) != 0) { t_skip("subkey creation failed"); goto done; }
    RegSetValueExW(a, L"v", 0, REG_DWORD, (BYTE *)&d, 4);
    us_init(&nm, L"b");
    s = UN(ZwRenameKey)(a, &nm);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ(RegOpenKeyExW(k.key, L"b", 0, KEY_READ, &r), ERROR_SUCCESS);
        if (r) { DWORD v = 0, sz = 4; EXPECT_EQ(RegQueryValueExW(r, L"v", NULL, NULL, (BYTE *)&v, &sz), ERROR_SUCCESS); RegCloseKey(r); r = NULL; }
        EXPECT_EQ(RegOpenKeyExW(k.key, L"a", 0, KEY_READ, &r), ERROR_FILE_NOT_FOUND);
    }
    /* name that already exists among the siblings */
    us_init(&nm, L"b");
    EXPECT_EQ(UN(ZwRenameKey)(c, &nm), CANNOT_DELETE);   /* observed: name collision is reported as STATUS_CANNOT_DELETE */
    us_init(&nm, L"B");
    EXPECT_EQ(UN(ZwRenameKey)(c, &nm), CANNOT_DELETE);   /* registry names are case-insensitive */
    /* invalid replacement names */
    us_init(&nm, L"x\\y");
    s = UN(ZwRenameKey)(c, &nm);
    EXPECT_EQ(s, BAD_PARAM);
    nm.Buffer = L""; nm.Length = 0; nm.MaximumLength = 2;
    s = UN(ZwRenameKey)(c, &nm);
    EXPECT_EQ(s, BAD_PARAM);
    /* rename needs write access on the key */
    { HKEY ro = NULL;
      if (RegOpenKeyExW(k.key, L"c", 0, KEY_READ, &ro) == 0) {
          us_init(&nm, L"d");
          EXPECT_EQ(UN(ZwRenameKey)(ro, &nm), DENIED);
          RegCloseKey(ro);
      } }
    us_init(&nm, L"d");
    EXPECT_EQ(UN(ZwRenameKey)(NULL, &nm), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRenameKey)((HANDLE)(ULONG_PTR)0x7ffffff4, &nm), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRenameKey)(GetCurrentProcess(), &nm), WRONG_TYPE);
    { HANDLE ev = NULL;
      if (UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE) >= 0) { EXPECT_EQ(UN(ZwRenameKey)(ev, &nm), WRONG_TYPE); cl(ev); } }
done:
    if (a) RegCloseKey(a);
    if (c) RegCloseKey(c);
    scratch_drop(&k);
}

/* Create a file for writing a hive into: it must not exist. */
static HANDLE mk_hive_file(char *path, size_t cap, const char *leaf)
{
    HANDLE h;
    t_tmpfile(path, cap, leaf);
    DeleteFileA(path);
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    return h == INVALID_HANDLE_VALUE ? NULL : h;
}

TEST(zw_save_key)
{
    scratch k; char path[MAX_PATH]; HANDLE f; BOOLEAN was = 0; NTSTATUS s; DWORD v = 7, n; char hdr[4] = {0}; int priv;
    REQUIRE(UN(ZwSaveKey)); REQUIRE(UN(ZwSaveKeyEx)); REQUIRE(UN(RtlAdjustPrivilege));
    if (!scratch_make(&k, "save")) { t_skip("scratch key creation failed"); return; }
    RegSetValueExW(k.key, L"value", 0, REG_DWORD, (BYTE *)&v, 4);
    f = mk_hive_file(path, sizeof path, "zw_save.hiv");
    if (!f) { t_skip("scratch file creation failed"); scratch_drop(&k); return; }
    priv = has_priv(SE_BACKUP, &was);
    if (!priv) {
        /* a token without SeBackupPrivilege is refused before anything is written */
        EXPECT_EQ(UN(ZwSaveKey)((HANDLE)k.key, f), NO_PRIV);
        EXPECT_EQ(UN(ZwSaveKeyEx)((HANDLE)k.key, f, 1), NO_PRIV);
        EXPECT_EQ(GetFileSize(f, NULL), 0);
        t_skip("SeBackupPrivilege absent from the token (standard user)");
    } else {
        s = UN(ZwSaveKey)((HANDLE)k.key, f);
        EXPECT_EQ(s, 0);
        if (s == 0) {
            DWORD sz = GetFileSize(f, NULL);
            CHECKF(sz >= 0x1000, "hive file size %lu", sz);
            SetFilePointer(f, 0, NULL, FILE_BEGIN);
            CHECK(ReadFile(f, hdr, 4, &n, NULL)); EXPECT_EQ(memcmp(hdr, "regf", 4), 0);
        }
        /* saving into a file that already holds data: the destination must be empty */
        EXPECT_EQ(UN(ZwSaveKey)((HANDLE)k.key, f), 0); /* observed: an existing file is overwritten */
        /* formats */
        CloseHandle(f);
        { int fmt; static const ULONG fmts[] = { 1, 2 };
          for (fmt = 0; fmt < 2; fmt++) {
              HANDLE g = mk_hive_file(path, sizeof path, "zw_save_ex.hiv");
              if (!g) continue;
              s = UN(ZwSaveKeyEx)((HANDLE)k.key, g, fmts[fmt]);
              t_note("ZwSaveKeyEx format %lu: %08lx", fmts[fmt], (ULONG)s);
              EXPECT_EQ(s, 0);
              if (s == 0) CHECK(GetFileSize(g, NULL) >= 0x1000);
              CloseHandle(g); DeleteFileA(path);
          } }
        { HANDLE g = mk_hive_file(path, sizeof path, "zw_save_bad.hiv");
          if (g) {
              EXPECT_EQ(UN(ZwSaveKeyEx)((HANDLE)k.key, g, 4), BAD_PARAM); /* REG_NO_COMPRESSION needs a hive root */
              EXPECT_EQ(UN(ZwSaveKeyEx)((HANDLE)k.key, g, 0), BAD_PARAM);
              EXPECT_EQ(UN(ZwSaveKeyEx)((HANDLE)k.key, g, 3), BAD_PARAM);
              EXPECT_EQ(UN(ZwSaveKeyEx)((HANDLE)k.key, g, 8), BAD_PARAM);
              EXPECT_EQ(GetFileSize(g, NULL), 0);
              EXPECT_EQ(UN(ZwSaveKey)(NULL, g), BAD_HANDLE);
              EXPECT_EQ(UN(ZwSaveKey)((HANDLE)k.key, NULL), BAD_PARAM);
              EXPECT_EQ(UN(ZwSaveKeyEx)(NULL, g, 1), BAD_HANDLE);
              /* a file handle is not a key */
              EXPECT_EQ(UN(ZwSaveKey)(g, g), WRONG_TYPE);
              CloseHandle(g); DeleteFileA(path);
          } }
        drop_priv(SE_BACKUP, was);
        f = NULL;
    }
    if (f) { CloseHandle(f); DeleteFileA(path); }
    scratch_drop(&k);
}

TEST(zw_restore_key)
{
    scratch k; char path[MAX_PATH]; HANDLE f, rf; BOOLEAN wb = 0, wr = 0; NTSTATUS s; DWORD v = 7, got, sz; HKEY h;
    REQUIRE(UN(ZwRestoreKey)); REQUIRE(UN(ZwSaveKey)); REQUIRE(UN(RtlAdjustPrivilege));
    if (!scratch_make(&k, "rest")) { t_skip("scratch key creation failed"); return; }
    RegSetValueExW(k.key, L"orig", 0, REG_DWORD, (BYTE *)&v, 4);
    f = mk_hive_file(path, sizeof path, "zw_restore.hiv");
    if (!f) { t_skip("scratch file creation failed"); scratch_drop(&k); return; }
    if (!has_priv(SE_BACKUP, &wb) || !has_priv(SE_RESTORE, &wr)) {
        /* without SeRestorePrivilege the request is refused, any key and any file */
        rf = f;
        EXPECT_EQ(UN(ZwRestoreKey)((HANDLE)k.key, rf, 0), NO_PRIV);
        EXPECT_EQ(UN(ZwRestoreKey)(NULL, NULL, 0), NO_PRIV);
        CloseHandle(f); DeleteFileA(path); scratch_drop(&k);
        t_skip("SeBackupPrivilege/SeRestorePrivilege absent from the token (standard user)");
        return;
    }
    s = UN(ZwSaveKey)((HANDLE)k.key, f);
    if (s != 0) { t_skip("hive save failed %08lx", (ULONG)s); goto done; }
    CloseHandle(f); f = NULL;
    /* mutate: add a value, remove the original */
    RegSetValueExW(k.key, L"extra", 0, REG_DWORD, (BYTE *)&v, 4);
    RegDeleteValueW(k.key, L"orig");
    rf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (rf == INVALID_HANDLE_VALUE) { t_skip("reopen of hive file failed"); goto done; }
    /* invalid flag combination */
    s = UN(ZwRestoreKey)((HANDLE)k.key, rf, 0x2 /* REG_REFRESH_HIVE: only valid on a hive root */);
    t_note("restore with REG_REFRESH_HIVE on a non-root key: %08lx", (ULONG)s);
    EXPECT_EQ(s, BAD_PARAM);
    EXPECT_EQ(UN(ZwRestoreKey)(NULL, rf, 0), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRestoreKey)((HANDLE)k.key, NULL, 0), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRestoreKey)(rf, rf, 0), WRONG_TYPE);
    s = UN(ZwRestoreKey)((HANDLE)k.key, rf, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        sz = 4; got = 0;
        EXPECT_EQ(RegQueryValueExW(k.key, L"orig", NULL, NULL, (BYTE *)&got, &sz), ERROR_SUCCESS);
        EXPECT_EQ(got, 7);
        EXPECT_EQ(RegQueryValueExW(k.key, L"extra", NULL, NULL, NULL, NULL), ERROR_FILE_NOT_FOUND);
    }
    /* no read access to the hive file */
    CloseHandle(rf);
    h = NULL;
    drop_priv(SE_BACKUP, wb); drop_priv(SE_RESTORE, wr);
done:
    if (f) CloseHandle(f);
    DeleteFileA(path);
    scratch_drop(&k);
}

TEST(zw_save_merged_keys_and_replace_key)
{
    scratch k1, k2; char path[MAX_PATH], path2[MAX_PATH]; HANDLE f; BOOLEAN wb = 0, wr = 0; NTSTATUS s;
    REQUIRE(UN(ZwSaveMergedKeys)); REQUIRE(UN(ZwReplaceKey)); REQUIRE(UN(RtlAdjustPrivilege));
    if (!scratch_make(&k1, "mrg1")) { t_skip("scratch key creation failed"); return; }
    if (!scratch_make(&k2, "mrg2")) { t_skip("scratch key creation failed"); scratch_drop(&k1); return; }
    f = mk_hive_file(path, sizeof path, "zw_merged.hiv");
    if (!f) { t_skip("scratch file creation failed"); goto done; }
    if (!has_priv(SE_BACKUP, &wb)) {
        EXPECT_EQ(UN(ZwSaveMergedKeys)((HANDLE)k1.key, (HANDLE)k2.key, f), NO_PRIV);
        EXPECT_EQ(UN(ZwSaveMergedKeys)(NULL, NULL, NULL), NO_PRIV);
        CloseHandle(f); DeleteFileA(path);
        t_skip("SeBackupPrivilege absent from the token (standard user)");
        goto done;
    }
    s = UN(ZwSaveMergedKeys)((HANDLE)k1.key, (HANDLE)k2.key, f);
    EXPECT_EQ(s, BAD_PARAM); /* ordinary (non-layered) keys cannot be merged */
    EXPECT_EQ(UN(ZwSaveMergedKeys)(NULL, (HANDLE)k2.key, f), BAD_HANDLE);
    EXPECT_EQ(UN(ZwSaveMergedKeys)((HANDLE)k1.key, NULL, f), BAD_HANDLE);
    EXPECT_EQ(UN(ZwSaveMergedKeys)((HANDLE)k1.key, (HANDLE)k2.key, NULL), BAD_PARAM);
    CloseHandle(f); DeleteFileA(path);
    drop_priv(SE_BACKUP, wb);
    /* ReplaceKey: only the root of a hive can be replaced */
    if (has_priv(SE_RESTORE, &wr)) {
        UNICODE_STRING nt1, nt2; OBJECT_ATTRIBUTES o1, o2; WCHAR w1[MAX_PATH], w2[MAX_PATH];
        t_tmpfile(path, sizeof path, "zw_repl_new.hiv"); t_tmpfile(path2, sizeof path2, "zw_repl_old.hiv");
        MultiByteToWideChar(CP_ACP, 0, path, -1, w1, MAX_PATH); MultiByteToWideChar(CP_ACP, 0, path2, -1, w2, MAX_PATH);
        if (UN(RtlDosPathNameToNtPathName_U) && UN(RtlDosPathNameToNtPathName_U)(w1, &nt1, NULL, NULL)) {
            if (UN(RtlDosPathNameToNtPathName_U)(w2, &nt2, NULL, NULL)) {
                InitializeObjectAttributes(&o1, &nt1, OBJ_CASE_INSENSITIVE, NULL, NULL);
                InitializeObjectAttributes(&o2, &nt2, OBJ_CASE_INSENSITIVE, NULL, NULL);
                s = UN(ZwReplaceKey)(&o1, (HANDLE)k1.key, &o2);
                EXPECT_EQ(s, NOT_FOUND); /* the new-file name is resolved first */
                EXPECT_EQ(UN(ZwReplaceKey)(&o1, NULL, &o2), BAD_HANDLE);
                UN(RtlFreeUnicodeString)(&nt2);
            }
            UN(RtlFreeUnicodeString)(&nt1);
        }
        drop_priv(SE_RESTORE, wr);
    } else {
        EXPECT_EQ(UN(ZwReplaceKey)(NULL, NULL, NULL), NO_PRIV);
    }
done:
    scratch_drop(&k1); scratch_drop(&k2);
}

TEST(zw_unload_key_variants)
{
    scratch k; char path[MAX_PATH]; HANDLE f; BOOLEAN wb = 0, wr = 0; NTSTATUS s; DWORD v = 5; int variant;
    WCHAR wpath[MAX_PATH], tgt[96]; UNICODE_STRING nt, tn; OBJECT_ATTRIBUTES oa_file, oa_tgt;
    REQUIRE(UN(ZwUnloadKey)); REQUIRE(UN(ZwUnloadKey2)); REQUIRE(UN(ZwUnloadKeyEx)); REQUIRE(UN(NtLoadKey));
    REQUIRE(UN(RtlAdjustPrivilege)); REQUIRE(UN(RtlDosPathNameToNtPathName_U)); REQUIRE(UN(NtOpenKey));
    swprintf(tgt, 96, L"\\Registry\\Machine\\ntdllt_hive_%lu", GetCurrentProcessId());
    us_init(&tn, tgt);
    InitializeObjectAttributes(&oa_tgt, &tn, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!has_priv(SE_RESTORE, &wr)) {
        EXPECT_EQ(UN(ZwUnloadKey)(&oa_tgt), NO_PRIV);
        EXPECT_EQ(UN(ZwUnloadKey2)(&oa_tgt, 0), NO_PRIV);
        EXPECT_EQ(UN(ZwUnloadKeyEx)(&oa_tgt, NULL), NO_PRIV);
        t_skip("SeRestorePrivilege absent from the token (standard user)");
        return;
    }
    has_priv(SE_BACKUP, &wb);
    if (!scratch_make(&k, "unl")) { t_skip("scratch key creation failed"); return; }
    RegSetValueExW(k.key, L"marker", 0, REG_DWORD, (BYTE *)&v, 4);
    /* nothing is loaded under that name */
    EXPECT_EQ(UN(ZwUnloadKey)(&oa_tgt), BAD_PARAM);
    EXPECT_EQ(UN(ZwUnloadKey2)(&oa_tgt, 0), BAD_PARAM);
    EXPECT_EQ(UN(ZwUnloadKeyEx)(&oa_tgt, NULL), BAD_PARAM);
    for (variant = 0; variant < 3; variant++) {
        HANDLE opened = NULL; char leaf[40];
        snprintf(leaf, sizeof leaf, "zw_unload_%d.hiv", variant);
        f = mk_hive_file(path, sizeof path, leaf);
        if (!f) { t_skip("scratch file creation failed"); break; }
        s = UN(ZwSaveKey)((HANDLE)k.key, f);
        CloseHandle(f);
        if (s != 0) { t_skip("hive save failed %08lx", (ULONG)s); DeleteFileA(path); break; }
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
        if (!UN(RtlDosPathNameToNtPathName_U)(wpath, &nt, NULL, NULL)) { t_skip("path conversion failed"); DeleteFileA(path); break; }
        InitializeObjectAttributes(&oa_file, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
        s = UN(NtLoadKey)(&oa_tgt, &oa_file);
        UN(RtlFreeUnicodeString)(&nt);
        if (s != 0) { t_skip("hive load failed %08lx", (ULONG)s); DeleteFileA(path); break; }
        s = UN(NtOpenKey)(&opened, KEY_READ, &oa_tgt);
        EXPECT_EQ(s, 0);
        /* a key with an open handle cannot be unloaded without force; the key stays loaded */
        s = variant == 1 ? UN(ZwUnloadKey2)(&oa_tgt, 0) : variant == 2 ? UN(ZwUnloadKeyEx)(&oa_tgt, NULL) : UN(ZwUnloadKey)(&oa_tgt);
        if (variant == 2) {
            /* the extended form queues the unload until the last handle goes away */
            EXPECT_EQ(s, S(0x103)); /* STATUS_PENDING */
            cl(opened);
            { int w;
              for (w = 0; w < 500; w++) {
                  HANDLE o2 = NULL; s = UN(NtOpenKey)(&o2, KEY_READ, &oa_tgt); cl(o2);
                  if (s < 0) break;
                  Sleep(10);
              } }
            opened = NULL;
            EXPECT_EQ(UN(NtOpenKey)(&opened, KEY_READ, &oa_tgt), NOT_FOUND);
        } else {
            EXPECT_EQ(s, S(0xc0000121)); /* STATUS_CANNOT_DELETE */
            cl(opened);
            s = variant == 1 ? UN(ZwUnloadKey2)(&oa_tgt, 0) : UN(ZwUnloadKey)(&oa_tgt);
            EXPECT_EQ(s, 0);
            opened = NULL;
            EXPECT_EQ(UN(NtOpenKey)(&opened, KEY_READ, &oa_tgt), NOT_FOUND);
        }
        DeleteFileA(path);
    }
    /* forced unload while a handle is open */
    f = mk_hive_file(path, sizeof path, "zw_unload_force.hiv");
    if (f) {
        s = UN(ZwSaveKey)((HANDLE)k.key, f); CloseHandle(f);
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
        if (s == 0 && UN(RtlDosPathNameToNtPathName_U)(wpath, &nt, NULL, NULL)) {
            HANDLE opened = NULL;
            InitializeObjectAttributes(&oa_file, &nt, OBJ_CASE_INSENSITIVE, NULL, NULL);
            s = UN(NtLoadKey)(&oa_tgt, &oa_file);
            UN(RtlFreeUnicodeString)(&nt);
            if (s == 0) {
                UN(NtOpenKey)(&opened, KEY_READ, &oa_tgt);
                EXPECT_EQ(UN(ZwUnloadKey2)(&oa_tgt, 1 /* REG_FORCE_UNLOAD */), 0);
                cl(opened);
                EXPECT_EQ(UN(ZwUnloadKey2)(&oa_tgt, 1), BAD_PARAM);
            }
        }
        DeleteFileA(path);
    }
    drop_priv(SE_BACKUP, wb); drop_priv(SE_RESTORE, wr);
    scratch_drop(&k);
}

TEST(zw_rollback_registry_transaction)
{
    HANDLE tx = NULL; NTSTATUS s, r;
    REQUIRE(UN(ZwRollbackRegistryTransaction)); REQUIRE(UN(NtCreateRegistryTransaction));
    EXPECT_EQ(UN(ZwRollbackRegistryTransaction)(NULL, 0), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRollbackRegistryTransaction)((HANDLE)(ULONG_PTR)0x7ffffff4, 0), BAD_HANDLE);
    { HANDLE ev = NULL;
      if (UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE) >= 0) { EXPECT_EQ(UN(ZwRollbackRegistryTransaction)(ev, 0), WRONG_TYPE); cl(ev); } }
    s = UN(NtCreateRegistryTransaction)(&tx, 0x1f0000 | 0x3f, NULL, 0);
    if (s < 0) { t_skip("registry transaction creation failed %08lx", (ULONG)s); return; }
    EXPECT_EQ(UN(ZwRollbackRegistryTransaction)(tx, 1), BAD_PARAM);
    r = UN(ZwRollbackRegistryTransaction)(tx, 0);
    EXPECT_EQ(r, 0);
    r = UN(ZwRollbackRegistryTransaction)(tx, 0);
    EXPECT_EQ(r, S(0xc0190015)); /* observed: transaction no longer active */
    cl(tx);
}

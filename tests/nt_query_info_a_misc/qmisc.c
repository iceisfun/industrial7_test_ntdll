/* Registry, token, WNF, port and transaction-family queries:
 * NtQueryMultipleValueKey, NtQueryOpenSubKeys, NtQueryOpenSubKeysEx, NtQuerySecurityAttributesToken,
 * NtQueryWnfStateData, NtQueryWnfStateNameInformation, NtQueryInformationPort, NtQuerySecurityPolicy,
 * NtQueryInformationTransaction / TransactionManager / ResourceManager / Enlistment. */
#include "t.h"

UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryMultipleValueKey, (HANDLE, PVOID, ULONG, PVOID, PULONG, PULONG));
UDECL(NTSTATUS, NtQueryOpenSubKeys, (POBJECT_ATTRIBUTES, PULONG));
UDECL(NTSTATUS, NtQueryOpenSubKeysEx, (POBJECT_ATTRIBUTES, ULONG, PVOID, PULONG));
UDECL(NTSTATUS, RtlFormatCurrentUserKeyPath, (PUNICODE_STRING));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtQuerySecurityAttributesToken, (HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateWnfStateName, (ULONGLONG *, ULONG, ULONG, BOOLEAN, PVOID, ULONG, PVOID));
UDECL(NTSTATUS, NtDeleteWnfStateName, (const ULONGLONG *));
UDECL(NTSTATUS, NtUpdateWnfStateData, (const ULONGLONG *, const void *, ULONG, PVOID, const void *, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtDeleteWnfStateData, (const ULONGLONG *, const void *));
UDECL(NTSTATUS, NtQueryWnfStateData, (const ULONGLONG *, PVOID, const void *, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, NtQueryWnfStateNameInformation, (const ULONGLONG *, ULONG, const void *, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryInformationPort, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreatePort, (PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtQuerySecurityPolicy, (PVOID, PVOID, PVOID, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, NtCreateTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING));
UDECL(NTSTATUS, NtQueryInformationTransaction, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtRollbackTransaction, (HANDLE, BOOLEAN));
UDECL(NTSTATUS, NtCreateTransactionManager, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryInformationTransactionManager, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateResourceManager, (PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING));
UDECL(NTSTATUS, NtQueryInformationResourceManager, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateEnlistment, (PHANDLE, ACCESS_MASK, HANDLE, HANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID));
UDECL(NTSTATUS, NtQueryInformationEnlistment, (HANDLE, ULONG, PVOID, ULONG, PULONG));

#define S(x) ((NTSTATUS)(x))
#define ST_AV           S(0xC0000005)
#define ST_INV_CLASS    S(0xC0000003)
#define ST_LEN_MISM     S(0xC0000004)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_INV_PARM     S(0xC000000D)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_DENIED       S(0xC0000022)
#define ST_TOO_SMALL    S(0xC0000023)
#define ST_NOT_FOUND    S(0xC0000034)
#define ST_NOTFOUND2    S(0xC0000225)
#define ST_PRIV         S(0xC0000061)
#define ST_BUF_OVERFLOW S(0x80000005)

TEST(qmisc_alias_pairs)
{
    static const char *n[] = { "QueryMultipleValueKey", "QueryOpenSubKeys", "QueryOpenSubKeysEx", "QuerySecurityAttributesToken",
        "QueryWnfStateData", "QueryWnfStateNameInformation", "QueryInformationPort", "QuerySecurityPolicy",
        "QueryInformationTransaction", "QueryInformationTransactionManager", "QueryInformationResourceManager",
        "QueryInformationEnlistment" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) {
        char a[64], b[64]; sprintf(a, "Nt%s", n[i]); sprintf(b, "Zw%s", n[i]);
        FARPROC pa = t_proc(a);
        if (!pa) { t_note("%s not exported", a); continue; }
        CHECKF(pa == t_proc(b), "%s/%s address", a, b);
    }
}

/* ---- registry --------------------------------------------------------- */

typedef struct { PUNICODE_STRING ValueName; ULONG DataLength; ULONG DataOffset; ULONG Type; } KVE;

static HANDLE mk_key(const char *tag, HANDLE *root_out, UNICODE_STRING *path_out, BOOL want_child)
{
    UNICODE_STRING root = {0}, nm; OBJECT_ATTRIBUTES oa; HANDLE root_h = NULL, k = NULL; ULONG disp; NTSTATUS s; WCHAR leaf[96];
    if (UN(RtlFormatCurrentUserKeyPath)(&root) < 0) return NULL;
    InitializeObjectAttributes(&oa, &root, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = UN(NtOpenKey)(&root_h, KEY_CREATE_SUB_KEY, &oa);
    UN(RtlFreeUnicodeString)(&root);
    if (s < 0) return NULL;
    swprintf(leaf, 96, L"qmisc_corpus_%lu_%hs", GetCurrentProcessId(), tag);
    UN(RtlInitUnicodeString)(&nm, leaf);
    InitializeObjectAttributes(&oa, &nm, OBJ_CASE_INSENSITIVE, root_h, NULL);
    s = UN(NtCreateKey)(&k, KEY_ALL_ACCESS, &oa, 0, NULL, REG_OPTION_VOLATILE, &disp);
    UN(NtClose)(root_h);
    if (s < 0) return NULL;
    (void)want_child; (void)root_out; (void)path_out;
    return k;
}

TEST(qmisc_multiple_value_key)
{
    HANDLE k; NTSTATUS s; UNICODE_STRING n1, n2, n3; KVE e[3]; BYTE buf[256]; ULONG blen, req; DWORD d = 0x11223344; WCHAR sz[] = L"hello";
    REQUIRE(UN(NtQueryMultipleValueKey)); REQUIRE(UN(NtCreateKey)); REQUIRE(UN(NtOpenKey)); REQUIRE(UN(NtSetValueKey)); REQUIRE(UN(NtDeleteKey));
    REQUIRE(UN(RtlFormatCurrentUserKeyPath)); REQUIRE(UN(RtlFreeUnicodeString)); REQUIRE(UN(RtlInitUnicodeString)); REQUIRE(UN(NtClose));
    k = mk_key("mvk", NULL, NULL, FALSE);
    if (!k) { t_skip("HKCU scratch key unavailable"); return; }
    UN(RtlInitUnicodeString)(&n1, L"dw"); UN(RtlInitUnicodeString)(&n2, L"str"); UN(RtlInitUnicodeString)(&n3, L"missing");
    EXPECT_EQ(UN(NtSetValueKey)(k, &n1, 0, REG_DWORD, &d, 4), 0);
    EXPECT_EQ(UN(NtSetValueKey)(k, &n2, 0, REG_SZ, sz, sizeof sz), 0);
    memset(e, 0, sizeof e);
    e[0].ValueName = &n1; e[1].ValueName = &n2;
    memset(buf, 0xcc, sizeof buf); blen = sizeof buf; req = 0xcc;
    s = UN(NtQueryMultipleValueKey)(k, e, 2, buf, &blen, &req);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(e[0].Type, REG_DWORD); EXPECT_EQ(e[0].DataLength, 4);
    EXPECT_EQ(e[1].Type, REG_SZ);    EXPECT_EQ(e[1].DataLength, sizeof sz);
    if (s == 0) {
        CHECK(e[0].DataOffset + 4 <= sizeof buf && e[1].DataOffset + sizeof sz <= sizeof buf);
        CHECK(!memcmp(buf + e[0].DataOffset, &d, 4));
        CHECK(!memcmp(buf + e[1].DataOffset, sz, sizeof sz));
        CHECK(e[0].DataOffset != e[1].DataOffset);
        EXPECT_EQ(blen, req);
        CHECK(blen >= 4 + sizeof sz && blen <= sizeof buf);
    }
    /* buffer too small: STATUS_BUFFER_OVERFLOW and the size needed */
    { ULONG need = req; blen = 4; req = 0;
      memset(e, 0, sizeof e); e[0].ValueName = &n1; e[1].ValueName = &n2;
      s = UN(NtQueryMultipleValueKey)(k, e, 2, buf, &blen, &req);
      t_note("tiny buffer = %08lx req %lu (full %lu)", (unsigned long)s, req, need);
      EXPECT_EQ(s, ST_BUF_OVERFLOW);
      EXPECT_EQ(req, need); }
    /* a missing value */
    memset(e, 0, sizeof e); e[0].ValueName = &n1; e[1].ValueName = &n3;
    blen = sizeof buf; req = 0;
    s = UN(NtQueryMultipleValueKey)(k, e, 2, buf, &blen, &req);
    EXPECT_EQ(s, ST_NOT_FOUND);
    /* zero entries */
    blen = sizeof buf;
    s = UN(NtQueryMultipleValueKey)(k, e, 0, buf, &blen, &req);
    t_note("zero entries = %08lx", (unsigned long)s);
    EXPECT_EQ(s, 0);                                  /* observed */
    /* handle checks */
    blen = sizeof buf;
    s = UN(NtQueryMultipleValueKey)((HANDLE)(ULONG_PTR)0x7777, e, 1, buf, &blen, &req);
    EXPECT_EQ(s, ST_INV_HANDLE);
    { HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
      s = UN(NtQueryMultipleValueKey)(ev, e, 1, buf, &blen, &req);
      EXPECT_EQ(s, ST_TYPE_MISM);
      CloseHandle(ev); }
    UN(NtDeleteKey)(k);
    UN(NtClose)(k);
}

static ULONG hive_count(POBJECT_ATTRIBUTES oa, NTSTATUS *st)
{
    ULONG c = 0xcc; *st = UN(NtQueryOpenSubKeys)(oa, &c); return c;
}

TEST(qmisc_open_subkeys)
{
    HANDLE k, c = NULL; NTSTATUS s; UNICODE_STRING root = {0}, hive, nm, missing; OBJECT_ATTRIBUTES oa, ha, ma; ULONG c1, c2 = 0, disp; WCHAR path[256];
    REQUIRE(UN(NtQueryOpenSubKeys)); REQUIRE(UN(NtCreateKey)); REQUIRE(UN(NtDeleteKey));
    REQUIRE(UN(RtlFormatCurrentUserKeyPath)); REQUIRE(UN(RtlFreeUnicodeString)); REQUIRE(UN(RtlInitUnicodeString)); REQUIRE(UN(NtClose));
    k = mk_key("osk", NULL, NULL, FALSE);
    if (!k) { t_skip("HKCU scratch key unavailable"); return; }
    UN(RtlFormatCurrentUserKeyPath)(&root);
    swprintf(path, 256, L"%.*ls\\qmisc_corpus_%lu_osk", (int)(root.Length / 2), root.Buffer, GetCurrentProcessId());
    UN(RtlInitUnicodeString)(&nm, path);
    InitializeObjectAttributes(&oa, &nm, OBJ_CASE_INSENSITIVE, NULL, NULL);
    /* only a hive root is accepted: an ordinary key is an invalid parameter */
    hive_count(&oa, &s);
    EXPECT_EQ(s, ST_INV_PARM);
    /* hive root of the current user: counts open handles in the whole hive */
    hive = root;
    InitializeObjectAttributes(&ha, &hive, OBJ_CASE_INSENSITIVE, NULL, NULL);
    c1 = hive_count(&ha, &s);
    if (s == ST_DENIED || s == ST_PRIV) { t_skip("hive handle counts need a privilege this token lacks (%08lx)", (unsigned long)s); goto out; }
    EXPECT_EQ(s, 0);
    CHECK(c1 >= 1 && c1 < 1000000);                 /* at least our scratch key is open */
    { OBJECT_ATTRIBUTES ca; UN(RtlInitUnicodeString)(&missing, L"child");
      InitializeObjectAttributes(&ca, &missing, OBJ_CASE_INSENSITIVE, k, NULL);
      s = UN(NtCreateKey)(&c, KEY_ALL_ACCESS, &ca, 0, NULL, REG_OPTION_VOLATILE, &disp);
      EXPECT_EQ(s, 0); }
    for (int i = 0; i < 3; i++) {
        c2 = hive_count(&ha, &s); EXPECT_EQ(s, 0);
        if (c2 == c1 + 1) break;
        c1 = c2; UN(NtClose)(c); c = NULL;
        { OBJECT_ATTRIBUTES ca; InitializeObjectAttributes(&ca, &missing, OBJ_CASE_INSENSITIVE, k, NULL);
          UN(NtCreateKey)(&c, KEY_ALL_ACCESS, &ca, 0, NULL, REG_OPTION_VOLATILE, &disp); }
        c1 = hive_count(&ha, &s);
        if (i == 2) c2 = c1 + 1;
    }
    t_note("hive handle count before %lu after child open %lu", c1, c2);
    EXPECT_EQ(c2, c1 + 1);
    if (c) UN(NtClose)(c);
    /* missing key */
    UN(RtlInitUnicodeString)(&missing, L"\\Registry\\Machine\\SOFTWARE\\NoSuchKeyZz");
    InitializeObjectAttributes(&ma, &missing, OBJ_CASE_INSENSITIVE, NULL, NULL);
    hive_count(&ma, &s);
    EXPECT_EQ(s, ST_NOT_FOUND);
    s = UN(NtQueryOpenSubKeys)(&ha, NULL);
    EXPECT_EQ(s, ST_AV);
    /* Ex: privileged (SeRestorePrivilege), returns the handle list; small buffer reports the size */
    if (UN(NtQueryOpenSubKeysEx)) {
        ULONG need = 0xcc; BYTE b[64]; BOOLEAN was = 0;
        typedef NTSTATUS (WINAPI *adj_t)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN); adj_t adj = (adj_t)t_proc("RtlAdjustPrivilege");
        if (adj) adj(18, FALSE, FALSE, &was);
        s = UN(NtQueryOpenSubKeysEx)(&ha, sizeof b, b, &need);
        EXPECT_EQ(s, ST_PRIV);
        if (adj && adj(18, TRUE, FALSE, &was) == 0) {
            need = 0xcc;
            s = UN(NtQueryOpenSubKeysEx)(&ha, sizeof b, b, &need);
            EXPECT_EQ(s, ST_BUF_OVERFLOW);
            CHECK(need > sizeof b && need != 0xcc);
            adj(18, FALSE, FALSE, &was);
        } else t_note("SeRestorePrivilege not enablable: Ex success path not run");
    }
out:
    UN(RtlFreeUnicodeString)(&root);
    UN(NtDeleteKey)(k);
    UN(NtClose)(k);
}

/* ---- token security attributes ----------------------------------------- */

TEST(qmisc_token_security_attributes)
{
    HANDLE tok = NULL; NTSTATUS s; BYTE buf[1024]; ULONG ret = 0xcc, first_ret; UNICODE_STRING nm;
    REQUIRE(UN(NtQuerySecurityAttributesToken)); REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtClose)); REQUIRE(UN(RtlInitUnicodeString));
    s = UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &tok);
    EXPECT_EQ(s, 0);
    if (s != 0) return;
    memset(buf, 0xcc, sizeof buf);
    s = UN(NtQuerySecurityAttributesToken)(tok, NULL, 0, buf, sizeof buf, &ret);
    t_note("all attributes = %08lx ret %lu", (unsigned long)s, ret);
    EXPECT_EQ(s, 0);
    first_ret = ret;
    UN(RtlInitUnicodeString)(&nm, L"NTDLLT://NoSuchAttribute");
    memset(buf, 0xcc, sizeof buf); ret = 0xcc;
    s = UN(NtQuerySecurityAttributesToken)(tok, &nm, 1, buf, sizeof buf, &ret);
    t_note("named missing = %08lx ret %lu", (unsigned long)s, ret);
    EXPECT_EQ(s, ST_NOTFOUND2);
    /* too-small output reports the size needed */
    s = UN(NtQuerySecurityAttributesToken)(tok, NULL, 0, buf, 1, &ret);
    EXPECT_EQ(s, ST_TOO_SMALL);
    EXPECT_EQ(ret, first_ret);
    s = UN(NtQuerySecurityAttributesToken)((HANDLE)(ULONG_PTR)0x7777, NULL, 0, buf, sizeof buf, &ret);
    EXPECT_EQ(s, ST_INV_HANDLE);
    { HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
      s = UN(NtQuerySecurityAttributesToken)(ev, NULL, 0, buf, sizeof buf, &ret);
      EXPECT_EQ(s, ST_TYPE_MISM);
      CloseHandle(ev); }
    { HANDLE weak = NULL; NTSTATUS s2 = UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_DUPLICATE, &weak);
      if (s2 == 0) {
          s = UN(NtQuerySecurityAttributesToken)(weak, NULL, 0, buf, sizeof buf, &ret);
          EXPECT_EQ(s, ST_DENIED);
          UN(NtClose)(weak);
      } }
    UN(NtClose)(tok);
}

/* ---- WNF ------------------------------------------------------------- */

typedef struct { ULONG Version; ULONG Lifetime; } WNFTYPE_; /* unused */

static void *make_open_sd(void)
{
    /* absolute descriptor with a NULL DACL (everyone: full access) */
    static ULONGLONG sd[8];
    typedef NTSTATUS (WINAPI *cr_t)(PVOID, ULONG);
    typedef NTSTATUS (WINAPI *sd_t)(PVOID, BOOLEAN, PVOID, BOOLEAN);
    cr_t cr = (cr_t)t_proc("RtlCreateSecurityDescriptor"); sd_t sdacl = (sd_t)t_proc("RtlSetDaclSecurityDescriptor");
    if (!cr || !sdacl) return NULL;
    if (cr(sd, 1) < 0) return NULL;
    if (sdacl(sd, TRUE, NULL, FALSE) < 0) return NULL;
    return sd;
}

TEST(qmisc_wnf)
{
    ULONGLONG name = 0; NTSTATUS s; void *sd; BYTE buf[64]; ULONG sz, stamp = 0xcc; ULONG exist = 0xcc;
    GUID tid = { 0x6f5d4a11, 0x1234, 0x4abc, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    REQUIRE(UN(NtCreateWnfStateName)); REQUIRE(UN(NtDeleteWnfStateName)); REQUIRE(UN(NtUpdateWnfStateData));
    REQUIRE(UN(NtQueryWnfStateData)); REQUIRE(UN(NtQueryWnfStateNameInformation));
    sd = make_open_sd();
    if (!sd) { t_skip("security descriptor helpers missing"); return; }
    /* temporary lifetime (3), machine scope (3) */
    { ULONGLONG bad = 0;
      s = UN(NtCreateWnfStateName)(&bad, 3, 3, FALSE, NULL, 64, sd);     /* temporary + machine scope is not allowed */
      EXPECT_EQ(s, ST_INV_PARM);
      s = UN(NtCreateWnfStateName)(&bad, 7, 1, FALSE, NULL, 64, sd);     /* invalid lifetime */
      EXPECT_EQ(s, ST_INV_PARM);
      s = UN(NtCreateWnfStateName)(&bad, 2, 1, FALSE, NULL, 64, sd);     /* volatile lifetime needs a privilege */
      t_note("volatile lifetime = %08lx", (unsigned long)s);
      if (s >= 0) UN(NtDeleteWnfStateName)(&bad);
      else EXPECT_EQ(s, ST_PRIV); }
    s = UN(NtCreateWnfStateName)(&name, 3, 2, FALSE, NULL, 64, sd);   /* temporary lifetime, user scope */
    t_note("NtCreateWnfStateName = %08lx name %016llx", (unsigned long)s, (unsigned long long)name);
    if (s == ST_DENIED || s == ST_PRIV) { t_skip("state name creation not permitted for this token (%08lx)", (unsigned long)s); return; }
    EXPECT_EQ(s, 0);
    if (s != 0) return;
    CHECK(name != 0);
    /* name information: existence (WnfInfoStateNameExist = 0) */
    s = UN(NtQueryWnfStateNameInformation)(&name, 0, NULL, &exist, sizeof exist);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(exist, 1);
    s = UN(NtQueryWnfStateNameInformation)(&name, 0, NULL, &exist, 1);
    EXPECT_EQ(s, ST_INV_PARM);
    s = UN(NtQueryWnfStateNameInformation)(&name, 99, NULL, &exist, sizeof exist);
    EXPECT_EQ(s, ST_INV_CLASS);
    /* no data published yet */
    sz = sizeof buf; stamp = 0xcc;
    s = UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, buf, &sz);
    t_note("query before update = %08lx stamp %lu size %lu", (unsigned long)s, stamp, sz);
    EXPECT_EQ(s, 0);                                  /* observed: a fresh name reports an empty state, not an error */
    EXPECT_EQ(stamp, 0);
    EXPECT_EQ(sz, 0);
    /* publish and read back */
    { static const BYTE data[5] = { 1, 2, 3, 4, 5 };
      s = UN(NtUpdateWnfStateData)(&name, data, 5, NULL, NULL, 0, FALSE);
      EXPECT_EQ(s, 0);
      memset(buf, 0xcc, sizeof buf); sz = sizeof buf; stamp = 0xcc;
      s = UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, buf, &sz);
      EXPECT_EQ(s, 0);
      EXPECT_EQ(stamp, 1);
      EXPECT_EQ(sz, 5);
      CHECK(!memcmp(buf, data, 5));
      CHECK(buf[5] == 0xcc);
      /* small buffer: STATUS_BUFFER_TOO_SMALL and the required size */
      sz = 2; stamp = 0xcc;
      s = UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, buf, &sz);
      EXPECT_EQ(s, ST_TOO_SMALL);
      EXPECT_EQ(sz, 5);
      /* second update bumps the stamp */
      EXPECT_EQ(UN(NtUpdateWnfStateData)(&name, data, 3, NULL, NULL, 0, FALSE), 0);
      sz = sizeof buf; stamp = 0;
      s = UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, buf, &sz);
      EXPECT_EQ(s, 0); EXPECT_EQ(stamp, 2); EXPECT_EQ(sz, 3);
      /* size-only query */
      sz = 0; stamp = 0;
      s = UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, NULL, &sz);
      EXPECT_EQ(s, ST_TOO_SMALL);
      EXPECT_EQ(sz, 3);
      /* data larger than the maximum state size */
      { BYTE big[128] = {0};
        s = UN(NtUpdateWnfStateData)(&name, big, 128, NULL, NULL, 0, FALSE);
        EXPECT_EQ(s, ST_INV_PARM); }
    }
    /* delete the data, then the name; the name no longer exists */
    if (UN(NtDeleteWnfStateData)) { s = UN(NtDeleteWnfStateData)(&name, NULL); t_note("NtDeleteWnfStateData = %08lx", (unsigned long)s); }
    EXPECT_EQ(UN(NtDeleteWnfStateName)(&name), 0);
    exist = 0xcc;
    s = UN(NtQueryWnfStateNameInformation)(&name, 0, NULL, &exist, sizeof exist);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(exist, 0);
    sz = sizeof buf;
    s = UN(NtQueryWnfStateData)(&name, NULL, NULL, &stamp, buf, &sz);
    EXPECT_EQ(s, ST_NOT_FOUND);
    (void)tid;
}

/* ---- ALPC port information, security policy --------------------------- */

TEST(qmisc_port_info)
{
    NTSTATUS s; BYTE buf[64]; ULONG ret = 0;
    REQUIRE(UN(NtQueryInformationPort));
    for (ULONG c = 0; c < 6; c++) {
        s = UN(NtQueryInformationPort)((HANDLE)(ULONG_PTR)0x7777, c, buf, sizeof buf, &ret);
        EXPECT_EQ(s, ST_INV_HANDLE);
    }
    { HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
      s = UN(NtQueryInformationPort)(ev, 0, buf, sizeof buf, &ret);
      t_note("port info on event = %08lx", (unsigned long)s);
      CHECK(s == ST_TYPE_MISM || s == ST_INV_HANDLE);
      CloseHandle(ev); }
    /* a real (legacy LPC) server port */
    if (UN(NtCreatePort)) {
        UNICODE_STRING pn; OBJECT_ATTRIBUTES oa; WCHAR nm[96]; HANDLE ph = NULL;
        swprintf(nm, 96, L"\\RPC Control\\ntdllt_qip_%lu", GetCurrentProcessId());
        UN(RtlInitUnicodeString)(&pn, nm);
        InitializeObjectAttributes(&oa, &pn, OBJ_CASE_INSENSITIVE, NULL, NULL);
        s = UN(NtCreatePort)(&ph, &oa, 0, 0x100, 0);
        t_note("NtCreatePort = %08lx", (unsigned long)s);
        if (s >= 0) {
            for (ULONG c = 0; c < 4; c++) {
                memset(buf, 0xcc, sizeof buf); ret = 0xcc;
                s = UN(NtQueryInformationPort)(ph, c, buf, sizeof buf, &ret);
                /* observed on 19041: the call is accepted and writes nothing (informational classes are unimplemented) */
                EXPECT_EQ(s, 0);
                EXPECT_EQ(ret, 0);
                CHECK(buf[0] == 0xcc && buf[sizeof buf - 1] == 0xcc);
            }
            s = UN(NtQueryInformationPort)(ph, 0x7777, buf, sizeof buf, &ret);
            t_note("QIP class 0x7777 = %08lx", (unsigned long)s);
            s = UN(NtQueryInformationPort)(ph, 0, buf, 0, &ret);
            t_note("QIP zero length = %08lx", (unsigned long)s);
            UN(NtClose)(ph);
        }
    }
}

TEST(qmisc_security_policy)
{
    NTSTATUS s;
    REQUIRE(UN(NtQuerySecurityPolicy));
    s = UN(NtQuerySecurityPolicy)(NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(s, ST_INV_PARM);          /* undocumented; only the all-NULL rejection is observed */
}

/* ---- kernel transaction manager family ------------------------------- */

#define TRANSACTION_ALL 0x1F003F
#define TM_ALL          0x1F00FF
#define RM_ALL          0x1F00FF
#define EN_ALL          0x1F00FF

TEST(qmisc_transaction)
{
    HANDLE tx = NULL; NTSTATUS s; union { ULONGLONG a; BYTE b[512]; } buf; ULONG ret; static const GUID zero;
    REQUIRE(UN(NtCreateTransaction)); REQUIRE(UN(NtQueryInformationTransaction)); REQUIRE(UN(NtClose));
    s = UN(NtCreateTransaction)(&tx, TRANSACTION_ALL, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
    t_note("NtCreateTransaction = %08lx", (unsigned long)s);
    if (s < 0) { t_skip("transaction creation unavailable (%08lx)", (unsigned long)s); return; }
    memset(&buf, 0xcc, sizeof buf); ret = 0xcc;
    s = UN(NtQueryInformationTransaction)(tx, 0, &buf, 24, &ret);          /* TransactionBasicInformation */
    EXPECT_EQ(s, 0);
    EXPECT_EQ(ret, 24);
    CHECK(memcmp(buf.b, &zero, 16) != 0);                                   /* transaction id */
    EXPECT_EQ(*(ULONG *)(buf.b + 16), 1);                                   /* TransactionStateNormal */
    EXPECT_EQ(*(ULONG *)(buf.b + 20), 1);                                   /* TransactionOutcomeUndetermined */
    s = UN(NtQueryInformationTransaction)(tx, 0, &buf, 23, &ret);
    EXPECT_EQ(s, ST_LEN_MISM);
    /* TransactionPropertiesInformation = 1 */
    memset(&buf, 0xcc, sizeof buf); ret = 0;
    s = UN(NtQueryInformationTransaction)(tx, 1, &buf, sizeof buf, &ret);
    t_note("Properties = %08lx ret %lu", (unsigned long)s, ret);
    EXPECT_EQ(s, 0);
    CHECK(ret >= 28);
    s = UN(NtQueryInformationTransaction)(tx, 0x7777, &buf, sizeof buf, &ret);
    EXPECT_EQ(s, ST_INV_CLASS);
    s = UN(NtQueryInformationTransaction)((HANDLE)(ULONG_PTR)0x7777, 0, &buf, 24, &ret);
    EXPECT_EQ(s, ST_INV_HANDLE);
    { HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
      s = UN(NtQueryInformationTransaction)(ev, 0, &buf, 24, &ret);
      EXPECT_EQ(s, ST_TYPE_MISM);
      CloseHandle(ev); }
    /* rolled back: state moves out of Normal */
    if (UN(NtRollbackTransaction)) {
        s = UN(NtRollbackTransaction)(tx, TRUE);
        t_note("rollback = %08lx", (unsigned long)s);
        s = UN(NtQueryInformationTransaction)(tx, 0, &buf, 24, &ret);
        EXPECT_EQ(s, 0);
        t_note("state %lu outcome %lu", *(ULONG *)(buf.b + 16), *(ULONG *)(buf.b + 20));
        CHECK(*(ULONG *)(buf.b + 20) == 3);        /* TransactionOutcomeAborted */
    }
    UN(NtClose)(tx);
}

TEST(qmisc_tm_rm_enlistment)
{
    HANDLE tm = NULL, rm = NULL, tx = NULL, en = NULL; NTSTATUS s; union { ULONGLONG a; BYTE b[512]; } buf; ULONG ret; static const GUID zero;
    GUID rmid = { 0x5a1b2c3d, 0x1111, 0x2222, { 9, 8, 7, 6, 5, 4, 3, 2 } }; UNICODE_STRING desc;
    REQUIRE(UN(NtCreateTransactionManager)); REQUIRE(UN(NtQueryInformationTransactionManager)); REQUIRE(UN(NtClose)); REQUIRE(UN(RtlInitUnicodeString));
    REQUIRE(UN(NtCreateResourceManager)); REQUIRE(UN(NtQueryInformationResourceManager));
    REQUIRE(UN(NtCreateEnlistment)); REQUIRE(UN(NtQueryInformationEnlistment)); REQUIRE(UN(NtCreateTransaction));
    s = UN(NtCreateTransactionManager)(&tm, TM_ALL, NULL, NULL, 1 /* TRANSACTION_MANAGER_VOLATILE */, 0);
    t_note("NtCreateTransactionManager = %08lx", (unsigned long)s);
    if (s < 0) { t_skip("volatile transaction manager unavailable (%08lx)", (unsigned long)s); return; }
    memset(&buf, 0xcc, sizeof buf); ret = 0xcc;
    s = UN(NtQueryInformationTransactionManager)(tm, 0, &buf, 24, &ret);   /* TransactionManagerBasicInformation */
    EXPECT_EQ(s, 0);
    EXPECT_EQ(ret, 24);
    CHECK(memcmp(buf.b, &zero, 16) != 0);
    s = UN(NtQueryInformationTransactionManager)(tm, 0, &buf, 23, &ret);
    EXPECT_EQ(s, ST_LEN_MISM);
    s = UN(NtQueryInformationTransactionManager)(tm, 0x7777, &buf, sizeof buf, &ret);
    EXPECT_EQ(s, ST_INV_CLASS);
    s = UN(NtQueryInformationTransactionManager)((HANDLE)(ULONG_PTR)0x7777, 0, &buf, 24, &ret);
    EXPECT_EQ(s, ST_INV_HANDLE);
    { HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
      s = UN(NtQueryInformationTransactionManager)(ev, 0, &buf, 24, &ret);
      EXPECT_EQ(s, ST_TYPE_MISM);
      CloseHandle(ev); }
    /* resource manager (volatile) */
    UN(RtlInitUnicodeString)(&desc, L"ntdllt_rm");
    s = UN(NtCreateResourceManager)(&rm, RM_ALL, tm, &rmid, NULL, 1 /* RESOURCE_MANAGER_VOLATILE */, &desc);
    t_note("NtCreateResourceManager = %08lx", (unsigned long)s);
    if (s >= 0) {
        memset(&buf, 0xcc, sizeof buf); ret = 0xcc;
        s = UN(NtQueryInformationResourceManager)(rm, 0, &buf, sizeof buf, &ret);   /* ResourceManagerBasicInformation */
        EXPECT_EQ(s, 0);
        CHECK(!memcmp(buf.b, &rmid, 16));
        EXPECT_EQ(*(ULONG *)(buf.b + 16), 18);                                       /* DescriptionLength bytes */
        CHECK(!memcmp(buf.b + 20, L"ntdllt_rm", 18));
        EXPECT_EQ(ret, 38);                                                          /* 20-byte header + description */
        s = UN(NtQueryInformationResourceManager)(rm, 0, &buf, 8, &ret);
        EXPECT_EQ(s, ST_TOO_SMALL);
        s = UN(NtQueryInformationResourceManager)(rm, 0x7777, &buf, sizeof buf, &ret);
        EXPECT_EQ(s, ST_INV_CLASS);
        s = UN(NtQueryInformationResourceManager)((HANDLE)(ULONG_PTR)0x7777, 0, &buf, sizeof buf, &ret);
        EXPECT_EQ(s, ST_INV_HANDLE);
        /* enlistment of a transaction in the resource manager */
        s = UN(NtCreateTransaction)(&tx, TRANSACTION_ALL, NULL, NULL, tm, 0, 0, 0, NULL, NULL);
        t_note("transaction bound to a TM handle = %08lx", (unsigned long)s);
        /* observed: binding a new transaction to an explicit TM handle is rejected (0xC000000D) on 19041, so no
           enlistment can be built; the enlistment class checks below only run if it is ever accepted */
        if (s >= 0) {
            s = UN(NtCreateEnlistment)(&en, EN_ALL, rm, tx, NULL, 0, 0x1 /* TRANSACTION_NOTIFY_PREPREPARE */, NULL);
            t_note("NtCreateEnlistment = %08lx", (unsigned long)s);
            if (s >= 0) {
                memset(&buf, 0xcc, sizeof buf); ret = 0xcc;
                s = UN(NtQueryInformationEnlistment)(en, 0, &buf, 48, &ret);
                EXPECT_EQ(s, 0);
                EXPECT_EQ(ret, 48);
                CHECK(!memcmp(buf.b + 32, &rmid, 16));                              /* ResourceManagerId */
                CHECK(memcmp(buf.b, &zero, 16) != 0);
                s = UN(NtQueryInformationEnlistment)(en, 0, &buf, 47, &ret);
                EXPECT_EQ(s, ST_LEN_MISM);
                s = UN(NtQueryInformationEnlistment)(en, 0x7777, &buf, sizeof buf, &ret);
                EXPECT_EQ(s, ST_INV_CLASS);
                UN(NtClose)(en);
            }
            UN(NtClose)(tx);
        }
        UN(NtClose)(rm);
    }
    s = UN(NtQueryInformationEnlistment)((HANDLE)(ULONG_PTR)0x7777, 0, &buf, 48, &ret);
    EXPECT_EQ(s, ST_INV_HANDLE);
    UN(NtClose)(tm);
}

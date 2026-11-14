/* ZwCreateKey / ZwOpenKey / ZwOpenKeyEx and the transacted variants, with registry transactions. */
#include "cob.h"

UDECL(NTSTATUS, ZwCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, ZwOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwOpenKeyEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, ZwCreateKeyTransacted, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, HANDLE, PULONG));
UDECL(NTSTATUS, ZwOpenKeyTransacted, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE));
UDECL(NTSTATUS, ZwOpenKeyTransactedEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, HANDLE));
UDECL(NTSTATUS, ZwCreateRegistryTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, ZwOpenRegistryTransaction, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCommitRegistryTransaction, (HANDLE, ULONG));
UDECL(NTSTATUS, NtRollbackRegistryTransaction, (HANDLE, ULONG));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtQueryKey, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, RtlFormatCurrentUserKeyPath, (PUNICODE_STRING));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));

#define KEY_ALL 0xF003F
#define KEY_READ_ 0x20019
#define S_INVPARAM4 ((NTSTATUS)0xC00000F2)
#define S_CHILDVOL ((NTSTATUS)0xC0000181)
#define REG_CREATED 1
#define REG_OPENED 2
#define REG_OPTION_VOLATILE_ 1
#define REG_OPTION_CREATE_LINK_ 2
#define REG_OPTION_OPEN_LINK_ 8
#define S_KEYDEL ((NTSTATUS)0xC000017C)  /* STATUS_KEY_DELETED */
#define S_CHILDLINK ((NTSTATUS)0xC0000181)
#define S_TXINVALID ((NTSTATUS)0xC00001A0)

/* Test-private base key path "\Registry\User\<sid>\Software\cobkey_<pid>_<tag>"; the caller creates and removes it. */
static int base_path(WCHAR *out, size_t cap, const char *tag)
{
    UNICODE_STRING cur = {0}; WCHAR t[64]; size_t n;
    if (!UN(RtlFormatCurrentUserKeyPath) || UN(RtlFormatCurrentUserKeyPath)(&cur) != 0) return 0;
    n = cur.Length / 2; if (n + 64 >= cap) { UN(RtlFreeUnicodeString)(&cur); return 0; }
    memcpy(out, cur.Buffer, cur.Length); out[n] = 0;
    UN(RtlFreeUnicodeString)(&cur);
    { char tmp[64]; size_t i; snprintf(tmp, sizeof tmp, "\\Software\\cobkey_%lu_%s", (unsigned long)GetCurrentProcessId(), tag);
      for (i = 0; tmp[i]; i++) { out[n + i] = (WCHAR)tmp[i]; } out[n + i] = 0; }
    return 1;
}
static NTSTATUS mk(HANDLE *h, const WCHAR *path, ACCESS_MASK acc, ULONG opts, ULONG *disp, HANDLE root)
{
    UNICODE_STRING u; OBJECT_ATTRIBUTES oa; cob_us(&u, path); cob_oa(&oa, &u, 0x40, root);
    return UN(ZwCreateKey)(h, acc, &oa, 0, NULL, opts, disp);
}
static void del(const WCHAR *path)
{
    HANDLE h = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; cob_us(&u, path); cob_oa(&oa, &u, 0x40, NULL);
    if (UN(ZwOpenKey)(&h, DELETE, &oa) == 0) { UN(NtDeleteKey)(h); cob_close(h); }
}
#define NEEDK() do { REQUIRE(UN(ZwCreateKey)); REQUIRE(UN(ZwOpenKey)); REQUIRE(UN(NtDeleteKey)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtQueryObject)); \
    REQUIRE(UN(RtlFormatCurrentUserKeyPath)); REQUIRE(UN(RtlFreeUnicodeString)); } while (0)

TEST(nt_create_open_b_key_create_open)
{
    WCHAR base[300], sub[340]; HANDLE h = NULL, h2 = NULL, c = NULL; ULONG disp = 0xcc; NTSTATUS s; UNICODE_STRING u, cls; OBJECT_ATTRIBUTES oa; WCHAR tn[40]; ULONG g = 0;
    NEEDK(); COB_ALIAS("CreateKey"); COB_ALIAS("OpenKey");
    CHECK(base_path(base, 300, "a")); del(base);
    s = mk(&h, base, KEY_ALL, 0, &disp, NULL); EXPECT_EQ(s, S_OK_); EXPECT_EQ(disp, REG_CREATED); if (!h) return;
    CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"Key");
    CHECK(cob_granted(h, &g)); EXPECT_EQ(g & KEY_ALL, KEY_ALL);
    s = mk(&h2, base, KEY_ALL, 0, &disp, NULL); EXPECT_EQ(s, S_OK_); EXPECT_EQ(disp, REG_OPENED); cob_close(h2); h2 = NULL;
    /* NULL disposition is accepted */
    s = mk(&h2, base, KEY_READ_, 0, NULL, NULL); EXPECT_EQ(s, S_OK_); cob_close(h2); h2 = NULL;
    /* nested relative creation: parent missing is created by ZwCreateKey one level at a time only */
    lstrcpyW(sub, base); lstrcatW(sub, L"\\one\\two");
    s = mk(&h2, sub, KEY_ALL, 0, &disp, NULL); EXPECT_EQ(s, S_NOTFOUND); cob_close(h2); h2 = NULL;
    lstrcpyW(sub, base); lstrcatW(sub, L"\\one");
    s = mk(&c, sub, KEY_ALL, REG_OPTION_VOLATILE_, &disp, NULL); EXPECT_EQ(s, S_OK_); EXPECT_EQ(disp, REG_CREATED);
    /* creating a persistent child below a volatile key is refused */
    { WCHAR sub2[360]; lstrcpyW(sub2, sub); lstrcatW(sub2, L"\\child");
      s = mk(&h2, sub2, KEY_ALL, 0, &disp, NULL); EXPECT_EQ(s, S_CHILDVOL); cob_close(h2); h2 = NULL;
      s = mk(&h2, sub2, KEY_ALL, REG_OPTION_VOLATILE_, &disp, NULL); EXPECT_EQ(s, S_OK_); if (h2) { UN(NtDeleteKey)(h2); } cob_close(h2); h2 = NULL; }
    /* relative create with root handle and class string */
    { UNICODE_STRING rel; OBJECT_ATTRIBUTES roa; cob_us(&rel, L"rel"); cob_oa(&roa, &rel, 0x40, h); cob_us(&cls, L"MyClass");
      s = UN(ZwCreateKey)(&h2, KEY_ALL, &roa, 0, &cls, 0, &disp); EXPECT_EQ(s, S_OK_); EXPECT_EQ(disp, REG_CREATED);
      if (h2) { UN(NtDeleteKey)(h2); cob_close(h2); h2 = NULL; } }
    if (c) { UN(NtDeleteKey)(c); cob_close(c); }
    /* open by name, access mask checks */
    cob_us(&u, base); cob_oa(&oa, &u, 0x40, NULL);
    s = UN(ZwOpenKey)(&h2, KEY_READ_, &oa); EXPECT_EQ(s, S_OK_);
    if (h2) { CHECK(cob_granted(h2, &g)); EXPECT_EQ(g & KEY_ALL, KEY_READ_); cob_close(h2); h2 = NULL; }
    /* open without case-insensitivity: key names are looked up case-insensitively regardless of the flag */
    cob_oa(&oa, &u, 0, NULL); s = UN(ZwOpenKey)(&h2, KEY_READ_, &oa); EXPECT_EQ(s, S_OK_); cob_close(h2); h2 = NULL;
    /* delete via the handle, then the key is unreachable and the handle is stale */
    EXPECT_EQ(UN(NtDeleteKey)(h), S_OK_);
    h2 = NULL; cob_oa(&oa, &u, 0x40, NULL); EXPECT_EQ(UN(ZwOpenKey)(&h2, KEY_READ_, &oa), S_NOTFOUND);
    { UNICODE_STRING rel; OBJECT_ATTRIBUTES roa; cob_us(&rel, L"x"); cob_oa(&roa, &rel, 0x40, h); EXPECT_EQ(UN(ZwOpenKey)(&h2, KEY_READ_, &roa), S_KEYDEL); }
    cob_close(h);
}

TEST(nt_create_open_b_key_errors)
{
    WCHAR base[300]; HANDLE h = (HANDLE)0x1234; NTSTATUS s; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; ULONG disp;
    NEEDK();
    CHECK(base_path(base, 300, "e")); del(base); cob_us(&u, base); cob_oa(&oa, &u, 0x40, NULL);
    EXPECT_EQ(UN(ZwOpenKey)(&h, KEY_READ_, &oa), S_NOTFOUND);
    EXPECT_EQ(UN(ZwOpenKey)(&h, KEY_READ_, NULL), S_AV);
    EXPECT_EQ(UN(ZwOpenKey)(NULL, KEY_READ_, &oa), S_AV);
    cob_oa(&oa, NULL, 0, NULL); EXPECT_EQ(UN(ZwOpenKey)(&h, KEY_READ_, &oa), S_AV);
    cob_us(&u, base); cob_oa(&oa, &u, 0x40, NULL); oa.Length = 8; EXPECT_EQ(UN(ZwOpenKey)(&h, KEY_READ_, &oa), S_INVPARAM);
    { UNICODE_STRING rel; OBJECT_ATTRIBUTES roa; cob_us(&rel, L"x"); cob_oa(&roa, &rel, 0x40, (HANDLE)(ULONG_PTR)0x7ffffff0); EXPECT_EQ(UN(ZwOpenKey)(&h, KEY_READ_, &roa), S_INVHANDLE); }
    /* a relative name that is not a registry path */
    { UNICODE_STRING bad; cob_us(&bad, L"relative_no_root"); cob_oa(&oa, &bad, 0x40, NULL); EXPECT_EQ(UN(ZwOpenKey)(&h, KEY_READ_, &oa), S_PATHSYN); }
    /* create: NULL OA, NULL handle, bad options */
    EXPECT_EQ(UN(ZwCreateKey)(&h, KEY_ALL, NULL, 0, NULL, 0, &disp), S_AV);
    cob_us(&u, base); cob_oa(&oa, &u, 0x40, NULL);
    EXPECT_EQ(UN(ZwCreateKey)(NULL, KEY_ALL, &oa, 0, NULL, 0, &disp), S_AV);
    EXPECT_EQ(UN(ZwCreateKey)(&h, KEY_ALL, &oa, 0, NULL, 0x100, &disp), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateKey)(&h, KEY_ALL, &oa, 0, NULL, REG_OPTION_CREATE_LINK_ | REG_OPTION_VOLATILE_, (PULONG)(ULONG_PTR)8), S_AV);
    /* nothing may have been left behind by the failed attempts */
    EXPECT_EQ(UN(ZwOpenKey)(&h, KEY_READ_, &oa), S_NOTFOUND);
    /* the registry root */
    { UNICODE_STRING r; cob_us(&r, L"\\Registry\\Machine"); cob_oa(&oa, &r, 0x40, NULL); h = NULL; s = UN(ZwOpenKey)(&h, KEY_READ_, &oa); EXPECT_EQ(s, S_OK_);
      if (h) { WCHAR tn[40]; CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"Key"); cob_close(h); }
      /* standard users cannot create under HKLM */
    }
}

TEST(nt_create_open_b_key_open_ex)
{
    WCHAR base[300]; HANDLE h = NULL, h2 = NULL, l = NULL; NTSTATUS s; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; ULONG disp;
    NEEDK(); REQUIRE(UN(ZwOpenKeyEx)); COB_ALIAS("OpenKeyEx");
    CHECK(base_path(base, 300, "x")); del(base);
    EXPECT_EQ(mk(&h, base, KEY_ALL, 0, &disp, NULL), S_OK_); if (!h) return;
    cob_us(&u, base); cob_oa(&oa, &u, 0x40, NULL);
    EXPECT_EQ(UN(ZwOpenKeyEx)(&h2, KEY_READ_, &oa, 0), S_OK_); cob_close(h2); h2 = NULL;
    EXPECT_EQ(UN(ZwOpenKeyEx)(&h2, KEY_READ_, &oa, REG_OPTION_OPEN_LINK_), S_OK_); cob_close(h2); h2 = NULL;   /* not a link: opens the key */
    EXPECT_EQ(UN(ZwOpenKeyEx)(&h2, KEY_READ_, &oa, 0x4 /* REG_OPTION_BACKUP_RESTORE */), S_DENIED); cob_close(h2); h2 = NULL;   /* needs SeBackupPrivilege enabled */
    EXPECT_EQ(UN(ZwOpenKeyEx)(&h2, KEY_READ_, &oa, 0x100), S_INVPARAM4);
    EXPECT_EQ(UN(ZwOpenKeyEx)(&h2, KEY_READ_, &oa, 0xffffffff), S_INVPARAM4);
    EXPECT_EQ(UN(ZwOpenKeyEx)(NULL, KEY_READ_, &oa, 0), S_AV);
    { UNICODE_STRING m; cob_us(&m, L"\\Registry\\Machine\\cob_no_such_key_zzz"); cob_oa(&oa, &m, 0x40, NULL); EXPECT_EQ(UN(ZwOpenKeyEx)(&h2, KEY_READ_, &oa, 0), S_NOTFOUND); }
    UN(NtDeleteKey)(h); cob_close(h);
}

TEST(nt_create_open_b_key_symbolic_link_option)
{
    WCHAR base[300], lk[360]; HANDLE h = NULL, l = NULL, o = NULL; NTSTATUS s; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; ULONG disp;
    NEEDK();
    CHECK(base_path(base, 300, "l")); del(base);
    EXPECT_EQ(mk(&h, base, KEY_ALL, 0, &disp, NULL), S_OK_); if (!h) return;
    lstrcpyW(lk, base); lstrcatW(lk, L"\\lnk");
    /* creating a link key needs KEY_CREATE_LINK access plus the link option; the SymbolicLinkValue is absent so opening follows nothing */
    s = mk(&l, lk, KEY_ALL | 0x20 /* KEY_CREATE_LINK */, REG_OPTION_CREATE_LINK_, &disp, NULL); EXPECT_EQ(s, S_OK_); EXPECT_EQ(disp, REG_CREATED);
    if (l) { cob_close(l); l = NULL;
        cob_us(&u, lk); cob_oa(&oa, &u, 0x40 | 0x100 /* OBJ_OPENLINK */, NULL);
        s = UN(ZwOpenKey)(&o, KEY_READ_, &oa); EXPECT_EQ(s, S_OK_); cob_close(o); o = NULL;
        /* without OPENLINK the dangling link cannot be followed */
        cob_oa(&oa, &u, 0x40, NULL);
        s = UN(ZwOpenKey)(&o, KEY_READ_, &oa); CHECK(s < 0); cob_close(o); o = NULL;
        /* delete the link key via an OPENLINK handle */
        cob_oa(&oa, &u, 0x40 | 0x100, NULL); if (UN(ZwOpenKey)(&o, DELETE, &oa) == 0) { UN(NtDeleteKey)(o); cob_close(o); } }
    UN(NtDeleteKey)(h); cob_close(h);
}

TEST(nt_create_open_b_key_transacted)
{
    WCHAR base[300], sub[360]; HANDLE tx = NULL, h = NULL, k = NULL, k2 = NULL; NTSTATUS s; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; ULONG disp = 0; WCHAR tn[40];
    NEEDK(); REQUIRE(UN(ZwCreateRegistryTransaction)); REQUIRE(UN(ZwCreateKeyTransacted)); REQUIRE(UN(ZwOpenKeyTransacted)); REQUIRE(UN(ZwOpenKeyTransactedEx));
    REQUIRE(UN(NtCommitRegistryTransaction)); REQUIRE(UN(NtRollbackRegistryTransaction));
    COB_ALIAS("CreateKeyTransacted"); COB_ALIAS("OpenKeyTransacted"); COB_ALIAS("OpenKeyTransactedEx"); COB_ALIAS("CreateRegistryTransaction");
    CHECK(base_path(base, 300, "t")); del(base);
    EXPECT_EQ(mk(&h, base, KEY_ALL, 0, &disp, NULL), S_OK_); if (!h) return;
    /* registry transaction object */
    s = UN(ZwCreateRegistryTransaction)(&tx, 0x1F003F /* TRANSACTION_ALL_ACCESS */, NULL, 0); EXPECT_EQ(s, S_OK_);
    if (s != S_OK_) { t_note("registry transactions unavailable: 0x%08lx", (unsigned long)s); UN(NtDeleteKey)(h); cob_close(h); return; }
    CHECK(cob_typename(tx, tn, 40)); EXPECT_WSTR(tn, L"RegistryTransaction");
    /* roll back: key created inside the transaction vanishes */
    lstrcpyW(sub, base); lstrcatW(sub, L"\\txkey"); cob_us(&u, sub); cob_oa(&oa, &u, 0x40, NULL);
    s = UN(ZwCreateKeyTransacted)(&k, KEY_ALL, &oa, 0, NULL, 0, tx, &disp); EXPECT_EQ(s, S_OK_); EXPECT_EQ(disp, REG_CREATED);
    /* not visible outside the transaction */
    EXPECT_EQ(UN(ZwOpenKey)(&k2, KEY_READ_, &oa), S_NOTFOUND);
    /* visible inside it */
    s = UN(ZwOpenKeyTransacted)(&k2, KEY_READ_, &oa, tx); EXPECT_EQ(s, S_OK_); cob_close(k2); k2 = NULL;
    s = UN(ZwOpenKeyTransactedEx)(&k2, KEY_READ_, &oa, 0, tx); EXPECT_EQ(s, S_OK_); cob_close(k2); k2 = NULL;
    cob_close(k); k = NULL;
    EXPECT_EQ(UN(NtRollbackRegistryTransaction)(tx, 0), S_OK_);
    EXPECT_EQ(UN(ZwOpenKey)(&k2, KEY_READ_, &oa), S_NOTFOUND);
    cob_close(tx); tx = NULL;
    /* commit: key persists */
    EXPECT_EQ(UN(ZwCreateRegistryTransaction)(&tx, 0x1F003F, NULL, 0), S_OK_);
    if (tx) {
        s = UN(ZwCreateKeyTransacted)(&k, KEY_ALL, &oa, 0, NULL, 0, tx, &disp); EXPECT_EQ(s, S_OK_); cob_close(k); k = NULL;
        EXPECT_EQ(UN(NtCommitRegistryTransaction)(tx, 0), S_OK_);
        s = UN(ZwOpenKey)(&k2, DELETE | KEY_READ_, &oa); EXPECT_EQ(s, S_OK_);
        if (k2) { UN(NtDeleteKey)(k2); cob_close(k2); k2 = NULL; }
        /* operations after commit fail */
        EXPECT_EQ(UN(ZwOpenKeyTransacted)(&k2, KEY_READ_, &oa, tx) < 0, 1); cob_close(k2); k2 = NULL;
        cob_close(tx); tx = NULL;
    }
    /* invalid transaction handles */
    cob_us(&u, base); cob_oa(&oa, &u, 0x40, NULL);
    EXPECT_EQ(UN(ZwOpenKeyTransacted)(&k2, KEY_READ_, &oa, (HANDLE)(ULONG_PTR)0x7ffffff0), S_INVHANDLE);
    EXPECT_EQ(UN(ZwOpenKeyTransacted)(&k2, KEY_READ_, &oa, NULL), S_INVHANDLE);
    EXPECT_EQ(UN(ZwCreateKeyTransacted)(&k2, KEY_ALL, &oa, 0, NULL, 0, (HANDLE)(ULONG_PTR)0x7ffffff0, &disp), S_INVHANDLE);
    EXPECT_EQ(UN(ZwOpenKeyTransactedEx)(&k2, KEY_READ_, &oa, 0, (HANDLE)(ULONG_PTR)0x7ffffff0), S_INVHANDLE);
    /* wrong object type as transaction */
    EXPECT_EQ(UN(ZwOpenKeyTransacted)(&k2, KEY_READ_, &oa, h), S_TYPEMM);
    UN(NtDeleteKey)(h); cob_close(h);
}

TEST(nt_create_open_b_registry_transaction_object)
{
    HANDLE tx = NULL, tx2 = NULL, o = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200]; NTSTATUS s;
    NEEDK(); REQUIRE(UN(ZwCreateRegistryTransaction)); REQUIRE(UN(ZwOpenRegistryTransaction)); REQUIRE(UN(NtRollbackRegistryTransaction));
    COB_ALIAS("OpenRegistryTransaction");
    EXPECT_EQ(UN(ZwCreateRegistryTransaction)(NULL, 0x1F003F, NULL, 0), S_AV);
    EXPECT_EQ(UN(ZwCreateRegistryTransaction)(&tx, 0x1F003F, NULL, 1), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateRegistryTransaction)(&tx, 0x1F003F, NULL, 0xffffffff), S_INVPARAM);
    cob_name(name, 200, "rtx"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    s = UN(ZwCreateRegistryTransaction)(&tx, 0x1F003F, &oa, 0); EXPECT_EQ(s, S_OK_);
    if (s == S_OK_) {
        EXPECT_EQ(UN(ZwCreateRegistryTransaction)(&tx2, 0x1F003F, &oa, 0), S_COLLIDE); cob_close(tx2);
        s = UN(ZwOpenRegistryTransaction)(&o, 0x1F003F, &oa); EXPECT_EQ(s, S_OK_);
        if (o) { WCHAR tn[40]; CHECK(cob_typename(o, tn, 40)); EXPECT_WSTR(tn, L"RegistryTransaction"); cob_close(o); }
        UN(NtRollbackRegistryTransaction)(tx, 0);
        cob_close(tx);
    }
    o = (HANDLE)0x1234; EXPECT_EQ(UN(ZwOpenRegistryTransaction)(&o, 0x1F003F, &oa), S_NOTFOUND);
    EXPECT_EQ(UN(ZwOpenRegistryTransaction)(&o, 0x1F003F, NULL), S_INVPARAM);
    EXPECT_EQ(UN(ZwOpenRegistryTransaction)(NULL, 0x1F003F, &oa), S_AV);
}

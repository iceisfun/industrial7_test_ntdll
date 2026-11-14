/* Registry services: NtFlushKey, NtNotifyChangeKey, NtNotifyChangeMultipleKeys.
 * One volatile key under the current user's hive per test, deleted afterwards. */
#include "t.h"

UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtFlushKey, (HANDLE));
UDECL(NTSTATUS, NtNotifyChangeKey, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtNotifyChangeMultipleKeys, (HANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtCancelIoFile, (HANDLE, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, RtlFormatCurrentUserKeyPath, (PUNICODE_STRING));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));

#define XS(x) ((NTSTATUS)(x))
#define N(f) UN(f)
#define ST_PENDING 0x103
#define BADH ((HANDLE)(LONG_PTR)-77)
#define KEY_NOTIFY_ 0x0010

typedef struct { HANDLE root, key; WCHAR name[96]; UNICODE_STRING us; int ok; } fx;

static void fx_free(fx *f)
{
    if (f->key) { N(NtDeleteKey)(f->key); N(NtClose)(f->key); f->key = NULL; }
    if (f->root) { N(NtClose)(f->root); f->root = NULL; }
}
static void fx_init(fx *f, const char *tag)
{
    UNICODE_STRING path = {0}, nm; OBJECT_ATTRIBUTES oa; ULONG disp; NTSTATUS s; memset(f, 0, sizeof *f);
    if (!N(RtlFormatCurrentUserKeyPath) || !N(NtCreateKey) || !N(NtOpenKey) || !N(NtDeleteKey) || !N(NtClose) || !N(NtCreateEvent)) { t_skip("missing registry exports"); return; }
    s = N(RtlFormatCurrentUserKeyPath)(&path);
    if (s < 0) { t_skip("no current user key path: 0x%08lx", (unsigned long)s); return; }
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = N(NtOpenKey)(&f->root, KEY_CREATE_SUB_KEY, &oa);
    N(RtlFreeUnicodeString)(&path);
    if (s < 0) { f->root = NULL; t_skip("current user root not writable: 0x%08lx", (unsigned long)s); return; }
    wsprintfW(f->name, L"other3a_key_%lu_%S", GetCurrentProcessId(), tag);
    nm.Buffer = f->name; nm.Length = (USHORT)(lstrlenW(f->name) * 2); nm.MaximumLength = nm.Length + 2;
    InitializeObjectAttributes(&oa, &nm, OBJ_CASE_INSENSITIVE, f->root, NULL);
    s = N(NtCreateKey)(&f->key, KEY_ALL_ACCESS, &oa, 0, NULL, REG_OPTION_VOLATILE, &disp);
    if (s < 0 || disp != REG_CREATED_NEW_KEY) { if (s >= 0) { N(NtClose)(f->key); f->key = NULL; } fx_free(f); t_skip("cannot create private key: 0x%08lx", (unsigned long)s); return; }
    f->ok = 1;
}
#define START(tag) fx f; fx_init(&f, tag); if (!f.ok) return
static HANDLE mkev(void) { HANDLE h = NULL; if (N(NtCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 1, FALSE) < 0) return NULL; return h; }
static NTSTATUS setval(HANDLE k, const WCHAR *n, ULONG v)
{
    UNICODE_STRING u; u.Buffer = (PWSTR)n; u.Length = (USHORT)(lstrlenW(n) * 2); u.MaximumLength = u.Length + 2;
    return N(NtSetValueKey)(k, &u, 0, REG_DWORD, &v, 4);
}
static HANDLE subkey(HANDLE parent, const WCHAR *n, ACCESS_MASK acc)
{
    UNICODE_STRING u; OBJECT_ATTRIBUTES oa; HANDLE h = NULL; ULONG d;
    u.Buffer = (PWSTR)n; u.Length = (USHORT)(lstrlenW(n) * 2); u.MaximumLength = u.Length + 2;
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE, parent, NULL);
    if (N(NtCreateKey)(&h, acc, &oa, 0, NULL, REG_OPTION_VOLATILE, &d) < 0) return NULL;
    return h;
}

TEST(other3a_key_nt_zw_aliases)
{
    CHECK(t_proc("NtFlushKey") && t_proc("NtFlushKey") == t_proc("ZwFlushKey"));
    CHECK(t_proc("NtNotifyChangeKey") && t_proc("NtNotifyChangeKey") == t_proc("ZwNotifyChangeKey"));
    CHECK(t_proc("NtNotifyChangeMultipleKeys") && t_proc("NtNotifyChangeMultipleKeys") == t_proc("ZwNotifyChangeMultipleKeys"));
}
TEST(other3a_flush_key_basic_and_errors)
{
    START("flush");
    REQUIRE(N(NtFlushKey)); REQUIRE(N(NtSetValueKey));
    EXPECT_EQ(setval(f.key, L"v", 1), 0);
    EXPECT_EQ(N(NtFlushKey)(f.key), 0);
    EXPECT_EQ(N(NtFlushKey)(f.key), 0);                                       /* idempotent */
    EXPECT_EQ(N(NtFlushKey)(BADH), XS(0xC0000008));
    EXPECT_EQ(N(NtFlushKey)(NULL), XS(0xC0000008));
    {   HANDLE ev = mkev();                                                    /* wrong object type */
        if (ev) { EXPECT_EQ(N(NtFlushKey)(ev), XS(0xC0000024)); N(NtClose)(ev); }
    }
    {   HANDLE rw = subkey(f.key, L"ro", KEY_ALL_ACCESS), q = NULL;           /* handle without write access */
        UNICODE_STRING u; OBJECT_ATTRIBUTES oa; NTSTATUS s;
        u.Buffer = L"ro"; u.Length = 4; u.MaximumLength = 6;
        InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE, f.key, NULL);
        if (rw && N(NtOpenKey)(&q, KEY_READ, &oa) == 0) {
            s = N(NtFlushKey)(q);
            EXPECT_EQ(s, 0);                                                 /* flushing needs no particular key access */
            N(NtClose)(q);
        }
        if (rw) { N(NtDeleteKey)(rw); N(NtClose)(rw); }
    }
    fx_free(&f);
}
TEST(other3a_notify_key_value_change_signals_event)
{
    HANDLE ev; IO_STATUS_BLOCK io; BYTE buf[64]; NTSTATUS s; START("nk1");
    REQUIRE(N(NtNotifyChangeKey)); REQUIRE(N(NtSetValueKey));
    ev = mkev(); CHECK(ev != NULL);
    if (ev) {
        memset(&io, 0xcc, sizeof io);
        s = N(NtNotifyChangeKey)(f.key, ev, NULL, NULL, &io, 0x4 /* REG_NOTIFY_CHANGE_LAST_SET */, FALSE, buf, sizeof buf, TRUE);
        EXPECT_EQ(s, ST_PENDING);
        EXPECT_EQ(WaitForSingleObject(ev, 50), WAIT_TIMEOUT);
        EXPECT_EQ(setval(f.key, L"x", 5), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, XS(0x0000010C)); EXPECT_EQ(io.Information, 0);       /* STATUS_NOTIFY_ENUM_DIR: registry reports "something changed" only */
    }
    if (ev) N(NtClose)(ev);
    fx_free(&f);
}
TEST(other3a_notify_key_name_filter_ignores_value_changes)
{
    HANDLE ev, g; IO_STATUS_BLOCK io; NTSTATUS s; START("nk2");
    REQUIRE(N(NtNotifyChangeKey));
    ev = mkev(); CHECK(ev != NULL);
    if (ev) {
        s = N(NtNotifyChangeKey)(f.key, ev, NULL, NULL, &io, 0x1 /* REG_NOTIFY_CHANGE_NAME */, FALSE, NULL, 0, TRUE);
        EXPECT_EQ(s, ST_PENDING);
        EXPECT_EQ(setval(f.key, L"ignored", 1), 0);                              /* value change does not match a NAME-only filter */
        EXPECT_EQ(WaitForSingleObject(ev, 300), WAIT_TIMEOUT);
        g = subkey(f.key, L"second", KEY_ALL_ACCESS);                            /* subkey creation matches */
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0); EXPECT_EQ(io.Status, XS(0x0000010C));
        if (g) { N(NtDeleteKey)(g); N(NtClose)(g); }
    }
    if (ev) N(NtClose)(ev);
    fx_free(&f);
}
TEST(other3a_notify_key_watch_subtree_flag)
{
    HANDLE ev, sub; IO_STATUS_BLOCK io; NTSTATUS s; START("nk4");
    REQUIRE(N(NtNotifyChangeKey));
    ev = mkev(); sub = subkey(f.key, L"child", KEY_ALL_ACCESS); CHECK(ev && sub);
    if (ev && sub) {
        s = N(NtNotifyChangeKey)(f.key, ev, NULL, NULL, &io, 0x4, FALSE, NULL, 0, TRUE);   /* this key only */
        EXPECT_EQ(s, ST_PENDING);
        EXPECT_EQ(setval(sub, L"deep", 1), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 300), WAIT_TIMEOUT);
        EXPECT_EQ(setval(f.key, L"top", 1), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0); EXPECT_EQ(io.Status, XS(0x0000010C));
    }
    if (ev) N(NtClose)(ev);
    if (sub) { N(NtDeleteKey)(sub); N(NtClose)(sub); }
    fx_free(&f);
}
TEST(other3a_notify_key_watch_subtree_true_sees_child)
{
    HANDLE ev, sub; IO_STATUS_BLOCK io; NTSTATUS s; START("nk5");
    REQUIRE(N(NtNotifyChangeKey));
    ev = mkev(); sub = subkey(f.key, L"child", KEY_ALL_ACCESS); CHECK(ev && sub);
    if (ev && sub) {
        s = N(NtNotifyChangeKey)(f.key, ev, NULL, NULL, &io, 0x4, TRUE, NULL, 0, TRUE);
        EXPECT_EQ(s, ST_PENDING);
        EXPECT_EQ(setval(sub, L"deep", 1), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0); EXPECT_EQ(io.Status, XS(0x0000010C));
    }
    if (ev) N(NtClose)(ev);
    if (sub) { N(NtDeleteKey)(sub); N(NtClose)(sub); }
    fx_free(&f);
}
TEST(other3a_notify_key_close_completes_with_cleanup)
{
    HANDLE ev; IO_STATUS_BLOCK io; NTSTATUS s; START("nk6");
    REQUIRE(N(NtNotifyChangeKey));
    ev = mkev(); CHECK(ev != NULL);
    if (ev) {
        s = N(NtNotifyChangeKey)(f.key, ev, NULL, NULL, &io, 0x4, FALSE, NULL, 0, TRUE);
        EXPECT_EQ(s, ST_PENDING);
        N(NtDeleteKey)(f.key); N(NtClose)(f.key); f.key = NULL;                  /* last handle closed: request cancelled */
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, XS(0x0000010B));                                    /* STATUS_NOTIFY_CLEANUP */
    }
    if (ev) N(NtClose)(ev);
    fx_free(&f);
}
TEST(other3a_notify_key_errors)
{
    HANDLE ev; IO_STATUS_BLOCK io; BYTE buf[16]; NTSTATUS s; START("nk3");
    REQUIRE(N(NtNotifyChangeKey));
    EXPECT_EQ(N(NtNotifyChangeKey)(BADH, NULL, NULL, NULL, &io, 4, FALSE, buf, sizeof buf, FALSE), XS(0xC0000008));
    ev = mkev();
    if (ev) { EXPECT_EQ(N(NtNotifyChangeKey)(ev, NULL, NULL, NULL, &io, 4, FALSE, buf, sizeof buf, TRUE), XS(0xC0000024)); N(NtClose)(ev); }
    fx_free(&f);
}
TEST(other3a_notify_key_filter_and_access_errors)
{
    HANDLE q = NULL, ev; IO_STATUS_BLOCK io; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; HANDLE sub; START("nk7");
    REQUIRE(N(NtNotifyChangeKey));
    ev = mkev(); CHECK(ev != NULL);
    if (ev) {                                                                                                              /* an empty filter is accepted and simply never matches */
        memset(&io, 0xcc, sizeof io);
        EXPECT_EQ(N(NtNotifyChangeKey)(f.key, ev, NULL, NULL, &io, 0, FALSE, NULL, 0, TRUE), ST_PENDING);
        EXPECT_EQ(setval(f.key, L"nomatch", 1), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 200), WAIT_TIMEOUT);
    }
    EXPECT_EQ(N(NtNotifyChangeKey)(f.key, NULL, NULL, NULL, &io, 0x80000000u, FALSE, NULL, 0, TRUE), XS(0xC000000D));  /* unknown filter bits */
    sub = subkey(f.key, L"noacc", KEY_ALL_ACCESS);
    u.Buffer = L"noacc"; u.Length = 10; u.MaximumLength = 12;
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE, f.key, NULL);
    if (sub && N(NtOpenKey)(&q, KEY_QUERY_VALUE, &oa) == 0) {
        EXPECT_EQ(N(NtNotifyChangeKey)(q, NULL, NULL, NULL, &io, 0x4, FALSE, NULL, 0, TRUE), XS(0xC0000022));        /* KEY_NOTIFY required */
        N(NtClose)(q);
    }
    if (sub) { N(NtDeleteKey)(sub); N(NtClose)(sub); }
    fx_free(&f);                                                                                                           /* last handle closed: pending request ends */
    if (ev) { EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0); EXPECT_EQ(io.Status, XS(0x0000010B)); N(NtClose)(ev); }
}
TEST(other3a_notify_multiple_keys_master_only)
{
    HANDLE ev; IO_STATUS_BLOCK io; NTSTATUS s; START("nm1");
    REQUIRE(N(NtNotifyChangeMultipleKeys));
    ev = mkev(); CHECK(ev != NULL);
    if (ev) {
        s = N(NtNotifyChangeMultipleKeys)(f.key, 0, NULL, ev, NULL, NULL, &io, 0x4, FALSE, NULL, 0, TRUE);
        EXPECT_EQ(s, ST_PENDING);
        EXPECT_EQ(setval(f.key, L"m", 1), 0);
        EXPECT_EQ(WaitForSingleObject(ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(io.Status, XS(0x0000010C));
        EXPECT_EQ(N(NtNotifyChangeMultipleKeys)(BADH, 0, NULL, NULL, NULL, NULL, &io, 0x4, FALSE, NULL, 0, TRUE), XS(0xC0000008));
    }
    if (ev) N(NtClose)(ev);
    fx_free(&f);
}
TEST(other3a_notify_multiple_keys_slave_array_rejected)
{
    HANDLE ev, sub; IO_STATUS_BLOCK io; NTSTATUS s; OBJECT_ATTRIBUTES slave; UNICODE_STRING u; START("nm2");
    REQUIRE(N(NtNotifyChangeMultipleKeys));
    ev = mkev(); sub = subkey(f.key, L"slave", KEY_ALL_ACCESS); CHECK(ev && sub);
    if (ev && sub) {
        u.Buffer = L"slave"; u.Length = 10; u.MaximumLength = 12;
        InitializeObjectAttributes(&slave, &u, OBJ_CASE_INSENSITIVE, f.key, NULL);
        s = N(NtNotifyChangeMultipleKeys)(f.key, 1, &slave, ev, NULL, NULL, &io, 0x4, FALSE, NULL, 0, TRUE);
        EXPECT_EQ(s, XS(0xC000000D));                                    /* an existing slave key is refused (observed) */
        u.Buffer = L"missing"; u.Length = 14; u.MaximumLength = 16;
        s = N(NtNotifyChangeMultipleKeys)(f.key, 1, &slave, ev, NULL, NULL, &io, 0x4, FALSE, NULL, 0, TRUE);
        EXPECT_EQ(s, XS(0xC0000034));                                    /* slave names are resolved first: STATUS_OBJECT_NAME_NOT_FOUND */
        s = N(NtNotifyChangeMultipleKeys)(f.key, 1, NULL, ev, NULL, NULL, &io, 0x4, FALSE, NULL, 0, TRUE);
        EXPECT_EQ(s, XS(0xC000000D));                                    /* count without an array */
    }
    if (ev) N(NtClose)(ev);
    if (sub) { N(NtDeleteKey)(sub); N(NtClose)(sub); }
    fx_free(&f);
}

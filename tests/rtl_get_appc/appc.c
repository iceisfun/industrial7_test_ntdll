#include "t.h"
#include <stdlib.h>
#include <sddl.h>

UDECL(NTSTATUS, RtlGetAppContainerSidType, (PSID, ULONG *));
UDECL(NTSTATUS, RtlGetAppContainerParent, (PSID, PSID *));
UDECL(NTSTATUS, RtlGetAppContainerNamedObjectPath, (HANDLE, PSID, BOOLEAN, PUNICODE_STRING));
UDECL(NTSTATUS, RtlGetTokenNamedObjectPath, (HANDLE, BOOLEAN, PUNICODE_STRING));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(PVOID, RtlFreeSid, (PSID));
UDECL(NTSTATUS, RtlGetSetBootStatusData, (HANDLE, BOOLEAN, ULONG, PVOID, ULONG, ULONG *));
UDECL(NTSTATUS, RtlGetSystemBootStatusEx, (PVOID, ULONG, PULONG));
UDECL(NTSTATUS, RtlGetSystemBootStatus, (ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, RtlGetPersistedStateLocation, (PCWSTR, PCWSTR, PCWSTR, ULONG, PWSTR, ULONG, ULONG *));

#define ST_INVALID_PARAM ((NTSTATUS)0xC000000D)
#define ST_NOT_APPCONTAINER ((NTSTATUS)0xC000A200)

typedef struct { BYTE Rev, Count; BYTE Auth[6]; ULONG Sub[16]; } SIDB;
static void make_sid(SIDB *s, BYTE rev, BYTE auth5, ULONG first, int count) {
    memset(s, 0, sizeof *s); s->Rev = rev; s->Count = (BYTE)count; s->Auth[5] = auth5;
    for (int i = 0; i < count; i++) s->Sub[i] = i == 0 ? first : 0x1000 + i;
}

TEST(get_app_container_sid_type) {
    REQUIRE(UN(RtlGetAppContainerSidType));
    SIDB s; ULONG type = 0xdead;
    make_sid(&s, 1, 15, 2, 8);                       /* package SID */
    EXPECT_EQ(UN(RtlGetAppContainerSidType)(&s, &type), 0); EXPECT_EQ(type, 2);
    make_sid(&s, 1, 15, 2, 12);                      /* child package SID */
    type = 0xdead; EXPECT_EQ(UN(RtlGetAppContainerSidType)(&s, &type), 0); EXPECT_EQ(type, 1);
    make_sid(&s, 1, 15, 2, 9);                       /* wrong subauthority count */
    type = 0xdead; EXPECT_EQ(UN(RtlGetAppContainerSidType)(&s, &type), ST_NOT_APPCONTAINER); EXPECT_EQ(type, 3);
    make_sid(&s, 1, 15, 2, 1);                       /* too short */
    type = 0xdead; EXPECT_EQ(UN(RtlGetAppContainerSidType)(&s, &type), ST_NOT_APPCONTAINER); EXPECT_EQ(type, 0);
    make_sid(&s, 1, 15, 3, 8);                       /* S-1-15-3: capability SID, not a package */
    type = 0xdead; EXPECT_EQ(UN(RtlGetAppContainerSidType)(&s, &type), ST_NOT_APPCONTAINER); EXPECT_EQ(type, 0);
    make_sid(&s, 1, 5, 2, 8);                        /* wrong authority */
    type = 0xdead; EXPECT_EQ(UN(RtlGetAppContainerSidType)(&s, &type), ST_NOT_APPCONTAINER); EXPECT_EQ(type, 0);
    make_sid(&s, 2, 15, 2, 8);                       /* wrong revision */
    type = 0xdead; EXPECT_EQ(UN(RtlGetAppContainerSidType)(&s, &type), ST_NOT_APPCONTAINER); EXPECT_EQ(type, 0);
    /* well-known SID: S-1-5-18 (system) */
    BYTE sysbuf[SECURITY_MAX_SID_SIZE]; DWORD sz = sizeof sysbuf;
    if (UIN("advapi32.dll", CreateWellKnownSid)(WinLocalSystemSid, NULL, sysbuf, &sz)) {
        type = 0xdead; EXPECT_EQ(UN(RtlGetAppContainerSidType)(sysbuf, &type), ST_NOT_APPCONTAINER); EXPECT_EQ(type, 0);
    }
    /* the current process token is not an app container */
    HANDLE tok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        BYTE tu[256]; DWORD rl = 0;
        if (GetTokenInformation(tok, TokenUser, tu, sizeof tu, &rl)) {
            PSID user = ((TOKEN_USER *)tu)->User.Sid;
            type = 0xdead; EXPECT_EQ(UN(RtlGetAppContainerSidType)(user, &type), ST_NOT_APPCONTAINER); EXPECT_EQ(type, 0);
        }
        CloseHandle(tok);
    }
}

TEST(get_app_container_parent) {
    REQUIRE(UN(RtlGetAppContainerParent)); REQUIRE(UN(RtlFreeSid));
    SIDB child, par; PSID out = (PSID)1;
    make_sid(&child, 1, 15, 2, 12);
    EXPECT_EQ(UN(RtlGetAppContainerParent)(&child, &out), 0);
    CHECK(out != NULL && out != (PSID)1);
    if (out && out != (PSID)1) {
        SIDB *o = (SIDB *)out;
        EXPECT_EQ(o->Rev, 1); EXPECT_EQ(o->Count, 8); EXPECT_EQ(o->Auth[5], 15);
        EXPECT_EQ(memcmp(o->Sub, child.Sub, 8 * 4), 0);
        ULONG type = 0; EXPECT_EQ(UN(RtlGetAppContainerSidType)(out, &type), 0); EXPECT_EQ(type, 2);
        CHECK(IsValidSid(out));
        UN(RtlFreeSid)(out);
    }
    /* a parent has no parent, other SIDs are rejected; the output is cleared first */
    make_sid(&par, 1, 15, 2, 8); out = (PSID)1;
    EXPECT_EQ(UN(RtlGetAppContainerParent)(&par, &out), ST_INVALID_PARAM); EXPECT_EQ(out, NULL);
    make_sid(&par, 1, 5, 21, 5); out = (PSID)1;
    EXPECT_EQ(UN(RtlGetAppContainerParent)(&par, &out), ST_INVALID_PARAM); EXPECT_EQ(out, NULL);
}

static void sid_string(PSID sid, WCHAR *out, size_t cap) {
    UNICODE_STRING u; WCHAR *s = NULL;
    BOOL (WINAPI *conv)(PSID, LPWSTR *) = (void *)UIN("advapi32.dll", ConvertSidToStringSidW);
    if (conv && conv(sid, &s)) { wcsncpy(out, s, cap - 1); out[cap - 1] = 0; LocalFree(s); } else out[0] = 0;
    (void)u;
}

TEST(get_app_container_named_object_path) {
    REQUIRE(UN(RtlGetAppContainerNamedObjectPath)); REQUIRE(UN(RtlFreeUnicodeString));
    SIDB child; make_sid(&child, 1, 15, 2, 8);
    DWORD session = 0; ProcessIdToSessionId(GetCurrentProcessId(), &session);
    WCHAR sidstr[256]; sid_string(&child, sidstr, 256);
    UNICODE_STRING p; memset(&p, 0xcc, sizeof p);
    NTSTATUS s = UN(RtlGetAppContainerNamedObjectPath)(NULL, &child, FALSE, &p);
    t_note("AppContainerNamedObjectPath(sid,abs) = %08lx '%.*ls'", (ULONG)s, s == 0 ? p.Length / 2 : 0, s == 0 ? p.Buffer : L"");
    EXPECT_EQ(s, 0);
    if (s == 0) {
        WCHAR want[512];
        if (session) wsprintfW(want, L"\\Sessions\\%lu\\AppContainerNamedObjects\\%s", session, sidstr);
        else wsprintfW(want, L"\\AppContainerNamedObjects\\%s", sidstr);
        CHECK(p.Length == wcslen(want) * 2 && !_wcsnicmp(p.Buffer, want, p.Length / 2));
        CHECK(p.MaximumLength >= p.Length);
        UN(RtlFreeUnicodeString)(&p);
    }
    memset(&p, 0xcc, sizeof p);
    s = UN(RtlGetAppContainerNamedObjectPath)(NULL, &child, TRUE, &p);
    t_note("AppContainerNamedObjectPath(sid,rel) = %08lx '%.*ls'", (ULONG)s, s == 0 ? p.Length / 2 : 0, s == 0 ? p.Buffer : L"");
    EXPECT_EQ(s, 0);
    if (s == 0) {
        WCHAR want[512]; wsprintfW(want, L"AppContainerNamedObjects\\%s", sidstr);
        CHECK(p.Length == wcslen(want) * 2 && !_wcsnicmp(p.Buffer, want, p.Length / 2));
        UN(RtlFreeUnicodeString)(&p);
    }
    /* a non app-container SID is rejected */
    SIDB bad; make_sid(&bad, 1, 5, 21, 5); memset(&p, 0xcc, sizeof p);
    s = UN(RtlGetAppContainerNamedObjectPath)(NULL, &bad, FALSE, &p);
    t_note("AppContainerNamedObjectPath(non-ac sid) = %08lx", (ULONG)s);
    EXPECT_EQ(s, ST_NOT_APPCONTAINER);
}

TEST(get_token_named_object_path) {
    REQUIRE(UN(RtlGetTokenNamedObjectPath)); REQUIRE(UN(RtlFreeUnicodeString));
    DWORD session = 0; ProcessIdToSessionId(GetCurrentProcessId(), &session);
    HANDLE tok = NULL;
    CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok));
    UNICODE_STRING p; memset(&p, 0xcc, sizeof p);
    NTSTATUS s = UN(RtlGetTokenNamedObjectPath)(tok, FALSE, &p);
    t_note("TokenNamedObjectPath(abs) = %08lx '%.*ls'", (ULONG)s, s == 0 ? p.Length / 2 : 0, s == 0 ? p.Buffer : L"");
    EXPECT_EQ(s, 0);
    if (s == 0) {
        WCHAR want[128];
        if (session) wsprintfW(want, L"\\Sessions\\%lu\\BaseNamedObjects", session); else wcscpy(want, L"\\BaseNamedObjects");
        CHECK(p.Length == wcslen(want) * 2 && !_wcsnicmp(p.Buffer, want, p.Length / 2));
        UN(RtlFreeUnicodeString)(&p);
    }
    memset(&p, 0xcc, sizeof p);
    s = UN(RtlGetTokenNamedObjectPath)(tok, TRUE, &p);
    t_note("TokenNamedObjectPath(rel) = %08lx '%.*ls'", (ULONG)s, s == 0 ? p.Length / 2 : 0, s == 0 ? p.Buffer : L"");
    EXPECT_EQ(s, 0);
    if (s == 0) {
        if (session) { WCHAR want[64]; wsprintfW(want, L"Global\\Session\\%lu", session); CHECK(p.Length == wcslen(want) * 2 && !_wcsnicmp(p.Buffer, want, p.Length / 2)); }
        else CHECK(p.Length > 0);
        UN(RtlFreeUnicodeString)(&p);
    }
    /* pseudo token handle */
    memset(&p, 0xcc, sizeof p);
    s = UN(RtlGetTokenNamedObjectPath)((HANDLE)(LONG_PTR)-4, FALSE, &p);   /* effective-token pseudo handle */
    EXPECT_EQ(s, 0);
    if (s == 0) {
        WCHAR want[128];
        if (session) wsprintfW(want, L"\\Sessions\\%lu\\BaseNamedObjects", session); else wcscpy(want, L"\\BaseNamedObjects");
        CHECK(p.Length == wcslen(want) * 2 && !_wcsnicmp(p.Buffer, want, p.Length / 2));
        UN(RtlFreeUnicodeString)(&p);
    }
    /* bad handle: the underlying token query fails */
    memset(&p, 0xcc, sizeof p);
    s = UN(RtlGetTokenNamedObjectPath)((HANDLE)(ULONG_PTR)0x7777, FALSE, &p);
    EXPECT_EQ(s, (NTSTATUS)0xC0000008);
    CloseHandle(tok);
}

TEST(get_set_boot_status_data) {
    REQUIRE(UN(RtlGetSetBootStatusData));
    UCHAR buf[16]; ULONG ret = 0xdead;
    /* write requests for the checksum item are rejected before any I/O */
    EXPECT_EQ(UN(RtlGetSetBootStatusData)((HANDLE)(ULONG_PTR)0x7777, FALSE, 0xf, buf, sizeof buf, &ret), ST_INVALID_PARAM);
    EXPECT_EQ(ret, 0xdead);
    /* a read through a handle that does not exist fails in the first read */
    NTSTATUS s = UN(RtlGetSetBootStatusData)((HANDLE)(ULONG_PTR)0x7777, TRUE, 0, buf, sizeof buf, &ret);
    EXPECT_EQ(s, (NTSTATUS)0xC0000008);
    EXPECT_EQ(ret, 0xdead);
    s = UN(RtlGetSetBootStatusData)(NULL, TRUE, 0, buf, sizeof buf, &ret);
    EXPECT_EQ(s, (NTSTATUS)0xC0000008);
}

TEST(get_system_boot_status) {
    REQUIRE(UN(RtlGetSystemBootStatusEx));
    ULONG len = 0xdead; UCHAR buf[16];
    /* an output length at/over 1 GiB is an integer overflow and never reaches the kernel */
    EXPECT_EQ(UN(RtlGetSystemBootStatusEx)(buf, 0x40000000, &len), (NTSTATUS)0xC0000095);
    EXPECT_EQ(UN(RtlGetSystemBootStatusEx)(buf, 0xffffffff, &len), (NTSTATUS)0xC0000095);
    EXPECT_EQ(len, 0xdead);
    if (UN(RtlGetSystemBootStatus)) {
        len = 0xdead; memset(buf, 0, sizeof buf);
        NTSTATUS s = UN(RtlGetSystemBootStatus)(0, buf, sizeof buf, &len);
        t_note("RtlGetSystemBootStatus(class 0) = %08lx len=%lu", (ULONG)s, len);
        if (s == (NTSTATUS)0xC0000022 || s == (NTSTATUS)0xC0000061) { t_skip("boot status query denied for this account (%08lx)", (ULONG)s); return; }
        EXPECT_EQ(s, 0);
        EXPECT_EQ(len, 4);                            /* one ULONG status item */
        /* the Ex form takes an array of {class, buffer, length} requests; one request must match */
        struct { ULONG cls; PVOID buf; ULONG len; } req; UCHAR b2[16]; ULONG l2 = 0xdead;
        memset(&req, 0, sizeof req); memset(b2, 0, sizeof b2);
        req.cls = 0; req.buf = b2; req.len = sizeof b2;
        NTSTATUS s2 = UN(RtlGetSystemBootStatusEx)(&req, 1, &l2);
        EXPECT_EQ(s2, 0); EXPECT_EQ(l2, 4); CHECK(!memcmp(b2, buf, 4));
        l2 = 0xdead; req.cls = 0x7fffffff;
        s2 = UN(RtlGetSystemBootStatusEx)(&req, 1, &l2);
        EXPECT_EQ(s2, ST_INVALID_PARAM); EXPECT_EQ(l2, 0xdead);
        EXPECT_EQ(UN(RtlGetSystemBootStatus)(0x7fffffff, buf, sizeof buf, &len), ST_INVALID_PARAM);
    }
}

TEST(get_persisted_state_location) {
    REQUIRE(UN(RtlGetPersistedStateLocation));
    const WCHAR *def = L"C:\\Default\\State";
    ULONG want = (ULONG)(wcslen(def) + 1) * 2;
    WCHAR out[260]; ULONG need = 0xdead;
    /* with no policy key for the source the default location is returned */
    NTSTATUS s = UN(RtlGetPersistedStateLocation)(L"RtlGetTestSource", NULL, def, 0, out, sizeof out, &need);
    if (s != 0 || wcscmp(out, def)) { t_skip("a persisted-state policy key exists on this system (status %08lx)", (ULONG)s); return; }
    EXPECT_EQ(need, want);
    memset(out, 0, sizeof out); need = 0xdead;
    EXPECT_EQ(UN(RtlGetPersistedStateLocation)(L"RtlGetTestSource", NULL, def, 1, out, sizeof out, &need), 0);
    EXPECT_WSTR(out, def); EXPECT_EQ(need, want);
    /* location type must be 0 or 1 */
    EXPECT_EQ(UN(RtlGetPersistedStateLocation)(L"RtlGetTestSource", NULL, def, 2, out, sizeof out, &need), (NTSTATUS)0xC00000F1);
    /* buffer too small: STATUS_BUFFER_OVERFLOW with the required size */
    memset(out, 0x55, sizeof out); need = 0xdead;
    EXPECT_EQ(UN(RtlGetPersistedStateLocation)(L"RtlGetTestSource", NULL, def, 0, out, 4, &need), (NTSTATUS)0x80000005);
    EXPECT_EQ(need, want);
    EXPECT_EQ(out[0], 0x5555);
}

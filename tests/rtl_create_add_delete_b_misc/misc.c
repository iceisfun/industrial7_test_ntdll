/* Security objects, virtual account SIDs, boundary descriptors, registry values, current-user key, privileges,
 * path releases, user stacks/threads, activation context release, UMS deletes and dynamic function tables. */
#include "t.h"
#include <stdint.h>

#define S(x) ((NTSTATUS)(x))
#define K(name) UIN("kernel32.dll", name)
#define A(name) UIN("advapi32.dll", name)

typedef struct { UCHAR AceType, InheritFlags, AceFlags; ACCESS_MASK Mask; PSID *Sid; } TACEDATA;
typedef struct { PVOID Fn; } TFN;
typedef struct { UNICODE_STRING RelativeName; HANDLE ContainingDirectory; PVOID CurDirRef; } TRELNAME;
typedef struct { PVOID OldStackBase, OldStackLimit, StackBase, StackLimit, AllocatedStackBase; } TINITIALTEB;

UDECL(NTSTATUS, RtlCreateUserSecurityObject, (TACEDATA *, ULONG, PSID, PSID, BOOLEAN, PGENERIC_MAPPING, PSECURITY_DESCRIPTOR *));
UDECL(NTSTATUS, RtlDeleteSecurityObject, (PSECURITY_DESCRIPTOR *));
UDECL(NTSTATUS, RtlCreateVirtualAccountSid, (PCUNICODE_STRING, ULONG, PSID, PULONG));
UDECL(NTSTATUS, RtlCreateServiceSid, (PCUNICODE_STRING, PSID, PULONG));
UDECL(PVOID, RtlCreateBoundaryDescriptor, (PCUNICODE_STRING, ULONG));
UDECL(NTSTATUS, RtlAddSIDToBoundaryDescriptor, (PVOID *, PSID));
UDECL(VOID, RtlDeleteBoundaryDescriptor, (PVOID));
UDECL(NTSTATUS, RtlDeleteRegistryValue, (ULONG, PCWSTR, PCWSTR));
UDECL(NTSTATUS, RtlOpenCurrentUser, (ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, RtlRemovePrivileges, (HANDLE, PULONG, ULONG));
UDECL(NTSTATUS, RtlAcquirePrivilege, (PULONG, ULONG, ULONG, PVOID *));
UDECL(VOID, RtlReleasePrivilege, (PVOID));
UDECL(NTSTATUS, RtlGetExePath, (PCWSTR, PWSTR *));
UDECL(VOID, RtlReleasePath, (PWSTR));
UDECL(NTSTATUS, RtlDosPathNameToRelativeNtPathName_U_WithStatus, (PCWSTR, PUNICODE_STRING, PWSTR *, TRELNAME *));
UDECL(VOID, RtlReleaseRelativeName, (TRELNAME *));
UDECL(VOID, RtlFreeUnicodeString, (PUNICODE_STRING));
UDECL(NTSTATUS, RtlCreateUserStack, (SIZE_T, SIZE_T, ULONG_PTR, SIZE_T, SIZE_T, TINITIALTEB *));
UDECL(NTSTATUS, RtlFreeUserStack, (PVOID));
UDECL(NTSTATUS, RtlCreateUserThread, (HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PCLIENT_ID));
UDECL(NTSTATUS, NtResumeThread, (HANDLE, PULONG));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtOpenThreadToken, (HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE));
UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryKey, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, RtlAddRefActivationContext, (PVOID));
UDECL(VOID, RtlReleaseActivationContext, (PVOID));
UDECL(NTSTATUS, RtlCreateUmsCompletionList, (PVOID *));
UDECL(NTSTATUS, RtlDeleteUmsCompletionList, (PVOID));
UDECL(NTSTATUS, RtlCreateUmsThreadContext, (PVOID *));
UDECL(NTSTATUS, RtlDeleteUmsThreadContext, (PVOID));
UDECL(BOOLEAN, RtlAddFunctionTable, (PRUNTIME_FUNCTION, DWORD, DWORD64));
UDECL(BOOLEAN, RtlDeleteFunctionTable, (PRUNTIME_FUNCTION));
UDECL(NTSTATUS, RtlAddGrowableFunctionTable, (PVOID *, PRUNTIME_FUNCTION, DWORD, DWORD, ULONG_PTR, ULONG_PTR));
UDECL(VOID, RtlDeleteGrowableFunctionTable, (PVOID));
UDECL(PRUNTIME_FUNCTION, RtlLookupFunctionEntry, (DWORD64, PDWORD64, PVOID));
UDECL(NTSTATUS, RtlAllocateAndInitializeSid, (PSID_IDENTIFIER_AUTHORITY, UCHAR, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PSID *));
UDECL(PVOID, RtlFreeSid, (PSID));
UDECL(BOOLEAN, RtlEqualSid, (PSID, PSID));
UDECL(ULONG, RtlLengthSid, (PSID));
UDECL(NTSTATUS, RtlGetOwnerSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetGroupSecurityDescriptor, (PSECURITY_DESCRIPTOR, PSID *, PBOOLEAN));
UDECL(NTSTATUS, RtlGetDaclSecurityDescriptor, (PSECURITY_DESCRIPTOR, PBOOLEAN, PACL *, PBOOLEAN));
UDECL(BOOLEAN, RtlValidSecurityDescriptor, (PSECURITY_DESCRIPTOR));
UDECL(PVOID, RtlAllocateHeap, (PVOID, ULONG, SIZE_T));
UDECL(PVOID, RtlFreeHeap, (PVOID, ULONG, PVOID));

/* ---------------- SHA-1 (reference for virtual account SIDs) ---------------- */
static uint32_t rol(uint32_t v, int s) { return (v << s) | (v >> (32 - s)); }
static void sha1(const unsigned char *m, size_t len, uint32_t h[5]) {
    unsigned char buf[256]; size_t padded = ((len + 8) / 64 + 1) * 64; memset(buf, 0, sizeof buf);
    if (padded > sizeof buf) return;
    memcpy(buf, m, len); buf[len] = 0x80; uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[padded - 1 - i] = (unsigned char)(bits >> (8 * i));
    h[0] = 0x67452301; h[1] = 0xefcdab89; h[2] = 0x98badcfe; h[3] = 0x10325476; h[4] = 0xc3d2e1f0;
    for (size_t off = 0; off < padded; off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) w[i] = (uint32_t)buf[off + 4*i] << 24 | buf[off + 4*i + 1] << 16 | buf[off + 4*i + 2] << 8 | buf[off + 4*i + 3];
        for (int i = 16; i < 80; i++) w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
            else { f = b ^ c ^ d; k = 0xca62c1d6; }
            uint32_t t = rol(a, 5) + f + e + k + w[i]; e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
}
static void init_us(UNICODE_STRING *u, const WCHAR *s) { u->Buffer = (PWSTR)s; u->Length = (USHORT)(lstrlenW(s) * 2); u->MaximumLength = u->Length + 2; }

TEST(rtl_cad_b_virtual_account_sid) {
    REQUIRE(UN(RtlCreateVirtualAccountSid)); REQUIRE(UN(RtlCreateServiceSid));
    UNICODE_STRING nm; init_us(&nm, L"MyVirtualSvc");
    BYTE sid[64]; ULONG len = sizeof sid;
    NTSTATUS s = UN(RtlCreateVirtualAccountSid)(&nm, 80, sid, &len);
    EXPECT_EQ(s, 0); EXPECT_EQ(len, 32);
    if (s != 0) return;
    EXPECT_EQ(sid[0], 1); EXPECT_EQ(sid[1], 6);
    static const BYTE nt[6] = { 0, 0, 0, 0, 0, 5 }; CHECK(!memcmp(sid + 2, nt, 6));
    EXPECT_EQ(*(ULONG *)(sid + 8), 80);
    /* sub-authorities 1..5 are SHA-1 of the upper-cased UTF-16LE name (little-endian dwords of the digest bytes) */
    uint32_t h[5]; static const WCHAR up[] = L"MYVIRTUALSVC"; sha1((const unsigned char *)up, lstrlenW(up) * 2, h);
    unsigned char dig[20]; for (int i = 0; i < 5; i++) { dig[4*i] = h[i] >> 24; dig[4*i+1] = h[i] >> 16; dig[4*i+2] = h[i] >> 8; dig[4*i+3] = h[i]; }
    CHECK(!memcmp(sid + 12, dig, 20));
    /* case-insensitive name */
    UNICODE_STRING n2; init_us(&n2, L"myvirtualsvc"); BYTE sid2[64]; ULONG l2 = sizeof sid2;
    EXPECT_EQ(UN(RtlCreateVirtualAccountSid)(&n2, 80, sid2, &l2), 0); CHECK(!memcmp(sid, sid2, 32));
    /* a different base changes only the first sub-authority */
    l2 = sizeof sid2; EXPECT_EQ(UN(RtlCreateVirtualAccountSid)(&nm, 0x6f, sid2, &l2), 0);
    EXPECT_EQ(*(ULONG *)(sid2 + 8), 0x6f); CHECK(!memcmp(sid + 12, sid2 + 12, 20));
    /* service SIDs are virtual account SIDs with base 80 */
    BYTE ssid[64]; ULONG sl = sizeof ssid; s = UN(RtlCreateServiceSid)(&nm, ssid, &sl);
    EXPECT_EQ(s, 0); if (s == 0) { EXPECT_EQ(sl, 32); CHECK(!memcmp(sid, ssid, 32)); }
    /* errors */
    len = 31; memset(sid2, 0, sizeof sid2);
    EXPECT_EQ(UN(RtlCreateVirtualAccountSid)(&nm, 80, sid2, &len), S(0xC0000023)); EXPECT_EQ(len, 32);
    len = sizeof sid;
    EXPECT_EQ(UN(RtlCreateVirtualAccountSid)(&nm, 79, sid2, &len), S(0xC000000D));
    EXPECT_EQ(UN(RtlCreateVirtualAccountSid)(&nm, 0x70, sid2, &len), S(0xC000000D));
    EXPECT_EQ(UN(RtlCreateVirtualAccountSid)(NULL, 80, sid2, &len), S(0xC000000D));
    EXPECT_EQ(UN(RtlCreateVirtualAccountSid)(&nm, 80, sid2, NULL), S(0xC000000D));
    EXPECT_EQ(UN(RtlCreateVirtualAccountSid)(&nm, 0x50, sid2, &len), 0);
    EXPECT_EQ(UN(RtlCreateVirtualAccountSid)(&nm, 0x6f, sid2, &len), 0);
}

/* ---------------- security objects ---------------- */
TEST(rtl_cad_b_user_security_object) {
    REQUIRE(UN(RtlCreateUserSecurityObject)); REQUIRE(UN(RtlDeleteSecurityObject)); REQUIRE(UN(RtlAllocateAndInitializeSid));
    REQUIRE(UN(RtlFreeSid)); REQUIRE(UN(RtlEqualSid)); REQUIRE(UN(RtlGetOwnerSecurityDescriptor)); REQUIRE(UN(RtlGetGroupSecurityDescriptor));
    REQUIRE(UN(RtlGetDaclSecurityDescriptor)); REQUIRE(UN(RtlValidSecurityDescriptor)); REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtQueryInformationToken));
    HANDLE tok = NULL; EXPECT_EQ(UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &tok), 0); if (!tok) return;
    BYTE ubuf[256], gbuf[256]; ULONG rl = 0;
    NTSTATUS s1 = UN(NtQueryInformationToken)(tok, 1 /* TokenUser */, ubuf, sizeof ubuf, &rl);
    NTSTATUS s2 = UN(NtQueryInformationToken)(tok, 5 /* TokenPrimaryGroup */, gbuf, sizeof gbuf, &rl);
    UN(NtClose)(tok);
    EXPECT_EQ(s1, 0); EXPECT_EQ(s2, 0); if (s1 || s2) return;
    PSID owner = *(PSID *)ubuf, group = *(PSID *)gbuf;
    SID_IDENTIFIER_AUTHORITY wa = { {0,0,0,0,0,1} }; PSID everyone = NULL;
    EXPECT_EQ(UN(RtlAllocateAndInitializeSid)(&wa, 1, 0, 0, 0, 0, 0, 0, 0, 0, &everyone), 0); if (!everyone) return;
    TACEDATA ace[2] = { { ACCESS_ALLOWED_ACE_TYPE, 0, 0, 0x00120089, &everyone }, { ACCESS_DENIED_ACE_TYPE, 0, 0, 0x00000002, &group } };
    GENERIC_MAPPING gm = { 0x120089, 0x120116, 0x1200a0, 0x1f01ff };
    PSECURITY_DESCRIPTOR sd = NULL;
    NTSTATUS s = UN(RtlCreateUserSecurityObject)(ace, 2, owner, group, FALSE, &gm, &sd);
    EXPECT_EQ(s, 0);
    if (s == 0 && sd) {
        CHECK(UN(RtlValidSecurityDescriptor)(sd));
        PSID o = NULL, g = NULL; BOOLEAN def = 1, present = 0; PACL dacl = NULL;
        EXPECT_EQ(UN(RtlGetOwnerSecurityDescriptor)(sd, &o, &def), 0); CHECK(o && UN(RtlEqualSid)(o, owner));
        EXPECT_EQ(UN(RtlGetGroupSecurityDescriptor)(sd, &g, &def), 0); CHECK(g && UN(RtlEqualSid)(g, group));
        EXPECT_EQ(UN(RtlGetDaclSecurityDescriptor)(sd, &present, &dacl, &def), 0);
        EXPECT_EQ(present, 1); CHECK(dacl != NULL);
        if (dacl) {
            EXPECT_EQ(dacl->AceCount, 2);
            ACCESS_ALLOWED_ACE *a0 = (ACCESS_ALLOWED_ACE *)(dacl + 1);
            EXPECT_EQ(a0->Header.AceType, ACCESS_ALLOWED_ACE_TYPE); EXPECT_EQ(a0->Mask, 0x120089);
            CHECK(UN(RtlEqualSid)((PSID)&a0->SidStart, everyone));
            ACCESS_DENIED_ACE *a1 = (ACCESS_DENIED_ACE *)((BYTE *)a0 + a0->Header.AceSize);
            EXPECT_EQ(a1->Header.AceType, ACCESS_DENIED_ACE_TYPE); EXPECT_EQ(a1->Mask, 2);
        }
        EXPECT_EQ(UN(RtlDeleteSecurityObject)(&sd), 0);
    }
    UN(RtlFreeSid)(everyone);
}

/* ---------------- boundary descriptors ---------------- */
TEST(rtl_cad_b_boundary_descriptor) {
    REQUIRE(UN(RtlCreateBoundaryDescriptor)); REQUIRE(UN(RtlDeleteBoundaryDescriptor)); REQUIRE(UN(RtlAddSIDToBoundaryDescriptor));
    REQUIRE(UN(RtlAllocateAndInitializeSid)); REQUIRE(UN(RtlFreeSid));
    UNICODE_STRING nm; init_us(&nm, L"i7CadBoundary");
    PVOID bd = UN(RtlCreateBoundaryDescriptor)(&nm, 0);
    CHECK(bd != NULL); if (!bd) return;
    ULONG *w = bd;
    EXPECT_EQ(w[0], 1);   /* version */
    PVOID bd2 = UN(RtlCreateBoundaryDescriptor)(&nm, 0);
    CHECK(bd2 != NULL && bd2 != bd);
    SID_IDENTIFIER_AUTHORITY wa = { {0,0,0,0,0,1} }; PSID everyone = NULL;
    EXPECT_EQ(UN(RtlAllocateAndInitializeSid)(&wa, 1, 0, 0, 0, 0, 0, 0, 0, 0, &everyone), 0);
    if (everyone) {
        PVOID before = bd;
        EXPECT_EQ(UN(RtlAddSIDToBoundaryDescriptor)(&bd, everyone), 0);
        CHECK(bd != NULL); (void)before;
        EXPECT_EQ(UN(RtlAddSIDToBoundaryDescriptor)(&bd, everyone), 0);   /* duplicates are stored too */
        UN(RtlFreeSid)(everyone);
    }
    UN(RtlDeleteBoundaryDescriptor)(bd);
    UN(RtlDeleteBoundaryDescriptor)(bd2);
}

/* ---------------- registry value deletion / current user ---------------- */
TEST(rtl_cad_b_delete_registry_value) {
    REQUIRE(UN(RtlDeleteRegistryValue));
    WCHAR sub[64]; wsprintfW(sub, L"Software\\i7CadBVal%lu", GetCurrentProcessId());
    HKEY k = NULL; LONG e = RegCreateKeyExW(HKEY_CURRENT_USER, sub, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL);
    if (e) { t_skip("cannot create HKCU test key (%ld)", e); return; }
    DWORD v = 7;
    RegSetValueExW(k, L"gone", 0, REG_DWORD, (BYTE *)&v, 4); RegSetValueExW(k, L"stays", 0, REG_DWORD, (BYTE *)&v, 4);
    EXPECT_EQ(UN(RtlDeleteRegistryValue)(5 /* RTL_REGISTRY_USER */, sub, L"gone"), 0);
    DWORD t, n = 4; EXPECT_EQ(RegQueryValueExW(k, L"gone", NULL, &t, (BYTE *)&v, &n), ERROR_FILE_NOT_FOUND);
    n = 4; EXPECT_EQ(RegQueryValueExW(k, L"stays", NULL, &t, (BYTE *)&v, &n), 0);
    EXPECT_EQ(UN(RtlDeleteRegistryValue)(5, sub, L"gone"), S(0xC0000034));       /* value no longer exists */
    EXPECT_EQ(UN(RtlDeleteRegistryValue)(5, sub, L"nope"), S(0xC0000034));
    /* an open handle in place of a path */
    EXPECT_EQ(UN(RtlDeleteRegistryValue)(0x40000000 | 0 /* RTL_REGISTRY_HANDLE | ABSOLUTE */, (PCWSTR)k, L"stays"), 0);
    n = 4; EXPECT_EQ(RegQueryValueExW(k, L"stays", NULL, &t, (BYTE *)&v, &n), ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(UN(RtlDeleteRegistryValue)(0x40000000, (PCWSTR)k, L"stays"), S(0xC0000034));
    /* relative-to class out of range */
    EXPECT_EQ(UN(RtlDeleteRegistryValue)(0x1234, sub, L"gone"), S(0xC000000D));
    RegCloseKey(k); RegDeleteKeyW(HKEY_CURRENT_USER, sub);
}
TEST(rtl_cad_b_open_current_user) {
    REQUIRE(UN(RtlOpenCurrentUser)); REQUIRE(UN(NtQueryKey)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtQueryInformationToken));
    HANDLE h = NULL; NTSTATUS s = UN(RtlOpenCurrentUser)(KEY_READ, &h);
    EXPECT_EQ(s, 0); CHECK(h != NULL); if (s != 0 || !h) return;
    BYTE nb[1024]; ULONG rl = 0;
    EXPECT_EQ(UN(NtQueryKey)(h, 3 /* KeyNameInformation */, nb, sizeof nb, &rl), 0);
    ULONG nl = *(ULONG *)nb; WCHAR *name = (WCHAR *)(nb + 4); WCHAR full[600]; memcpy(full, name, nl); full[nl / 2] = 0;
    CHECK(!_wcsnicmp(full, L"\\REGISTRY\\USER\\", 15));
    /* the key is the user's hive root: either the token user SID or .DEFAULT */
    HANDLE tok = NULL; BYTE ub[256];
    UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &tok);
    if (tok) {
        if (UN(NtQueryInformationToken)(tok, 1, ub, sizeof ub, &rl) == 0) {
            LPWSTR str = NULL; typedef BOOL (WINAPI *cvt)(PSID, LPWSTR *);
            cvt f = (cvt)t_proc_in("advapi32.dll", "ConvertSidToStringSidW");
            if (f && f(*(PSID *)ub, &str)) {
                WCHAR want[200]; wsprintfW(want, L"\\REGISTRY\\USER\\%ls", str);
                CHECKF(!_wcsicmp(full, want) || !_wcsicmp(full, L"\\REGISTRY\\USER\\.DEFAULT"), "key name %ls", full);
                LocalFree(str);
            }
        }
        UN(NtClose)(tok);
    }
    UN(NtClose)(h);
    h = (HANDLE)0x1; s = UN(RtlOpenCurrentUser)(0, &h);   /* zero access is accepted by NtOpenKey? record only */
    if (s == 0 && h) UN(NtClose)(h);
}

/* ---------------- privileges ---------------- */
TEST(rtl_cad_b_remove_privileges) {
    REQUIRE(UN(RtlRemovePrivileges)); REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtDuplicateToken)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtClose));
    HANDLE ptok = NULL, dup = NULL;
    EXPECT_EQ(UN(NtOpenProcessToken)((HANDLE)(LONG_PTR)-1, TOKEN_DUPLICATE, &ptok), 0); if (!ptok) return;
    OBJECT_ATTRIBUTES oa = { sizeof oa };
    NTSTATUS s = UN(NtDuplicateToken)(ptok, TOKEN_ALL_ACCESS, &oa, FALSE, 2 /* TokenImpersonation */, &dup);
    UN(NtClose)(ptok);
    if (s < 0 || !dup) { t_skip("cannot duplicate token %08lx", (unsigned long)s); return; }
    /* invalid privilege values */
    ULONG bad1 = 1, bad2 = 0x25;
    EXPECT_EQ(UN(RtlRemovePrivileges)(dup, &bad1, 1), S(0xC000000D));
    EXPECT_EQ(UN(RtlRemovePrivileges)(dup, &bad2, 1), S(0xC000000D));
    /* the keep-list names a privilege the token does not hold: nothing is removed, STATUS_NOT_ALL_ASSIGNED */
    ULONG create_token = 2; BYTE buf[2048]; ULONG rl = 0;
    EXPECT_EQ(UN(RtlRemovePrivileges)(dup, &create_token, 1), S(0x106));
    EXPECT_EQ(UN(NtQueryInformationToken)(dup, 3 /* TokenPrivileges */, buf, sizeof buf, &rl), 0);
    ULONG before = *(ULONG *)buf; CHECK(before >= 1);
    /* keep only SeChangeNotifyPrivilege: every other privilege is removed */
    ULONG chg = 23;
    EXPECT_EQ(UN(RtlRemovePrivileges)(dup, &chg, 1), 0);
    EXPECT_EQ(UN(NtQueryInformationToken)(dup, 3, buf, sizeof buf, &rl), 0);
    ULONG cnt = *(ULONG *)buf; EXPECT_EQ(cnt, 1);
    if (cnt == 1) EXPECT_EQ(*(ULONG *)(buf + 4), 23);
    /* second call: nothing more to remove */
    EXPECT_EQ(UN(RtlRemovePrivileges)(dup, &chg, 1), 0);
    UN(NtClose)(dup);
}
/* 1: held and enabled on the thread token, 0: held but disabled, -1: no thread token / not present */
static int priv_enabled_on_thread(ULONG luid) {
    HANDLE tok = NULL; int r = -1; BYTE buf[2048]; ULONG rl;
    if (UN(NtOpenThreadToken)(GetCurrentThread() ? (HANDLE)(LONG_PTR)-2 : NULL, TOKEN_QUERY, TRUE, &tok) != 0 || !tok) return -1;
    if (UN(NtQueryInformationToken)(tok, 3, buf, sizeof buf, &rl) == 0) {
        ULONG n = *(ULONG *)buf; LUID_AND_ATTRIBUTES *p = (LUID_AND_ATTRIBUTES *)(buf + 4);
        for (ULONG i = 0; i < n; i++) if (p[i].Luid.LowPart == luid && p[i].Luid.HighPart == 0) r = (p[i].Attributes & SE_PRIVILEGE_ENABLED) ? 1 : 0;
    }
    UN(NtClose)(tok); return r;
}
TEST(rtl_cad_b_release_privilege) {
    REQUIRE(UN(RtlAcquirePrivilege)); REQUIRE(UN(RtlReleasePrivilege)); REQUIRE(UN(NtOpenThreadToken)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtClose));
    ULONG priv = 14;   /* SeIncreaseWorkingSetPrivilege: held (disabled) by standard users and administrators */
    PVOID state = NULL; NTSTATUS s = UN(RtlAcquirePrivilege)(&priv, 1, 0, &state);
    if (s == S(0xC0000061)) { t_skip("account does not hold SeIncreaseWorkingSetPrivilege (STATUS_PRIVILEGE_NOT_HELD)"); return; }
    EXPECT_EQ(s, 0); if (s != 0) return;
    CHECK(state != NULL);
    /* while held, the calling thread's token has the privilege enabled */
    int on = priv_enabled_on_thread(priv);
    EXPECT_EQ(on, 1);
    UN(RtlReleasePrivilege)(state);
    on = priv_enabled_on_thread(priv);
    EXPECT_NE(on, 1);                  /* no token left, or the privilege is disabled again */
    /* a second acquisition after release works again */
    state = NULL; EXPECT_EQ(UN(RtlAcquirePrivilege)(&priv, 1, 0, &state), 0);
    if (state) UN(RtlReleasePrivilege)(state);
}

/* ---------------- paths ---------------- */
TEST(rtl_cad_b_release_path) {
    REQUIRE(UN(RtlGetExePath)); REQUIRE(UN(RtlReleasePath));
    PWSTR p1 = NULL, p2 = NULL;
    EXPECT_EQ(UN(RtlGetExePath)(L"app.exe", &p1), 0);
    CHECK(p1 != NULL && p1[0] != 0); if (!p1) return;
    EXPECT_EQ(UN(RtlGetExePath)(L"app.exe", &p2), 0);     /* cached: same reference counted string */
    CHECK(p2 != NULL);
    EXPECT_EQ((ULONG_PTR)p1, (ULONG_PTR)p2);
    UN(RtlReleasePath)(p1);
    CHECK(p2[0] != 0);   /* still valid after one release */
    UN(RtlReleasePath)(p2);
}
TEST(rtl_cad_b_release_relative_name) {
    REQUIRE(UN(RtlDosPathNameToRelativeNtPathName_U_WithStatus)); REQUIRE(UN(RtlReleaseRelativeName)); REQUIRE(UN(RtlFreeUnicodeString));
    UNICODE_STRING nt; PWSTR part = NULL; TRELNAME rel; memset(&rel, 0xCC, sizeof rel);
    NTSTATUS s = UN(RtlDosPathNameToRelativeNtPathName_U_WithStatus)(L"sub\\file.txt", &nt, &part, &rel);
    EXPECT_EQ(s, 0); if (s != 0) return;
    CHECK(nt.Buffer != NULL); CHECK(part != NULL && !lstrcmpW(part, L"file.txt"));
    UN(RtlReleaseRelativeName)(&rel);
    EXPECT_EQ((ULONG_PTR)rel.CurDirRef, 0);        /* reference dropped and cleared */
    UN(RtlReleaseRelativeName)(&rel);              /* second release is a no-op */
    EXPECT_EQ((ULONG_PTR)rel.CurDirRef, 0);
    UN(RtlFreeUnicodeString)(&nt);
    /* absolute path produces no relative name reference */
    memset(&rel, 0xCC, sizeof rel);
    s = UN(RtlDosPathNameToRelativeNtPathName_U_WithStatus)(L"C:\\Windows\\notepad.exe", &nt, &part, &rel);
    EXPECT_EQ(s, 0);
    if (s == 0) { UN(RtlReleaseRelativeName)(&rel); EXPECT_EQ((ULONG_PTR)rel.CurDirRef, 0); UN(RtlFreeUnicodeString)(&nt); }
}

/* ---------------- user stack / thread ---------------- */
TEST(rtl_cad_b_user_stack) {
    REQUIRE(UN(RtlCreateUserStack)); REQUIRE(UN(RtlFreeUserStack));
    TINITIALTEB t; memset(&t, 0xCC, sizeof t);
    NTSTATUS s = UN(RtlCreateUserStack)(0x4000, 0x100000, 0, 0x1000, 0x10000, &t);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        EXPECT_EQ((ULONG_PTR)t.OldStackBase, 0); EXPECT_EQ((ULONG_PTR)t.OldStackLimit, 0);
        CHECK(t.AllocatedStackBase != NULL);
        EXPECT_EQ((ULONG_PTR)t.StackBase - (ULONG_PTR)t.AllocatedStackBase, 0x100000);
        CHECK((ULONG_PTR)t.StackLimit < (ULONG_PTR)t.StackBase && (ULONG_PTR)t.StackLimit >= (ULONG_PTR)t.AllocatedStackBase);
        MEMORY_BASIC_INFORMATION mbi;
        CHECK(VirtualQuery((BYTE *)t.StackBase - 0x1000, &mbi, sizeof mbi) != 0);
        EXPECT_EQ(mbi.State, MEM_COMMIT);
        CHECK(VirtualQuery(t.AllocatedStackBase, &mbi, sizeof mbi) != 0);
        EXPECT_EQ(mbi.State, MEM_RESERVE);
        EXPECT_EQ(UN(RtlFreeUserStack)(t.AllocatedStackBase), 0);
        CHECK(VirtualQuery(t.AllocatedStackBase, &mbi, sizeof mbi) != 0);
        EXPECT_EQ(mbi.State, MEM_FREE);
    }
    TINITIALTEB u;
    EXPECT_EQ(UN(RtlCreateUserStack)(0x4000, 0x100000, 0, 0, 0x10000, &u), S(0xC000000D));        /* page size 0 */
    EXPECT_EQ(UN(RtlCreateUserStack)(0x4000, 0x100000, 0, 0x1000, 0, &u), S(0xC000000D));         /* alignment 0 */
    EXPECT_EQ(UN(RtlCreateUserStack)(0x4000, 0x100000, 0, 0x10000, 0x1000, &u), S(0xC000000D));   /* alignment < page */
    EXPECT_EQ(UN(RtlCreateUserStack)(0x4000, 0x100000, 0, 0x4100000000000000ULL | 0x1000, 0x10000, &u), S(0xC000000D));
}
typedef struct { volatile LONG v; HANDLE ev; } UTARG;
static DWORD NTAPI ut_start(PVOID p) { UTARG *a = p; a->v = (LONG)GetCurrentThreadId(); SetEvent(a->ev); return 0x1234; }
TEST(rtl_cad_b_create_user_thread) {
    REQUIRE(UN(RtlCreateUserThread)); REQUIRE(UN(NtResumeThread)); REQUIRE(UN(NtClose));
    UTARG a = { 0, CreateEventW(NULL, TRUE, FALSE, NULL) };
    HANDLE th = NULL; CLIENT_ID cid = {0};
    /* suspended: thread exists but does not run */
    NTSTATUS s = UN(RtlCreateUserThread)((HANDLE)(LONG_PTR)-1, NULL, TRUE, 0, 0, 0, (PVOID)ut_start, &a, &th, &cid);
    EXPECT_EQ(s, 0); CHECK(th != NULL); if (s != 0 || !th) { CloseHandle(a.ev); return; }
    CHECK((ULONG_PTR)cid.UniqueThread != 0); EXPECT_EQ((ULONG_PTR)cid.UniqueProcess, GetCurrentProcessId());
    EXPECT_EQ(WaitForSingleObject(a.ev, 150), WAIT_TIMEOUT); EXPECT_EQ(a.v, 0);
    ULONG prev = 99; EXPECT_EQ(UN(NtResumeThread)(th, &prev), 0); EXPECT_EQ(prev, 1);
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    EXPECT_EQ(a.v, (LONG)(ULONG_PTR)cid.UniqueThread);
    DWORD ec = 0; GetExitCodeThread(th, &ec); EXPECT_EQ(ec, 0x1234);
    UN(NtClose)(th);
    /* running immediately */
    ResetEvent(a.ev); a.v = 0; th = NULL; memset(&cid, 0, sizeof cid);
    s = UN(RtlCreateUserThread)((HANDLE)(LONG_PTR)-1, NULL, FALSE, 0, 0, 0, (PVOID)ut_start, &a, &th, &cid);
    EXPECT_EQ(s, 0);
    if (s == 0) { EXPECT_EQ(WaitForSingleObject(a.ev, 10000), WAIT_OBJECT_0); WaitForSingleObject(th, 10000); UN(NtClose)(th); }
    /* bad process handle */
    th = NULL; s = UN(RtlCreateUserThread)((HANDLE)(ULONG_PTR)0x7777, NULL, TRUE, 0, 0, 0, (PVOID)ut_start, &a, &th, &cid);
    EXPECT_EQ(s, S(0xC0000008)); EXPECT_EQ((ULONG_PTR)th, 0);
    CloseHandle(a.ev);
}

/* ---------------- activation context reference counting ---------------- */
TEST(rtl_cad_b_release_activation_context) {
    REQUIRE(UN(RtlAddRefActivationContext)); REQUIRE(UN(RtlReleaseActivationContext));
    UN(RtlReleaseActivationContext)(NULL);                 /* NULL is ignored */
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "cadb.manifest");
    const char *xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
        "<assemblyIdentity type=\"win32\" name=\"I7.CadB.Test\" version=\"1.0.0.0\"/></assembly>";
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL); DWORD w;
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot write manifest"); return; }
    WriteFile(f, xml, (DWORD)strlen(xml), &w, NULL); CloseHandle(f);
    ACTCTXA ac; memset(&ac, 0, sizeof ac); ac.cbSize = sizeof ac; ac.lpSource = path; HANDLE h = K(CreateActCtxA)(&ac);
    if (h == INVALID_HANDLE_VALUE) { t_skip("CreateActCtx failed %lu", GetLastError()); DeleteFileA(path); return; }
    volatile LONG *rc = (volatile LONG *)h;      /* first dword of the context is the reference count */
    LONG base = *rc; CHECK(base >= 1 && base < 100);
    UN(RtlAddRefActivationContext)(h); EXPECT_EQ(*rc, base + 1);
    UN(RtlReleaseActivationContext)(h);               EXPECT_EQ(*rc, base);
    K(ReleaseActCtx)(h);
    DeleteFileA(path);
}

/* ---------------- UMS deletes ---------------- */
TEST(rtl_cad_b_ums_delete) {
    REQUIRE(UN(RtlDeleteUmsCompletionList)); REQUIRE(UN(RtlDeleteUmsThreadContext));
    EXPECT_EQ(UN(RtlDeleteUmsCompletionList)(NULL), S(0xC000000D));
    EXPECT_EQ(UN(RtlDeleteUmsThreadContext)(NULL), S(0xC000000D));
    if (UN(RtlCreateUmsCompletionList)) {
        PVOID cl = NULL; NTSTATUS s = UN(RtlCreateUmsCompletionList)(&cl);
        if (s == 0 && cl) EXPECT_EQ(UN(RtlDeleteUmsCompletionList)(cl), 0); else t_note("RtlCreateUmsCompletionList %08lx", (unsigned long)s);
    }
    if (UN(RtlCreateUmsThreadContext)) {
        PVOID tc = NULL; NTSTATUS s = UN(RtlCreateUmsThreadContext)(&tc);
        if (s == 0 && tc) EXPECT_EQ(UN(RtlDeleteUmsThreadContext)(tc), 0); else t_note("RtlCreateUmsThreadContext %08lx", (unsigned long)s);
    }
}

/* ---------------- dynamic function tables ---------------- */
TEST(rtl_cad_b_delete_function_table) {
    REQUIRE(UN(RtlAddFunctionTable)); REQUIRE(UN(RtlDeleteFunctionTable)); REQUIRE(UN(RtlLookupFunctionEntry));
    BYTE *base = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    CHECK(base != NULL); if (!base) return;
    RUNTIME_FUNCTION *tab = (RUNTIME_FUNCTION *)(base + 0x8000);
    tab[0].BeginAddress = 0x100; tab[0].EndAddress = 0x200; tab[0].UnwindData = 0x300;
    tab[1].BeginAddress = 0x200; tab[1].EndAddress = 0x300; tab[1].UnwindData = 0x300;
    DWORD64 ib = 0;
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(base + 0x180), &ib, NULL), 0);
    EXPECT_EQ(UN(RtlDeleteFunctionTable)(tab), FALSE);          /* never registered */
    EXPECT_EQ(UN(RtlAddFunctionTable)(tab, 2, (DWORD64)base), TRUE);
    PRUNTIME_FUNCTION f = UN(RtlLookupFunctionEntry)((DWORD64)(base + 0x180), &ib, NULL);
    EXPECT_EQ((ULONG_PTR)f, (ULONG_PTR)&tab[0]); EXPECT_EQ(ib, (DWORD64)base);
    f = UN(RtlLookupFunctionEntry)((DWORD64)(base + 0x250), &ib, NULL);
    EXPECT_EQ((ULONG_PTR)f, (ULONG_PTR)&tab[1]);
    EXPECT_EQ(UN(RtlDeleteFunctionTable)(tab), TRUE);
    EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(base + 0x180), &ib, NULL), 0);
    EXPECT_EQ(UN(RtlDeleteFunctionTable)(tab), FALSE);          /* already deleted */
    EXPECT_EQ(UN(RtlDeleteFunctionTable)(NULL), FALSE);
    VirtualFree(base, 0, MEM_RELEASE);
}
TEST(rtl_cad_b_delete_growable_function_table) {
    REQUIRE(UN(RtlAddGrowableFunctionTable)); REQUIRE(UN(RtlDeleteGrowableFunctionTable)); REQUIRE(UN(RtlLookupFunctionEntry));
    BYTE *base = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    CHECK(base != NULL); if (!base) return;
    RUNTIME_FUNCTION *tab = (RUNTIME_FUNCTION *)(base + 0x8000);
    tab[0].BeginAddress = 0x100; tab[0].EndAddress = 0x200; tab[0].UnwindData = 0x300;
    PVOID h = NULL; DWORD64 ib = 0;
    NTSTATUS s = UN(RtlAddGrowableFunctionTable)(&h, tab, 1, 4, (ULONG_PTR)base, (ULONG_PTR)base + 0x10000);
    EXPECT_EQ(s, 0); CHECK(h != NULL);
    if (s == 0 && h) {
        PRUNTIME_FUNCTION f = UN(RtlLookupFunctionEntry)((DWORD64)(base + 0x180), &ib, NULL);
        EXPECT_EQ((ULONG_PTR)f, (ULONG_PTR)&tab[0]);
        UN(RtlDeleteGrowableFunctionTable)(h);
        EXPECT_EQ((ULONG_PTR)UN(RtlLookupFunctionEntry)((DWORD64)(base + 0x180), &ib, NULL), 0);
    }
    VirtualFree(base, 0, MEM_RELEASE);
}

/* ---------------- atom deletion ---------------- */
UDECL(NTSTATUS, RtlCreateAtomTable, (ULONG, PVOID *));
UDECL(NTSTATUS, RtlDestroyAtomTable, (PVOID));
UDECL(NTSTATUS, RtlAddAtomToAtomTable, (PVOID, PCWSTR, PUSHORT));
UDECL(NTSTATUS, RtlLookupAtomInAtomTable, (PVOID, PCWSTR, PUSHORT));
UDECL(NTSTATUS, RtlPinAtomInAtomTable, (PVOID, USHORT));
UDECL(NTSTATUS, RtlDeleteAtomFromAtomTable, (PVOID, USHORT));
TEST(rtl_cad_b_delete_atom) {
    REQUIRE(UN(RtlCreateAtomTable)); REQUIRE(UN(RtlDestroyAtomTable)); REQUIRE(UN(RtlAddAtomToAtomTable)); REQUIRE(UN(RtlLookupAtomInAtomTable));
    REQUIRE(UN(RtlPinAtomInAtomTable)); REQUIRE(UN(RtlDeleteAtomFromAtomTable));
    PVOID tb = NULL; EXPECT_EQ(UN(RtlCreateAtomTable)(37, &tb), 0); if (!tb) return;
    USHORT a = 0, b = 0, c = 0;
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tb, L"i7CadBAtomOne", &a), 0); CHECK(a >= 0xC000);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tb, L"i7CadBAtomOne", &b), 0); EXPECT_EQ(a, b);
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tb, a), 0);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tb, L"i7CadBAtomOne", &b), S(0xC0000034));
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tb, a), S(0xC0000008));      /* already gone */
    /* reference counted: two adds need two deletes */
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tb, L"i7CadBAtomTwo", &a), 0);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tb, L"i7CadBAtomTwo", &c), 0); EXPECT_EQ(a, c);
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tb, a), 0);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tb, L"i7CadBAtomTwo", &b), 0);
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tb, a), 0);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tb, L"i7CadBAtomTwo", &b), S(0xC0000034));
    /* pinned atoms cannot be deleted */
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(tb, L"i7CadBAtomPin", &a), 0);
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(tb, a), 0);
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tb, a), S(0x40000019));
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(tb, L"i7CadBAtomPin", &b), 0);
    /* integer atoms: nonzero deletes succeed trivially, zero is an invalid handle */
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tb, 0x1234), 0);
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tb, 0), S(0xC0000008));
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(tb, 0xCFFF), S(0xC0000008)); /* string-atom range, never allocated */
    EXPECT_EQ(UN(RtlDestroyAtomTable)(tb), 0);
}

/* ---------------- memory stream stubs ---------------- */
UDECL(LONG, RtlLockMemoryStreamRegion, (PVOID, ULONGLONG, ULONGLONG, ULONG));
UDECL(LONG, RtlUnlockMemoryStreamRegion, (PVOID, ULONGLONG, ULONGLONG, ULONG));
UDECL(ULONG, RtlReleaseMemoryStream, (PVOID));
UDECL(ULONG, RtlAddRefMemoryStream, (PVOID));
TEST(rtl_cad_b_memory_stream_stubs) {
    REQUIRE(UN(RtlLockMemoryStreamRegion)); REQUIRE(UN(RtlUnlockMemoryStreamRegion)); REQUIRE(UN(RtlReleaseMemoryStream));
    /* the stream implementation is not available: the region calls report E_NOTIMPL, the reference calls return 0 and touch nothing */
    EXPECT_EQ(UN(RtlLockMemoryStreamRegion)(NULL, 0, 16, 1), S(0x80004001));
    EXPECT_EQ(UN(RtlLockMemoryStreamRegion)((PVOID)0x1000, 5, 6, 0), S(0x80004001));
    EXPECT_EQ(UN(RtlUnlockMemoryStreamRegion)(NULL, 0, 16, 1), S(0x80004001));
    EXPECT_EQ(UN(RtlUnlockMemoryStreamRegion)((PVOID)0x1000, 5, 6, 0), S(0x80004001));
    EXPECT_EQ(UN(RtlReleaseMemoryStream)(NULL), 0);
    EXPECT_EQ(UN(RtlReleaseMemoryStream)((PVOID)0x1000), 0);
    if (UN(RtlAddRefMemoryStream)) EXPECT_EQ(UN(RtlAddRefMemoryStream)(NULL), 0);
}

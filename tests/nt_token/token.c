#include "t.h"
#include <stdlib.h>

UDECL(NTSTATUS, NtOpenProcessToken, (HANDLE, ACCESS_MASK, PHANDLE));
UDECL(NTSTATUS, NtOpenThreadToken, (HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE));

#define TS(x) ((NTSTATUS)(x))
#define NTK_APIS() REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtQueryInformationToken))
_Static_assert(sizeof(TOKEN_USER) == 16 && offsetof(TOKEN_GROUPS,Groups) == 8, "x64 token SID layouts");
_Static_assert(offsetof(TOKEN_PRIVILEGES,Privileges) == 4 && sizeof(LUID_AND_ATTRIBUTES) == 12, "privilege layout");
_Static_assert(sizeof(TOKEN_STATISTICS) == 56 && sizeof(SECURITY_QUALITY_OF_SERVICE) == 12, "token/QoS layout");

static BOOL ntk_untouched(const BYTE *p, SIZE_T n)
{
    for (SIZE_T i = 0; i < n; i++) if (p[i] != 0xa5) return FALSE;
    return TRUE;
}

static BOOL ntk_open(ACCESS_MASK access, HANDLE *h)
{
    NTSTATUS st = UN(NtOpenProcessToken)(GetCurrentProcess(),access,h);
    if (st == TS(0xc0000022)) {
        t_skip("own token access 0x%lx denied by security policy",access);
        return FALSE;
    }
    EXPECT_EQ(st,0);
    if (st != 0) return FALSE;
    CHECK(*h != NULL);
    return *h != NULL;
}

static BOOL ntk_span(const void *base, ULONG length, const void *p, SIZE_T bytes)
{
    ULONG_PTR b = (ULONG_PTR)base, v = (ULONG_PTR)p;
    BOOL ok = v >= b && v-b <= length && bytes <= length-(v-b);
    CHECK(ok);
    return ok;
}

static void ntk_sid(const void *base, ULONG length, PSID p)
{
    if (!ntk_span(base,length,p,8)) return;
    SID *sid = p;
    EXPECT_EQ(sid->Revision,1); CHECK(sid->SubAuthorityCount <= 15);
    ntk_span(base,length,p,8+4*sid->SubAuthorityCount);
}

/* Each information class independently exercises 0, 1, exact-1 and exact bytes.
 * Token contents are environment-dependent; only structural contracts are hard. */
static void ntk_query(TOKEN_INFORMATION_CLASS cls)
{
    HANDLE h = NULL; ULONG n = 0, got = 0; BYTE *buffer = NULL; NTSTATUS st;
    NTK_APIS();
    if (!ntk_open(TOKEN_QUERY,&h)) return;
    st = UN(NtQueryInformationToken)(h,cls,NULL,0,&n);
    EXPECT_EQ(st,TS(0xc0000023));
    CHECK(n > 0 && n <= 1024*1024);
    if (st != TS(0xc0000023) || !n || n > 1024*1024) goto done;
    buffer = malloc(n+16); CHECK(buffer != NULL); if (!buffer) goto done;
    memset(buffer,0xa5,n+16);
    if (n > 1) {
        st = UN(NtQueryInformationToken)(h,cls,buffer,1,&got);
        EXPECT_EQ(st,TS(0xc0000023)); EXPECT_EQ(got,n);
        CHECK(ntk_untouched(buffer,n+16));
        memset(buffer,0xa5,n+16);
        st = UN(NtQueryInformationToken)(h,cls,buffer,n-1,&got);
        EXPECT_EQ(st,TS(0xc0000023)); EXPECT_EQ(got,n);
        CHECK(ntk_untouched(buffer,n+16));
    }
    memset(buffer,0xa5,n+16);
    st = UN(NtQueryInformationToken)(h,cls,buffer,n,&got);
    EXPECT_EQ(st,0); if (st != 0) goto done;
    EXPECT_EQ(got,n);
    for (unsigned i = 0; i < 16; i++) EXPECT_EQ(buffer[n+i],0xa5);
    switch (cls) {
    case TokenUser:
        if (ntk_span(buffer,n,buffer,sizeof(TOKEN_USER))) ntk_sid(buffer,n,((TOKEN_USER *)buffer)->User.Sid);
        break;
    case TokenOwner:
        if (ntk_span(buffer,n,buffer,sizeof(TOKEN_OWNER))) ntk_sid(buffer,n,((TOKEN_OWNER *)buffer)->Owner);
        break;
    case TokenPrimaryGroup:
        if (ntk_span(buffer,n,buffer,sizeof(TOKEN_PRIMARY_GROUP))) ntk_sid(buffer,n,((TOKEN_PRIMARY_GROUP *)buffer)->PrimaryGroup);
        break;
    case TokenIntegrityLevel:
        if (ntk_span(buffer,n,buffer,sizeof(TOKEN_MANDATORY_LABEL))) ntk_sid(buffer,n,((TOKEN_MANDATORY_LABEL *)buffer)->Label.Sid);
        break;
    case TokenGroups:
    case TokenRestrictedSids: {
        TOKEN_GROUPS *g = (TOKEN_GROUPS *)buffer;
        if (!ntk_span(buffer,n,g,offsetof(TOKEN_GROUPS,Groups))) break;
        CHECK(g->GroupCount <= n/sizeof(SID_AND_ATTRIBUTES));
        if (g->GroupCount > n/sizeof(SID_AND_ATTRIBUTES)) break;
        if (!ntk_span(buffer,n,g->Groups,g->GroupCount*sizeof(SID_AND_ATTRIBUTES))) break;
        for (DWORD i = 0; i < g->GroupCount; i++) ntk_sid(buffer,n,g->Groups[i].Sid);
        break;
    }
    case TokenPrivileges: {
        TOKEN_PRIVILEGES *p = (TOKEN_PRIVILEGES *)buffer;
        if (!ntk_span(buffer,n,p,sizeof(DWORD))) break;
        CHECK(p->PrivilegeCount <= n/sizeof(LUID_AND_ATTRIBUTES));
        if (p->PrivilegeCount <= n/sizeof(LUID_AND_ATTRIBUTES))
            ntk_span(buffer,n,p->Privileges,p->PrivilegeCount*sizeof(LUID_AND_ATTRIBUTES));
        break;
    }
    case TokenDefaultDacl: {
        TOKEN_DEFAULT_DACL *d = (TOKEN_DEFAULT_DACL *)buffer;
        if (!ntk_span(buffer,n,d,sizeof *d)) break;
        if (d->DefaultDacl && ntk_span(buffer,n,d->DefaultDacl,sizeof(ACL)))
            ntk_span(buffer,n,d->DefaultDacl,d->DefaultDacl->AclSize);
        break;
    }
    case TokenType:
        EXPECT_EQ(n,sizeof(TOKEN_TYPE)); if (n >= sizeof(TOKEN_TYPE)) EXPECT_EQ(*(TOKEN_TYPE *)buffer,TokenPrimary);
        break;
    case TokenStatistics:
        EXPECT_EQ(n,sizeof(TOKEN_STATISTICS));
        if (n >= sizeof(TOKEN_STATISTICS)) EXPECT_EQ(((TOKEN_STATISTICS *)buffer)->TokenType,TokenPrimary);
        break;
    case TokenHasRestrictions:
        EXPECT_EQ(n,1); CHECK(buffer[0] <= 1);
        break;
    case TokenVirtualizationAllowed:
    case TokenVirtualizationEnabled:
    case TokenUIAccess:
        EXPECT_EQ(n,sizeof(DWORD));
        if (n >= sizeof(DWORD)) CHECK(*(DWORD *)buffer <= 1);
        break;
    case TokenSessionId:
    case TokenElevationType:
    case TokenMandatoryPolicy:
        EXPECT_EQ(n,sizeof(DWORD));
        t_note("class %u size %lu value byte 0x%02x",cls,n,buffer[0]);
        break;
    default:
        t_note("class %u size %lu value byte 0x%02x",cls,n,buffer[0]);
        break;
    }
done:
    free(buffer); CloseHandle(h);
}

#define NTK_QUERY(name, cls) TEST(nttoken_query_##name) { ntk_query(cls); }
NTK_QUERY(user, TokenUser)
NTK_QUERY(groups, TokenGroups)
NTK_QUERY(privileges, TokenPrivileges)
NTK_QUERY(owner, TokenOwner)
NTK_QUERY(primary_group, TokenPrimaryGroup)
NTK_QUERY(default_dacl, TokenDefaultDacl)
NTK_QUERY(type, TokenType)
NTK_QUERY(statistics, TokenStatistics)
NTK_QUERY(restricted_sids, TokenRestrictedSids)
NTK_QUERY(session_id, TokenSessionId)
NTK_QUERY(elevation_type, TokenElevationType)
NTK_QUERY(has_restrictions, TokenHasRestrictions)
NTK_QUERY(virtualization_allowed, TokenVirtualizationAllowed)
NTK_QUERY(virtualization_enabled, TokenVirtualizationEnabled)
NTK_QUERY(integrity, TokenIntegrityLevel)
NTK_QUERY(ui_access, TokenUIAccess)
NTK_QUERY(mandatory_policy, TokenMandatoryPolicy)

TEST(nttoken_open_process_query)
{
    HANDLE h = NULL; REQUIRE(UN(NtOpenProcessToken));
    if (!ntk_open(TOKEN_QUERY,&h)) return;
    DWORD flags = 0; CHECK(GetHandleInformation(h,&flags)); EXPECT_EQ(flags & HANDLE_FLAG_INHERIT,0); CloseHandle(h);
}

/* New kernel32-created threads start without an impersonation token. */
typedef struct { BOOLEAN self; NTSTATUS status; HANDLE token; } ntk_thread_result;
static DWORD WINAPI ntk_thread(void *arg)
{
    ntk_thread_result *r = arg;
    r->status = UN(NtOpenThreadToken)(GetCurrentThread(),TOKEN_QUERY,r->self,&r->token);
    return 0;
}
CHILD(nttoken_fresh_thread)
{
    ntk_thread_result r = {argc > 1 && argv[1][0] == '1', TS(0xdeadbeef), NULL}; DWORD id;
    if (!UN(NtOpenThreadToken)) return 2;
    HANDLE thread = CreateThread(NULL,0,ntk_thread,&r,0,&id);
    if (!thread) return 3;
    DWORD wait = WaitForSingleObject(thread,30000);
    if (wait != WAIT_OBJECT_0) { CloseHandle(thread); return 4; }
    t_note("fresh thread self=%u status=0x%08lx token=%p",r.self,r.status,r.token);
    BOOL ok = r.status == TS(0xc000007c) && r.token == NULL;
    if (r.status == 0 && r.token) CloseHandle(r.token);
    CloseHandle(thread);
    return ok ? 0 : 5;
}
TEST(nttoken_thread_no_token_as_thread) { REQUIRE(UN(NtOpenThreadToken)); EXPECT_EQ(t_run_child("nttoken_fresh_thread","0",35000),0); }
TEST(nttoken_thread_no_token_as_self) { REQUIRE(UN(NtOpenThreadToken)); EXPECT_EQ(t_run_child("nttoken_fresh_thread","1",35000),0); }

static void ntk_duplicate(TOKEN_TYPE type, BOOLEAN effective, ACCESS_MASK access)
{
    HANDLE original = NULL, duplicate = NULL; TOKEN_TYPE actual = 0; ULONG n = 0;
    SECURITY_QUALITY_OF_SERVICE qos = {sizeof qos,SecurityIdentification,SECURITY_STATIC_TRACKING,FALSE};
    OBJECT_ATTRIBUTES oa; memset(&oa,0,sizeof oa); oa.Length = sizeof oa; oa.SecurityQualityOfService = &qos;
    NTK_APIS(); REQUIRE(UN(NtDuplicateToken));
    if (!ntk_open(TOKEN_QUERY|TOKEN_DUPLICATE,&original)) return;
    NTSTATUS st = UN(NtDuplicateToken)(original,access,&oa,effective,type,&duplicate);
    if (st == TS(0xc0000022)) { t_skip("own token duplication denied by policy"); CloseHandle(original); return; }
    EXPECT_EQ(st,0); if (st != 0) goto done;
    CHECK(duplicate != NULL); if (!duplicate) goto done;
    st = UN(NtQueryInformationToken)(duplicate,TokenType,&actual,sizeof actual,&n);
    EXPECT_EQ(st,0); if (st != 0) goto done;
    EXPECT_EQ(actual,type); EXPECT_EQ(n,sizeof actual);
    if (type == TokenImpersonation) {
        SECURITY_IMPERSONATION_LEVEL level = SecurityAnonymous;
        st = UN(NtQueryInformationToken)(duplicate,TokenImpersonationLevel,&level,sizeof level,&n);
        EXPECT_EQ(st,0); if (st == 0) EXPECT_EQ(level,SecurityIdentification);
    }
    TOKEN_STATISTICS a, b;
    st = UN(NtQueryInformationToken)(original,TokenStatistics,&a,sizeof a,&n);
    EXPECT_EQ(st,0); if (st != 0) goto done;
    st = UN(NtQueryInformationToken)(duplicate,TokenStatistics,&b,sizeof b,&n);
    EXPECT_EQ(st,0); if (st != 0) goto done;
    EXPECT_EQ(a.AuthenticationId.LowPart,b.AuthenticationId.LowPart);
    EXPECT_EQ(a.AuthenticationId.HighPart,b.AuthenticationId.HighPart);
done:
    if (duplicate) CloseHandle(duplicate);
    CloseHandle(original);
}
TEST(nttoken_duplicate_primary) { ntk_duplicate(TokenPrimary,FALSE,TOKEN_QUERY); }
TEST(nttoken_duplicate_impersonation_unattached) { ntk_duplicate(TokenImpersonation,FALSE,TOKEN_QUERY); }
TEST(nttoken_duplicate_effective_only) { ntk_duplicate(TokenPrimary,TRUE,TOKEN_QUERY); }
TEST(nttoken_duplicate_same_access) { ntk_duplicate(TokenPrimary,FALSE,0); }

TEST(nttoken_duplicate_without_duplicate_right)
{
    HANDLE original = NULL, duplicate = NULL;
    REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtDuplicateToken));
    if (!ntk_open(TOKEN_QUERY,&original)) return;
    NTSTATUS st = UN(NtDuplicateToken)(original,TOKEN_QUERY,NULL,FALSE,TokenPrimary,&duplicate);
    EXPECT_EQ(st,TS(0xc0000022)); CHECK(duplicate == NULL);
    if (st == 0 && duplicate) CloseHandle(duplicate);
    CloseHandle(original);
}
TEST(nttoken_duplicate_bad_type)
{
    HANDLE original = NULL, duplicate = NULL;
    REQUIRE(UN(NtOpenProcessToken)); REQUIRE(UN(NtDuplicateToken));
    if (!ntk_open(TOKEN_QUERY|TOKEN_DUPLICATE,&original)) return;
    NTSTATUS st = UN(NtDuplicateToken)(original,TOKEN_QUERY,NULL,FALSE,(TOKEN_TYPE)0,&duplicate);
    EXPECT_EQ(st,TS(0xc000000d)); CHECK(duplicate == NULL);
    if (st == 0 && duplicate) CloseHandle(duplicate);
    CloseHandle(original);
}

TEST(nttoken_query_without_query_right)
{
    HANDLE h = NULL; TOKEN_TYPE type = 0; ULONG n = 0; NTK_APIS();
    if (!ntk_open(TOKEN_DUPLICATE,&h)) return;
    EXPECT_EQ(UN(NtQueryInformationToken)(h,TokenType,&type,sizeof type,&n),TS(0xc0000022));
    CloseHandle(h);
}

TEST(nttoken_query_access_before_size)
{
    HANDLE h = NULL; TOKEN_TYPE type = (TOKEN_TYPE)0x1234; ULONG n = 0xa5a5a5a5; NTK_APIS();
    if (!ntk_open(TOKEN_DUPLICATE,&h)) return;
    EXPECT_EQ(UN(NtQueryInformationToken)(h,TokenType,&type,0,&n),TS(0xc0000022));
    EXPECT_EQ(type,0x1234); EXPECT_EQ(n,0xa5a5a5a5);
    CloseHandle(h);
}

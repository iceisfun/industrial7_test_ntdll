#include "t.h"

UDECL(NTSTATUS, RtlFormatCurrentUserKeyPath, (PUNICODE_STRING));
UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtSetValueKey, (HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryValueKey, (HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtDeleteValueKey, (HANDLE, PUNICODE_STRING));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtEnumerateValueKey, (HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtEnumerateKey, (HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryKey, (HANDLE, ULONG, PVOID, ULONG, PULONG));
#define OK(s) ((NTSTATUS)(s)>=0)
#define SMALL ((NTSTATUS)0xc0000023)
#define OVERFLOW ((NTSTATUS)0x80000005)
#define MISSING ((NTSTATUS)0xc0000034)
#define END ((NTSTATUS)0x8000001a)
typedef struct { HANDLE root,key; BOOL ready; } fixture;
typedef struct { ULONG title,type,length; BYTE data[1024]; } partial;
static UNICODE_STRING us(const WCHAR *s)
{
    UNICODE_STRING u; u.Buffer=(PWSTR)s; u.Length=(USHORT)(wcslen(s)*2); u.MaximumLength=u.Length; return u;
}
static void finish(fixture *f)
{
    if(f->key) { NTSTATUS s=UN(NtDeleteKey)(f->key); EXPECT_EQ(s,0); U(NtClose)(f->key); }
    if(f->root) U(NtClose)(f->root);
}
static void setup(fixture *f,const char *tag)
{
    WCHAR leaf[160]; UNICODE_STRING name,root_path={0}; OBJECT_ATTRIBUTES oa; ULONG disp; NTSTATUS s;
    memset(f,0,sizeof(*f));
    REQUIRE(UN(RtlFormatCurrentUserKeyPath)); REQUIRE(U(RtlFreeUnicodeString)); REQUIRE(UN(NtCreateKey)); REQUIRE(UN(NtOpenKey));
    REQUIRE(UN(NtSetValueKey)); REQUIRE(UN(NtQueryValueKey)); REQUIRE(UN(NtDeleteValueKey));
    REQUIRE(UN(NtDeleteKey)); REQUIRE(UN(NtEnumerateKey)); REQUIRE(UN(NtEnumerateValueKey)); REQUIRE(UN(NtQueryKey));
    REQUIRE(U(NtClose)); REQUIRE(UIN("kernel32.dll", GetCurrentProcessId));
    /* Unlike RtlOpenCurrentUser, this does not fall back to .DEFAULT. */
    s=UN(RtlFormatCurrentUserKeyPath)(&root_path);
    if(!OK(s)) { t_skip("current user path prerequisite %08lx",s); return; }
    InitializeObjectAttributes(&oa,&root_path,OBJ_CASE_INSENSITIVE,NULL,NULL);
    s=UN(NtOpenKey)(&f->root,KEY_CREATE_SUB_KEY,&oa);
    U(RtlFreeUnicodeString)(&root_path);
    if(!OK(s)) { f->root=NULL; t_skip("HKCU root prerequisite %08lx",s); return; }
    swprintf(leaf,160,L"nt_registry_corpus_%lu_%hs",UIN("kernel32.dll", GetCurrentProcessId)(),tag);
    name=us(leaf); InitializeObjectAttributes(&oa,&name,OBJ_CASE_INSENSITIVE,f->root,NULL);
    s=UN(NtCreateKey)(&f->key,KEY_ALL_ACCESS,&oa,0,NULL,REG_OPTION_VOLATILE,&disp);
    if(!OK(s)) { f->key=NULL; t_skip("private key prerequisite %08lx",s); finish(f); return; }
    if(disp!=REG_CREATED_NEW_KEY) { t_skip("private key name already exists; not modifying it"); U(NtClose)(f->key); U(NtClose)(f->root); f->key=f->root=NULL; return; }
    f->ready=TRUE;
}
#define START(tag) fixture f; setup(&f,tag); if(!f.ready) return
static void value_case(const char *tag, const WCHAR *value, ULONG type, const void *data, ULONG size)
{
    UNICODE_STRING name=us(value); partial p; ULONG length=0; NTSTATUS s;
    START(tag);
    s=UN(NtSetValueKey)(f.key,&name,0,type,(void *)data,size); EXPECT_EQ(s,0);
    if(OK(s)) {
        memset(&p,0xcc,sizeof p);
        s=UN(NtQueryValueKey)(f.key,&name,2,&p,sizeof p,&length); EXPECT_EQ(s,0);
        if(OK(s)) { EXPECT_EQ(p.type,type); EXPECT_EQ(p.length,size); EXPECT_EQ(length,12+size); CHECK(!memcmp(p.data,data?data:"",size)); }
        s=UN(NtDeleteValueKey)(f.key,&name); EXPECT_EQ(s,0);
        s=UN(NtQueryValueKey)(f.key,&name,2,&p,sizeof p,&length); EXPECT_EQ(s,MISSING);
    }
    finish(&f);
}
static const DWORD dword=0x1234abcd;
static const ULONGLONG qword=0xfedcba9876543210ULL;
static const BYTE binary[]={0,1,0x80,0xff,0,3,9};
static const WCHAR unicode[]=L"\x03a9\x4e2d\x00e9";
static const WCHAR multi[]=L"one\0\x03a9\0";
#define VALUE(n,v,t,d,s) TEST(nt_registry_value_##n) { value_case(#n,v,t,d,s); }
VALUE(dword,L"dword",REG_DWORD,&dword,4)
VALUE(qword,L"qword",REG_QWORD,&qword,8)
VALUE(binary,L"binary",REG_BINARY,binary,sizeof binary)
VALUE(binary_empty,L"empty",REG_BINARY,NULL,0)
VALUE(none,L"none",REG_NONE,binary,sizeof binary)
VALUE(none_empty,L"none",REG_NONE,NULL,0)
VALUE(sz,L"text",REG_SZ,L"private",16)
VALUE(sz_empty,L"text",REG_SZ,L"",2)
VALUE(unicode,L"\x4e2d\x03a9",REG_SZ,unicode,sizeof unicode)
VALUE(expand,L"expand",REG_EXPAND_SZ,L"%TEMP%",14)
VALUE(multi,L"multi",REG_MULTI_SZ,multi,sizeof multi)
VALUE(default,L"",REG_BINARY,binary,sizeof binary)
VALUE(big_endian,L"be",REG_DWORD_BIG_ENDIAN,binary,4)
VALUE(long_name,L"nt_registry_long_value_name_01234567890123456789",REG_BINARY,binary,1)

static void value_buffer(const char *tag,ULONG cls,int mode)
{
    UNICODE_STRING name=us(L"buffer_\x03a9"); union { ULONGLONG align; BYTE b[512]; } b;
    ULONG needed=0, actual=0, cap; NTSTATUS s;
    START(tag);
    s=UN(NtSetValueKey)(f.key,&name,0,REG_BINARY,(void *)binary,sizeof binary); EXPECT_EQ(s,0);
    if(!OK(s)) goto done;
    s=UN(NtQueryValueKey)(f.key,&name,cls,NULL,0,&needed);
    CHECK(s==SMALL || s==OVERFLOW); CHECK(needed>0); CHECK(needed<=sizeof b);
    if(!needed || needed>sizeof b) goto done;
    cap=mode==0?0:mode==1?1:mode==2?needed-1:mode==3?needed:sizeof b;
    s=UN(NtQueryValueKey)(f.key,&name,cls,&b,cap,&actual);
    EXPECT_EQ(actual,needed);
    if(cap<needed) CHECK(s==SMALL || s==OVERFLOW); else EXPECT_EQ(s,0);
done: finish(&f);
}
#define BUF(n,c,m) TEST(nt_registry_buffer_##n) { value_buffer("buffer_" #n,c,m); }
BUF(basic_zero,0,0) BUF(basic_one,0,1) BUF(basic_short,0,2) BUF(basic_exact,0,3) BUF(basic_large,0,4)
BUF(full_zero,1,0) BUF(full_one,1,1) BUF(full_short,1,2) BUF(full_exact,1,3) BUF(full_large,1,4)
BUF(partial_zero,2,0) BUF(partial_one,2,1) BUF(partial_short,2,2) BUF(partial_exact,2,3) BUF(partial_large,2,4)

static void key_query(const char *tag,ULONG cls)
{
    union { ULONGLONG align; BYTE b[1024]; } b; ULONG size=0,got=0; NTSTATUS s;
    START(tag);
    s=UN(NtQueryKey)(f.key,cls,NULL,0,&size); CHECK(s==SMALL || s==OVERFLOW);
    CHECK(size>0); CHECK(size<=sizeof b);
    if(size && size<=sizeof b) {
        s=UN(NtQueryKey)(f.key,cls,&b,size,&got); EXPECT_EQ(s,0); if(OK(s)) EXPECT_EQ(got,size);
    }
    finish(&f);
}
#define KEYQ(n,c) TEST(nt_registry_query_key_##n) { key_query("key_" #n,c); }
KEYQ(basic,0) KEYQ(node,1) KEYQ(full,2) KEYQ(name,3)

TEST(nt_registry_value_replace)
{
    UNICODE_STRING name=us(L"replace"); partial p; ULONG len; NTSTATUS s;
    START("replace");
    s=UN(NtSetValueKey)(f.key,&name,0,REG_DWORD,(void *)&dword,4); EXPECT_EQ(s,0);
    if(OK(s)) {
        s=UN(NtSetValueKey)(f.key,&name,0,REG_BINARY,(void *)binary,sizeof binary); EXPECT_EQ(s,0);
        if(OK(s)) {
            s=UN(NtQueryValueKey)(f.key,&name,2,&p,sizeof p,&len); EXPECT_EQ(s,0);
            if(OK(s)) { EXPECT_EQ(p.type,REG_BINARY); EXPECT_EQ(p.length,sizeof binary); CHECK(!memcmp(p.data,binary,sizeof binary)); }
        }
    }
    finish(&f);
}
TEST(nt_registry_missing_value)
{
    UNICODE_STRING name=us(L"absent"); partial p; ULONG len;
    START("missing_value");
    EXPECT_EQ(UN(NtQueryValueKey)(f.key,&name,2,&p,sizeof p,&len),MISSING);
    EXPECT_EQ(UN(NtDeleteValueKey)(f.key,&name),MISSING); finish(&f);
}
TEST(nt_registry_empty_enumerations)
{
    BYTE b[512]; ULONG len; START("empty_enumerations");
    EXPECT_EQ(UN(NtEnumerateKey)(f.key,0,0,b,sizeof b,&len),END);
    EXPECT_EQ(UN(NtEnumerateValueKey)(f.key,0,0,b,sizeof b,&len),END); finish(&f);
}
TEST(nt_registry_enumerate_value)
{
    UNICODE_STRING name=us(L"enumerated_\x03a9"); partial p; ULONG len; NTSTATUS s;
    START("enumerate_value");
    s=UN(NtSetValueKey)(f.key,&name,0,REG_BINARY,(void *)binary,sizeof binary); EXPECT_EQ(s,0);
    if(OK(s)) {
        s=UN(NtEnumerateValueKey)(f.key,0,2,&p,sizeof p,&len); EXPECT_EQ(s,0);
        if(OK(s)) { EXPECT_EQ(p.type,REG_BINARY); EXPECT_EQ(p.length,sizeof binary); CHECK(!memcmp(p.data,binary,sizeof binary)); }
        EXPECT_EQ(UN(NtEnumerateValueKey)(f.key,1,2,&p,sizeof p,&len),END);
    }
    finish(&f);
}
TEST(nt_registry_child_create_open_enumerate_delete)
{
    UNICODE_STRING name=us(L"nt_registry_child_\x03a9"); OBJECT_ATTRIBUTES oa; HANDLE child=NULL,opened=NULL;
    ULONG disp,len; BYTE b[512]; NTSTATUS s;
    START("child"); InitializeObjectAttributes(&oa,&name,OBJ_CASE_INSENSITIVE,f.key,NULL);
    s=UN(NtCreateKey)(&child,KEY_ALL_ACCESS,&oa,0,NULL,REG_OPTION_VOLATILE,&disp); EXPECT_EQ(s,0);
    if(OK(s)) {
        EXPECT_EQ(disp,REG_CREATED_NEW_KEY);
        s=UN(NtOpenKey)(&opened,KEY_READ,&oa); EXPECT_EQ(s,0); if(OK(s)) U(NtClose)(opened);
        s=UN(NtEnumerateKey)(f.key,0,0,b,sizeof b,&len); EXPECT_EQ(s,0);
        if(OK(s) && len>=16) { ULONG n; memcpy(&n,b+12,4); EXPECT_EQ(n,name.Length); if(n==name.Length && n<=sizeof b-16) CHECK(!memcmp(b+16,name.Buffer,n)); }
        EXPECT_EQ(UN(NtEnumerateKey)(f.key,1,0,b,sizeof b,&len),END);
        EXPECT_EQ(UN(NtDeleteKey)(child),0); U(NtClose)(child);
        opened=NULL; s=UN(NtOpenKey)(&opened,KEY_READ,&oa); EXPECT_EQ(s,MISSING); if(OK(s)) U(NtClose)(opened);
    }
    finish(&f);
}
TEST(nt_registry_write_access_denied)
{
    UNICODE_STRING empty=us(L""), name=us(L"denied"); OBJECT_ATTRIBUTES oa; HANDLE h=NULL; NTSTATUS s;
    START("access_denied"); InitializeObjectAttributes(&oa,&empty,0,f.key,NULL);
    s=UN(NtOpenKey)(&h,KEY_QUERY_VALUE,&oa); EXPECT_EQ(s,0);
    if(OK(s)) { EXPECT_EQ(UN(NtSetValueKey)(h,&name,0,REG_DWORD,(void *)&dword,4),(NTSTATUS)0xc0000022); U(NtClose)(h); }
    finish(&f);
}
TEST(nt_registry_invalid_value_information_class)
{
    UNICODE_STRING name=us(L"value"); BYTE b[128]; ULONG len; NTSTATUS s;
    START("invalid_class");
    s=UN(NtSetValueKey)(f.key,&name,0,REG_BINARY,(void *)binary,sizeof binary); EXPECT_EQ(s,0);
    if(OK(s)) EXPECT_EQ(UN(NtQueryValueKey)(f.key,&name,99,b,sizeof b,&len),(NTSTATUS)0xc000000d);
    finish(&f);
}

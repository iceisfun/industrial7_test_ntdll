#include "t.h"

UDECL(NTSTATUS, RtlOemStringToUnicodeString, (PUNICODE_STRING, const ANSI_STRING *, BOOLEAN));
UDECL(NTSTATUS, RtlUnicodeStringToOemString, (PANSI_STRING, PCUNICODE_STRING, BOOLEAN));
UDECL(NTSTATUS, RtlMultiByteToUnicodeN, (PWSTR, ULONG, PULONG, PCSTR, ULONG));
UDECL(NTSTATUS, RtlOemToUnicodeN, (PWSTR, ULONG, PULONG, PCSTR, ULONG));
UDECL(NTSTATUS, RtlUnicodeToMultiByteN, (PCHAR, ULONG, PULONG, PCWSTR, ULONG));
UDECL(NTSTATUS, RtlUnicodeToOemN, (PCHAR, ULONG, PULONG, PCWSTR, ULONG));
UDECL(NTSTATUS, RtlMultiByteToUnicodeSize, (PULONG, PCSTR, ULONG));
UDECL(NTSTATUS, RtlUnicodeToMultiByteSize, (PULONG, PCWSTR, ULONG));
UDECL(NTSTATUS, RtlUTF8ToUnicodeN, (PWSTR, ULONG, PULONG, PCSTR, ULONG));
UDECL(NTSTATUS, RtlUnicodeToUTF8N, (PCHAR, ULONG, PULONG, PCWSTR, ULONG));

#define SMALL ((NTSTATUS)0xc0000023)
#define OVERFLOW ((NTSTATUS)0x80000005)

/* All active ANSI/OEM code pages agree on these ASCII values, including NUL. */
static void raw_case(unsigned kind, ULONG cap, BOOL no_count)
{
    char a[16]; WCHAR w[16]; ULONG count=0x55555555;
    const char input[]={'A',0,'z','7'}; const WCHAR wide[]={'A',0,'z','7'};
    NTSTATUS st; unsigned n;
    memset(a,0x55,sizeof a); for(unsigned i=0;i<16;++i) w[i]=0x5555;
    if(kind<2) {
        n=cap/2<4?cap/2:4;
        if(kind==0) { REQUIRE(UN(RtlMultiByteToUnicodeN)); st=UN(RtlMultiByteToUnicodeN)(w,cap,no_count?NULL:&count,input,4); }
        else { REQUIRE(UN(RtlOemToUnicodeN)); st=UN(RtlOemToUnicodeN)(w,cap,no_count?NULL:&count,input,4); }
        EXPECT_EQ(st,kind==1 && n<4?OVERFLOW:0);
        if(!no_count) EXPECT_EQ(count,n*2);
        CHECK(!memcmp(w,wide,n*2)); EXPECT_EQ(w[n],0x5555);
    } else {
        n=cap<4?cap:4;
        if(kind==2) { REQUIRE(UN(RtlUnicodeToMultiByteN)); st=UN(RtlUnicodeToMultiByteN)(a,cap,no_count?NULL:&count,wide,8); }
        else { REQUIRE(UN(RtlUnicodeToOemN)); st=UN(RtlUnicodeToOemN)(a,cap,no_count?NULL:&count,wide,8); }
        EXPECT_EQ(st,kind==3 && n<4?OVERFLOW:0);
        if(!no_count) EXPECT_EQ(count,n);
        CHECK(!memcmp(a,input,n)); EXPECT_EQ(a[n],0x55);
    }
}
#define RAW(n,k,c,z) TEST(rtl_conversion_raw_##n) { raw_case(k,c,z); }
RAW(ansi_zero,0,0,0) RAW(ansi_one,0,1,0) RAW(ansi_short,0,6,0) RAW(ansi_odd,0,7,0) RAW(ansi_exact,0,8,0) RAW(ansi_spare,0,10,0) RAW(ansi_no_count,0,8,1)
RAW(oem_zero,1,0,0) RAW(oem_one,1,1,0) RAW(oem_short,1,6,0) RAW(oem_odd,1,7,0) RAW(oem_exact,1,8,0) RAW(oem_spare,1,10,0) RAW(oem_no_count,1,8,1)
RAW(to_ansi_zero,2,0,0) RAW(to_ansi_one,2,1,0) RAW(to_ansi_short,2,3,0) RAW(to_ansi_exact,2,4,0) RAW(to_ansi_spare,2,6,0) RAW(to_ansi_no_count,2,4,1)
RAW(to_oem_zero,3,0,0) RAW(to_oem_one,3,1,0) RAW(to_oem_short,3,3,0) RAW(to_oem_exact,3,4,0) RAW(to_oem_spare,3,6,0) RAW(to_oem_no_count,3,4,1)

static void size_case(ULONG len)
{
    ULONG a=0x55555555,w=0x55555555;
    REQUIRE(UN(RtlMultiByteToUnicodeSize)); REQUIRE(UN(RtlUnicodeToMultiByteSize));
    EXPECT_EQ(UN(RtlMultiByteToUnicodeSize)(&w,"a\0z7",len),0); EXPECT_EQ(w,len*2);
    EXPECT_EQ(UN(RtlUnicodeToMultiByteSize)(&a,L"a\0z7",len*2),0); EXPECT_EQ(a,len);
}
TEST(rtl_conversion_size_empty) { size_case(0); }
TEST(rtl_conversion_size_one) { size_case(1); }
TEST(rtl_conversion_size_embedded_nul) { size_case(4); }

static void descriptor_case(unsigned kind, USHORT cap, BOOL allocate, BOOL empty)
{
    char a[16]; WCHAR w[16];
    ANSI_STRING as={empty?0:3,3,"a\0z"}, ad={0,cap,allocate?NULL:a};
    UNICODE_STRING ws={empty?0:6,6,L"a\0z"}, wd={0,cap,allocate?NULL:w};
    NTSTATUS st; unsigned len=empty?0:3;
    memset(a,0x55,sizeof a); for(unsigned i=0;i<16;++i) w[i]=0x5555;
    if(kind<2) {
        REQUIRE(U(RtlFreeUnicodeString));
        if(kind==0) { REQUIRE(U(RtlAnsiStringToUnicodeString)); st=U(RtlAnsiStringToUnicodeString)(&wd,&as,allocate); }
        else { REQUIRE(UN(RtlOemStringToUnicodeString)); st=UN(RtlOemStringToUnicodeString)(&wd,&as,allocate); }
        EXPECT_EQ(st,!allocate && cap<len*2+2?OVERFLOW:0); EXPECT_EQ(wd.Length,len*2);
        EXPECT_EQ(wd.MaximumLength,allocate?len*2+2:cap);
        if(st==0) { CHECK(wd.Buffer!=NULL); if(wd.Buffer) { CHECK(!memcmp(wd.Buffer,ws.Buffer,len*2)); EXPECT_EQ(wd.Buffer[len],0); } }
        else EXPECT_EQ(w[0],0x5555);
        if(allocate && wd.Buffer) { U(RtlFreeUnicodeString)(&wd); EXPECT_EQ(wd.Buffer,NULL); EXPECT_EQ(wd.Length,0); EXPECT_EQ(wd.MaximumLength,0); }
    } else {
        if(kind==2) { REQUIRE(U(RtlFreeAnsiString)); REQUIRE(U(RtlUnicodeStringToAnsiString)); st=U(RtlUnicodeStringToAnsiString)(&ad,&ws,allocate); }
        else { REQUIRE(U(RtlFreeOemString)); REQUIRE(UN(RtlUnicodeStringToOemString)); st=UN(RtlUnicodeStringToOemString)(&ad,&ws,allocate); }
        EXPECT_EQ(st,!allocate && cap<len+1?OVERFLOW:0);
        unsigned written=!allocate && kind==2 && cap && cap<=len?cap-1:len;
        EXPECT_EQ(ad.Length,written); EXPECT_EQ(ad.MaximumLength,allocate?len+1:cap);
        if(st==0 || (kind==2 && cap)) { CHECK(ad.Buffer!=NULL); if(ad.Buffer) { CHECK(!memcmp(ad.Buffer,as.Buffer,written)); EXPECT_EQ(ad.Buffer[written],0); } }
        else EXPECT_EQ(a[0],0x55);
        if(allocate && ad.Buffer) {
            if(kind==2) { U(RtlFreeAnsiString)(&ad); EXPECT_EQ(ad.Buffer,NULL); EXPECT_EQ(ad.Length,0); EXPECT_EQ(ad.MaximumLength,0); }
            else { U(RtlFreeOemString)(&ad); /* Windows does not clear this descriptor. */ }
        }
    }
}
#define DESC(n,k,c,a,e) TEST(rtl_conversion_descriptor_##n) { descriptor_case(k,c,a,e); }
DESC(ansi_zero,0,0,0,0) DESC(ansi_exact_data,0,6,0,0) DESC(ansi_exact_term,0,8,0,0) DESC(ansi_allocate,0,0,1,0) DESC(ansi_empty,0,2,0,1)
DESC(oem_zero,1,0,0,0) DESC(oem_exact_data,1,6,0,0) DESC(oem_exact_term,1,8,0,0) DESC(oem_allocate,1,0,1,0) DESC(oem_empty,1,2,0,1)
DESC(to_ansi_zero,2,0,0,0) DESC(to_ansi_one,2,1,0,0) DESC(to_ansi_exact_data,2,3,0,0) DESC(to_ansi_exact_term,2,4,0,0) DESC(to_ansi_allocate,2,0,1,0) DESC(to_ansi_empty,2,1,0,1)
DESC(to_oem_zero,3,0,0,0) DESC(to_oem_exact_data,3,3,0,0) DESC(to_oem_exact_term,3,4,0,0) DESC(to_oem_allocate,3,0,1,0) DESC(to_oem_empty,3,1,0,1)

/* UTF-8 arithmetic and surrogate assembly are explicit in the Windows bodies. */
static void utf_case(unsigned v, BOOL encode, BOOL query)
{
    static const char *bytes[]={"A\0z","\xc2\xa2","\xe2\x82\xac","\xf0\x9f\x98\x80"};
    static const WCHAR *wide[]={L"A\0z",L"\x00a2",L"\x20ac",L"\xd83d\xde00"};
    static const ULONG bn[]={3,2,3,4}, wn[]={6,2,2,4};
    char a[16]; WCHAR w[16]; ULONG count=0x55555555;
    memset(a,0x55,sizeof a); for(unsigned i=0;i<16;++i) w[i]=0x5555;
    if(encode) {
        REQUIRE(UN(RtlUnicodeToUTF8N));
        EXPECT_EQ(UN(RtlUnicodeToUTF8N)(query?NULL:a,query?0:bn[v],&count,wide[v],wn[v]),0);
        EXPECT_EQ(count,bn[v]); if(!query) { CHECK(!memcmp(a,bytes[v],bn[v])); EXPECT_EQ(a[bn[v]],0x55); }
    } else {
        REQUIRE(UN(RtlUTF8ToUnicodeN));
        EXPECT_EQ(UN(RtlUTF8ToUnicodeN)(query?NULL:w,query?0:wn[v],&count,bytes[v],bn[v]),0);
        EXPECT_EQ(count,wn[v]); if(!query) { CHECK(!memcmp(w,wide[v],wn[v])); EXPECT_EQ(w[wn[v]/2],0x5555); }
    }
}
#define UTF(n,v,e,q) TEST(rtl_conversion_utf_##n) { utf_case(v,e,q); }
UTF(ascii_decode,0,0,0) UTF(two_decode,1,0,0) UTF(three_decode,2,0,0) UTF(pair_decode,3,0,0)
UTF(ascii_encode,0,1,0) UTF(two_encode,1,1,0) UTF(three_encode,2,1,0) UTF(pair_encode,3,1,0)
UTF(ascii_decode_size,0,0,1) UTF(two_decode_size,1,0,1) UTF(three_decode_size,2,0,1) UTF(pair_decode_size,3,0,1)
UTF(ascii_encode_size,0,1,1) UTF(two_encode_size,1,1,1) UTF(three_encode_size,2,1,1) UTF(pair_encode_size,3,1,1)

TEST(rtl_conversion_utf_decode_short)
{
    WCHAR w[4]={0x5555,0x5555,0x5555,0x5555}; ULONG n=99;
    REQUIRE(UN(RtlUTF8ToUnicodeN));
    EXPECT_EQ(UN(RtlUTF8ToUnicodeN)(w,3,&n,"AB",2),SMALL); EXPECT_EQ(n,2); EXPECT_EQ(w[0],'A'); EXPECT_EQ(w[1],0x5555);
}
TEST(rtl_conversion_utf_encode_short)
{
    char a[8]; ULONG n=99; memset(a,0x55,sizeof a);
    REQUIRE(UN(RtlUnicodeToUTF8N));
    EXPECT_EQ(UN(RtlUnicodeToUTF8N)(a,2,&n,L"A\x20ac",4),SMALL); EXPECT_EQ(n,1); EXPECT_EQ(a[0],'A'); EXPECT_EQ(a[1],0x55);
}
TEST(rtl_conversion_utf_odd_source)
{
    char a[8]; ULONG n=99; memset(a,0x55,sizeof a);
    REQUIRE(UN(RtlUnicodeToUTF8N));
    EXPECT_EQ(UN(RtlUnicodeToUTF8N)(a,8,&n,L"AB",3),(NTSTATUS)0xc00000f3); EXPECT_EQ(n,99); EXPECT_EQ(a[0],0x55);
}
TEST(rtl_conversion_utf_unpaired_surrogate)
{
    char a[8]; ULONG n=99; memset(a,0x55,sizeof a);
    REQUIRE(UN(RtlUnicodeToUTF8N));
    EXPECT_EQ(UN(RtlUnicodeToUTF8N)(a,8,&n,L"\xd800",2),0x107); EXPECT_EQ(n,3); CHECK(!memcmp(a,"\xef\xbf\xbd",3)); EXPECT_EQ(a[3],0x55);
}
TEST(rtl_conversion_utf_incomplete_sequence)
{
    WCHAR w[4]={0x5555,0x5555,0x5555,0x5555}; ULONG n=99;
    REQUIRE(UN(RtlUTF8ToUnicodeN));
    EXPECT_EQ(UN(RtlUTF8ToUnicodeN)(w,8,&n,"\xe2\x82",2),0x107); EXPECT_EQ(n,2); EXPECT_EQ(w[0],0xfffd); EXPECT_EQ(w[1],0x5555);
}

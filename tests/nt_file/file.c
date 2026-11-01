#include "t.h"

UDECL(BOOLEAN, RtlDosPathNameToNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, void *));
UDECL(NTSTATUS, NtFlushBuffersFile, (HANDLE, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtReadFile, (HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtWriteFile, (HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(NTSTATUS, NtQueryDirectoryFile, (HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN));
UDECL(NTSTATUS, NtQueryVolumeInformationFile, (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FS_INFORMATION_CLASS));

#define OK(s) ((NTSTATUS)(s) >= 0)
#define SYNC (FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE)
#define ACCESS (FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
typedef struct { HANDLE h; UNICODE_STRING path; WCHAR dos[MAX_PATH]; BOOL ready; } fixture;
static void finish(fixture *f)
{
    if (f->h) { U(NtClose)(f->h); f->h = NULL; }
    if (f->path.Buffer) { U(RtlFreeUnicodeString)(&f->path); f->path.Buffer = NULL; }
    if (f->ready) CHECK(UIN("kernel32.dll", DeleteFileW)(f->dos));
}
static void setup(fixture *f, const char *tag)
{
    char path[MAX_PATH], leaf[100]; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; NTSTATUS s;
    memset(f, 0, sizeof(*f));
    REQUIRE(U(NtCreateFile)); REQUIRE(U(NtOpenFile)); REQUIRE(UN(NtReadFile)); REQUIRE(UN(NtWriteFile));
    REQUIRE(U(NtQueryInformationFile)); REQUIRE(U(NtSetInformationFile)); REQUIRE(U(NtClose));
    REQUIRE(UN(NtQueryDirectoryFile)); REQUIRE(UN(NtQueryVolumeInformationFile)); REQUIRE(UN(NtFlushBuffersFile));
    REQUIRE(UN(RtlDosPathNameToNtPathName_U)); REQUIRE(U(RtlFreeUnicodeString));
    REQUIRE(UIN("kernel32.dll", MultiByteToWideChar)); REQUIRE(UIN("kernel32.dll", GetCurrentProcessId)); REQUIRE(UIN("kernel32.dll", DeleteFileW));
    snprintf(leaf, sizeof leaf, "nt_file_%lu_%s.tmp", UIN("kernel32.dll", GetCurrentProcessId)(), tag);
    t_tmpfile(path, sizeof path, leaf);
    if (!UIN("kernel32.dll", MultiByteToWideChar)(CP_ACP, 0, path, -1, f->dos, MAX_PATH) ||
        !UN(RtlDosPathNameToNtPathName_U)(f->dos, &f->path, NULL, NULL)) { t_skip("scratch path conversion"); return; }
    InitializeObjectAttributes(&oa, &f->path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = U(NtCreateFile)(&f->h, ACCESS, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, SYNC, NULL, 0);
    if (!OK(s)) { f->h = NULL; t_skip("private scratch create status=%08lx", s); finish(f); return; }
    f->ready = TRUE;
}
#define START(tag) fixture f; setup(&f, tag); if (!f.ready) return
static void disposition(const char *tag, ULONG disp, NTSTATUS expected, ULONG_PTR action)
{
    HANDLE h = NULL; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io = {0}; NTSTATUS s;
    START(tag);
    InitializeObjectAttributes(&oa, &f.path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = U(NtCreateFile)(&h, ACCESS, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, disp, SYNC, NULL, 0);
    EXPECT_EQ(s, expected);
    if (OK(s)) { CHECK(h != NULL); EXPECT_EQ(io.Information, action); U(NtClose)(h); }
    finish(&f);
}
#define DISP(n,d,s,a) TEST(nt_file_create_##n) { disposition(#n,d,(NTSTATUS)(s),a); }
DISP(collision, FILE_CREATE, 0xc0000035, 0)
DISP(open, FILE_OPEN, 0, FILE_OPENED)
DISP(open_if, FILE_OPEN_IF, 0, FILE_OPENED)
DISP(overwrite, FILE_OVERWRITE, 0, FILE_OVERWRITTEN)
DISP(overwrite_if, FILE_OVERWRITE_IF, 0, FILE_OVERWRITTEN)
DISP(supersede, FILE_SUPERSEDE, 0, FILE_SUPERSEDED)

static void open_access(const char *tag, ACCESS_MASK access)
{
    HANDLE h = NULL; IO_STATUS_BLOCK io; OBJECT_ATTRIBUTES oa; NTSTATUS s;
    START(tag);
    InitializeObjectAttributes(&oa, &f.path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    s = U(NtOpenFile)(&h, access | SYNCHRONIZE, &oa, &io,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, SYNC);
    EXPECT_EQ(s, 0);
    if (OK(s)) { CHECK(h != NULL); EXPECT_EQ(io.Information, FILE_OPENED); U(NtClose)(h); }
    finish(&f);
}
#define OPEN(n,a) TEST(nt_file_open_##n) { open_access("open_" #n,a); }
OPEN(read,FILE_READ_DATA) OPEN(write,FILE_WRITE_DATA) OPEN(attributes,FILE_READ_ATTRIBUTES)
OPEN(append,FILE_APPEND_DATA) OPEN(delete,DELETE) OPEN(read_write,FILE_READ_DATA|FILE_WRITE_DATA)

static void roundtrip(const char *tag, ULONG count, ULONG offset)
{
    BYTE src[4096], dst[4096]; LARGE_INTEGER pos; IO_STATUS_BLOCK io; NTSTATUS s;
    START(tag);
    for (ULONG i=0;i<count;i++) src[i]=(BYTE)(i*37+11);
    pos.QuadPart=offset;
    s=UN(NtWriteFile)(f.h,NULL,NULL,NULL,&io,src,count,&pos,NULL);
    EXPECT_EQ(s,0);
    if (OK(s)) {
        EXPECT_EQ(io.Status,0); EXPECT_EQ(io.Information,count);
        memset(dst,0xcc,sizeof dst); pos.QuadPart=offset;
        s=UN(NtReadFile)(f.h,NULL,NULL,NULL,&io,dst,count,&pos,NULL);
        EXPECT_EQ(s,0);
        if (OK(s)) { EXPECT_EQ(io.Status,0); EXPECT_EQ(io.Information,count); CHECK(!memcmp(src,dst,count)); }
    }
    finish(&f);
}
#define IO(n,c,o) TEST(nt_file_io_##n) { roundtrip("io_" #n,c,o); }
IO(byte,1,0) IO(two,2,0) IO(odd,17,0) IO(sector,512,0) IO(page,4096,0)
IO(offset_one,23,1) IO(offset_odd,43,17) IO(offset_sector,127,512) IO(offset_page,513,4096) IO(offset_tail,31,60000)

typedef struct { LARGE_INTEGER allocation, eof; ULONG links; BOOLEAN deleting, directory; } standard_info;
static void information(const char *tag, FILE_INFORMATION_CLASS cls, ULONG size)
{
    union { ULONGLONG align; BYTE bytes[1024]; } b; IO_STATUS_BLOCK io; NTSTATUS s;
    START(tag);
    memset(&b,0xcc,sizeof b);
    s=U(NtQueryInformationFile)(f.h,&io,&b,size,cls);
    EXPECT_EQ(s,0);
    if (OK(s)) {
        CHECK(io.Information>0); CHECK(io.Information<=size);
        if (cls==FileStandardInformation) { standard_info *v=(void *)&b; EXPECT_EQ(v->eof.QuadPart,0); CHECK(!v->directory); CHECK(!v->deleting); }
        if (cls==FilePositionInformation) EXPECT_EQ(((LARGE_INTEGER *)&b)->QuadPart,0);
    }
    finish(&f);
}
#define INFO(n,c,s) TEST(nt_file_query_##n) { information("query_" #n,c,s); }
INFO(basic,FileBasicInformation,40) INFO(standard,FileStandardInformation,24)
INFO(position,FilePositionInformation,8) INFO(internal,FileInternalInformation,8)
INFO(name,FileNameInformation,1024) INFO(all,FileAllInformation,1024)

static void eof_case(const char *tag, LONGLONG length)
{
    LARGE_INTEGER eof; standard_info st; IO_STATUS_BLOCK io; NTSTATUS s;
    START(tag);
    eof.QuadPart=length;
    s=U(NtSetInformationFile)(f.h,&io,&eof,sizeof eof,FileEndOfFileInformation);
    EXPECT_EQ(s,0);
    if (OK(s)) {
        s=U(NtQueryInformationFile)(f.h,&io,&st,sizeof st,FileStandardInformation);
        EXPECT_EQ(s,0); if (OK(s)) EXPECT_EQ(st.eof.QuadPart,length);
    }
    finish(&f);
}
#define EOFCASE(n,v) TEST(nt_file_eof_##n) { eof_case("eof_" #n,v); }
EOFCASE(zero,0) EOFCASE(byte,1) EOFCASE(odd,37) EOFCASE(sector,512) EOFCASE(page,4096) EOFCASE(limit,65536)

static void volume_case(const char *tag, FS_INFORMATION_CLASS cls)
{
    union { ULONGLONG align; BYTE bytes[1024]; } b; IO_STATUS_BLOCK io; NTSTATUS s;
    START(tag);
    s=UN(NtQueryVolumeInformationFile)(f.h,&io,&b,sizeof b,cls);
    EXPECT_EQ(s,0); if (OK(s)) { CHECK(io.Information>0); CHECK(io.Information<=sizeof b); }
    finish(&f);
}
#define VOL(n,c) TEST(nt_file_volume_##n) { volume_case("volume_" #n,c); }
VOL(size,FileFsSizeInformation) VOL(device,FileFsDeviceInformation)
VOL(attributes,FileFsAttributeInformation) VOL(volume,FileFsVolumeInformation)

static void directory_case(const char *tag, FILE_INFORMATION_CLASS cls)
{
    HANDLE dir=NULL; UNICODE_STRING p={0}, filter; WCHAR dos[MAX_PATH];
    OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; NTSTATUS s; BYTE data[4096];
    START(tag);
    if (!UIN("kernel32.dll", MultiByteToWideChar)(CP_ACP,0,t_tmpdir(),-1,dos,MAX_PATH) ||
        !UN(RtlDosPathNameToNtPathName_U)(dos,&p,NULL,NULL)) { t_skip("directory conversion"); finish(&f); return; }
    InitializeObjectAttributes(&oa,&p,OBJ_CASE_INSENSITIVE,NULL,NULL);
    s=U(NtOpenFile)(&dir,FILE_LIST_DIRECTORY|SYNCHRONIZE,&oa,&io,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT);
    if (!OK(s)) { t_skip("scratch directory open %08lx",s); goto done; }
    WCHAR *leaf=wcsrchr(f.dos,L'\\'); leaf=leaf?leaf+1:f.dos;
    filter.Buffer=leaf; filter.Length=(USHORT)(wcslen(leaf)*2); filter.MaximumLength=filter.Length;
    s=UN(NtQueryDirectoryFile)(dir,NULL,NULL,NULL,&io,data,sizeof data,cls,TRUE,&filter,TRUE);
    EXPECT_EQ(s,0);
    if (OK(s)) { CHECK(io.Information>0); CHECK(io.Information<=sizeof data); }
    s=UN(NtQueryDirectoryFile)(dir,NULL,NULL,NULL,&io,data,sizeof data,cls,TRUE,NULL,FALSE);
    EXPECT_EQ(s,(NTSTATUS)0x80000006);
done:
    if (dir) U(NtClose)(dir);
    U(RtlFreeUnicodeString)(&p); finish(&f);
}
#define DIR(n,c) TEST(nt_file_directory_##n) { directory_case("directory_" #n,c); }
DIR(names,FileNamesInformation) DIR(basic,FileDirectoryInformation) DIR(full,FileFullDirectoryInformation)

static void flush_case(const char *tag, BOOL write)
{
    IO_STATUS_BLOCK io; LARGE_INTEGER p; char data[]="private flush"; NTSTATUS s;
    START(tag);
    if (write) {
        p.QuadPart=0; s=UN(NtWriteFile)(f.h,NULL,NULL,NULL,&io,data,sizeof data,&p,NULL);
        EXPECT_EQ(s,0); if (!OK(s)) { finish(&f); return; }
    }
    s=UN(NtFlushBuffersFile)(f.h,&io); EXPECT_EQ(s,0); if (OK(s)) EXPECT_EQ(io.Status,0);
    finish(&f);
}
TEST(nt_file_flush_empty) { flush_case("flush_empty",FALSE); }
TEST(nt_file_flush_written) { flush_case("flush_written",TRUE); }
TEST(nt_file_read_empty_eof)
{
    IO_STATUS_BLOCK io; LARGE_INTEGER p; BYTE b=0xcc; NTSTATUS s;
    START("read_empty_eof"); p.QuadPart=0;
    s=UN(NtReadFile)(f.h,NULL,NULL,NULL,&io,&b,1,&p,NULL);
    EXPECT_EQ(s,(NTSTATUS)0xc0000011); finish(&f);
}

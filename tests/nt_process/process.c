#include "t.h"

UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQuerySystemInformation, (ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenProcess, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID *));
UDECL(NTSTATUS, NtOpenThread, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID *));
UDECL(NTSTATUS, NtDuplicateObject, (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG));
UDECL(NTSTATUS, NtQueryObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));

#define SELF ((HANDLE)(LONG_PTR)-1)
#define THREAD_SELF ((HANDLE)(LONG_PTR)-2)
#define ST(x) ((NTSTATUS)(x))
typedef struct {
    NTSTATUS ExitStatus; PVOID Peb; ULONG_PTR Affinity; LONG BasePriority;
    ULONG_PTR Pid, ParentPid;
} NP_PROCESS_BASIC;
typedef struct {
    NTSTATUS ExitStatus; PVOID Teb; CLIENT_ID Id; ULONG_PTR Affinity;
    LONG Priority, BasePriority;
} NP_THREAD_BASIC;
typedef struct { ULONG Attributes, Access, HandleCount, PointerCount, Reserved[10]; } NP_OBJECT_BASIC;

static void process_basic(ULONG bytes, int optional) {
    REQUIRE(UN(NtQueryInformationProcess));
    union { NP_PROCESS_BASIC basic; BYTE room[80]; } out;
    memset(&out,0xa5,sizeof out); ULONG n=0;
    NTSTATUS s=UN(NtQueryInformationProcess)(SELF,0,&out,bytes,optional ? NULL : &n);
    if(bytes!=sizeof(NP_PROCESS_BASIC)) { EXPECT_EQ(s,ST(0xc0000004)); EXPECT_EQ(n,0); return; }
    EXPECT_EQ(s,0); if(s<0) return;
    if(!optional) EXPECT_EQ(n,sizeof(NP_PROCESS_BASIC));
    EXPECT_EQ(out.basic.Pid,GetCurrentProcessId()); CHECK(out.basic.Peb!=NULL);
    EXPECT_EQ(out.basic.ExitStatus,ST(0x103));
    t_note("process parent=%llu priority=%ld affinity=%llx",(unsigned long long)out.basic.ParentPid,out.basic.BasePriority,(unsigned long long)out.basic.Affinity);
    for(SIZE_T i=sizeof(NP_PROCESS_BASIC);i<sizeof out;++i) EXPECT_EQ(out.room[i],0xa5);
}
TEST(nt_process_basic_current_pseudohandle) { process_basic(sizeof(NP_PROCESS_BASIC),0); }
TEST(nt_process_basic_optional_length) { process_basic(sizeof(NP_PROCESS_BASIC),1); }
TEST(nt_process_basic_zero_length) { process_basic(0,0); }
TEST(nt_process_basic_one_byte) { process_basic(1,0); }
TEST(nt_process_basic_short_length) { process_basic(sizeof(NP_PROCESS_BASIC)-1,0); }
TEST(nt_process_basic_oversized_length) { process_basic(sizeof(NP_PROCESS_BASIC)+1,0); }

static void process_scalar(ULONG cls, int short_buffer, int optional) {
    REQUIRE(UN(NtQueryInformationProcess)); ULONG_PTR value=~(ULONG_PTR)0; ULONG n=0;
    NTSTATUS s=UN(NtQueryInformationProcess)(SELF,cls,&value,short_buffer ? sizeof value-1 : sizeof value,optional ? NULL : &n);
    if(short_buffer) { EXPECT_EQ(s,ST(0xc0000004)); return; }
    EXPECT_EQ(s,0); if(s<0) return;
    if(!optional) EXPECT_EQ(n,sizeof value);
    if(cls==26) EXPECT_EQ(value,0); /* This corpus is a native x64 executable. */
    else t_note("debug port=%llx (debugger/environment dependent)",(unsigned long long)value);
}
TEST(nt_process_wow64_native_x64) { process_scalar(26,0,0); }
TEST(nt_process_wow64_short_buffer) { process_scalar(26,1,0); }
TEST(nt_process_wow64_optional_length) { process_scalar(26,0,1); }
TEST(nt_process_debug_port_query) { process_scalar(7,0,0); }
TEST(nt_process_debug_port_short_buffer) { process_scalar(7,1,0); }
TEST(nt_process_debug_port_optional_length) { process_scalar(7,0,1); }

static void image_name(int mode) {
    REQUIRE(UN(NtQueryInformationProcess));
    union { ULONG_PTR align; BYTE data[65536]; } out; ULONG need=0;
    memset(&out,0,sizeof out);
    NTSTATUS s=UN(NtQueryInformationProcess)(SELF,27,out.data,mode==1 ? sizeof(UNICODE_STRING)-1 : 0,&need);
    EXPECT_EQ(s,ST(0xc0000004)); CHECK(need>=sizeof(UNICODE_STRING));
    if(mode==1) return;
    if(need<sizeof(UNICODE_STRING) || need>sizeof out.data) { t_skip("image name exceeds bounded fixture"); return; }
    ULONG capacity=mode==2 ? sizeof out.data : need;
    s=UN(NtQueryInformationProcess)(SELF,27,out.data,capacity,&need); EXPECT_EQ(s,0);
    if(s<0) return;
    UNICODE_STRING *u=(UNICODE_STRING *)out.data;
    CHECK(u->Length>0); EXPECT_EQ(u->Length%sizeof(WCHAR),0); CHECK(u->Length<=u->MaximumLength);
    ULONG_PTR start=(ULONG_PTR)out.data, end=start+capacity, ptr=(ULONG_PTR)u->Buffer;
    CHECK(ptr>=start && ptr<=end && u->Length<=end-ptr);
    t_note("image name length=%u",u->Length);
}
TEST(nt_process_image_name_size_then_exact) { image_name(0); }
TEST(nt_process_image_name_short_header) { image_name(1); }
TEST(nt_process_image_name_large_buffer) { image_name(2); }

static void thread_basic(ULONG bytes, int optional) {
    REQUIRE(UN(NtQueryInformationThread));
    union { NP_THREAD_BASIC basic; BYTE room[64]; } storage, before;
    NP_THREAD_BASIC *out=&storage.basic; ULONG n=0;
    memset(&storage,0xa5,sizeof storage); memcpy(&before,&storage,sizeof storage);
    NTSTATUS s=UN(NtQueryInformationThread)(THREAD_SELF,0,out,bytes,optional ? NULL : &n);
    if(bytes!=sizeof *out) { EXPECT_EQ(s,ST(0xc0000004)); EXPECT_EQ(n,0); CHECK(!memcmp(&storage,&before,sizeof storage)); return; }
    EXPECT_EQ(s,0); if(s<0) return;
    if(!optional) EXPECT_EQ(n,sizeof *out);
    EXPECT_EQ(out->Id.UniqueProcess,(HANDLE)(ULONG_PTR)GetCurrentProcessId());
    EXPECT_EQ(out->Id.UniqueThread,(HANDLE)(ULONG_PTR)GetCurrentThreadId());
    CHECK(out->Teb!=NULL); EXPECT_EQ(out->ExitStatus,ST(0x103));
    CHECK(!memcmp(storage.room+sizeof *out,before.room+sizeof *out,sizeof storage-sizeof *out));
    t_note("thread priority=%ld base=%ld affinity=%llx",out->Priority,out->BasePriority,(unsigned long long)out->Affinity);
}
TEST(nt_process_thread_basic_pseudohandle) { thread_basic(sizeof(NP_THREAD_BASIC),0); }
TEST(nt_process_thread_basic_optional_length) { thread_basic(sizeof(NP_THREAD_BASIC),1); }
TEST(nt_process_thread_basic_zero_length) { thread_basic(0,0); }
TEST(nt_process_thread_basic_one_byte) { thread_basic(1,0); }
TEST(nt_process_thread_basic_short_length) { thread_basic(sizeof(NP_THREAD_BASIC)-1,0); }
TEST(nt_process_thread_basic_oversized_length) { thread_basic(sizeof(NP_THREAD_BASIC)+1,0); }

static void thread_scalar(ULONG cls, ULONG bytes, int optional) {
    REQUIRE(UN(NtQueryInformationThread)); ULONG_PTR value=~(ULONG_PTR)0; ULONG n=0;
    ULONG exact=cls==9 ? sizeof(PVOID) : sizeof(ULONG);
    NTSTATUS s=UN(NtQueryInformationThread)(THREAD_SELF,cls,&value,bytes,optional ? NULL : &n);
    if(bytes!=exact) { EXPECT_EQ(s,ST(0xc0000004)); EXPECT_EQ(n,0); EXPECT_EQ(value,~(ULONG_PTR)0); return; }
    EXPECT_EQ(s,0); if(s<0) return;
    if(!optional) EXPECT_EQ(n,exact);
    t_note("thread class=%lu value=%llx",cls,(unsigned long long)(cls==16 ? (ULONG)value : value));
}
TEST(nt_process_thread_start_address) { thread_scalar(9,sizeof(PVOID),0); }
TEST(nt_process_thread_start_address_short) { thread_scalar(9,sizeof(PVOID)-1,0); }
TEST(nt_process_thread_start_address_optional_length) { thread_scalar(9,sizeof(PVOID),1); }
TEST(nt_process_thread_io_pending) { thread_scalar(16,sizeof(ULONG),0); }
TEST(nt_process_thread_io_pending_short) { thread_scalar(16,sizeof(ULONG)-1,0); }

static void system_basic(ULONG bytes, int optional) {
    REQUIRE(UN(NtQuerySystemInformation));
    struct { BYTE Reserved1[24]; PVOID Reserved2[4]; BYTE Processors; } out;
    ULONG n=0; memset(&out,0,sizeof out);
    NTSTATUS s=UN(NtQuerySystemInformation)(0,&out,bytes,optional ? NULL : &n);
    if(bytes!=sizeof out) { EXPECT_EQ(s,ST(0xc0000004)); if(!optional) EXPECT_EQ(n,sizeof out); return; }
    EXPECT_EQ(s,0); if(s<0) return;
    if(!optional) EXPECT_EQ(n,sizeof out);
    CHECK(out.Processors!=0); t_note("system processor count=%u",out.Processors);
}
TEST(nt_process_system_basic) { system_basic(64,0); }
TEST(nt_process_system_basic_optional_length) { system_basic(64,1); }
TEST(nt_process_system_basic_zero_length) { system_basic(0,0); }
TEST(nt_process_system_basic_short_length) { system_basic(63,0); }
static void system_opaque(ULONG cls, ULONG bytes) {
    REQUIRE(UN(NtQuerySystemInformation));
    union { ULONG_PTR align; BYTE data[128]; } out; ULONG n=0;
    memset(&out,0xa5,sizeof out);
    NTSTATUS s=UN(NtQuerySystemInformation)(cls,out.data,bytes,&n);
    if(cls==33 && bytes<16) { EXPECT_EQ(s,ST(0xc0000004)); EXPECT_EQ(n,16); return; }
    EXPECT_EQ(s,0);
    if(s>=0) { EXPECT_EQ(n,cls==33 ? 16 : 48); t_note("system class=%lu returned=%lu",cls,n); }
}
TEST(nt_process_system_timeofday_safe_query) { system_opaque(3,48); }
TEST(nt_process_system_exception_safe_query) { system_opaque(33,16); }
TEST(nt_process_system_exception_short_length) { system_opaque(33,15); }

static HANDLE open_self(int thread, ACCESS_MASK access) {
    OBJECT_ATTRIBUTES oa; CLIENT_ID id; HANDLE h=NULL;
    memset(&oa,0,sizeof oa); oa.Length=sizeof oa;
    id.UniqueProcess=(HANDLE)(ULONG_PTR)GetCurrentProcessId();
    id.UniqueThread=thread ? (HANDLE)(ULONG_PTR)GetCurrentThreadId() : NULL;
    NTSTATUS s=thread ? UN(NtOpenThread)(&h,access,&oa,&id) : UN(NtOpenProcess)(&h,access,&oa,&id);
    EXPECT_EQ(s,0); if(s<0) return NULL;
    CHECK(h!=NULL); return h;
}
static void open_case(int thread, ACCESS_MASK access) {
    REQUIRE(UN(NtOpenProcess)); REQUIRE(UN(NtOpenThread));
    REQUIRE(UN(NtQueryInformationProcess)); REQUIRE(UN(NtQueryInformationThread));
    HANDLE h=open_self(thread,access); if(!h) return;
    if(thread) {
        NP_THREAD_BASIC out={0}; NTSTATUS s=UN(NtQueryInformationThread)(h,0,&out,sizeof out,NULL);
        EXPECT_EQ(s,0); if(s>=0) EXPECT_EQ(out.Id.UniqueThread,(HANDLE)(ULONG_PTR)GetCurrentThreadId());
    } else {
        NP_PROCESS_BASIC out={0}; NTSTATUS s=UN(NtQueryInformationProcess)(h,0,&out,sizeof out,NULL);
        EXPECT_EQ(s,0); if(s>=0) EXPECT_EQ(out.Pid,GetCurrentProcessId());
    }
    CHECK(CloseHandle(h));
}
TEST(nt_process_open_current_query) { open_case(0,PROCESS_QUERY_INFORMATION); }
TEST(nt_process_open_current_limited_query) { open_case(0,PROCESS_QUERY_LIMITED_INFORMATION); }
TEST(nt_process_open_current_vm_query_rights) { open_case(0,PROCESS_QUERY_INFORMATION|PROCESS_VM_READ); }
TEST(nt_process_open_current_thread_query) { open_case(1,THREAD_QUERY_INFORMATION); }
TEST(nt_process_open_current_thread_limited_query) { open_case(1,THREAD_QUERY_LIMITED_INFORMATION); }

static int object_basic(HANDLE h, NP_OBJECT_BASIC *out) {
    memset(out,0,sizeof *out);
    ULONG n=0; NTSTATUS s=UN(NtQueryObject)(h,0,out,sizeof *out,&n);
    EXPECT_EQ(s,0); if(s<0) return 0;
    EXPECT_EQ(n,sizeof *out); CHECK(out->HandleCount>=1); CHECK(out->PointerCount>=1); return 1;
}
static void duplicate_case(int thread, int reduced, int inherit) {
    REQUIRE(UN(NtDuplicateObject)); REQUIRE(UN(NtQueryObject));
    REQUIRE(UN(NtQueryInformationProcess)); REQUIRE(UN(NtQueryInformationThread));
    HANDLE h=NULL; ACCESS_MASK access=thread ? THREAD_QUERY_INFORMATION : PROCESS_QUERY_INFORMATION;
    NTSTATUS s=UN(NtDuplicateObject)(SELF,thread ? THREAD_SELF : SELF,SELF,&h,access,inherit ? 2 : 0,reduced ? 0 : DUPLICATE_SAME_ACCESS);
    EXPECT_EQ(s,0); if(s<0 || !h) { if(s>=0) CHECK(h!=NULL); return; }
    NP_OBJECT_BASIC info;
    if(object_basic(h,&info)) {
        CHECK((info.Access & access)==access);
        /* Object-manager access mapping may add the limited-query right. */
        if(reduced) CHECK(!(info.Access & 1));
        EXPECT_EQ(info.Attributes & 2,inherit ? 2 : 0);
    }
    BYTE flags[2]={0xa5,0xa5}; ULONG n=0;
    s=UN(NtQueryObject)(h,4,flags,sizeof flags,&n); EXPECT_EQ(s,0);
    if(s>=0) { EXPECT_EQ(n,sizeof flags); EXPECT_EQ(flags[0],inherit ? 1 : 0); EXPECT_EQ(flags[1],0); }
    if(thread) {
        NP_THREAD_BASIC out={0}; s=UN(NtQueryInformationThread)(h,0,&out,sizeof out,NULL);
        EXPECT_EQ(s,0); if(s>=0) EXPECT_EQ(out.Id.UniqueThread,(HANDLE)(ULONG_PTR)GetCurrentThreadId());
    } else {
        NP_PROCESS_BASIC out={0}; s=UN(NtQueryInformationProcess)(h,0,&out,sizeof out,NULL);
        EXPECT_EQ(s,0); if(s>=0) EXPECT_EQ(out.Pid,GetCurrentProcessId());
    }
    CHECK(CloseHandle(h));
}
TEST(nt_process_duplicate_process_pseudohandle) { duplicate_case(0,0,0); }
TEST(nt_process_duplicate_thread_pseudohandle) { duplicate_case(1,0,0); }
TEST(nt_process_duplicate_reduced_process_access) { duplicate_case(0,1,0); }
TEST(nt_process_duplicate_reduced_thread_access) { duplicate_case(1,1,0); }
TEST(nt_process_duplicate_inheritable_handle) { duplicate_case(0,1,1); }

static void object_type(int thread, int size_only) {
    REQUIRE(UN(NtOpenProcess)); REQUIRE(UN(NtOpenThread)); REQUIRE(UN(NtQueryObject));
    HANDLE h=open_self(thread,thread ? THREAD_QUERY_INFORMATION : PROCESS_QUERY_INFORMATION);
    if(!h) return;
    union { ULONG_PTR align; BYTE data[4096]; } out; ULONG need=0;
    memset(&out,0,sizeof out);
    NTSTATUS s=UN(NtQueryObject)(h,2,out.data,size_only ? 0 : sizeof out.data,&need);
    if(size_only) { CHECK(s<0); CHECK(need>=sizeof(UNICODE_STRING)); t_note("object type sizing status=%08lx required=%lu",(ULONG)s,need); }
    else {
        EXPECT_EQ(s,0);
        if(s>=0) {
            UNICODE_STRING *u=(UNICODE_STRING *)out.data;
            const WCHAR *expected=thread ? L"Thread" : L"Process";
            SIZE_T len=wcslen(expected)*sizeof(WCHAR);
            EXPECT_EQ(u->Length,len);
            ULONG_PTR start=(ULONG_PTR)out.data,ptr=(ULONG_PTR)u->Buffer,end=start+sizeof out.data;
            int valid=ptr>=start && ptr<=end && u->Length<=end-ptr;
            CHECK(valid); if(valid && u->Length==len) CHECK(!memcmp(u->Buffer,expected,len));
        }
    }
    CHECK(CloseHandle(h));
}
TEST(nt_process_query_object_process_type) { object_type(0,0); }
TEST(nt_process_query_object_thread_type) { object_type(1,0); }
TEST(nt_process_query_object_type_size_protocol) { object_type(0,1); }
TEST(nt_process_query_object_basic_short_buffer) {
    REQUIRE(UN(NtOpenProcess)); REQUIRE(UN(NtQueryObject));
    HANDLE h=open_self(0,PROCESS_QUERY_INFORMATION); if(!h) return;
    NP_OBJECT_BASIC out; ULONG n=0;
    NTSTATUS s=UN(NtQueryObject)(h,0,&out,sizeof out-1,&n);
    /* The kernel's basic-info size branch returns before ReturnLength is written. */
    EXPECT_EQ(s,ST(0xc0000004)); EXPECT_EQ(n,0); CHECK(CloseHandle(h));
}

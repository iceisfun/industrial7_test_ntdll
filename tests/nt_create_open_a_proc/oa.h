/* Shared declarations for the nt_create_open_a_proc area. */
#include "t.h"

UDECL(NTSTATUS, NtClose, (HANDLE));

#define ST(x)           ((NTSTATUS)(x))
#define ST_SUCCESS      ST(0)
#define ST_INVALID_PARAMETER ST(0xC000000D)
#define ST_ACCESS_VIOLATION  ST(0xC0000005)
#define ST_ACCESS_DENIED     ST(0xC0000022)
#define ST_NAME_NOT_FOUND    ST(0xC0000034)
#define ST_NAME_COLLISION    ST(0xC0000035)

static UNICODE_STRING *oa_us(const WCHAR *s)
{
    static UNICODE_STRING u[8]; static int k;
    UNICODE_STRING *r = &u[k++ & 7];
    r->Buffer = (PWSTR)s; r->Length = (USHORT)(lstrlenW(s) * 2); r->MaximumLength = (USHORT)(r->Length + 2);
    return r;
}
static void oa_init(OBJECT_ATTRIBUTES *o, const WCHAR *name, ULONG attr)
{
    memset(o, 0, sizeof *o);
    o->Length = sizeof *o; o->ObjectName = oa_us(name); o->Attributes = attr;
}
#define OBJ_CI 0x40

UDECL(NTSTATUS, NtCreateProcess, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE));
UDECL(NTSTATUS, NtCreateProcessEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, ULONG));
UDECL(NTSTATUS, NtCreateThread, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PVOID, BOOLEAN));
UDECL(NTSTATUS, NtCreateThreadEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID));
UDECL(NTSTATUS, NtCreateUserProcess, (PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID, PVOID, PVOID));
UDECL(NTSTATUS, NtOpenProcessTokenEx, (HANDLE, ACCESS_MASK, ULONG, PHANDLE));
UDECL(NTSTATUS, NtOpenThreadTokenEx, (HANDLE, ACCESS_MASK, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtQueryInformationToken, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationProcess, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtQueryInformationThread, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtSetInformationThread, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtDuplicateToken, (HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, ULONG, PHANDLE));
UDECL(NTSTATUS, NtTerminateProcess, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, NtTerminateThread, (HANDLE, NTSTATUS));
UDECL(NTSTATUS, NtResumeThread, (HANDLE, PULONG));
UDECL(NTSTATUS, RtlCreateProcessParametersEx, (PVOID *, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG));
UDECL(NTSTATUS, RtlDestroyProcessParameters, (PVOID));

#define ST_INV_HANDLE ST(0xC0000008)
#define ST_TYPE_MISMATCH ST(0xC0000024)
#define NT_CUR_PROC ((HANDLE)(LONG_PTR)-1)
#define NT_CUR_THREAD ((HANDLE)(LONG_PTR)-2)
#define CLOSE(h) do { if (h) { UN(NtClose)(h); (h) = NULL; } } while (0)

typedef struct { NTSTATUS exit; PVOID peb; ULONG_PTR affinity; LONG prio; ULONG_PTR pid, parent; } pbi_t;
typedef struct { LUID id; LUID auth; LARGE_INTEGER exp; ULONG type, level, dyn_charged, dyn_avail, groups, privs; LUID mod; } tstat_t;

static BOOL token_id(HANDLE tok, LUID *id)
{
    tstat_t s; ULONG ret = 0;
    if (!UN(NtQueryInformationToken) || UN(NtQueryInformationToken)(tok, 10 /* TokenStatistics */, &s, sizeof s, &ret) < 0) return FALSE;
    *id = s.id; return TRUE;
}

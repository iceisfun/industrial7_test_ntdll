/* Shared declarations for the nt_create_open_a_objects area. */
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

UDECL(NTSTATUS, NtCreateDirectoryObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateDirectoryObjectEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG));
UDECL(NTSTATUS, NtOpenDirectoryObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateSymbolicLinkObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING));
UDECL(NTSTATUS, NtOpenSymbolicLinkObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtQuerySymbolicLinkObject, (HANDLE, PUNICODE_STRING, PULONG));
UDECL(NTSTATUS, NtCreateEventPair, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtOpenEventPair, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateKeyedEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtOpenKeyedEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateJobObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtOpenJobObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateJobSet, (ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtCreateSectionEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE, PVOID, ULONG));
UDECL(NTSTATUS, NtOpenSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtQuerySection, (HANDLE, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtCreatePrivateNamespace, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, NtOpenPrivateNamespace, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, NtDeletePrivateNamespace, (HANDLE));
UDECL(NTSTATUS, NtCreateTimer2, (PHANDLE, PVOID, POBJECT_ATTRIBUTES, ULONG, ACCESS_MASK));
UDECL(NTSTATUS, NtCreateIRTimer, (PHANDLE, PVOID, ACCESS_MASK));
UDECL(NTSTATUS, NtCreateDebugObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtCreatePort, (PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtCreateWaitablePort, (PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtOpenEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtQueryObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(PVOID, RtlCreateBoundaryDescriptor, (PUNICODE_STRING, ULONG));
UDECL(NTSTATUS, RtlAddSIDToBoundaryDescriptor, (PVOID *, PSID));
UDECL(VOID, RtlDeleteBoundaryDescriptor, (PVOID));
UDECL(NTSTATUS, ZwCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));

#define ST_NOT_IMPL    ST(0xC0000002)
#define ST_NOT_SUPP    ST(0xC00000BB)
#define ST_INV_HANDLE  ST(0xC0000008)
#define ST_PARAM4      ST(0xC00000F2)

#define CLOSE(h) do { if (h) { UN(NtClose)(h); (h) = NULL; } } while (0)
static unsigned g_serial;
/* "\BaseNamedObjects\<leaf>_<pid>_<n>" */
static void bno_name(WCHAR *out, const WCHAR *leaf)
{
    wsprintfW(out, L"\\BaseNamedObjects\\%s_%lu_%u", leaf, GetCurrentProcessId(), ++g_serial);
}
/* Object type name of a handle via NtQueryObject(ObjectTypeInformation); false if unavailable. */
static BOOL type_name(HANDLE h, WCHAR *out, size_t cap)
{
    BYTE buf[512]; ULONG ret = 0; UNICODE_STRING *u = (UNICODE_STRING *)buf;
    if (!UN(NtQueryObject) || UN(NtQueryObject)(h, 2, buf, sizeof buf, &ret) < 0) return FALSE;
    size_t n = u->Length / 2; if (n >= cap) n = cap - 1;
    memcpy(out, u->Buffer, n * 2); out[n] = 0; return TRUE;
}

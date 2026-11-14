/* Shared declarations for the nt_create_open_a_io area. */
#include "t.h"

UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtCreateMailslotFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, PLARGE_INTEGER));
UDECL(NTSTATUS, NtCreateNamedPipeFile, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PLARGE_INTEGER));

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

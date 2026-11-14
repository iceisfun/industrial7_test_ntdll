/* Shared helpers for the nt_create_open_b_* areas: object-attribute plumbing,
 * unique object names in the caller's session namespace, status shorthands. */
#ifndef COB_H
#define COB_H
#include "t.h"

#define S_OK_      ((NTSTATUS)0)
#define S_EXISTS   ((NTSTATUS)0x40000000)
#define S_INVHANDLE ((NTSTATUS)0xC0000008)
#define S_AV       ((NTSTATUS)0xC0000005)
#define S_INVPARAM ((NTSTATUS)0xC000000D)
#define S_NOTFOUND ((NTSTATUS)0xC0000034)
#define S_PATHNF   ((NTSTATUS)0xC000003A)
#define S_COLLIDE  ((NTSTATUS)0xC0000035)
#define S_TYPEMM   ((NTSTATUS)0xC0000024)
#define S_DENIED   ((NTSTATUS)0xC0000022)
#define S_NAMEINV  ((NTSTATUS)0xC0000033)
#define S_TIMEOUT  ((NTSTATUS)0x00000102)
#define S_BUFSMALL ((NTSTATUS)0xC0000023)
#define S_LENMM    ((NTSTATUS)0xC0000004)
#define S_PRIVNH   ((NTSTATUS)0xC0000061)
#define S_NOTSUPP  ((NTSTATUS)0xC00000BB)
#define S_PATHSYN  ((NTSTATUS)0xC000003B)
#define OBJ_OPENIF_ 0x80
#define S_NOTIMPL ((NTSTATUS)0xC0000002)
#define S_PARAM2 ((NTSTATUS)0xC00000F0)
#define S_PARAM3 ((NTSTATUS)0xC00000F1)
#define S_INVPARAM4 ((NTSTATUS)0xC00000F2)
#define S_ISDIR    ((NTSTATUS)0xC00000BA)

#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 1
#endif
#ifndef SEMAPHORE_QUERY_STATE
#define SEMAPHORE_QUERY_STATE 1
#endif
#ifndef MUTANT_QUERY_STATE
#define MUTANT_QUERY_STATE 1
#endif
#ifndef MUTANT_ALL_ACCESS
#define MUTANT_ALL_ACCESS 0x1F0001
#endif
#ifndef TIMER_QUERY_STATE
#define TIMER_QUERY_STATE 1
#endif
#ifndef TIMER_ALL_ACCESS
#define TIMER_ALL_ACCESS 0x1F0003
#endif
/* Unbuffered output so that a hung test leaves its progress in the log. */
static void __attribute__((constructor)) cob_unbuf(void) { setvbuf(stdout, NULL, _IONBF, 0); }
#define COB_OK(s) ((NTSTATUS)(s) >= 0)

UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, NtQueryObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));

static inline void cob_us(UNICODE_STRING *u, const WCHAR *s)
{
    u->Buffer = (PWSTR)s; u->Length = (USHORT)(lstrlenW(s) * 2); u->MaximumLength = u->Length;
}
static inline void cob_oa(OBJECT_ATTRIBUTES *oa, UNICODE_STRING *name, ULONG attr, HANDLE root)
{
    memset(oa, 0, sizeof *oa);
    oa->Length = sizeof *oa; oa->RootDirectory = root; oa->ObjectName = name; oa->Attributes = attr;
}
/* Directory holding the caller's session-local named objects. */
static inline void cob_bno(WCHAR *out, size_t cap)
{
    DWORD sid = 0; char tmp[96];
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sid)) sid = 0;
    if (sid == 0) snprintf(tmp, sizeof tmp, "\\BaseNamedObjects");
    else snprintf(tmp, sizeof tmp, "\\Sessions\\%lu\\BaseNamedObjects", (unsigned long)sid);
    for (size_t i = 0; i < cap; i++) { out[i] = (WCHAR)(unsigned char)tmp[i]; if (!tmp[i]) break; }
}
/* Unique full path "<bno>\cob_<tag>_<pid>_<n>". */
static inline void cob_name(WCHAR *out, size_t cap, const char *tag)
{
    static LONG n; char tmp[160]; WCHAR dir[96]; size_t k = 0, i;
    cob_bno(dir, 96);
    for (i = 0; dir[i]; i++) out[k++] = dir[i];
    snprintf(tmp, sizeof tmp, "\\cob_%s_%lu_%ld", tag, (unsigned long)GetCurrentProcessId(), (long)InterlockedIncrement(&n));
    for (i = 0; tmp[i] && k + 1 < cap; i++) out[k++] = (WCHAR)(unsigned char)tmp[i];
    out[k] = 0;
}
/* Type name of an object via NtQueryObject(ObjectTypeInformation). */
static inline int cob_typename(HANDLE h, WCHAR *out, size_t cap)
{
    union { ULONGLONG a; BYTE b[512]; } buf; ULONG ret; UNICODE_STRING *u = (UNICODE_STRING *)buf.b;
    if (!UN(NtQueryObject) || UN(NtQueryObject)(h, 2, &buf, sizeof buf, &ret) != 0) return 0;
    size_t n = u->Length / 2; if (n >= cap) n = cap - 1;
    memcpy(out, u->Buffer, n * 2); out[n] = 0; return 1;
}
/* GrantedAccess from ObjectBasicInformation. */
static inline int cob_granted(HANDLE h, ULONG *g)
{
    ULONG b[14] = {0}; ULONG ret;
    if (!UN(NtQueryObject) || UN(NtQueryObject)(h, 0, b, sizeof b, &ret) != 0) return 0;
    *g = b[1]; return 1;
}
static inline void cob_close(HANDLE h) { if (h && UN(NtClose)) UN(NtClose)(h); }
#define COB_ALIAS(n) do { FARPROC a_ = t_proc("Nt" n), b_ = t_proc("Zw" n); CHECKF(a_ && a_ == b_, "Nt/Zw alias for " n); } while (0)
#endif

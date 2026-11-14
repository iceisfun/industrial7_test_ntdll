/* User-mode ETW provider side of ntdll: EtwEventRegister family, Etw*Write* on disabled/invalid
 * registrations, activity ids, trace-handle decoders, instance ids, enumeration of registered GUIDs.
 * No trace session is ever started: every provider stays disabled, so writes are no-ops.
 * Status values are Win32 error codes (ULONG), not NTSTATUS:
 *   0 success, 6 ERROR_INVALID_HANDLE, 24 ERROR_BAD_LENGTH, 50 ERROR_NOT_SUPPORTED,
 *   87 ERROR_INVALID_PARAMETER, 122 ERROR_INSUFFICIENT_BUFFER.
 */
#include "t.h"

typedef struct { USHORT Id; UCHAR Version, Channel, Level, Opcode; USHORT Task; ULONGLONG Keyword; } EVD;
typedef struct { ULONGLONG Ptr; ULONG Size; ULONG Reserved; } EDD;
typedef ULONGLONG RH;
typedef void (WINAPI *ENABLECB)(const GUID *, ULONG, UCHAR, ULONGLONG, ULONGLONG, PVOID, PVOID);

UDECL(ULONG, EtwEventRegister, (const GUID *, ENABLECB, PVOID, RH *));
UDECL(ULONG, EtwEventUnregister, (RH));
UDECL(ULONG, EtwNotificationRegister, (const GUID *, ULONG, ENABLECB, PVOID, RH *));
UDECL(ULONG, EtwNotificationUnregister, (RH, PVOID *));
UDECL(BOOLEAN, EtwEventEnabled, (RH, const EVD *));
UDECL(BOOLEAN, EtwEventProviderEnabled, (RH, UCHAR, ULONGLONG));
UDECL(ULONG, EtwEventWrite, (RH, const EVD *, ULONG, EDD *));
UDECL(ULONG, EtwEventWriteTransfer, (RH, const EVD *, const GUID *, const GUID *, ULONG, EDD *));
UDECL(ULONG, EtwEventWriteEx, (RH, const EVD *, ULONGLONG, ULONG, const GUID *, const GUID *, ULONG, EDD *));
UDECL(ULONG, EtwEventWriteFull, (RH, const EVD *, USHORT, const GUID *, const GUID *, ULONG, EDD *));
UDECL(ULONG, EtwEventWriteString, (RH, UCHAR, ULONGLONG, const WCHAR *));
UDECL(ULONG, EtwEventWriteStartScenario, (RH, const EVD *, ULONG, EDD *));
UDECL(ULONG, EtwEventWriteEndScenario, (RH, const EVD *, ULONG, EDD *));
UDECL(ULONG, EtwEventWriteNoRegistration, (const GUID *, const EVD *, ULONG, EDD *));
UDECL(ULONG, EtwEventSetInformation, (RH, ULONG, PVOID, ULONG));
UDECL(ULONG, EtwEventActivityIdControl, (ULONG, GUID *));
UDECL(ULONG, EtwCreateTraceInstanceId, (PVOID, PVOID));
UDECL(ULONG, EtwEnumerateProcessRegGuids, (PVOID, ULONG, ULONG *));
UDECL(ULONG, EtwGetTraceEnableFlags, (ULONGLONG));
UDECL(UCHAR, EtwGetTraceEnableLevel, (ULONGLONG));
UDECL(ULONGLONG, EtwGetTraceLoggerHandle, (PVOID));
UDECL(ULONG, EtwLogTraceEvent, (ULONGLONG, PVOID));
UDECL(ULONG, EtwTraceEventInstance, (ULONGLONG, PVOID, PVOID, PVOID));
UDECL(ULONG, EtwRegisterTraceGuidsW, (PVOID, PVOID, const GUID *, ULONG, PVOID, PCWSTR, PCWSTR, RH *));
UDECL(ULONG, EtwRegisterTraceGuidsA, (PVOID, PVOID, const GUID *, ULONG, PVOID, PCSTR, PCSTR, RH *));
UDECL(ULONG, EtwProcessPrivateLoggerRequest, (PVOID, PVOID, ULONG_PTR));

static const GUID G1 = {0x6a1f0001, 0x1111, 0x4222, {0x83, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01}};
static const GUID G2 = {0x6a1f0002, 0x1111, 0x4222, {0x83, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x02}};
static const GUID G3 = {0x6a1f0003, 0x1111, 0x4222, {0x83, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x03}};
static const GUID GZ;
static const EVD ED = {1, 0, 0, 4, 0, 0, 0x10};

static void WINAPI cb(const GUID *g, ULONG en, UCHAR lv, ULONGLONG a, ULONGLONG b, PVOID f, PVOID c) { (void)g; (void)en; (void)lv; (void)a; (void)b; (void)f; (void)c; }
static ULONG WINAPI reqcb(ULONG a, PVOID b, PVOID c, PVOID d) { return 0; }

#define NEED(n) REQUIRE(UN(n))

TEST(etw_register_errors)
{
    NEED(EtwEventRegister); NEED(EtwEventUnregister);
    RH h = 0x1234;
    SET_ERR(0); EXPECT_EQ(UN(EtwEventRegister)(NULL, cb, NULL, &h), 87); EXPECT_ERR(87);
    EXPECT_EQ(h, 0x1234);
    SET_ERR(0); EXPECT_EQ(UN(EtwEventRegister)(&G1, cb, NULL, NULL), 87); EXPECT_ERR(87);
    /* a context without a callback is rejected before any registration happens */
    h = 0x1234;
    EXPECT_EQ(UN(EtwEventRegister)(&G1, NULL, (PVOID)1, &h), 87);   /* no last-error update on this path */
    EXPECT_EQ(h, 0x1234);
    /* callback and context both NULL is legal */
    EXPECT_EQ(UN(EtwEventRegister)(&G1, NULL, NULL, &h), 0);
    CHECK(h != 0 && h != 0x1234);
    EXPECT_EQ(UN(EtwEventUnregister)(h), 0);
}

TEST(etw_register_handle_shape)
{
    NEED(EtwEventRegister); NEED(EtwEventUnregister);
    RH h1 = 0, h2 = 0;
    EXPECT_EQ(UN(EtwEventRegister)(&G1, cb, NULL, &h1), 0);
    EXPECT_EQ(UN(EtwEventRegister)(&G1, cb, NULL, &h2), 0);   /* same GUID twice is fine */
    CHECK(h1 != h2);
    /* handle = 16-bit tag in the top, 8-byte aligned pointer below it */
    CHECK((h1 >> 48) != 0);
    CHECK((h1 & 1) == 0);
    CHECK((h2 >> 48) != 0);
    EXPECT_EQ(UN(EtwEventUnregister)(h1), 0);
    EXPECT_EQ(UN(EtwEventUnregister)(h2), 0);
}

TEST(etw_unregister_errors)
{
    NEED(EtwEventUnregister); NEED(EtwNotificationUnregister); NEED(EtwEventRegister);
    SET_ERR(0); EXPECT_EQ(UN(EtwEventUnregister)(0), 6);
    EXPECT_EQ(UN(EtwEventUnregister)(1), 6);                 /* tag 0 */
    EXPECT_EQ(UN(EtwEventUnregister)(0x00010000deadbee1ULL), 6);  /* odd pointer part is rejected without dereference */
    SET_ERR(0); EXPECT_EQ(UN(EtwNotificationUnregister)(0, NULL), 6); EXPECT_ERR(6);
    RH h = 0;
    PVOID ctx = (PVOID)0x5150, out = NULL;
    EXPECT_EQ(UN(EtwEventRegister)(&G2, cb, ctx, &h), 0);
    EXPECT_EQ(UN(EtwNotificationUnregister)(h, &out), 0);
    EXPECT_EQ((ULONG_PTR)out, 0x5150);                       /* user context handed back */
    EXPECT_EQ(UN(EtwEventUnregister)(h), 6);                 /* stale: tag was cleared */
    EXPECT_EQ(UN(EtwNotificationUnregister)(h, &out), 6);
}

TEST(etw_notification_register)
{
    NEED(EtwNotificationRegister); NEED(EtwNotificationUnregister);
    RH h = 0x77;
    SET_ERR(0); EXPECT_EQ(UN(EtwNotificationRegister)(NULL, 3, cb, NULL, &h), 87); EXPECT_ERR(87);
    SET_ERR(0); EXPECT_EQ(UN(EtwNotificationRegister)(&G1, 3, cb, NULL, NULL), 87); EXPECT_ERR(87);
    EXPECT_EQ(h, 0x77);
    PVOID out = NULL;
    EXPECT_EQ(UN(EtwNotificationRegister)(&G3, 3, cb, (PVOID)0x99, &h), 0);
    CHECK(h != 0 && h != 0x77);
    EXPECT_EQ(UN(EtwNotificationUnregister)(h, &out), 0);
    EXPECT_EQ((ULONG_PTR)out, 0x99);
}

TEST(etw_enabled_disabled_provider)
{
    NEED(EtwEventRegister); NEED(EtwEventUnregister); NEED(EtwEventEnabled); NEED(EtwEventProviderEnabled);
    RH h = 0;
    EXPECT_EQ(UN(EtwEventRegister)(&G1, cb, NULL, &h), 0);
    EXPECT_EQ(UN(EtwEventEnabled)(h, &ED), 0);
    EXPECT_EQ(UN(EtwEventEnabled)(h, NULL), 0);
    EXPECT_EQ(UN(EtwEventProviderEnabled)(h, 0, 0), 0);
    EXPECT_EQ(UN(EtwEventProviderEnabled)(h, 5, ~0ULL), 0);
    /* invalid handles are simply "not enabled" */
    EXPECT_EQ(UN(EtwEventEnabled)(0, &ED), 0);
    EXPECT_EQ(UN(EtwEventEnabled)(1, &ED), 0);
    EXPECT_EQ(UN(EtwEventProviderEnabled)(0, 0, 0), 0);
    EXPECT_EQ(UN(EtwEventProviderEnabled)(1, 0, 0), 0);
    EXPECT_EQ(UN(EtwEventUnregister)(h), 0);
    EXPECT_EQ(UN(EtwEventEnabled)(h, &ED), 0);               /* stale */
    EXPECT_EQ(UN(EtwEventProviderEnabled)(h, 0, 0), 0);
}

TEST(etw_write_family_disabled)
{
    NEED(EtwEventRegister); NEED(EtwEventUnregister); NEED(EtwEventWrite); NEED(EtwEventWriteTransfer);
    NEED(EtwEventWriteEx); NEED(EtwEventWriteFull); NEED(EtwEventWriteString);
    RH h = 0;
    EXPECT_EQ(UN(EtwEventRegister)(&G1, cb, NULL, &h), 0);
    char payload[8] = {1};
    EDD d = {(ULONGLONG)(ULONG_PTR)payload, sizeof payload, 0};
    GUID act = G2, rel = G3;
    EXPECT_EQ(UN(EtwEventWrite)(h, &ED, 1, &d), 0);
    EXPECT_EQ(UN(EtwEventWrite)(h, &ED, 0, NULL), 0);
    EXPECT_EQ(UN(EtwEventWriteTransfer)(h, &ED, &act, &rel, 1, &d), 0);
    EXPECT_EQ(UN(EtwEventWriteTransfer)(h, &ED, NULL, NULL, 0, NULL), 0);
    EXPECT_EQ(UN(EtwEventWriteEx)(h, &ED, 0, 0, &act, NULL, 1, &d), 0);
    EXPECT_EQ(UN(EtwEventWriteFull)(h, &ED, 0, &act, NULL, 1, &d), 0);
    EXPECT_EQ(UN(EtwEventWriteString)(h, 4, 0x10, L"hello"), 0);
    EXPECT_EQ(UN(EtwEventWriteString)(h, 0, 0, L""), 0);
    /* a NULL string is rejected even though the provider is disabled */
    EXPECT_EQ(UN(EtwEventWriteString)(h, 4, 0x10, NULL), 87);
    EXPECT_EQ(UN(EtwEventUnregister)(h), 0);
}

TEST(etw_write_invalid_handle)
{
    NEED(EtwEventWriteString); NEED(EtwEventWrite); NEED(EtwEventWriteTransfer); NEED(EtwEventWriteEx); NEED(EtwEventWriteFull);
    /* handle 0, odd handle, tag-less handle: invalid, checked before the string pointer */
    EXPECT_EQ(UN(EtwEventWriteString)(0, 4, 0, L"x"), 6);
    EXPECT_EQ(UN(EtwEventWriteString)(1, 4, 0, L"x"), 6);
    EXPECT_EQ(UN(EtwEventWriteString)(0, 4, 0, NULL), 6);
    ULONG r;
    r = UN(EtwEventWrite)(0, &ED, 0, NULL); EXPECT_EQ(r, 6);
    r = UN(EtwEventWriteTransfer)(0, &ED, NULL, NULL, 0, NULL); EXPECT_EQ(r, 6);
    r = UN(EtwEventWriteEx)(0, &ED, 0, 0, NULL, NULL, 0, NULL); EXPECT_EQ(r, 6);
    r = UN(EtwEventWriteFull)(0, &ED, 0, NULL, NULL, 0, NULL); EXPECT_EQ(r, 6);
}

TEST(etw_write_stale_handle)
{
    NEED(EtwEventRegister); NEED(EtwEventUnregister); NEED(EtwEventWriteString); NEED(EtwEventWrite);
    RH h = 0;
    EXPECT_EQ(UN(EtwEventRegister)(&G1, cb, NULL, &h), 0);
    EXPECT_EQ(UN(EtwEventUnregister)(h), 0);
    EXPECT_EQ(UN(EtwEventWriteString)(h, 4, 0, L"x"), 6);
    EXPECT_EQ(UN(EtwEventWrite)(h, &ED, 0, NULL), 6);
}

TEST(etw_scenarios)
{
    NEED(EtwEventRegister); NEED(EtwEventUnregister); NEED(EtwEventWriteStartScenario); NEED(EtwEventWriteEndScenario);
    RH h = 0;
    EXPECT_EQ(UN(EtwEventWriteStartScenario)(0, NULL, 0, NULL), 87);
    EXPECT_EQ(UN(EtwEventWriteEndScenario)(0, NULL, 0, NULL), 87);
    /* not enabled (invalid handle or disabled provider): ERROR_INVALID_HANDLE */
    EXPECT_EQ(UN(EtwEventWriteStartScenario)(0, &ED, 0, NULL), 6);
    EXPECT_EQ(UN(EtwEventWriteEndScenario)(0, &ED, 0, NULL), 6);
    EXPECT_EQ(UN(EtwEventRegister)(&G1, cb, NULL, &h), 0);
    EXPECT_EQ(UN(EtwEventWriteStartScenario)(h, NULL, 0, NULL), 87);
    EXPECT_EQ(UN(EtwEventWriteEndScenario)(h, NULL, 0, NULL), 87);
    EXPECT_EQ(UN(EtwEventWriteStartScenario)(h, &ED, 0, NULL), 6);
    EXPECT_EQ(UN(EtwEventWriteEndScenario)(h, &ED, 0, NULL), 6);
    EXPECT_EQ(UN(EtwEventUnregister)(h), 0);
}

TEST(etw_write_no_registration)
{
    NEED(EtwEventWriteNoRegistration);
    EDD d = {0, 0, 0};
    EXPECT_EQ(UN(EtwEventWriteNoRegistration)(NULL, &ED, 0, NULL), 87);
    EXPECT_EQ(UN(EtwEventWriteNoRegistration)(&G1, NULL, 0, NULL), 87);
    EXPECT_EQ(UN(EtwEventWriteNoRegistration)(NULL, NULL, 0, NULL), 87);
    ULONG r = UN(EtwEventWriteNoRegistration)(&G1, &ED, 0, NULL);
    EXPECT_EQ(r, 4212);   /* observed: no session to deliver to */
}

TEST(etw_set_information)
{
    NEED(EtwEventRegister); NEED(EtwEventUnregister); NEED(EtwEventSetInformation);
    RH h = 0;
    EXPECT_EQ(UN(EtwEventRegister)(&G1, cb, NULL, &h), 0);
    char buf[64] = {0};
    /* class values 1 and >= 4 are not supported, whatever the buffer */
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 1, buf, 8), 50);
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 4, buf, 8), 50);
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 5, NULL, 0), 50);
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 0x7fffffff, buf, 8), 50);
    EXPECT_EQ(UN(EtwEventSetInformation)(0, 1, buf, 8), 50);       /* class checked before handle */
    /* class 0 (binary track) wants a zero length */
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 0, buf, 8), 87);
    /* class 2 (traits): non-NULL buffer, length 3..0xfffe */
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 2, NULL, 8), 87);
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 2, buf, 2), 87);
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 2, buf, 0), 87);
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 2, buf, 0x10000), 87);
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 2, buf, 0xffffffff), 87);
    /* class 3 (descriptor type): exactly one byte */
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 3, NULL, 1), 87);
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 3, buf, 0), 87);
    EXPECT_EQ(UN(EtwEventSetInformation)(h, 3, buf, 2), 87);
    ULONG r = UN(EtwEventSetInformation)(h, 0, NULL, 0); t_note("class0 len0 = %lu", r);
    r = UN(EtwEventSetInformation)(h, 3, buf, 1); t_note("class3 len1 = %lu", r);
    EXPECT_EQ(UN(EtwEventUnregister)(h), 0);
}

TEST(etw_activity_id_control)
{
    NEED(EtwEventActivityIdControl);
    GUID save, a = G1, b = G2, out, c1, c2;
    EXPECT_EQ(UN(EtwEventActivityIdControl)(1, NULL), 87);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(2, NULL), 87);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(3, NULL), 87);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(0, &out), 87);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(6, &out), 87);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(0xffffffff, &out), 87);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(1, &save), 0);   /* GET */
    EXPECT_EQ(UN(EtwEventActivityIdControl)(2, &a), 0);      /* SET */
    memset(&out, 0xcc, sizeof out);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(1, &out), 0);
    CHECK(!memcmp(&out, &a, sizeof out));
    out = b;                                                 /* GET_SET swaps */
    EXPECT_EQ(UN(EtwEventActivityIdControl)(4, &out), 0);
    CHECK(!memcmp(&out, &a, sizeof out));
    memset(&out, 0, sizeof out);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(1, &out), 0);
    CHECK(!memcmp(&out, &b, sizeof out));
    /* CREATE produces a non-zero id and does not install it */
    EXPECT_EQ(UN(EtwEventActivityIdControl)(3, &c1), 0);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(3, &c2), 0);
    CHECK(memcmp(&c1, &GZ, sizeof c1) != 0);
    CHECK(memcmp(&c1, &c2, sizeof c1) != 0);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(1, &out), 0);
    CHECK(!memcmp(&out, &b, sizeof out));
    /* CREATE_SET returns the previous id and installs a new one */
    memset(&out, 0xcc, sizeof out);
    ULONG r = UN(EtwEventActivityIdControl)(5, &out);
    t_note("CREATE_SET rc=%lu", r);
    EXPECT_EQ(r, 0);
    CHECK(!memcmp(&out, &b, sizeof out));
    EXPECT_EQ(UN(EtwEventActivityIdControl)(1, &c1), 0);
    CHECK(memcmp(&c1, &b, sizeof c1) != 0);
    CHECK(memcmp(&c1, &GZ, sizeof c1) != 0);
    /* ids are per thread */
    EXPECT_EQ(UN(EtwEventActivityIdControl)(2, &a), 0);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(2, &save), 0);
}

static DWORD WINAPI actid_thread(LPVOID p)
{
    GUID g; memset(&g, 0xee, sizeof g);
    UN(EtwEventActivityIdControl)(1, &g);
    *(GUID *)p = g;
    return 0;
}
TEST(etw_activity_id_per_thread)
{
    NEED(EtwEventActivityIdControl);
    GUID save, a = G1, t;
    EXPECT_EQ(UN(EtwEventActivityIdControl)(1, &save), 0);
    EXPECT_EQ(UN(EtwEventActivityIdControl)(2, &a), 0);
    HANDLE th = CreateThread(NULL, 0, actid_thread, &t, 0, NULL);
    CHECK(th != NULL);
    if (th) { EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0); CloseHandle(th); }
    CHECK(!memcmp(&t, &GZ, sizeof t));       /* new thread starts with the zero id */
    EXPECT_EQ(UN(EtwEventActivityIdControl)(2, &save), 0);
}

TEST(etw_create_trace_instance_id)
{
    NEED(EtwCreateTraceInstanceId);
    struct { LONG counter; ULONG pid; } reg = {5, 0};
    struct { PVOID reg; ULONG id; ULONG pad; } inst;
    reg.pid = GetCurrentProcessId();
    SET_ERR(0); EXPECT_EQ(UN(EtwCreateTraceInstanceId)(NULL, &inst), 87); EXPECT_ERR(87);
    SET_ERR(0); EXPECT_EQ(UN(EtwCreateTraceInstanceId)(&reg, NULL), 87); EXPECT_ERR(87);
    memset(&inst, 0, sizeof inst);
    EXPECT_EQ(UN(EtwCreateTraceInstanceId)(&reg, &inst), 0);
    EXPECT_EQ((ULONG_PTR)inst.reg, (ULONG_PTR)&reg);
    EXPECT_EQ(inst.id, 6);
    EXPECT_EQ(reg.counter, 6);
    EXPECT_EQ(UN(EtwCreateTraceInstanceId)(&reg, &inst), 0);
    EXPECT_EQ(inst.id, 7);
    /* zero is never handed out */
    reg.counter = -1;
    EXPECT_EQ(UN(EtwCreateTraceInstanceId)(&reg, &inst), 0);
    EXPECT_EQ(inst.id, 1);
    EXPECT_EQ(reg.counter, 1);
    /* registration owned by another process id: parameter error, but the handle is still stored */
    struct { LONG counter; ULONG pid; } other = {9, GetCurrentProcessId() ^ 0x1000};
    memset(&inst, 0, sizeof inst);
    SET_ERR(0); EXPECT_EQ(UN(EtwCreateTraceInstanceId)(&other, &inst), 87); EXPECT_ERR(87);
    EXPECT_EQ((ULONG_PTR)inst.reg, (ULONG_PTR)&other);
    EXPECT_EQ(inst.id, 0);
    EXPECT_EQ(other.counter, 9);
}

TEST(etw_enumerate_reg_guids)
{
    NEED(EtwEventRegister); NEED(EtwEventUnregister); NEED(EtwEnumerateProcessRegGuids);
    RH h1 = 0, h2 = 0, h3 = 0;
    ULONG need = 0xdead, r;
    SET_ERR(0);
    EXPECT_EQ(UN(EtwEnumerateProcessRegGuids)(NULL, 16, &need), 87);
    ULONG base_need = 0;
    r = UN(EtwEnumerateProcessRegGuids)(NULL, 0, &base_need);
    CHECK(r == 0 || r == 122);
    EXPECT_EQ(UN(EtwEventRegister)(&G1, cb, NULL, &h1), 0);
    EXPECT_EQ(UN(EtwEventRegister)(&G2, cb, NULL, &h2), 0);
    EXPECT_EQ(UN(EtwEventRegister)(&G2, cb, NULL, &h3), 0);   /* duplicate GUID counted once */
    ULONG n2 = 0;
    /* with no room the count is the number of registrations (duplicates included) times 16 */
    EXPECT_EQ(UN(EtwEnumerateProcessRegGuids)(NULL, 0, &n2) & 0xff, 122);
    CHECK(n2 >= 48 && (n2 % 16) == 0);
    GUID *g = (GUID *)calloc(n2 / 16 + 8, 16);
    ULONG got = 0;
    EXPECT_EQ(UN(EtwEnumerateProcessRegGuids)(g, n2, &got), 0);
    CHECK(got >= 32 && got <= n2 && (got % 16) == 0);
    int f1 = 0, f2 = 0, dup = 0;
    for (ULONG i = 0; i < got / 16; i++) {
        if (!memcmp(&g[i], &G1, 16)) f1++;
        if (!memcmp(&g[i], &G2, 16)) f2++;
        for (ULONG j = 0; j < i; j++) if (!memcmp(&g[i], &g[j], 16)) dup++;
    }
    EXPECT_EQ(f1, 1); EXPECT_EQ(f2, 1); EXPECT_EQ(dup, 0);   /* duplicates collapsed */
    /* exactly enough room, and one slot too small */
    ULONG got2 = 0;
    EXPECT_EQ(UN(EtwEnumerateProcessRegGuids)(g, got, &got2), 0);
    EXPECT_EQ(got2, got);
    got2 = 0;
    EXPECT_EQ(UN(EtwEnumerateProcessRegGuids)(g, got - 16, &got2) & 0xff, 122);
    CHECK(got2 >= got);
    /* a size that is not a multiple of 16 counts whole entries only */
    got2 = 0;
    EXPECT_EQ(UN(EtwEnumerateProcessRegGuids)(g, got + 15, &got2), 0);
    EXPECT_EQ(got2, got);
    EXPECT_EQ(UN(EtwEventUnregister)(h2), 0);
    got2 = 0;
    EXPECT_EQ(UN(EtwEnumerateProcessRegGuids)(g, n2, &got2), 0);
    EXPECT_EQ(got2, got);                                      /* second registration of G2 still there */
    EXPECT_EQ(UN(EtwEventUnregister)(h3), 0);
    got2 = 0;
    EXPECT_EQ(UN(EtwEnumerateProcessRegGuids)(g, n2, &got2), 0);
    EXPECT_EQ(got2, got - 16);
    EXPECT_EQ(UN(EtwEventUnregister)(h1), 0);
    free(g);
}

TEST(etw_trace_handle_decoders)
{
    NEED(EtwGetTraceEnableFlags); NEED(EtwGetTraceEnableLevel); NEED(EtwGetTraceLoggerHandle);
    ULONGLONG h = (0xAABBCCDDULL << 32) | (0x77ULL << 16) | 1;
    SET_ERR(0);
    EXPECT_EQ(UN(EtwGetTraceEnableFlags)(h), 0xAABBCCDD);
    EXPECT_EQ(UN(EtwGetTraceEnableLevel)(h), 0x77);
    ULONGLONG hf = (0x01020304ULL << 32) | (0x05ULL << 16) | 0xffff;   /* 0xffff selects the kernel-less logger */
    EXPECT_EQ(UN(EtwGetTraceEnableFlags)(hf), 0x01020304);
    EXPECT_EQ(UN(EtwGetTraceEnableLevel)(hf), 5);
    /* zero handle and out-of-range logger id: 0 and ERROR_INVALID_HANDLE */
    SET_ERR(0); EXPECT_EQ(UN(EtwGetTraceEnableFlags)(0), 0); EXPECT_ERR(6);
    SET_ERR(0); EXPECT_EQ(UN(EtwGetTraceEnableLevel)(0), 0); EXPECT_ERR(6);
    ULONGLONG bad = (0x11111111ULL << 32) | (0x22ULL << 16) | 0x7000;
    SET_ERR(0); EXPECT_EQ(UN(EtwGetTraceEnableFlags)(bad), 0); EXPECT_ERR(6);
    SET_ERR(0); EXPECT_EQ(UN(EtwGetTraceEnableLevel)(bad), 0); EXPECT_ERR(6);

    struct { ULONG size; ULONG prov; ULONGLONG hist; BYTE rest[0x28]; } w;
    memset(&w, 0, sizeof w);
    w.size = sizeof w;
    w.hist = 0x1234000000000003ULL;
    SET_ERR(0); EXPECT_EQ(UN(EtwGetTraceLoggerHandle)(&w), 0x1234000000000003ULL);
    w.hist = 0x00000000000000ffffULL;
    EXPECT_EQ(UN(EtwGetTraceLoggerHandle)(&w), 0xffff);
    w.hist = 0x7000;
    SET_ERR(0); EXPECT_EQ(UN(EtwGetTraceLoggerHandle)(&w), ~0ULL); EXPECT_ERR(6);
    w.hist = 1; w.size = 0x2f;
    SET_ERR(0); EXPECT_EQ(UN(EtwGetTraceLoggerHandle)(&w), ~0ULL); EXPECT_ERR(24);
    w.size = 0; 
    SET_ERR(0); EXPECT_EQ(UN(EtwGetTraceLoggerHandle)(&w), ~0ULL); EXPECT_ERR(24);
    w.size = 0x30;
    SET_ERR(0); EXPECT_EQ(UN(EtwGetTraceLoggerHandle)(&w), 1); 
    SET_ERR(0); EXPECT_EQ(UN(EtwGetTraceLoggerHandle)(NULL), ~0ULL); EXPECT_ERR(87);
}

TEST(etw_log_trace_event_errors)
{
    NEED(EtwLogTraceEvent); NEED(EtwTraceEventInstance);
    EXPECT_EQ(UN(EtwLogTraceEvent)(1, NULL), 87);
    EXPECT_EQ(UN(EtwLogTraceEvent)(0x1000001, NULL), 87);
    /* EtwTraceEventInstance: header >= 0x38 bytes, instance with a registration */
    BYTE hdr[0x80]; memset(hdr, 0, sizeof hdr);
    struct { PVOID reg; ULONG id; ULONG pad; } inst; BYTE regmem[0x40] = {0};
    inst.reg = regmem; inst.id = 1; inst.pad = 0;
    *(USHORT *)hdr = 0x38;
    EXPECT_EQ(UN(EtwTraceEventInstance)(1, NULL, &inst, NULL), 87);
    EXPECT_EQ(UN(EtwTraceEventInstance)(1, hdr, NULL, NULL), 87);
    *(USHORT *)hdr = 0x37;
    EXPECT_EQ(UN(EtwTraceEventInstance)(1, hdr, &inst, NULL), 87);
    *(USHORT *)hdr = 0;
    EXPECT_EQ(UN(EtwTraceEventInstance)(1, hdr, &inst, NULL), 87);
    *(USHORT *)hdr = 0x38;
    struct { PVOID reg; ULONG id; ULONG pad; } nullinst = {NULL, 1, 0};
    EXPECT_EQ(UN(EtwTraceEventInstance)(1, hdr, &nullinst, NULL), 87);
    EXPECT_EQ(UN(EtwTraceEventInstance)(1, hdr, &inst, &nullinst), 87);
    /* class 'continuation' header with a payload that is not a multiple of 16 */
    *(USHORT *)hdr = 0x38 + 8;
    *(ULONG *)(hdr + 0x2c) = 0x100000;
    EXPECT_EQ(UN(EtwTraceEventInstance)(1, hdr, &inst, NULL), 87);
    *(USHORT *)hdr = 0x38 + 0x110;
    EXPECT_EQ(UN(EtwTraceEventInstance)(1, hdr, &inst, NULL), 87);
}

static DWORD g_reqcb_dummy;
TEST(etw_register_trace_guids)
{
    NEED(EtwRegisterTraceGuidsW); NEED(EtwRegisterTraceGuidsA); NEED(EtwNotificationUnregister);
    RH h = 0x55;
    SET_ERR(0); EXPECT_EQ(UN(EtwRegisterTraceGuidsW)(NULL, NULL, &G1, 0, NULL, NULL, NULL, &h), 87); EXPECT_ERR(87);
    SET_ERR(0); EXPECT_EQ(UN(EtwRegisterTraceGuidsW)(reqcb, NULL, NULL, 0, NULL, NULL, NULL, &h), 87); EXPECT_ERR(87);
    SET_ERR(0); EXPECT_EQ(UN(EtwRegisterTraceGuidsW)(reqcb, NULL, &G1, 0, NULL, NULL, NULL, NULL), 87); EXPECT_ERR(87);
    SET_ERR(0); EXPECT_EQ(UN(EtwRegisterTraceGuidsW)(reqcb, NULL, &G1, 0x10001, NULL, NULL, NULL, &h), 87); EXPECT_ERR(87);
    SET_ERR(0); EXPECT_EQ(UN(EtwRegisterTraceGuidsA)(NULL, NULL, &G1, 0, NULL, NULL, NULL, &h), 87); EXPECT_ERR(87);
    SET_ERR(0); EXPECT_EQ(UN(EtwRegisterTraceGuidsA)(reqcb, NULL, NULL, 0, NULL, NULL, NULL, &h), 87); EXPECT_ERR(87);
    EXPECT_EQ(h, 0x55);
    ULONG r = UN(EtwRegisterTraceGuidsW)(reqcb, NULL, &G1, 0, NULL, NULL, NULL, &h);
    EXPECT_EQ(r, 0);
    CHECK(h != 0x55 && (h >> 48) != 0);
    if (r == 0) { EXPECT_EQ(UN(EtwNotificationUnregister)(h, NULL), 0); }
    h = 0x55;
    r = UN(EtwRegisterTraceGuidsA)(reqcb, NULL, &G2, 0, NULL, NULL, NULL, &h);
    EXPECT_EQ(r, 0);
    CHECK(h != 0x55 && (h >> 48) != 0);
    if (r == 0) { EXPECT_EQ(UN(EtwNotificationUnregister)(h, NULL), 0); }
}

TEST(etw_private_logger_request_short)
{
    NEED(EtwProcessPrivateLoggerRequest);
    ULONG buf[0x80]; memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(EtwProcessPrivateLoggerRequest)(buf, NULL, 0), 0x1071);
    buf[1] = 0xf7;
    EXPECT_EQ(UN(EtwProcessPrivateLoggerRequest)(buf, NULL, 0), 0x1071);
    memset(buf, 0, sizeof buf); buf[1] = 0xf8;
    ULONG r = UN(EtwProcessPrivateLoggerRequest)(buf, NULL, 0);
    EXPECT_EQ(r, 0);
}

UDECL(BOOLEAN, EtwCheckCoverage, (PVOID));
UDECL(ULONG, EtwSetMark, (ULONGLONG, PVOID, ULONG));
UDECL(ULONG, EtwTraceMessage, (ULONGLONG, ULONG, const GUID *, USHORT, ...));
UDECL(ULONG, EtwReplyNotification, (PVOID));
TEST(etw_check_coverage_no_sampler)
{
    NEED(EtwCheckCoverage);
    PBYTE peb = (PBYTE)NtCurrentTeb()->ProcessEnvironmentBlock;
    if (*(PVOID *)(peb + 0x7a0) != NULL) { t_skip("coverage sampler is active in this process"); return; }
    ULONG blk[8]; memset(blk, 0xab, sizeof blk);
    BOOLEAN r = UN(EtwCheckCoverage)(blk);
    EXPECT_EQ(r & 0xff, 0);
    EXPECT_EQ(blk[3], 0xabababab);        /* result slot untouched */
}

TEST(etw_logger_handle_zero_calls)
{
    /* logger handle 0 names no session: observed ERROR_INVALID_HANDLE from the kernel */
    BYTE mark[32] = {0};
    REQUIRE(UN(EtwSetMark)); REQUIRE(UN(EtwTraceMessage));
    EXPECT_EQ(UN(EtwSetMark)(0, mark, sizeof mark), 6);
    EXPECT_EQ(UN(EtwSetMark)(0, NULL, 0), 6);
    EXPECT_EQ(UN(EtwTraceMessage)(0, 0, &G1, 1, NULL, 0), 6);
    /* a zeroed notification header is rejected as a bad parameter (observed) */
    REQUIRE(UN(EtwReplyNotification));
    BYTE z[0x40] = {0};
    EXPECT_EQ(UN(EtwReplyNotification)(z), 87);
}

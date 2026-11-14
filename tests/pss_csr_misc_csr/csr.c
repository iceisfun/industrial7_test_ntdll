/* Csr* client-side helpers (capture buffers, message string capture, timeout conversion, region check,
 * and the stub routines). The test process is an ordinary console process, so the client connection to the
 * Windows subsystem already exists. See EVIDENCE.md. */
#include "t.h"
#include <tlhelp32.h>

#define ST_INV_PARAM ((NTSTATUS)0xC000000D)
#define ST_ILLEGAL_FN ((NTSTATUS)0xC00000AF)

UDECL(HANDLE, CsrGetProcessId, (void));
UDECL(PVOID, CsrAllocateCaptureBuffer, (ULONG, ULONG));
UDECL(ULONG, CsrAllocateMessagePointer, (PVOID, ULONG, PVOID *));
UDECL(VOID, CsrCaptureMessageBuffer, (PVOID, PVOID, ULONG, PVOID *));
UDECL(VOID, CsrCaptureMessageString, (PVOID, PVOID, ULONG, ULONG, PVOID));
UDECL(NTSTATUS, CsrCaptureMessageMultiUnicodeStringsInPlace, (PVOID *, ULONG, PUNICODE_STRING *));
UDECL(PLARGE_INTEGER, CsrCaptureTimeout, (ULONG, PLARGE_INTEGER));
UDECL(VOID, CsrFreeCaptureBuffer, (PVOID));
UDECL(BOOLEAN, CsrVerifyRegion, (PVOID, ULONG));
UDECL(NTSTATUS, CsrSetPriorityClass, (HANDLE, PULONG));
UDECL(NTSTATUS, CsrIdentifyAlertableThread, (void));
UDECL(NTSTATUS, CsrClientConnectToServer, (PWSTR, ULONG, PVOID, PULONG, PBOOLEAN));
UDECL(NTSTATUS, CsrClientCallServer, (PVOID, PVOID, ULONG, ULONG));

#define NEED(f) REQUIRE(UN(f))

TEST(process_id)
{
    NEED(CsrGetProcessId);
    ULONG_PTR pid = (ULONG_PTR)UN(CsrGetProcessId)();
    CHECK(pid != 0);
    EXPECT_EQ(UN(CsrGetProcessId)(), (HANDLE)pid);
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) { t_skip("process snapshot unavailable"); return; }
    PROCESSENTRY32W pe; pe.dwSize = sizeof pe;
    int found = 0;
    for (BOOL ok = Process32FirstW(s, &pe); ok; ok = Process32NextW(s, &pe))
        if (pe.th32ProcessID == pid) { found = 1; EXPECT_WSTR(pe.szExeFile, L"csrss.exe"); }
    CHECKF(found, "pid %llu not in process list", (unsigned long long)pid);
    CloseHandle(s);
}

TEST(alloc_capture_buffer)
{
    NEED(CsrAllocateCaptureBuffer); NEED(CsrFreeCaptureBuffer);
    BYTE *cb = UN(CsrAllocateCaptureBuffer)(2, 100);
    CHECK(cb != NULL);
    if (cb) {
        EXPECT_EQ(*(ULONG *)cb, 0x9c);               /* (100 + 0x23 + 2*11) & ~3 */
        EXPECT_EQ(*(ULONG *)(cb + 0x10), 0);         /* pointer count */
        EXPECT_EQ(*(BYTE **)(cb + 0x18), cb + 0x30); /* data area follows 2 pointer slots */
        EXPECT_EQ(*(ULONG64 *)(cb + 0x20), 0); EXPECT_EQ(*(ULONG64 *)(cb + 0x28), 0);
        UN(CsrFreeCaptureBuffer)(cb);
    }
    cb = UN(CsrAllocateCaptureBuffer)(0, 0);
    CHECK(cb != NULL);
    if (cb) {
        EXPECT_EQ(*(ULONG *)cb, 0x20);
        EXPECT_EQ(*(BYTE **)(cb + 0x18), cb + 0x20);
        UN(CsrFreeCaptureBuffer)(cb);
    }
    /* limits */
    EXPECT_EQ(UN(CsrAllocateCaptureBuffer)(0x10000000, 0), 0);
    EXPECT_EQ(UN(CsrAllocateCaptureBuffer)(0, 0x7fffffdc), 0);
    EXPECT_EQ(UN(CsrAllocateCaptureBuffer)(1, 0x7fffffd8), 0);
    EXPECT_EQ(UN(CsrAllocateCaptureBuffer)(0x0fffffff, 0), 0);
}

TEST(message_pointer_and_buffer)
{
    NEED(CsrAllocateCaptureBuffer); NEED(CsrFreeCaptureBuffer); NEED(CsrAllocateMessagePointer); NEED(CsrCaptureMessageBuffer);
    BYTE *cb = UN(CsrAllocateCaptureBuffer)(4, 100);
    if (!cb) { t_skip("no capture buffer"); return; }
    BYTE *data0 = *(BYTE **)(cb + 0x18);
    PVOID p1 = (PVOID)1, p2 = (PVOID)1, p3 = (PVOID)1;
    EXPECT_EQ(UN(CsrAllocateMessagePointer)(cb, 5, &p1), 8);        /* rounded up to 4 */
    EXPECT_EQ(p1, data0);
    EXPECT_EQ(*(ULONG *)(cb + 0x10), 1);
    EXPECT_EQ(*(PVOID *)(cb + 0x20), &p1);
    EXPECT_EQ(*(BYTE **)(cb + 0x18), data0 + 8);
    EXPECT_EQ(UN(CsrAllocateMessagePointer)(cb, 0, &p2), 0);        /* empty: NULL pointer, slot NULL */
    EXPECT_EQ(p2, 0);
    EXPECT_EQ(*(ULONG *)(cb + 0x10), 2);
    EXPECT_EQ(*(PVOID *)(cb + 0x28), 0);
    EXPECT_EQ(*(BYTE **)(cb + 0x18), data0 + 8);
    EXPECT_EQ(UN(CsrAllocateMessagePointer)(cb, 12, &p3), 12);
    EXPECT_EQ(p3, data0 + 8);
    EXPECT_EQ(*(ULONG *)(cb + 0x10), 3);

    /* CaptureMessageBuffer copies the bytes into the data area */
    PVOID p4 = NULL; const char src[] = "abcdefg";
    UN(CsrCaptureMessageBuffer)(cb, (PVOID)src, 7, &p4);
    EXPECT_EQ(p4, data0 + 20);
    CHECK(memcmp(p4, src, 7) == 0);
    EXPECT_EQ(*(ULONG *)(cb + 0x10), 4);
    EXPECT_EQ(*(BYTE **)(cb + 0x18), data0 + 28);
    UN(CsrFreeCaptureBuffer)(cb);
}

TEST(capture_message_string)
{
    NEED(CsrAllocateCaptureBuffer); NEED(CsrFreeCaptureBuffer); NEED(CsrCaptureMessageString);
    BYTE *cb = UN(CsrAllocateCaptureBuffer)(3, 100);
    if (!cb) { t_skip("no capture buffer"); return; }
    BYTE *data0 = *(BYTE **)(cb + 0x18);
    struct { USHORT Length, Max; ULONG pad; PCHAR Buffer; } s;
    memset(&s, 0xcc, sizeof s);
    UN(CsrCaptureMessageString)(cb, (PVOID)"hello!", 5, 6, &s);
    EXPECT_EQ(s.Length, 5);
    EXPECT_EQ(s.Max, 8);                          /* allocation rounded to 4 */
    EXPECT_EQ(s.Buffer, (PCHAR)data0);
    CHECK(memcmp(s.Buffer, "hello", 5) == 0);
    EXPECT_EQ(s.Buffer[5], 0);                    /* terminated when room remains */
    /* NULL source: empty string of the requested capacity */
    memset(&s, 0xcc, sizeof s);
    UN(CsrCaptureMessageString)(cb, NULL, 0, 10, &s);
    EXPECT_EQ(s.Length, 0);
    EXPECT_EQ(s.Max, 10);                         /* not rounded in this path */
    EXPECT_EQ(s.Buffer, (PCHAR)(data0 + 8));
    EXPECT_EQ(s.Buffer[0], 0);
    EXPECT_EQ(*(ULONG *)(cb + 0x10), 2);
    UN(CsrFreeCaptureBuffer)(cb);
}

TEST(capture_multi_unicode)
{
    NEED(CsrCaptureMessageMultiUnicodeStringsInPlace); NEED(CsrFreeCaptureBuffer);
    EXPECT_EQ(UN(CsrCaptureMessageMultiUnicodeStringsInPlace)(NULL, 1, NULL), ST_INV_PARAM);
    static WCHAR w1[4] = { 'A', 'B', 'C', 0 }, w2[2] = { 'x', 'y' };
    UNICODE_STRING u1 = { 4, 8, w1 }, u2 = { 2, 4, w2 };
    PUNICODE_STRING arr[3] = { &u1, NULL, &u2 };
    PVOID cb = NULL;
    NTSTATUS st = UN(CsrCaptureMessageMultiUnicodeStringsInPlace)(&cb, 3, arr);
    EXPECT_EQ(st, 0);
    CHECK(cb != NULL);
    if (cb) {
        CHECK(u1.Buffer != w1 && u2.Buffer != w2);
        EXPECT_EQ(u1.Length, 4); EXPECT_EQ(u1.MaximumLength, 8);
        EXPECT_EQ(u2.Length, 2); EXPECT_EQ(u2.MaximumLength, 4);
        CHECK(u1.Buffer[0] == 'A' && u1.Buffer[1] == 'B' && u1.Buffer[2] == 0);
        CHECK(u2.Buffer[0] == 'x' && u2.Buffer[1] == 0);
        CHECK((BYTE *)u1.Buffer >= (BYTE *)cb && (BYTE *)u1.Buffer < (BYTE *)cb + *(ULONG *)cb);
        EXPECT_EQ(*(ULONG *)((BYTE *)cb + 0x10), 2);    /* NULL array entries are skipped */
        UN(CsrFreeCaptureBuffer)(cb);
    }
}

TEST(timeout_and_simple_stubs)
{
    NEED(CsrCaptureTimeout); NEED(CsrSetPriorityClass); NEED(CsrIdentifyAlertableThread);
    LARGE_INTEGER li; li.QuadPart = 0x1234;
    EXPECT_EQ(UN(CsrCaptureTimeout)(-1, &li), 0);               /* infinite: NULL, untouched */
    EXPECT_EQ(li.QuadPart, 0x1234);
    EXPECT_EQ(UN(CsrCaptureTimeout)(100, &li), &li);
    EXPECT_EQ(li.QuadPart, -1000000LL);
    EXPECT_EQ(UN(CsrCaptureTimeout)(0, &li), &li);
    EXPECT_EQ(li.QuadPart, 0);
    EXPECT_EQ(UN(CsrCaptureTimeout)(1, &li), &li);
    EXPECT_EQ(li.QuadPart, -10000LL);
    EXPECT_EQ(UN(CsrCaptureTimeout)(0x7fffffff, &li), &li);
    EXPECT_EQ(li.QuadPart, -(LONGLONG)0x7fffffff * 10000);
    EXPECT_EQ(UN(CsrCaptureTimeout)(-2, &li), &li);             /* signed argument */
    EXPECT_EQ(li.QuadPart, 20000);

    ULONG pc = 0;
    EXPECT_EQ(UN(CsrSetPriorityClass)((HANDLE)-1, &pc), ST_INV_PARAM);
    EXPECT_EQ(UN(CsrSetPriorityClass)(NULL, NULL), ST_INV_PARAM);
    EXPECT_EQ(UN(CsrIdentifyAlertableThread)(), 0);
}

TEST(verify_region)
{
    NEED(CsrVerifyRegion);
    /* never valid: NULL, wrap-around, zero length at the very top */
    EXPECT_EQ(UN(CsrVerifyRegion)(NULL, 16) & 0xff, 0);
    EXPECT_EQ(UN(CsrVerifyRegion)((PVOID)(ULONG_PTR)-16, 0x20) & 0xff, 0);
    BYTE local[16];
    EXPECT_EQ(UN(CsrVerifyRegion)(local, sizeof local) & 0xff, 0);   /* a stack buffer is not in the read-only shared area */
    PVOID base = *(PVOID *)((BYTE *)NtCurrentTeb()->ProcessEnvironmentBlock + 0x88);
    t_note("PEB.ReadOnlySharedMemoryBase=%p VerifyRegion(base,1)=%d", base, UN(CsrVerifyRegion)(base, 1) & 0xff);
    if (base) {
        EXPECT_EQ(UN(CsrVerifyRegion)(base, 1) & 0xff, 1);          /* first byte of the read-only shared area */
        EXPECT_EQ(UN(CsrVerifyRegion)(base, 0) & 0xff, 0);          /* zero length wraps below the base */
        EXPECT_EQ(UN(CsrVerifyRegion)((BYTE *)base - 1, 1) & 0xff, 0);
    }
}

TEST(client_connect_and_call)
{
    NEED(CsrClientConnectToServer); NEED(CsrClientCallServer);
    BOOLEAN b = 7;
    /* already connected client, no connection info: nothing to do, not a server-to-server call */
    EXPECT_EQ(UN(CsrClientConnectToServer)(NULL, 0, NULL, NULL, &b), 0);
    EXPECT_EQ(b, 0);
    EXPECT_EQ(UN(CsrClientConnectToServer)(NULL, 0, NULL, NULL, NULL), 0);
    /* connection info without a size is rejected before anything is sent */
    BYTE info[8] = {0};
    EXPECT_EQ(UN(CsrClientConnectToServer)(NULL, 0, info, NULL, &b), ST_INV_PARAM);

    /* an API number outside every server DLL's table is refused by the subsystem */
    BYTE msg[0x100]; memset(msg, 0, sizeof msg);
    NTSTATUS st = UN(CsrClientCallServer)(msg, NULL, (1u << 16) | 0xFFFF, 0x20);
    EXPECT_EQ(st, ST_ILLEGAL_FN);
    EXPECT_EQ(*(ULONG *)(msg + 0x34), (ULONG)ST_ILLEGAL_FN);
    EXPECT_EQ(*(ULONG *)(msg + 0x30), 0x1ffff);
    EXPECT_EQ(*(ULONG *)msg, 0x00600038);                      /* total/data length prepared in the PORT_MESSAGE */
}

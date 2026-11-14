/* Zw-named legacy LPC port services: a purpose-built server thread and client in this process. */
#include "t.h"

typedef struct {
    USHORT DataLength, TotalLength, Type, DataInfoOffset;
    HANDLE Pid, Tid;
    ULONG MessageId; ULONG pad;
    ULONG_PTR ClientViewSize;
} PM;                                  /* PORT_MESSAGE, 40 bytes on x64 */
typedef struct { PM h; char d[64]; } LMSG;
typedef struct { ULONG Length; SECURITY_IMPERSONATION_LEVEL L; UCHAR Mode; BOOLEAN Eff; } SQOS;

#define LPC_REQUEST 1
#define LPC_REPLY 2
#define LPC_DATAGRAM 3
#define LPC_CLIENT_DIED 6
#define LPC_PORT_CLOSED 7
#define LPC_CONNECTION_REQUEST 10

UDECL(NTSTATUS, NtCreatePort, (PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtConnectPort, (PHANDLE, PUNICODE_STRING, SQOS *, PVOID, PVOID, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, ZwSecureConnectPort, (PHANDLE, PUNICODE_STRING, SQOS *, PVOID, PSID, PVOID, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, NtAcceptConnectPort, (PHANDLE, PVOID, PM *, BOOLEAN, PVOID, PVOID));
UDECL(NTSTATUS, NtCompleteConnectPort, (HANDLE));
UDECL(NTSTATUS, ZwReplyWaitReceivePort, (HANDLE, PVOID *, PM *, PM *));
UDECL(NTSTATUS, ZwReplyWaitReceivePortEx, (HANDLE, PVOID *, PM *, PM *, PLARGE_INTEGER));
UDECL(NTSTATUS, ZwRequestPort, (HANDLE, PM *));
UDECL(NTSTATUS, ZwRequestWaitReplyPort, (HANDLE, PM *, PM *));
UDECL(NTSTATUS, ZwReplyPort, (HANDLE, PM *));
UDECL(NTSTATUS, ZwReplyWaitReplyPort, (HANDLE, PM *));
UDECL(NTSTATUS, ZwReadRequestData, (HANDLE, PM *, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, ZwWriteRequestData, (HANDLE, PM *, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, ZwRegisterThreadTerminatePort, (HANDLE));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtClose, (HANDLE));

static void RtlInitUnicodeString_(PUNICODE_STRING d, PCWSTR s) { d->Buffer = (PWSTR)s; d->Length = (USHORT)(lstrlenW(s) * 2); d->MaximumLength = d->Length + 2; }
#include <wchar.h>
#define S(x) ((NTSTATUS)(x))
#define BAD_HANDLE S(0xc0000008)
#define BAD_PARAM S(0xc000000d)
#define WRONG_TYPE S(0xc0000024)
#define TIMEOUT S(0x102)

static LARGE_INTEGER rel_ms(LONG ms) { LARGE_INTEGER t; t.QuadPart = -(LONGLONG)ms * 10000; return t; }
static int have_all(void)
{
    return UN(NtCreatePort) && UN(NtConnectPort) && UN(NtAcceptConnectPort) && UN(NtCompleteConnectPort) &&
        UN(ZwReplyWaitReceivePort) && UN(ZwReplyWaitReceivePortEx) && UN(ZwRequestPort) && UN(ZwRequestWaitReplyPort) &&
        UN(ZwReplyPort) && UN(ZwReplyWaitReplyPort) && UN(ZwReadRequestData) && UN(ZwWriteRequestData) &&
        UN(ZwRegisterThreadTerminatePort) && UN(ZwSecureConnectPort) && UN(NtClose);
}

TEST(zw_port_aliases)
{
    static const char *names[] = { "ReplyPort", "ReplyWaitReceivePort", "ReplyWaitReceivePortEx", "ReplyWaitReplyPort",
        "RequestPort", "RequestWaitReplyPort", "ReadRequestData", "WriteRequestData", "SecureConnectPort",
        "RegisterThreadTerminatePort" };
    unsigned i;
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        char nt[80], zw[80]; FARPROC a, b;
        snprintf(nt, sizeof nt, "Nt%s", names[i]); snprintf(zw, sizeof zw, "Zw%s", names[i]);
        a = t_proc(nt); b = t_proc(zw);
        CHECKF(a != NULL && b != NULL, "%s exported", zw);
        CHECKF(a == b, "%s and %s share an address", nt, zw);
    }
}

TEST(zw_port_invalid_handles)
{
    LMSG m, r; PVOID ctx = NULL; SIZE_T n; LARGE_INTEGER z = {0}; HANDLE ev = NULL; HANDLE bad = (HANDLE)(ULONG_PTR)0x7ffffff4;
    REQUIRE(have_all()); REQUIRE(UN(NtCreateEvent));
    memset(&m, 0, sizeof m); memset(&r, 0, sizeof r);
    m.h.DataLength = 8; m.h.TotalLength = sizeof(PM) + 8;
    EXPECT_EQ(UN(ZwRequestPort)(NULL, &m.h), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRequestPort)(bad, &m.h), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRequestWaitReplyPort)(NULL, &m.h, &r.h), BAD_HANDLE);
    EXPECT_EQ(UN(ZwReplyPort)(NULL, &m.h), BAD_HANDLE);
    EXPECT_EQ(UN(ZwReplyWaitReceivePort)(NULL, &ctx, NULL, &r.h), BAD_HANDLE);
    EXPECT_EQ(UN(ZwReplyWaitReceivePortEx)(NULL, &ctx, NULL, &r.h, &z), BAD_HANDLE);
    EXPECT_EQ(UN(ZwReplyWaitReplyPort)(NULL, &m.h), BAD_HANDLE);
    EXPECT_EQ(UN(ZwReadRequestData)(NULL, &m.h, 0, r.d, 8, &n), BAD_PARAM); /* message validated before the handle */
    EXPECT_EQ(UN(ZwWriteRequestData)(NULL, &m.h, 0, r.d, 8, &n), BAD_PARAM);
    EXPECT_EQ(UN(ZwRegisterThreadTerminatePort)(NULL), BAD_HANDLE);
    EXPECT_EQ(UN(ZwRegisterThreadTerminatePort)(bad), BAD_HANDLE);
    if (UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, NULL, 0, FALSE) >= 0) {
        EXPECT_EQ(UN(ZwRequestPort)(ev, &m.h), WRONG_TYPE);
        EXPECT_EQ(UN(ZwRequestWaitReplyPort)(ev, &m.h, &r.h), WRONG_TYPE);
        EXPECT_EQ(UN(ZwReplyPort)(ev, &m.h), WRONG_TYPE);
        EXPECT_EQ(UN(ZwReplyWaitReceivePort)(ev, &ctx, NULL, &r.h), WRONG_TYPE);
        EXPECT_EQ(UN(ZwReplyWaitReceivePortEx)(ev, &ctx, NULL, &r.h, &z), WRONG_TYPE);
        EXPECT_EQ(UN(ZwReplyWaitReplyPort)(ev, &m.h), WRONG_TYPE);
        EXPECT_EQ(UN(ZwReadRequestData)(ev, &m.h, 0, r.d, 8, &n), BAD_PARAM);
        EXPECT_EQ(UN(ZwWriteRequestData)(ev, &m.h, 0, r.d, 8, &n), BAD_PARAM);
        EXPECT_EQ(UN(ZwRegisterThreadTerminatePort)(ev), WRONG_TYPE);
        UN(NtClose)(ev);
    }
}

static HANDLE g_port, g_comm;
static volatile LONG g_ready, g_done, g_requests, g_datagrams, g_closed, g_died, g_wait_dgram;
static volatile NTSTATUS g_srv_status, g_wr_status;
static char g_dgram[16], g_wdgram[16];

static DWORD WINAPI server(PVOID arg)
{
    LMSG msg, out; PVOID ctx = NULL; PM *reply = NULL; int iter; NTSTATUS s;
    LARGE_INTEGER to = rel_ms(5000);
    memset(&out, 0, sizeof out);
    for (iter = 0; iter < 40; iter++) {
        memset(&msg, 0, sizeof msg);
        s = UN(ZwReplyWaitReceivePortEx)(g_port, &ctx, reply, &msg.h, &to);
        reply = NULL;
        if (s == TIMEOUT) { g_srv_status = s; break; }
        if (s < 0) { g_srv_status = s; break; }
        if (msg.h.Type == LPC_CONNECTION_REQUEST) {
            HANDLE c = NULL;
            s = UN(NtAcceptConnectPort)(&c, (PVOID)0xabcd, &msg.h, TRUE, NULL, NULL);
            if (s >= 0) { if (!g_comm) g_comm = c; UN(NtCompleteConnectPort)(c); }
            InterlockedIncrement(&g_ready);
            g_srv_status = s;
        } else if ((msg.h.Type & 0xff) == LPC_REQUEST) {
            int i; InterlockedIncrement(&g_requests);
            out = msg;
            for (i = 0; i < msg.h.DataLength && i < 64; i++) out.d[i] = (char)(msg.d[i] + 1);
            if (msg.d[0] == 'P') { /* reply straight on the communication port */
                s = UN(ZwReplyPort)(g_comm, &out.h);
                g_srv_status = s;
            } else if (msg.d[0] == 'W') { /* reply and wait on the communication port for the next client message */
                LMSG nxt = out;
                s = UN(ZwReplyWaitReplyPort)(g_comm, &nxt.h);
                g_wr_status = s; InterlockedIncrement(&g_wait_dgram);
            } else reply = &out.h;
        } else if ((msg.h.Type & 0xff) == LPC_DATAGRAM) {
            memcpy(g_dgram, msg.d, 8); InterlockedIncrement(&g_datagrams);
        } else if ((msg.h.Type & 0xff) == LPC_PORT_CLOSED) {
            InterlockedIncrement(&g_closed); break;
        } else if ((msg.h.Type & 0xff) == LPC_CLIENT_DIED) {
            InterlockedIncrement(&g_died);
        }
    }
    InterlockedExchange(&g_done, 1);
    return 0;
}

static void wait_for(volatile LONG *v, LONG n, int ms)
{
    int i; for (i = 0; i < ms / 10 && *v < n; i++) Sleep(10);
}

TEST(zw_port_round_trip)
{
    WCHAR name[96]; UNICODE_STRING us; OBJECT_ATTRIBUTES oa; NTSTATUS s; HANDLE cli = NULL, th, cli2 = NULL;
    SQOS q = { sizeof q, SecurityImpersonation, 1, TRUE };
    LMSG req, rep; ULONG maxlen = 0, i; SIZE_T n;
    REQUIRE(have_all());
    g_port = g_comm = NULL; g_wr_status = 0; g_ready = g_done = g_requests = g_datagrams = g_closed = g_died = g_wait_dgram = 0; g_srv_status = 0;
    memset(g_dgram, 0, sizeof g_dgram); memset(g_wdgram, 0, sizeof g_wdgram);
    swprintf(name, 96, L"\\RPC Control\\ntdllt_lpc_%lu", GetCurrentProcessId());
    RtlInitUnicodeString_(&us, name);
    memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &us; oa.Attributes = OBJ_CASE_INSENSITIVE;
    s = UN(NtCreatePort)(&g_port, &oa, 0, 0x148, 0);
    if (s < 0) { t_skip("port creation failed %08lx", (ULONG)s); return; }
    th = CreateThread(NULL, 0, server, NULL, 0, NULL);
    if (!th) { t_skip("CreateThread failed"); UN(NtClose)(g_port); return; }
    s = UN(NtConnectPort)(&cli, &us, &q, NULL, NULL, &maxlen, NULL, NULL);
    EXPECT_EQ(s, 0);
    if (s < 0) goto out;
    wait_for(&g_ready, 1, 5000);
    EXPECT_EQ(g_ready, 1); EXPECT_EQ(g_srv_status, 0);
    CHECKF(maxlen >= 0x100, "negotiated max message length %lu", maxlen);

    /* request / reply through ReplyWaitReceivePort */
    memset(&req, 0, sizeof req); memset(&rep, 0, sizeof rep);
    req.h.DataLength = 8; req.h.TotalLength = sizeof(PM) + 8; memcpy(req.d, "abcdefg", 8);
    s = UN(ZwRequestWaitReplyPort)(cli, &req.h, &rep.h);
    EXPECT_EQ(s, 0);
    EXPECT_EQ(rep.h.Type & 0xff, LPC_REPLY);
    EXPECT_EQ(rep.h.DataLength, 8);
    EXPECT_EQ(rep.h.TotalLength, sizeof(PM) + 8);
    CHECK(rep.h.MessageId != 0);
    EXPECT_EQ(rep.d[0], 'b'); EXPECT_EQ(rep.d[1], 'c'); EXPECT_EQ(rep.d[6], 'h');
    EXPECT_EQ(g_requests, 1);

    /* reply through ZwReplyPort on the communication port */
    memset(&req, 0, sizeof req); memset(&rep, 0, sizeof rep);
    req.h.DataLength = 8; req.h.TotalLength = sizeof(PM) + 8; memcpy(req.d, "Pxyzabc", 8);
    EXPECT_EQ(UN(ZwRequestWaitReplyPort)(cli, &req.h, &rep.h), 0);
    EXPECT_EQ(rep.d[0], 'Q'); EXPECT_EQ(rep.d[1], 'y'); EXPECT_EQ(g_requests, 2);

    /* datagram: no reply */
    memset(&req, 0, sizeof req);
    req.h.DataLength = 8; req.h.TotalLength = sizeof(PM) + 8; memcpy(req.d, "datagram", 8);
    EXPECT_EQ(UN(ZwRequestPort)(cli, &req.h), 0);
    wait_for(&g_datagrams, 1, 5000);
    EXPECT_EQ(g_datagrams, 1);
    EXPECT_EQ(memcmp(g_dgram, "datagram", 8), 0);

    /* invalid messages */
    memset(&req, 0, sizeof req);
    req.h.DataLength = 8; req.h.TotalLength = 8;           /* shorter than the header */
    EXPECT_EQ(UN(ZwRequestPort)(cli, &req.h), BAD_PARAM);
    req.h.DataLength = 8; req.h.TotalLength = sizeof(PM) + 4; /* data longer than the total */
    EXPECT_EQ(UN(ZwRequestPort)(cli, &req.h), BAD_PARAM);
    req.h.DataLength = 0x400; req.h.TotalLength = sizeof(PM) + 0x400; /* beyond the port maximum */
    s = UN(ZwRequestPort)(cli, &req.h);
    EXPECT_EQ(s, S(0xc000002f)); /* STATUS_PORT_MESSAGE_TOO_LONG */

    /* data-transfer services on a message that carries no data entries */
    { char b[16];
      n = 77; s = UN(ZwReadRequestData)(g_comm, &req.h, 0, b, sizeof b, &n);
      EXPECT_EQ(s, BAD_PARAM);
      n = 77; s = UN(ZwWriteRequestData)(g_comm, &req.h, 0, b, sizeof b, &n);
      EXPECT_EQ(s, BAD_PARAM); }

    /* thread termination registration */
    EXPECT_EQ(UN(ZwRegisterThreadTerminatePort)(cli), 0);

    /* second client through the secure connect form */
    maxlen = 0;
    s = UN(ZwSecureConnectPort)(&cli2, &us, &q, NULL, NULL, NULL, &maxlen, NULL, NULL);
    EXPECT_EQ(s, 0);
    if (s >= 0) { wait_for(&g_ready, 2, 5000); EXPECT_EQ(g_ready, 2); UN(NtClose)(cli2); }
    /* nobody is listening on a name that does not exist */
    { UNICODE_STRING nx; static WCHAR nn[] = L"\\RPC Control\\ntdllt_lpc_nonexistent_port"; HANDLE hx = NULL;
      nx.Buffer = nn; nx.Length = sizeof nn - 2; nx.MaximumLength = sizeof nn;
      EXPECT_EQ(UN(NtConnectPort)(&hx, &nx, &q, NULL, NULL, NULL, NULL, NULL), S(0xc0000034)); EXPECT_EQ(hx, 0);
      EXPECT_EQ(UN(ZwSecureConnectPort)(&hx, &nx, &q, NULL, NULL, NULL, NULL, NULL, NULL), S(0xc0000034)); }
    /* reply-and-wait on the communication port: the request is answered, then the server blocks waiting for a
       reply to a callback; closing the client end releases it with an error status */
    memset(&req, 0, sizeof req); memset(&rep, 0, sizeof rep);
    req.h.DataLength = 8; req.h.TotalLength = sizeof(PM) + 8; memcpy(req.d, "Wait....", 8);
    EXPECT_EQ(UN(ZwRequestWaitReplyPort)(cli, &req.h, &rep.h), 0);
    EXPECT_EQ(rep.d[0], 'X');
    Sleep(200);
    EXPECT_EQ(g_wait_dgram, 0);       /* still blocked */
    UN(NtClose)(cli); cli = NULL;
    wait_for(&g_wait_dgram, 1, 5000);
    EXPECT_EQ(g_wait_dgram, 1);
    EXPECT_EQ(g_wr_status, S(0xc0000253)); /* STATUS_PORT_DISCONNECTED */
out:
    if (cli) UN(NtClose)(cli);
    /* wake the server if it has not already ended: closing the server port ends its wait */
    WaitForSingleObject(th, 3000);
    if (!g_done) { UN(NtClose)(g_port); g_port = NULL; WaitForSingleObject(th, 8000); }
    CloseHandle(th);
    if (g_comm) UN(NtClose)(g_comm);
    if (g_port) UN(NtClose)(g_port);
    g_comm = g_port = NULL;
}

TEST(zw_port_receive_timeout)
{
    WCHAR name[96]; UNICODE_STRING us; OBJECT_ATTRIBUTES oa; HANDLE port = NULL; LMSG m; PVOID ctx; LARGE_INTEGER t = rel_ms(30);
    REQUIRE(have_all());
    swprintf(name, 96, L"\\RPC Control\\ntdllt_lpc_to_%lu", GetCurrentProcessId());
    RtlInitUnicodeString_(&us, name);
    memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &us; oa.Attributes = OBJ_CASE_INSENSITIVE;
    if (UN(NtCreatePort)(&port, &oa, 0, 0x148, 0) < 0) { t_skip("port creation failed"); return; }
    memset(&m, 0, sizeof m);
    EXPECT_EQ(UN(ZwReplyWaitReceivePortEx)(port, &ctx, NULL, &m.h, &t), TIMEOUT);
    t.QuadPart = 0;
    EXPECT_EQ(UN(ZwReplyWaitReceivePortEx)(port, &ctx, NULL, &m.h, &t), TIMEOUT);
    /* a server port cannot be used to send a request */
    m.h.DataLength = 8; m.h.TotalLength = sizeof(PM) + 8;
    t_note("ZwRequestPort on a server connection port: %08lx", (ULONG)UN(ZwRequestPort)(port, &m.h));
    UN(NtClose)(port);
}

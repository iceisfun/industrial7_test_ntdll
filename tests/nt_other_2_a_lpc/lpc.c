/* Legacy LPC port calls: a real server/client exchange (listen, accept, request, reply, datagram,
 * secure connect, close notification) plus argument validation for every message call.
 * Expected values: see EVIDENCE.md. */
#include "t.h"

#define S(x) ((NTSTATUS)(x))
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_TYPE_MISM    S(0xC0000024)
#define ST_TIMEOUT      S(0x102)
#define BOGUS ((HANDLE)(ULONG_PTR)0x7ffffff4)

typedef struct {
    USHORT DataLength, TotalLength, Type, DataInfoOffset;
    PVOID ClientProcess, ClientThread;
    ULONG MessageId; ULONG pad;
    ULONG_PTR ClientViewSize;
} PM;
typedef struct { PM h; char data[200]; } LMSG;
#define LPC_REQUEST 1
#define LPC_REPLY 2
#define LPC_DATAGRAM 3
#define LPC_PORT_CLOSED 5
#define LPC_CONNECTION_REQUEST 10

UDECL(NTSTATUS, NtCreatePort, (PHANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtSecureConnectPort, (PHANDLE, PUNICODE_STRING, PSECURITY_QUALITY_OF_SERVICE, PVOID, PSID, PVOID, PULONG, PVOID, PULONG));
UDECL(NTSTATUS, NtAcceptConnectPort, (PHANDLE, PVOID, PVOID, BOOLEAN, PVOID, PVOID));
UDECL(NTSTATUS, NtCompleteConnectPort, (HANDLE));
UDECL(NTSTATUS, NtRequestPort, (HANDLE, PVOID));
UDECL(NTSTATUS, NtReplyPort, (HANDLE, PVOID));
UDECL(NTSTATUS, NtRequestWaitReplyPort, (HANDLE, PVOID, PVOID));
UDECL(NTSTATUS, NtReplyWaitReceivePort, (HANDLE, PVOID *, PVOID, PVOID));
UDECL(NTSTATUS, NtReplyWaitReceivePortEx, (HANDLE, PVOID *, PVOID, PVOID, PLARGE_INTEGER));
UDECL(NTSTATUS, NtReplyWaitReplyPort, (HANDLE, PVOID));
UDECL(NTSTATUS, NtRegisterThreadTerminatePort, (HANDLE));
UDECL(NTSTATUS, NtWriteRequestData, (HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(VOID, RtlInitUnicodeString, (PUNICODE_STRING, PCWSTR));

#define EXPECT_ST(call, want) do { NTSTATUS st_ = (call); t_check(st_ == (NTSTATUS)(want), __FILE__, __LINE__, #call " == " #want, "got 0x%lx want 0x%lx", (unsigned long)st_, (unsigned long)(NTSTATUS)(want)); } while (0)
#define NEED() do { REQUIRE(UN(NtCreatePort)); REQUIRE(UN(NtSecureConnectPort)); REQUIRE(UN(NtAcceptConnectPort)); REQUIRE(UN(NtCompleteConnectPort)); \
    REQUIRE(UN(NtRequestPort)); REQUIRE(UN(NtReplyPort)); REQUIRE(UN(NtRequestWaitReplyPort)); REQUIRE(UN(NtReplyWaitReceivePort)); \
    REQUIRE(UN(NtReplyWaitReceivePortEx)); REQUIRE(UN(NtReplyWaitReplyPort)); REQUIRE(UN(NtRegisterThreadTerminatePort)); REQUIRE(UN(RtlInitUnicodeString)); } while (0)

static void fill(LMSG *m, const char *txt)
{
    memset(m, 0, sizeof *m);
    m->h.DataLength = (USHORT)strlen(txt) + 1;
    m->h.TotalLength = (USHORT)(sizeof(PM) + m->h.DataLength);
    memcpy(m->data, txt, m->h.DataLength);
}

TEST(port_calls_invalid_handles)
{
    NEED();
    LMSG m, r; fill(&m, "x"); fill(&r, "y");
    PVOID ctx = NULL; LARGE_INTEGER zero = {0};
    EXPECT_ST(UN(NtRequestPort)(BOGUS, &m), ST_INV_HANDLE);
    EXPECT_ST(UN(NtReplyPort)(BOGUS, &m), ST_INV_HANDLE);
    EXPECT_ST(UN(NtRequestWaitReplyPort)(BOGUS, &m, &r), ST_INV_HANDLE);
    EXPECT_ST(UN(NtReplyWaitReceivePort)(BOGUS, &ctx, NULL, &r), ST_INV_HANDLE);
    EXPECT_ST(UN(NtReplyWaitReceivePortEx)(BOGUS, &ctx, NULL, &r, &zero), ST_INV_HANDLE);
    EXPECT_ST(UN(NtReplyWaitReplyPort)(BOGUS, &m), ST_INV_HANDLE);
    EXPECT_ST(UN(NtRegisterThreadTerminatePort)(BOGUS), ST_INV_HANDLE);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_ST(UN(NtRequestPort)(ev, &m), ST_TYPE_MISM);
    EXPECT_ST(UN(NtReplyPort)(ev, &m), ST_TYPE_MISM);
    EXPECT_ST(UN(NtRequestWaitReplyPort)(ev, &m, &r), ST_TYPE_MISM);
    EXPECT_ST(UN(NtReplyWaitReceivePort)(ev, &ctx, NULL, &r), ST_TYPE_MISM);
    EXPECT_ST(UN(NtReplyWaitReceivePortEx)(ev, &ctx, NULL, &r, &zero), ST_TYPE_MISM);
    EXPECT_ST(UN(NtReplyWaitReplyPort)(ev, &m), ST_TYPE_MISM);
    EXPECT_ST(UN(NtRegisterThreadTerminatePort)(ev), ST_TYPE_MISM);
    if (UN(NtWriteRequestData)) {
        SIZE_T ret = 0xcc; char buf[8] = "data";
        /* the message (no data-info descriptor) is rejected before the handle is looked at */
        EXPECT_ST(UN(NtWriteRequestData)(BOGUS, &m, 0, buf, sizeof buf, &ret), S(0xC000000D));
        EXPECT_ST(UN(NtWriteRequestData)(ev, &m, 0, buf, sizeof buf, &ret), S(0xC000000D));
        CHECK(t_proc("NtWriteRequestData") == t_proc("ZwWriteRequestData"));
    }
    CloseHandle(ev);
    /* accept with a message that never came from a connection request */
    HANDLE h = NULL;
    NTSTATUS st = UN(NtAcceptConnectPort)(&h, NULL, &m, TRUE, NULL, NULL);
    EXPECT_ST(st, S(0xC000021F));     /* STATUS_REPLY_MESSAGE_MISMATCH: not a pending connection request */
    CHECK(h == NULL);
    /* connect to a port name that does not exist */
    UNICODE_STRING nm; UN(RtlInitUnicodeString)(&nm, L"\\RPC Control\\NoSuchPortNtOther2a");
    SECURITY_QUALITY_OF_SERVICE q = { sizeof q, SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE };
    ULONG maxlen = 0;
    st = UN(NtSecureConnectPort)(&h, &nm, &q, NULL, NULL, NULL, &maxlen, NULL, NULL);
    EXPECT_ST(st, S(0xC0000034));   /* STATUS_OBJECT_NAME_NOT_FOUND */
    CHECK(h == NULL);
    UN(RtlInitUnicodeString)(&nm, L"\\NoSuchDirNtOther2a\\Port");
    st = UN(NtSecureConnectPort)(&h, &nm, &q, NULL, NULL, NULL, &maxlen, NULL, NULL);
    EXPECT_ST(st, S(0xC000003A));   /* STATUS_OBJECT_PATH_NOT_FOUND */
    CHECK(t_proc("NtRequestPort") == t_proc("ZwRequestPort"));
    CHECK(t_proc("NtReplyPort") == t_proc("ZwReplyPort"));
    CHECK(t_proc("NtRequestWaitReplyPort") == t_proc("ZwRequestWaitReplyPort"));
    CHECK(t_proc("NtReplyWaitReceivePort") == t_proc("ZwReplyWaitReceivePort"));
    CHECK(t_proc("NtReplyWaitReceivePortEx") == t_proc("ZwReplyWaitReceivePortEx"));
    CHECK(t_proc("NtReplyWaitReplyPort") == t_proc("ZwReplyWaitReplyPort"));
    CHECK(t_proc("NtRegisterThreadTerminatePort") == t_proc("ZwRegisterThreadTerminatePort"));
    CHECK(t_proc("NtSecureConnectPort") == t_proc("ZwSecureConnectPort"));
    CHECK(t_proc("NtAcceptConnectPort") == t_proc("ZwAcceptConnectPort"));
}

typedef struct {
    HANDLE port, conn;
    volatile LONG ready, done;
    NTSTATUS st_accept, st_complete, st_reply1, st_reply2;
    ULONG n_requests, n_datagrams, saw_closed, conn_type;
    PVOID ctx_seen;
} srv_t;

static DWORD WINAPI server_main(LPVOID p)
{
    srv_t *s = p;
    LMSG in, out; PVOID ctx = NULL; LARGE_INTEGER to; to.QuadPart = -50000000LL; /* 5 s */
    int have_reply = 0;
    InterlockedExchange(&s->ready, 1);
    NTSTATUS st = UN(NtReplyWaitReceivePortEx)(s->port, &ctx, NULL, &in, &to);
    if (st) { s->done = 1; return 1; }
    s->conn_type = in.h.Type;
    if (in.h.Type != LPC_CONNECTION_REQUEST) { s->done = 1; return 2; }
    s->st_accept = UN(NtAcceptConnectPort)(&s->conn, (PVOID)(ULONG_PTR)0xABCD, &in, TRUE, NULL, NULL);
    s->st_complete = UN(NtCompleteConnectPort)(s->conn);
    int round = 0;
    for (;;) {
        /* the first loop iteration uses the timed variant, later ones the plain one (the client closes the port at the end) */
        if (round == 0) st = UN(NtReplyWaitReceivePortEx)(s->port, &ctx, have_reply ? &out : NULL, &in, &to);
        else st = UN(NtReplyWaitReceivePort)(s->port, &ctx, have_reply ? &out : NULL, &in);
        have_reply = 0;
        if (st) break;
        if (in.h.Type == LPC_REQUEST) {
            s->n_requests++; s->ctx_seen = ctx;
            out = in;
            for (USHORT i = 0; i < in.h.DataLength && i < sizeof in.data; i++) out.data[i] = in.data[i] + 1;
            if (round++ == 0) {
                /* answer the first request with an explicit NtReplyPort, the second via the next receive */
                s->st_reply1 = UN(NtReplyPort)(s->conn, &out);
            } else have_reply = 1;
        } else if (in.h.Type == LPC_DATAGRAM) {
            s->n_datagrams++;
        } else if (in.h.Type == LPC_PORT_CLOSED) {
            s->saw_closed = 1; break;
        }
    }
    s->done = 1;
    return 0;
}

TEST(port_exchange)
{
    NEED();
    WCHAR name[96]; wsprintfW(name, L"\\RPC Control\\NtOther2aPort_%lu", GetCurrentProcessId());
    UNICODE_STRING us; UN(RtlInitUnicodeString)(&us, name);
    OBJECT_ATTRIBUTES oa; memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &us; oa.Attributes = 0x40;
    srv_t srv; memset(&srv, 0, sizeof srv);
    NTSTATUS st = UN(NtCreatePort)(&srv.port, &oa, 0, 0x100, 0);
    if (st) { t_skip("NtCreatePort status 0x%lx", (unsigned long)st); return; }
    HANDLE th = CreateThread(NULL, 0, server_main, &srv, 0, NULL);
    REQUIRE(th);
    while (!srv.ready) Sleep(1);
    SECURITY_QUALITY_OF_SERVICE q = { sizeof q, SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE };
    HANDLE client = NULL; ULONG maxlen = 0;
    st = UN(NtSecureConnectPort)(&client, &us, &q, NULL, NULL, NULL, &maxlen, NULL, NULL);
    EXPECT_ST(st, 0);
    if (st) { WaitForSingleObject(th, 6000); CloseHandle(th); UN(NtClose)(srv.port); return; }
    EXPECT_EQ(maxlen, 0x100);   /* the server's maximum message length */
    EXPECT_ST(srv.st_accept, 0);
    EXPECT_ST(srv.st_complete, 0);
    EXPECT_EQ(srv.conn_type, LPC_CONNECTION_REQUEST);
    /* request 1 (answered with NtReplyPort), request 2 (answered through the next receive) */
    for (int i = 0; i < 2; i++) {
        LMSG req, rep; fill(&req, "abc"); memset(&rep, 0xcc, sizeof rep);
        st = UN(NtRequestWaitReplyPort)(client, &req, &rep);
        EXPECT_ST(st, 0);
        EXPECT_EQ(rep.h.Type, LPC_REPLY);
        EXPECT_EQ(rep.h.DataLength, 4);
        CHECK(!memcmp(rep.data, "bcd\x01", 4));   /* server adds one to every byte, terminator included */
        CHECK(rep.h.MessageId != 0);
    }
    /* datagram: no reply */
    LMSG dg; fill(&dg, "dgram");
    EXPECT_ST(UN(NtRequestPort)(client, &dg), 0);
    /* a third request guarantees the datagram has been consumed first */
    { LMSG req, rep; fill(&req, "z"); EXPECT_ST(UN(NtRequestWaitReplyPort)(client, &req, &rep), 0); }
    EXPECT_ST(srv.st_reply1, 0);
    EXPECT_EQ(srv.n_requests, 3);
    EXPECT_EQ(srv.n_datagrams, 1);
    EXPECT_EQ((ULONG_PTR)srv.ctx_seen, 0xABCD);   /* port context given at accept time */
    /* a reply that matches no outstanding request is refused */
    LMSG stray; fill(&stray, "stray"); stray.h.Type = LPC_REPLY; stray.h.MessageId = 0x12345;
    st = UN(NtReplyPort)(srv.conn, &stray);
    EXPECT_ST(st, S(0xC0000702));     /* observed: no such outstanding request */
    /* closing the client delivers LPC_PORT_CLOSED to the server and ends the loop */
    UN(NtClose)(client);
    EXPECT_EQ(WaitForSingleObject(th, 8000), WAIT_OBJECT_0);
    EXPECT_EQ(srv.saw_closed, 1);
    CloseHandle(th);
    /* nothing pending now: receive times out */
    PVOID ctx = NULL; LMSG in; LARGE_INTEGER to = { .QuadPart = -300000 };
    EXPECT_ST(UN(NtReplyWaitReceivePortEx)(srv.port, &ctx, NULL, &in, &to), ST_TIMEOUT);
    to.QuadPart = 0;
    EXPECT_ST(UN(NtReplyWaitReceivePortEx)(srv.port, &ctx, NULL, &in, &to), ST_TIMEOUT);
    if (srv.conn) UN(NtClose)(srv.conn);
    UN(NtClose)(srv.port);
}

TEST(port_register_thread_terminate)
{
    NEED();
    WCHAR name[96]; wsprintfW(name, L"\\RPC Control\\NtOther2aTerm_%lu", GetCurrentProcessId());
    UNICODE_STRING us; UN(RtlInitUnicodeString)(&us, name);
    OBJECT_ATTRIBUTES oa; memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &us; oa.Attributes = 0x40;
    HANDLE port = NULL;
    NTSTATUS st = UN(NtCreatePort)(&port, &oa, 0, 0x100, 0);
    if (st) { t_skip("NtCreatePort status 0x%lx", (unsigned long)st); return; }
    /* a server (listening) port can be registered for thread-termination notices */
    EXPECT_ST(UN(NtRegisterThreadTerminatePort)(port), 0);
    UN(NtClose)(port);
}

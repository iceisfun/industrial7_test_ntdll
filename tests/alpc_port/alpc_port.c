/* NtAlpc* port lifecycle, connection, messaging, message queries and per-port resources, driven over a
 * loopback ALPC connection inside one process (server thread + client). See EVIDENCE.md. */
#include "fixture.h"

#define SYNC_CONNECT 0x20000
#define SYNC_REQUEST 0x20000

static const char *const pairs[] = {
    "AcceptConnectPort", "CancelMessage", "ConnectPort", "ConnectPortEx", "CreatePort", "CreatePortSection",
    "CreateResourceReserve", "CreateSectionView", "CreateSecurityContext", "DeletePortSection",
    "DeleteResourceReserve", "DeleteSectionView", "DeleteSecurityContext", "DisconnectPort",
    "ImpersonateClientContainerOfPort", "ImpersonateClientOfPort", "OpenSenderProcess", "OpenSenderThread",
    "QueryInformation", "QueryInformationMessage", "RevokeSecurityContext", "SendWaitReceivePort", "SetInformation",
};

#define NEED() do { REQUIRE(NT(NtAlpcCreatePort)); REQUIRE(NT(NtAlpcConnectPort)); REQUIRE(NT(NtAlpcAcceptConnectPort)); \
    REQUIRE(NT(NtAlpcSendWaitReceivePort)); REQUIRE(NT(NtAlpcQueryInformation)); REQUIRE(NT(NtClose)); \
    REQUIRE(NT(AlpcGetMessageAttribute)); } while (0)

TEST(alpc_port_nt_zw_aliases) {
    for (size_t i = 0; i < sizeof pairs / sizeof *pairs; i++) {
        char n[80], z[80];
        snprintf(n, sizeof n, "NtAlpc%s", pairs[i]); snprintf(z, sizeof z, "ZwAlpc%s", pairs[i]);
        FARPROC a = t_proc(n), b = t_proc(z);
        CHECKF(a != NULL, "%s missing", n);
        CHECKF(a == b, "%s and %s differ", n, z);
    }
}

TEST(alpc_port_create_and_basic_info) {
    NEED();
    WCHAR nm[100]; UNICODE_STRING us; OBJECT_ATTRIBUTES oa; A_PORT_ATTR pa; HANDLE p = NULL, p2 = NULL;
    a_name(nm, 100, "create"); a_oa(&oa, &us, nm, 0);
    memset(&pa, 0, sizeof pa); pa.MaxMessageLength = 0x1000;
    EXPECT_EQ(NT(NtAlpcCreatePort)(&p, &oa, &pa), 0);
    CHECK(p != NULL);
    /* same name again */
    EXPECT_EQ(NT(NtAlpcCreatePort)(&p2, &oa, &pa), S(0xC0000035));
    EXPECT_EQ(p2, NULL);
    /* NULL result pointer */
    a_name(nm, 100, "create2"); a_oa(&oa, &us, nm, 0);
    EXPECT_EQ(NT(NtAlpcCreatePort)(NULL, &oa, &pa), S(0xC0000005));
    /* undefined flag bits and an excessive MaxMessageLength are rejected */
    pa.Flags = 0xffffffff;
    EXPECT_EQ(NT(NtAlpcCreatePort)(&p2, &oa, &pa), S(0xC000000D));
    pa.Flags = 0; pa.MaxMessageLength = 0x100000;
    EXPECT_EQ(NT(NtAlpcCreatePort)(&p2, &oa, &pa), S(0xC000000D));
    EXPECT_EQ(p2, NULL);
    /* the failed creates did not leave the name behind */
    pa.MaxMessageLength = 0x1000;
    EXPECT_EQ(NT(NtAlpcCreatePort)(&p2, &oa, &pa), 0);
    if (p2) NT(NtClose)(p2);
    /* unnamed ports, with and without attributes */
    p2 = NULL; EXPECT_EQ(NT(NtAlpcCreatePort)(&p2, NULL, NULL), 0); CHECK(p2 != NULL);
    if (p2) {
        A_BASIC_INFO bi; ULONG rl = 0;
        memset(&bi, 0xcc, sizeof bi);
        EXPECT_EQ(NT(NtAlpcQueryInformation)(p2, 0, &bi, sizeof bi, &rl), 0);
        EXPECT_EQ(rl, sizeof bi);
        EXPECT_EQ(bi.PortContext, NULL);
        NT(NtClose)(p2);
    }
    p2 = NULL; EXPECT_EQ(NT(NtAlpcCreatePort)(&p2, NULL, &pa), 0);
    if (p2) NT(NtClose)(p2);

    /* class 0 (AlpcBasicInformation): {Flags, SequenceNo, PortContext}, 16 bytes */
    A_BASIC_INFO bi; ULONG rl = 0xdead;
    memset(&bi, 0xcc, sizeof bi);
    EXPECT_EQ(NT(NtAlpcQueryInformation)(p, 0, &bi, sizeof bi, &rl), 0);
    EXPECT_EQ(rl, 16);
    EXPECT_EQ(bi.PortContext, NULL);
    CHECKF(bi.Flags & 0x20000, "server connection port lacks the request-accepting flag: %lx", bi.Flags);
    /* larger buffer: still 16 returned; return length is optional */
    BYTE big[64]; memset(big, 0xcc, sizeof big); rl = 0xdead;
    EXPECT_EQ(NT(NtAlpcQueryInformation)(p, 0, big, sizeof big, &rl), 0);
    EXPECT_EQ(rl, 16); EXPECT_EQ(big[16], 0xcc);
    EXPECT_EQ(NT(NtAlpcQueryInformation)(p, 0, &bi, sizeof bi, NULL), 0);
    /* too-small buffers */
    rl = 0xdead; EXPECT_EQ(NT(NtAlpcQueryInformation)(p, 0, &bi, 15, &rl), S(0xC0000004));
    EXPECT_EQ(NT(NtAlpcQueryInformation)(p, 0, &bi, 4, &rl), S(0xC0000004));
    EXPECT_EQ(NT(NtAlpcQueryInformation)(p, 0, &bi, 0, &rl), S(0xC0000004));
    /* bad pointer / class / handles */
    EXPECT_EQ(NT(NtAlpcQueryInformation)(p, 0, NULL, 16, &rl), S(0xC000000D));
    EXPECT_EQ(NT(NtAlpcQueryInformation)(p, 99, &bi, 16, &rl), S(0xC000000D));
    EXPECT_EQ(NT(NtAlpcQueryInformation)(NULL, 0, &bi, 16, &rl), S(0xC000000D));
    EXPECT_EQ(NT(NtAlpcQueryInformation)((HANDLE)(LONG_PTR)-1, 0, &bi, 16, &rl), S(0xC0000024));
    EXPECT_EQ(NT(NtAlpcQueryInformation)(GetCurrentProcess(), 0, &bi, 16, &rl), S(0xC0000024));
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    EXPECT_EQ(NT(NtAlpcQueryInformation)(ev, 0, &bi, 16, &rl), S(0xC0000024));
    CloseHandle(ev);
    /* class 12 (server session information): {SessionId, ProcessId} of the port owner */
    ULONG ss[4] = { 0xcccccccc, 0xcccccccc, 0xcccccccc, 0xcccccccc }; DWORD sid = 0;
    rl = 0; EXPECT_EQ(NT(NtAlpcQueryInformation)(p, 12, ss, sizeof ss, &rl), 0);
    EXPECT_EQ(rl, 8);
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sid)) EXPECT_EQ(ss[0], sid);
    EXPECT_EQ(ss[1], GetCurrentProcessId());
    EXPECT_EQ(ss[2], 0xcccccccc);
    EXPECT_EQ(NT(NtAlpcQueryInformation)(p, 12, ss, 4, &rl), S(0xC0000004));
    NT(NtClose)(p);
}

TEST(alpc_port_set_information_errors) {
    NEED(); REQUIRE(NT(NtAlpcSetInformation));
    HANDLE p = NULL; EXPECT_EQ(NT(NtAlpcCreatePort)(&p, NULL, NULL), 0);
    if (!p) return;
    ULONG_PTR buf[8] = { 0 };
    /* classes 1 and 2 are settable but have a fixed size: a mismatched length is rejected before the content */
    EXPECT_EQ(NT(NtAlpcSetInformation)(p, 1, buf, sizeof buf), S(0xC0000004));
    EXPECT_EQ(NT(NtAlpcSetInformation)(p, 2, buf, sizeof buf), S(0xC0000004));
    EXPECT_EQ(NT(NtAlpcSetInformation)(p, 2, buf, 0), S(0xC0000004));
    /* associate-completion-port with a NULL completion port */
    EXPECT_EQ(NT(NtAlpcSetInformation)(p, 2, buf, 16), S(0xC000000D));
    /* a class that cannot be set and one that does not exist */
    EXPECT_EQ(NT(NtAlpcSetInformation)(p, 0, buf, sizeof buf), S(0xC000000D));
    EXPECT_EQ(NT(NtAlpcSetInformation)(p, 99, buf, sizeof buf), S(0xC000000D));
    EXPECT_EQ(NT(NtAlpcSetInformation)(NULL, 2, buf, 16), S(0xC000000D));
    NT(NtClose)(p);
}

TEST(alpc_port_connect_errors_and_refusal) {
    NEED();
    WCHAR nm[100]; SRV s; HANDLE h; AMSG rep; ULONG cl;
    /* nothing listens */
    WCHAR gone[100]; a_name(gone, 100, "nobody");
    h = (HANDLE)(ULONG_PTR)0x1111;
    EXPECT_EQ(a_connect(&h, gone, "x", &rep, &cl, -10000000), S(0xC0000034));
    EXPECT_EQ(h, (HANDLE)(ULONG_PTR)0x1111);
    /* port exists, but nobody receives: synchronous connect times out and leaves the handle alone */
    EXPECT_EQ(srv_start(&s, "refuse", nm, 100), 0);
    InterlockedExchange(&s.quit, 1); WaitForSingleObject(s.thread, 10000); CloseHandle(s.thread); s.thread = NULL; s.quit = 0;
    h = (HANDLE)(ULONG_PTR)0x1111;
    EXPECT_EQ(a_connect(&h, nm, "late", &rep, &cl, -2000000), S(0x102));
    EXPECT_EQ(h, (HANDLE)(ULONG_PTR)0x1111);
    /* receiver present but refuses */
    s.thread = CreateThread(NULL, 0, srv_main, &s, 0, NULL);
    h = (HANDLE)(ULONG_PTR)0x1111;
    EXPECT_EQ(a_connect(&h, nm, "refuse", &rep, &cl, -50000000), S(0xC0000041));
    EXPECT_EQ(h, (HANDLE)(ULONG_PTR)0x1111);
    EXPECT_EQ(s.ncomm, 0);
    srv_stop(&s);
}

static BOOL my_user_sid(BYTE *buf, DWORD cap)
{
    HANDLE t; DWORD n = 0; BOOL ok = FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return FALSE;
    BYTE tmp[256];
    if (GetTokenInformation(t, TokenUser, tmp, sizeof tmp, &n)) { PSID sid = ((TOKEN_USER *)tmp)->User.Sid; n = GetLengthSid(sid); if (n <= cap) { memcpy(buf, sid, n); ok = TRUE; } }
    CloseHandle(t);
    return ok;
}
static BOOL my_modified_id(LUID *id)
{
    HANDLE t; DWORD n = 0; TOKEN_STATISTICS st; BOOL ok = FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return FALSE;
    if (GetTokenInformation(t, TokenStatistics, &st, sizeof st, &n)) { *id = st.ModifiedId; ok = TRUE; }
    CloseHandle(t);
    return ok;
}

TEST(alpc_port_connect_request_reply) {
    NEED();
    WCHAR nm[100]; SRV s; HANDLE ch = NULL; AMSG rep; ULONG cl = 0;
    EXPECT_EQ(srv_start(&s, "flow", nm, 100), 0);
    memset(&rep, 0, sizeof rep);
    NTSTATUS st = a_connect(&ch, nm, "hello", &rep, &cl, -100000000);
    EXPECT_EQ(st, 0);
    CHECK(ch != NULL);
    if (st < 0 || !ch) { srv_stop(&s); return; }
    /* what the server saw of the connection request */
    EXPECT_EQ(s.c_type & 0xff, LPC_CONNECTION_REQUEST);
    EXPECT_EQ(s.c_dl, 6);
    EXPECT_STR(s.c_data, "hello");
    EXPECT_EQ(s.c_pid, GetCurrentProcessId());
    CHECKF(s.c_valid & A_ATTR_TOKEN, "connection request lacks the token attribute: %lx", s.c_valid);
    srv_wait_comm(&s, 1);
    EXPECT_EQ(s.accept_st, 0);
    /* what the client got back in the connection message buffer */
    EXPECT_STR(rep.d, "welcome");
    EXPECT_EQ(cl, sizeof(A_MSG) + 8);
    /* accept returned a port bound to the supplied context */
    EXPECT_EQ(s.ncomm, 1);
    if (s.ncomm == 1) {
        A_BASIC_INFO bi; ULONG rl = 0;
        EXPECT_EQ(NT(NtAlpcQueryInformation)(s.comm[0], 0, &bi, sizeof bi, &rl), 0);
        EXPECT_EQ(bi.PortContext, (PVOID)(ULONG_PTR)0x5151);
        ULONG ss[2] = { 0, 0 }; DWORD sid = 0;
        EXPECT_EQ(NT(NtAlpcQueryInformation)(s.comm[0], 12, ss, sizeof ss, &rl), 0);
        EXPECT_EQ(ss[1], GetCurrentProcessId());
    }
    /* the client's port reports the server process through class 12 */
    { ULONG ss[2] = { 0, 0 }, rl = 0; EXPECT_EQ(NT(NtAlpcQueryInformation)(ch, 12, ss, sizeof ss, &rl), 0); EXPECT_EQ(ss[1], GetCurrentProcessId()); }

    /* ---- synchronous request/reply, no security attribute ---- */
    AMSG rq, rp; SIZE_T rlen; LARGE_INTEGER t5; t5.QuadPart = -100000000;
    a_mk(&rq, "ping"); memset(&rp, 0, sizeof rp); rlen = sizeof rp;
    EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(ch, SYNC_REQUEST, &rq.h, NULL, &rp.h, &rlen, NULL, &t5), 0);
    EXPECT_STR(rp.d, "pong");
    EXPECT_EQ(rp.h.DataLength, 5);
    EXPECT_EQ(rp.h.TotalLength, sizeof(A_MSG) + 5);
    EXPECT_EQ(rlen, sizeof(A_MSG) + 5);
    INSP *r = &s.plain;
    EXPECT_EQ(r->type & 0xff, LPC_REQUEST);
    EXPECT_EQ(r->dl, 5); EXPECT_EQ(r->tl, sizeof(A_MSG) + 5);
    EXPECT_EQ(r->pid, GetCurrentProcessId());
    EXPECT_EQ(r->tid, GetCurrentThreadId());
    CHECKF((r->valid & (A_ATTR_CONTEXT | A_ATTR_TOKEN)) == (A_ATTR_CONTEXT | A_ATTR_TOKEN), "valid attrs %lx", r->valid);
    EXPECT_EQ(r->have_ctx, 1);
    EXPECT_EQ(r->portctx, (PVOID)(ULONG_PTR)0x5151);
    /* sender identity */
    EXPECT_EQ(r->os_proc, 0); EXPECT_EQ(r->os_pid, GetCurrentProcessId());
    EXPECT_EQ(r->os_thr, 0);  EXPECT_EQ(r->os_tid, GetCurrentThreadId());
    EXPECT_EQ(r->os_ff, 0);                       /* the flags argument is ignored */
    EXPECT_EQ(r->os_acc0, S(0xC0000022));
    EXPECT_EQ(r->os_nullmsg, S(0xC0000005));
    EXPECT_EQ(r->os_nulloa, S(0xC0000005));
    EXPECT_EQ(r->os_bogus, S(0xC0000702));
    /* message token queries */
    EXPECT_EQ(r->qim_sid, 0);
    { BYTE mine[SECURITY_MAX_SID_SIZE]; if (my_user_sid(mine, sizeof mine)) {
        EXPECT_EQ(r->qim_sid_rl, GetLengthSid(mine));
        CHECK(EqualSid(r->sid, mine)); } }
    EXPECT_EQ(r->qim_sid_small, S(0xC0000023));
    EXPECT_EQ(r->qim_small_rl, r->qim_sid_rl);
    EXPECT_EQ(r->qim_luid, 0); EXPECT_EQ(r->qim_luid_rl, 8);
    { LUID mid; if (my_modified_id(&mid)) { EXPECT_EQ(r->luid.LowPart, mid.LowPart); EXPECT_EQ(r->luid.HighPart, mid.HighPart); } }
    EXPECT_EQ(r->qim_c2, S(0xC000000D));
    EXPECT_EQ(r->qim_c3, S(0xC0000004));
    EXPECT_EQ(r->qim_null, S(0xC0000005));
    EXPECT_EQ(r->qim_bogus, S(0xC0000702));
    /* impersonation needs the sender to have supplied a security attribute */
    EXPECT_EQ(r->imp_lport, S(0xC0000022));
    EXPECT_EQ(r->imp_comm, S(0xC0000022));
    EXPECT_EQ(r->imp_bogus, S(0xC0000702));

    /* ---- request carrying a security attribute: impersonation succeeds ---- */
    {
        A_SEC_ATTR ctx; A_QOS q = { sizeof q, SecurityImpersonation, 1, 0 };
        memset(&ctx, 0, sizeof ctx); ctx.SecurityQos = &q;
        EXPECT_EQ(NT(NtAlpcCreateSecurityContext)(ch, 0, &ctx), 0);
        struct { A_MSG_ATTR a; A_SEC_ATTR s; } sa; memset(&sa, 0, sizeof sa);
        sa.a.AllocatedAttributes = sa.a.ValidAttributes = A_ATTR_SECURITY; sa.s = ctx;
        a_mk(&rq, "pingsec"); memset(&rp, 0, sizeof rp); rlen = sizeof rp;
        EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(ch, SYNC_REQUEST, &rq.h, &sa.a, &rp.h, &rlen, NULL, &t5), 0);
        EXPECT_STR(rp.d, "pong");
        r = &s.sec;
        CHECKF(r->valid & A_ATTR_SECURITY, "security attribute not delivered: %lx", r->valid);
        EXPECT_EQ(r->imp_lport, 0);
        EXPECT_EQ(r->imp_token, 1);
        EXPECT_EQ(r->imp_comm, 0);
        EXPECT_EQ(r->imp_f1, 0); EXPECT_EQ(r->imp_f8, 0);
        EXPECT_EQ(r->imp_f10, S(0xC000000D));
        EXPECT_EQ(r->imp_bogus, S(0xC0000702));
        EXPECT_EQ(r->qim_sid, 0);
        NT(NtAlpcDeleteSecurityContext)(ch, 0, ctx.ContextHandle);
    }

    /* ---- asynchronous send, reply collected with a separate receive ---- */
    a_mk(&rq, "async"); memset(&rp, 0, sizeof rp); rlen = sizeof rp;
    EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(ch, 0, &rq.h, NULL, NULL, NULL, NULL, NULL), 0);
    EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(ch, 0, NULL, NULL, &rp.h, &rlen, NULL, &t5), 0);
    EXPECT_STR(rp.d, "pong");
    /* nothing more queued: a receive with a short timeout expires */
    { LARGE_INTEGER sh; sh.QuadPart = -1000000; memset(&rp, 0, sizeof rp); rlen = sizeof rp;
      EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(ch, 0, NULL, NULL, &rp.h, &rlen, NULL, &sh), S(0x102)); }

    /* ---- malformed outgoing messages ---- */
    { static BYTE bigbuf[0x2000]; A_MSG *bm = (A_MSG *)bigbuf; memset(bigbuf, 0, sizeof bigbuf);
      bm->DataLength = 0x1000; bm->TotalLength = 0x1028;                      /* exceeds MaxMessageLength */
      EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(ch, 0, bm, NULL, NULL, NULL, NULL, NULL), S(0xC000002F));
      bm->DataLength = 0x2000; bm->TotalLength = 0x2028;
      EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(ch, 0, bm, NULL, NULL, NULL, NULL, NULL), S(0xC000002F));
      bm->DataLength = 10; bm->TotalLength = 0x10;                            /* total shorter than the header */
      EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(ch, 0, bm, NULL, NULL, NULL, NULL, NULL), S(0xC000000D));
      bm->DataLength = 10; bm->TotalLength = 0x28;                            /* data longer than total - header */
      EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(ch, 0, bm, NULL, NULL, NULL, NULL, NULL), S(0xC000000D)); }

    /* ---- cancel of a message that is not pending ---- */
    { A_CTX_ATTR ca; memset(&ca, 0, sizeof ca);
      EXPECT_EQ(NT(NtAlpcCancelMessage)(ch, 0, &ca), S(0xC0000109));
      ca.MessageId = 12345;
      EXPECT_EQ(NT(NtAlpcCancelMessage)(ch, 0, &ca), S(0xC0000702));
      EXPECT_EQ(NT(NtAlpcCancelMessage)(ch, 0, NULL), S(0xC0000005)); }

    /* ---- disconnect: server sees the port close, the client port is dead ---- */
    EXPECT_EQ(NT(NtAlpcDisconnectPort)(ch, 0xffffffff), S(0xC000000D));
    EXPECT_EQ(NT(NtAlpcDisconnectPort)(NULL, 0), S(0xC0000008));
    EXPECT_EQ(NT(NtAlpcDisconnectPort)(ch, 0), 0);
    a_mk(&rq, "late");
    EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(ch, 0, &rq.h, NULL, NULL, NULL, NULL, NULL), S(0xC0000037));
    NT(NtClose)(ch);
    for (int i = 0; i < 100 && !s.closed_seen; i++) Sleep(50);
    CHECKF(s.closed_seen >= 1, "server did not see the client port close");
    srv_stop(&s);
}

TEST(alpc_port_connect_ex_and_second_client) {
    NEED(); REQUIRE(NT(NtAlpcConnectPortEx));
    WCHAR nm[100]; SRV s; UNICODE_STRING us; OBJECT_ATTRIBUTES oa; A_PORT_ATTR pa; AMSG m; ULONG cl; LARGE_INTEGER to;
    EXPECT_EQ(srv_start(&s, "connex", nm, 100), 0);
    a_oa(&oa, &us, nm, 0);
    memset(&pa, 0, sizeof pa); pa.MaxMessageLength = 0x1000;
    pa.SecurityQos.Length = sizeof pa.SecurityQos; pa.SecurityQos.ImpersonationLevel = SecurityImpersonation;
    to.QuadPart = -100000000;
    HANDLE c1 = NULL;
    a_mk(&m, "hello2"); cl = sizeof m;
    EXPECT_EQ(NT(NtAlpcConnectPortEx)(&c1, &oa, NULL, &pa, SYNC_CONNECT, NULL, &m.h, &cl, NULL, NULL, &to), 0);
    CHECK(c1 != NULL);
    EXPECT_STR(m.d, "welcome");
    EXPECT_STR(s.c_data, "hello2");
    /* a second connection gets its own server-side port */
    HANDLE c2 = NULL; AMSG rep;
    EXPECT_EQ(a_connect(&c2, nm, "again", &rep, &cl, -100000000), 0);
    CHECK(c2 != NULL && c2 != c1);
    srv_wait_comm(&s, 2);
    EXPECT_EQ(s.ncomm, 2);
    if (s.ncomm == 2) CHECK(s.comm[0] != s.comm[1]);
    /* both connections carry traffic */
    AMSG rq, rp; SIZE_T rlen; LARGE_INTEGER t5; t5.QuadPart = -100000000;
    HANDLE cs[2] = { c1, c2 };
    for (int i = 0; i < 2; i++) {
        if (!cs[i]) continue;
        a_mk(&rq, "x"); memset(&rp, 0, sizeof rp); rlen = sizeof rp;
        EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(cs[i], SYNC_REQUEST, &rq.h, NULL, &rp.h, &rlen, NULL, &t5), 0);
        EXPECT_STR(rp.d, "pong");
    }
    /* invalid name object attributes */
    HANDLE bad = (HANDLE)(ULONG_PTR)0x1111; WCHAR gone[100]; a_name(gone, 100, "connex_missing"); a_oa(&oa, &us, gone, 0);
    a_mk(&m, "x"); cl = sizeof m;
    EXPECT_EQ(NT(NtAlpcConnectPortEx)(&bad, &oa, NULL, &pa, SYNC_CONNECT, NULL, &m.h, &cl, NULL, NULL, &to), S(0xC0000034));
    EXPECT_EQ(bad, (HANDLE)(ULONG_PTR)0x1111);
    if (c1) NT(NtClose)(c1);
    if (c2) NT(NtClose)(c2);
    srv_stop(&s);
}

TEST(alpc_port_server_disconnect) {
    NEED();
    HANDLE p = NULL; EXPECT_EQ(NT(NtAlpcCreatePort)(&p, NULL, NULL), 0);
    if (!p) return;
    EXPECT_EQ(NT(NtAlpcDisconnectPort)(p, 0xffffffff), S(0xC000000D));
    EXPECT_EQ(NT(NtAlpcDisconnectPort)(p, 0), 0);
    /* a disconnected port refuses further traffic */
    AMSG m; a_mk(&m, "x");
    EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(p, 0, &m.h, NULL, NULL, NULL, NULL, NULL), S(0xC0000037));
    NT(NtClose)(p);
    /* invalid handles */
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    EXPECT_EQ(NT(NtAlpcDisconnectPort)(ev, 0), S(0xC0000024));
    CloseHandle(ev);
    EXPECT_EQ(NT(NtAlpcDisconnectPort)((HANDLE)(LONG_PTR)-1, 0), S(0xC0000024));
}

TEST(alpc_port_receive_timeout_and_args) {
    NEED();
    HANDLE p = NULL; EXPECT_EQ(NT(NtAlpcCreatePort)(&p, NULL, NULL), 0);
    if (!p) return;
    A_MSG m; SIZE_T len = sizeof m; LARGE_INTEGER to; to.QuadPart = -1000000;
    memset(&m, 0, sizeof m);
    EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(p, 0, NULL, NULL, &m, &len, NULL, &to), S(0x102));
    /* nothing to send or receive */
    EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(p, 0, NULL, NULL, NULL, NULL, NULL, &to), 0);
    EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(NULL, 0, NULL, NULL, &m, &len, NULL, &to), S(0xC0000008));
    EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)((HANDLE)(LONG_PTR)-1, 0, NULL, NULL, &m, &len, NULL, &to), S(0xC0000024));
    NT(NtClose)(p);
}

TEST(alpc_port_resources) {
    NEED();
    REQUIRE(NT(NtAlpcCreatePortSection)); REQUIRE(NT(NtAlpcCreateResourceReserve)); REQUIRE(NT(NtAlpcCreateSecurityContext));
    WCHAR nm[100]; SRV s; HANDLE ch = NULL; AMSG rep; ULONG cl;
    EXPECT_EQ(srv_start(&s, "res", nm, 100), 0);
    EXPECT_EQ(a_connect(&ch, nm, "hello", &rep, &cl, -100000000), 0);
    if (!ch) { srv_stop(&s); return; }
    NTSTATUS st;
    /* ---- resource reserve ---- */
    ALPC_HANDLE_T rr = 0;
    EXPECT_EQ(NT(NtAlpcCreateResourceReserve)(ch, 0, 0x100, &rr), 0);
    CHECK(rr != 0);
    EXPECT_EQ(NT(NtAlpcDeleteResourceReserve)(ch, 0, rr), 0);
    EXPECT_EQ(NT(NtAlpcDeleteResourceReserve)(ch, 0, rr), S(0xC0000008));
    EXPECT_EQ(NT(NtAlpcDeleteResourceReserve)(ch, 0, 0), S(0xC000000D));
    ALPC_HANDLE_T rr2 = 0x1234;
    st = NT(NtAlpcCreateResourceReserve)(ch, 0xffffffff, 0x100, &rr2); EXPECT_EQ(st, S(0xC000000D));
    st = NT(NtAlpcCreateResourceReserve)(ch, 0, 0, &rr2); EXPECT_EQ(st, S(0xC000000D)); if (st >= 0) NT(NtAlpcDeleteResourceReserve)(ch, 0, rr2);
    st = NT(NtAlpcCreateResourceReserve)(ch, 0, 0x100000, &rr2); EXPECT_EQ(st, S(0x80000005)); if (st >= 0) NT(NtAlpcDeleteResourceReserve)(ch, 0, rr2);
    st = NT(NtAlpcCreateResourceReserve)(ch, 0, 0x100, NULL); EXPECT_EQ(st, S(0xC0000005));
    st = NT(NtAlpcCreateResourceReserve)(NULL, 0, 0x100, &rr2); EXPECT_EQ(st, S(0xC0000008));
    st = NT(NtAlpcDeleteResourceReserve)(NULL, 0, 1); EXPECT_EQ(st, S(0xC000000D));
    st = NT(NtAlpcCreateResourceReserve)(s.lport, 0, 0x100, &rr2); EXPECT_EQ(st, S(0)); if (st >= 0) NT(NtAlpcDeleteResourceReserve)(s.lport, 0, rr2);
    /* ---- port section + view ---- */
    for (int withsec = 0; withsec < 2; withsec++) {
        HANDLE sec = withsec ? CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, NULL) : NULL;
        ALPC_HANDLE_T sh = 0; SIZE_T act = 0;
        EXPECT_EQ(NT(NtAlpcCreatePortSection)(ch, 0, sec, 0x10000, &sh, &act), 0);
        CHECK(sh != 0); EXPECT_EQ(act, 0x10000);
        if (sh) {
            A_VIEW_ATTR va; memset(&va, 0, sizeof va); va.SectionHandle = (HANDLE)sh; va.ViewSize = 0x1000;
            EXPECT_EQ(NT(NtAlpcCreateSectionView)(ch, 0, &va), 0);
            CHECK(va.ViewBase != NULL); EXPECT_EQ(va.ViewSize, 0x1000);
            if (va.ViewBase) {
                MEMORY_BASIC_INFORMATION mbi;
                CHECK(VirtualQuery(va.ViewBase, &mbi, sizeof mbi) != 0);
                EXPECT_EQ(mbi.State, MEM_COMMIT);
                *(volatile BYTE *)va.ViewBase = 0x5a; EXPECT_EQ(*(volatile BYTE *)va.ViewBase, 0x5a);
                EXPECT_EQ(NT(NtAlpcDeleteSectionView)(ch, 0, va.ViewBase), 0);
                EXPECT_EQ(NT(NtAlpcDeleteSectionView)(ch, 0, va.ViewBase), S(0xC0000141));
            }
            EXPECT_EQ(NT(NtAlpcDeletePortSection)(ch, 0, sh), 0);
            EXPECT_EQ(NT(NtAlpcDeletePortSection)(ch, 0, sh), S(0xC0000008));
        }
        if (sec) CloseHandle(sec);
    }
    { ALPC_HANDLE_T sh = 0; SIZE_T act = 0x77;
      st = NT(NtAlpcCreatePortSection)(ch, 0, NULL, 0, &sh, &act); EXPECT_EQ(st, S(0xC000000D)); if (st >= 0) NT(NtAlpcDeletePortSection)(ch, 0, sh);
      sh = 0; st = NT(NtAlpcCreatePortSection)(ch, 0xffffffff, NULL, 0x10000, &sh, &act); EXPECT_EQ(st, S(0xC000000D)); if (st >= 0) NT(NtAlpcDeletePortSection)(ch, 0, sh);
      st = NT(NtAlpcCreatePortSection)(ch, 0, NULL, 0x10000, NULL, &act); EXPECT_EQ(st, S(0xC0000005));
      st = NT(NtAlpcCreatePortSection)(ch, 0, (HANDLE)(LONG_PTR)-1, 0x10000, &sh, &act); EXPECT_EQ(st, S(0xC0000024)); if (st >= 0) NT(NtAlpcDeletePortSection)(ch, 0, sh);
      sh = 0; st = NT(NtAlpcCreatePortSection)(ch, 0, NULL, 0x10000, &sh, NULL); EXPECT_EQ(st, S(0xC0000005)); if (st >= 0) NT(NtAlpcDeletePortSection)(ch, 0, sh);
      sh = 0; st = NT(NtAlpcCreatePortSection)(NULL, 0, NULL, 0x10000, &sh, &act); EXPECT_EQ(st, S(0xC0000008));
      sh = 0; st = NT(NtAlpcCreatePortSection)(s.lport, 0, NULL, 0x10000, &sh, &act); EXPECT_EQ(st, S(0)); if (st >= 0) NT(NtAlpcDeletePortSection)(s.lport, 0, sh);
      A_VIEW_ATTR va; memset(&va, 0, sizeof va); va.SectionHandle = (HANDLE)0x999; va.ViewSize = 0x1000;
      st = NT(NtAlpcCreateSectionView)(ch, 0, &va); EXPECT_EQ(st, S(0xC0000008));
      st = NT(NtAlpcCreateSectionView)(ch, 0, NULL); EXPECT_EQ(st, S(0xC0000005));
      st = NT(NtAlpcDeleteSectionView)(ch, 0, NULL); EXPECT_EQ(st, S(0xC0000141));
      st = NT(NtAlpcDeleteSectionView)(ch, 0, (PVOID)0x10000); EXPECT_EQ(st, S(0xC0000141));
      st = NT(NtAlpcDeletePortSection)(NULL, 0, 1); EXPECT_EQ(st, S(0xC0000008)); }
    /* ---- security context ---- */
    { A_QOS q = { sizeof q, SecurityImpersonation, 0, 0 }; A_SEC_ATTR sa; memset(&sa, 0, sizeof sa); sa.SecurityQos = &q;
      EXPECT_EQ(NT(NtAlpcCreateSecurityContext)(ch, 0, &sa), 0);
      CHECK(sa.ContextHandle != 0);
      EXPECT_EQ(NT(NtAlpcRevokeSecurityContext)(ch, 0, sa.ContextHandle), 0);
      EXPECT_EQ(NT(NtAlpcDeleteSecurityContext)(ch, 0, sa.ContextHandle), 0);
      EXPECT_EQ(NT(NtAlpcDeleteSecurityContext)(ch, 0, sa.ContextHandle), S(0xC0000008));
      EXPECT_EQ(NT(NtAlpcRevokeSecurityContext)(ch, 0, sa.ContextHandle), S(0xC0000008));
      st = NT(NtAlpcCreateSecurityContext)(ch, 0, NULL); EXPECT_EQ(st, S(0xC0000005));
      memset(&sa, 0, sizeof sa); st = NT(NtAlpcCreateSecurityContext)(ch, 0, &sa); EXPECT_EQ(st, S(0)); if (st >= 0) NT(NtAlpcDeleteSecurityContext)(ch, 0, sa.ContextHandle);
      memset(&sa, 0, sizeof sa); sa.SecurityQos = &q; st = NT(NtAlpcCreateSecurityContext)(ch, 0xffffffff, &sa); EXPECT_EQ(st, S(0xC000000D)); if (st >= 0) NT(NtAlpcDeleteSecurityContext)(ch, 0, sa.ContextHandle);
      q.Length = 4; memset(&sa, 0, sizeof sa); sa.SecurityQos = &q; st = NT(NtAlpcCreateSecurityContext)(ch, 0, &sa); EXPECT_EQ(st, S(0)); if (st >= 0) NT(NtAlpcDeleteSecurityContext)(ch, 0, sa.ContextHandle);
      q.Length = sizeof q; memset(&sa, 0, sizeof sa); sa.SecurityQos = &q; st = NT(NtAlpcCreateSecurityContext)(NULL, 0, &sa); EXPECT_EQ(st, S(0xC0000008));
      sa.ContextHandle = 0; st = NT(NtAlpcCreateSecurityContext)(s.lport, 0, &sa); EXPECT_EQ(st, S(0)); if (st >= 0) NT(NtAlpcDeleteSecurityContext)(s.lport, 0, sa.ContextHandle);
      st = NT(NtAlpcDeleteSecurityContext)(NULL, 0, 1); EXPECT_EQ(st, S(0xC0000008));
      st = NT(NtAlpcRevokeSecurityContext)(NULL, 0, 1); EXPECT_EQ(st, S(0xC0000008)); }
    st = NT(NtAlpcImpersonateClientContainerOfPort)(ch, NULL, 0); EXPECT_EQ(st, S(0xC0000005));
    { AMSG m; a_mk(&m, "x"); st = NT(NtAlpcImpersonateClientContainerOfPort)(NULL, &m.h, 0); EXPECT_EQ(st, S(0xC0000008));
      st = NT(NtAlpcImpersonateClientOfPort)(NULL, &m.h, NULL); EXPECT_EQ(st, S(0xC000000D));
      HANDLE h = NULL; OBJECT_ATTRIBUTES eoa; memset(&eoa, 0, sizeof eoa); eoa.Length = sizeof eoa;
      st = NT(NtAlpcOpenSenderProcess)(&h, NULL, &m.h, 0, PROCESS_QUERY_LIMITED_INFORMATION, &eoa); EXPECT_EQ(st, S(0xC0000008));
      st = NT(NtAlpcOpenSenderThread)(&h, (HANDLE)(LONG_PTR)-1, &m.h, 0, PROCESS_QUERY_LIMITED_INFORMATION, &eoa); EXPECT_EQ(st, S(0xC0000024));
      st = NT(NtAlpcOpenSenderProcess)(&h, ch, &m.h, 0, PROCESS_QUERY_LIMITED_INFORMATION, &eoa); EXPECT_EQ(st, S(0xC0000702));
      st = NT(NtAlpcOpenSenderProcess)(NULL, ch, &m.h, 0, PROCESS_QUERY_LIMITED_INFORMATION, &eoa); EXPECT_EQ(st, S(0xC0000005));
      ULONG rl; BYTE b[64]; st = NT(NtAlpcQueryInformationMessage)(NULL, &m.h, 0, b, 64, &rl); EXPECT_EQ(st, S(0xC000000D));
      st = NT(NtAlpcQueryInformationMessage)(ch, &m.h, 99, b, 64, &rl); EXPECT_EQ(st, S(0xC000000D)); }
    NT(NtClose)(ch);
    srv_stop(&s);
}

/* Loopback ALPC server fixture shared by the alpc_* tests: a listening port, a server thread, and a
 * set of facts the server records about the messages it received (read by the test thread only after
 * the synchronous request that triggered them has returned). */
#ifndef ALPC_FIXTURE_H
#define ALPC_FIXTURE_H
#include "alpc.h"

UDECL(PVOID, AlpcGetMessageAttribute, (PVOID, ULONG));

typedef struct { A_MSG h; char d[64]; } AMSG;
static void a_mk(AMSG *m, const char *s)
{
    size_t n = strlen(s) + 1;
    memset(m, 0, sizeof *m); memcpy(m->d, s, n);
    m->h.DataLength = (USHORT)n; m->h.TotalLength = (USHORT)(sizeof(A_MSG) + n);
}

typedef struct {
    NTSTATUS imp_lport, imp_comm, imp_f1, imp_f8, imp_f10, imp_bogus, imp_container_bogus;
    int imp_token;
    NTSTATUS qim_sid, qim_sid_small, qim_luid, qim_c2, qim_c3, qim_null, qim_bogus;
    ULONG qim_sid_rl, qim_small_rl, qim_luid_rl;
    BYTE sid[SECURITY_MAX_SID_SIZE]; LUID luid;
    NTSTATUS os_proc, os_thr, os_ff, os_acc0, os_nullmsg, os_nulloa, os_bogus;
    ULONG os_pid, os_tid;
    ULONG valid; PVOID portctx; int have_ctx;
    USHORT dl; USHORT tl; SHORT type; ULONG pid, tid;
} INSP;

typedef struct {
    HANDLE lport, thread;
    volatile LONG quit, closed_seen, conn_seen, req_seen;
    HANDLE comm[8]; int ncomm;
    /* first connection request as received */
    SHORT c_type; USHORT c_dl; char c_data[16]; ULONG c_valid; ULONG_PTR c_pid;
    NTSTATUS accept_st;
    INSP plain, sec;
} SRV;

static void srv_inspect(SRV *s, A_MSG *m, A_MSG_ATTR *at, INSP *r)
{
    HANDLE h = NULL, comm = s->ncomm ? s->comm[s->ncomm - 1] : NULL;
    OBJECT_ATTRIBUTES eoa; memset(&eoa, 0, sizeof eoa); eoa.Length = sizeof eoa;
    r->valid = at->ValidAttributes; r->dl = m->DataLength; r->tl = m->TotalLength; r->type = m->Type;
    r->pid = (ULONG)(ULONG_PTR)m->ClientId.UniqueProcess; r->tid = (ULONG)(ULONG_PTR)m->ClientId.UniqueThread;
    A_CTX_ATTR *ca = (A_CTX_ATTR *)NT(AlpcGetMessageAttribute)(at, A_ATTR_CONTEXT);
    if ((at->ValidAttributes & A_ATTR_CONTEXT) && ca) { r->have_ctx = 1; r->portctx = ca->PortContext; }
    r->imp_lport = NT(NtAlpcImpersonateClientOfPort)(s->lport, m, NULL);
    if (r->imp_lport >= 0) { HANDLE tk = NULL; r->imp_token = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &tk); if (tk) CloseHandle(tk); RevertToSelf(); }
    r->imp_comm = comm ? NT(NtAlpcImpersonateClientOfPort)(comm, m, NULL) : 0; if (r->imp_comm >= 0) RevertToSelf();
    r->imp_f1 = NT(NtAlpcImpersonateClientOfPort)(s->lport, m, (PVOID)(ULONG_PTR)1); if (r->imp_f1 >= 0) RevertToSelf();
    r->imp_f8 = NT(NtAlpcImpersonateClientOfPort)(s->lport, m, (PVOID)(ULONG_PTR)8); if (r->imp_f8 >= 0) RevertToSelf();
    r->imp_f10 = NT(NtAlpcImpersonateClientOfPort)(s->lport, m, (PVOID)(ULONG_PTR)0x10); if (r->imp_f10 >= 0) RevertToSelf();
    A_MSG bogus = *m; bogus.MessageId += 1000;
    r->imp_bogus = NT(NtAlpcImpersonateClientOfPort)(s->lport, &bogus, NULL); if (r->imp_bogus >= 0) RevertToSelf();
    r->imp_container_bogus = NT(NtAlpcImpersonateClientContainerOfPort)(s->lport, &bogus, 0);
    BYTE buf[128]; ULONG rl = 0;
    memset(r->sid, 0, sizeof r->sid);
    rl = 0; r->qim_sid = NT(NtAlpcQueryInformationMessage)(s->lport, m, 0, r->sid, sizeof r->sid, &rl); r->qim_sid_rl = rl;
    rl = 0; r->qim_sid_small = NT(NtAlpcQueryInformationMessage)(s->lport, m, 0, buf, 8, &rl); r->qim_small_rl = rl;
    rl = 0; r->qim_luid = NT(NtAlpcQueryInformationMessage)(s->lport, m, 1, &r->luid, sizeof r->luid, &rl); r->qim_luid_rl = rl;
    r->qim_c2 = NT(NtAlpcQueryInformationMessage)(s->lport, m, 2, buf, sizeof buf, &rl);
    r->qim_c3 = NT(NtAlpcQueryInformationMessage)(s->lport, m, 3, buf, sizeof buf, &rl);
    r->qim_null = NT(NtAlpcQueryInformationMessage)(s->lport, NULL, 0, buf, sizeof buf, &rl);
    r->qim_bogus = NT(NtAlpcQueryInformationMessage)(s->lport, &bogus, 0, buf, sizeof buf, &rl);
    r->os_proc = NT(NtAlpcOpenSenderProcess)(&h, s->lport, m, 0, PROCESS_QUERY_LIMITED_INFORMATION, &eoa);
    if (r->os_proc >= 0) { r->os_pid = GetProcessId(h); CloseHandle(h); }
    h = NULL; r->os_thr = NT(NtAlpcOpenSenderThread)(&h, s->lport, m, 0, THREAD_QUERY_LIMITED_INFORMATION, &eoa);
    if (r->os_thr >= 0) { r->os_tid = GetThreadId(h); CloseHandle(h); }
    h = NULL; r->os_ff = NT(NtAlpcOpenSenderProcess)(&h, s->lport, m, 0xffffffff, PROCESS_QUERY_LIMITED_INFORMATION, &eoa); if (r->os_ff >= 0) CloseHandle(h);
    h = NULL; r->os_acc0 = NT(NtAlpcOpenSenderProcess)(&h, s->lport, m, 0, 0, &eoa); if (r->os_acc0 >= 0) CloseHandle(h);
    h = NULL; r->os_nullmsg = NT(NtAlpcOpenSenderProcess)(&h, s->lport, NULL, 0, PROCESS_QUERY_LIMITED_INFORMATION, &eoa);
    h = NULL; r->os_nulloa = NT(NtAlpcOpenSenderProcess)(&h, s->lport, m, 0, PROCESS_QUERY_LIMITED_INFORMATION, NULL);
    h = NULL; r->os_bogus = NT(NtAlpcOpenSenderProcess)(&h, s->lport, &bogus, 0, PROCESS_QUERY_LIMITED_INFORMATION, &eoa); if (r->os_bogus >= 0) CloseHandle(h);
}

static DWORD WINAPI srv_main(LPVOID p)
{
    SRV *s = p;
    for (int iter = 0; iter < 200 && !s->quit; iter++) {
        struct { A_MSG h; char d[0x200]; } rx; SIZE_T len = sizeof rx; memset(&rx, 0, sizeof rx);
        struct { A_MSG_ATTR a; BYTE b[0x100]; } at; memset(&at, 0, sizeof at);
        at.a.AllocatedAttributes = A_ATTR_SECURITY | A_ATTR_VIEW | A_ATTR_CONTEXT | A_ATTR_HANDLE | A_ATTR_TOKEN;
        LARGE_INTEGER to; to.QuadPart = -2000000;
        NTSTATUS st = NT(NtAlpcSendWaitReceivePort)(s->lport, 0, NULL, NULL, &rx.h, &len, &at.a, &to);
        if (st != 0) continue;
        int ty = ALPC_MSG_TYPE(&rx.h);
        if (ty == LPC_CONNECTION_REQUEST) {
            A_PORT_ATTR pa; memset(&pa, 0, sizeof pa); pa.MaxMessageLength = 0x1000;
            if (InterlockedIncrement(&s->conn_seen) == 1) {
                s->c_type = rx.h.Type; s->c_dl = rx.h.DataLength; s->c_valid = at.a.ValidAttributes;
                s->c_pid = (ULONG_PTR)rx.h.ClientId.UniqueProcess; memcpy(s->c_data, rx.d, 16); s->c_data[15] = 0;
            }
            if (!strcmp(rx.d, "refuse")) { HANDLE x = NULL; NT(NtAlpcAcceptConnectPort)(&x, s->lport, 0, NULL, &pa, NULL, &rx.h, NULL, FALSE); continue; }
            HANDLE c = NULL; strcpy(rx.d, "welcome"); rx.h.DataLength = 8; rx.h.TotalLength = sizeof(A_MSG) + 8;
            s->accept_st = NT(NtAlpcAcceptConnectPort)(&c, s->lport, 0, NULL, &pa, (PVOID)0x5151, &rx.h, NULL, TRUE);
            if (s->accept_st >= 0 && s->ncomm < 8) { s->comm[s->ncomm] = c; MemoryBarrier(); s->ncomm++; }
        } else if (ty == LPC_REQUEST) {
            if (!strcmp(rx.d, "ping")) srv_inspect(s, &rx.h, &at.a, &s->plain);
            else if (!strcmp(rx.d, "pingsec")) srv_inspect(s, &rx.h, &at.a, &s->sec);
            MemoryBarrier();
            AMSG rep; a_mk(&rep, "pong"); rep.h.MessageId = rx.h.MessageId; rep.h.ClientId = rx.h.ClientId;
            NT(NtAlpcSendWaitReceivePort)(s->lport, 0, &rep.h, NULL, NULL, NULL, NULL, NULL);
            InterlockedIncrement(&s->req_seen);
        } else if (ty == LPC_PORT_CLOSED || ty == LPC_CLIENT_DIED) {
            InterlockedIncrement(&s->closed_seen);
        }
    }
    return 0;
}

static NTSTATUS srv_start(SRV *s, const char *tag, WCHAR *nm_out, size_t cap)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; A_PORT_ATTR pa;
    memset(s, 0, sizeof *s);
    a_name(nm_out, cap, tag); a_oa(&oa, &us, nm_out, 0);
    memset(&pa, 0, sizeof pa); pa.MaxMessageLength = 0x1000;
    pa.SecurityQos.Length = sizeof pa.SecurityQos; pa.SecurityQos.ImpersonationLevel = SecurityImpersonation;
    NTSTATUS st = NT(NtAlpcCreatePort)(&s->lport, &oa, &pa);
    if (st < 0) return st;
    s->thread = CreateThread(NULL, 0, srv_main, s, 0, NULL);
    return s->thread ? 0 : (NTSTATUS)0xC0000001;
}
static void srv_wait_comm(SRV *s, int n) { for (int i = 0; i < 200 && s->ncomm < n; i++) Sleep(10); }
static void srv_stop(SRV *s)
{
    InterlockedExchange(&s->quit, 1);
    if (s->thread) { WaitForSingleObject(s->thread, 10000); CloseHandle(s->thread); }
    for (int i = 0; i < s->ncomm; i++) NT(NtClose)(s->comm[i]);
    if (s->lport) NT(NtClose)(s->lport);
}

/* Synchronous connect (ALPC_SYNC_CONNECTION, 0x20000) to the named port. */
static NTSTATUS a_connect(HANDLE *h, const WCHAR *name, const char *msgtext, AMSG *reply, ULONG *cl, LONGLONG timeout100ns)
{
    WCHAR nm[100]; UNICODE_STRING us; OBJECT_ATTRIBUTES oa; A_PORT_ATTR pa; AMSG m; ULONG l; LARGE_INTEGER to;
    wcscpy(nm, name); a_oa(&oa, &us, nm, 0);
    memset(&pa, 0, sizeof pa); pa.MaxMessageLength = 0x1000;
    pa.SecurityQos.Length = sizeof pa.SecurityQos; pa.SecurityQos.ImpersonationLevel = SecurityImpersonation;
    to.QuadPart = timeout100ns;
    if (msgtext) a_mk(&m, msgtext);
    l = sizeof m;
    NTSTATUS st = NT(NtAlpcConnectPort)(h, &us, NULL, &pa, 0x20000, NULL, msgtext ? &m.h : NULL, msgtext ? &l : NULL, NULL, NULL, &to);
    if (reply && msgtext) *reply = m;
    if (cl) *cl = l;
    return st;
}
#endif

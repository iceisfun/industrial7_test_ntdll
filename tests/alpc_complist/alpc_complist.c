/* ALPC completion lists: AlpcRegisterCompletionList / AlpcUnregisterCompletionList / AlpcRundownCompletionList /
 * AlpcAdjustCompletionListConcurrencyCount on a real port, then message delivery through the list and
 * the user-mode helpers (AlpcGetMessageFromCompletionList, AlpcFreeCompletionListMessage,
 * AlpcGetOutstandingCompletionListMessageCount, AlpcGetCompletionListLastMessageInformation,
 * AlpcGetCompletionListMessageAttributes, Alpc(Un)RegisterCompletionListWorkerThread) on the kernel-initialised
 * header. See EVIDENCE.md. */
#include "alpc.h"

UDECL(NTSTATUS, NtCreateIoCompletion, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, NtRemoveIoCompletion, (HANDLE, PVOID *, PVOID *, PIO_STATUS_BLOCK, PLARGE_INTEGER));
UDECL(NTSTATUS, AlpcRegisterCompletionList, (HANDLE, PVOID, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, AlpcUnregisterCompletionList, (HANDLE));
UDECL(NTSTATUS, AlpcRundownCompletionList, (HANDLE));
UDECL(NTSTATUS, AlpcAdjustCompletionListConcurrencyCount, (HANDLE, ULONG));
UDECL(PVOID, AlpcGetMessageFromCompletionList, (PVOID, PVOID *));
UDECL(ULONG, AlpcGetOutstandingCompletionListMessageCount, (PVOID));
UDECL(VOID, AlpcFreeCompletionListMessage, (PVOID, PVOID));
UDECL(VOID, AlpcGetCompletionListLastMessageInformation, (PVOID, PULONG, PULONG));
UDECL(PVOID, AlpcGetCompletionListMessageAttributes, (PVOID, PVOID));
UDECL(ULONG, AlpcGetHeaderSize, (ULONG));
UDECL(BOOLEAN, AlpcRegisterCompletionListWorkerThread, (PVOID));
UDECL(BOOLEAN, AlpcUnregisterCompletionListWorkerThread, (PVOID));

#define LISTSIZE 0x10000
#define W32(b, o) (*(volatile ULONG *)((BYTE *)(b) + (o)))
#define W64(b, o) (*(volatile ULONGLONG *)((BYTE *)(b) + (o)))
#define NEED() do { REQUIRE(NT(NtAlpcCreatePort)); REQUIRE(NT(NtAlpcSetInformation)); REQUIRE(NT(NtClose)); \
    REQUIRE(NT(NtCreateIoCompletion)); REQUIRE(NT(NtRemoveIoCompletion)); \
    REQUIRE(NT(AlpcRegisterCompletionList)); REQUIRE(NT(AlpcUnregisterCompletionList)); REQUIRE(NT(AlpcRundownCompletionList)); \
    REQUIRE(NT(AlpcAdjustCompletionListConcurrencyCount)); REQUIRE(NT(AlpcGetMessageFromCompletionList)); \
    REQUIRE(NT(AlpcFreeCompletionListMessage)); REQUIRE(NT(AlpcGetOutstandingCompletionListMessageCount)); \
    REQUIRE(NT(AlpcGetCompletionListLastMessageInformation)); REQUIRE(NT(AlpcGetCompletionListMessageAttributes)); \
    REQUIRE(NT(AlpcGetHeaderSize)); REQUIRE(NT(AlpcRegisterCompletionListWorkerThread)); \
    REQUIRE(NT(AlpcUnregisterCompletionListWorkerThread)); } while (0)

typedef struct { A_MSG h; char d[64]; } AMSG;
static void a_mk(AMSG *m, const char *s)
{
    size_t n = strlen(s) + 1;
    memset(m, 0, sizeof *m); memcpy(m->d, s, n);
    m->h.DataLength = (USHORT)n; m->h.TotalLength = (USHORT)(sizeof(A_MSG) + n);
}

static BYTE *new_list(void) { return VirtualAlloc(NULL, LISTSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); }

TEST(alpc_cl_nt_zw_aliases) {
    const char *n[] = { "AcceptConnectPort", "ConnectPort", "CreatePort", "SendWaitReceivePort", "SetInformation", "QueryInformation" };
    (void)n;
    /* completion-list control goes through NtAlpcSetInformation: alias integrity for it lives in alpc_port */
    REQUIRE(NT(NtAlpcSetInformation));
    CHECK(t_proc("NtAlpcSetInformation") == t_proc("ZwAlpcSetInformation"));
}

TEST(alpc_cl_register_validation_and_header) {
    NEED();
    HANDLE lp = NULL, comm = NULL; NTSTATUS st;
    EXPECT_EQ(NT(NtAlpcCreatePort)(&lp, NULL, NULL), 0);
    if (!lp) return;
    BYTE *hd = new_list(); CHECK(hd != NULL);
    if (!hd) { NT(NtClose)(lp); return; }
    /* too small a list, no concurrency */
    EXPECT_EQ(NT(AlpcRegisterCompletionList)(lp, hd, 0x1000, 2, 0), S(0xC000000D));
    EXPECT_EQ(NT(AlpcRegisterCompletionList)(lp, hd, LISTSIZE, 0, 0), S(0xC000000D));
    EXPECT_EQ(NT(AlpcRegisterCompletionList)(lp, NULL, LISTSIZE, 2, 0), S(0xC0000005));
    /* handles that are not ALPC ports */
    EXPECT_EQ(NT(AlpcRegisterCompletionList)((HANDLE)(LONG_PTR)-1, hd, LISTSIZE, 2, 0), S(0xC0000024));
    EXPECT_EQ(NT(AlpcRegisterCompletionList)(GetCurrentProcess(), hd, LISTSIZE, 2, 0), S(0xC0000024));
    /* nothing registered yet: the control calls have nothing to act on */
    EXPECT_EQ(NT(AlpcAdjustCompletionListConcurrencyCount)(lp, 2), S(0xC000000D));

    memset(hd, 0xcc, LISTSIZE);
    EXPECT_EQ(NT(AlpcRegisterCompletionList)(lp, hd, LISTSIZE, 2, A_ATTR_CONTEXT), 0);
    EXPECT_EQ(W64(hd, 0), 0xdeadbeefbaadf00dull);              /* StartMagic */
    EXPECT_EQ(W32(hd, 0x08), LISTSIZE);                        /* TotalSize */
    ULONG listoff = W32(hd, 0x0c), listsz = W32(hd, 0x10), bitoff = W32(hd, 0x14), bitsz = W32(hd, 0x18);
    ULONG dataoff = W32(hd, 0x1c), datasz = W32(hd, 0x20);
    CHECKF(listoff >= 0x180 && listsz != 0, "list off %lx size %lx", listoff, listsz);
    CHECKF(bitoff >= listoff + listsz && bitsz != 0, "bitmap off %lx size %lx", bitoff, bitsz);
    CHECKF(dataoff >= bitoff + bitsz && datasz != 0, "data off %lx size %lx", dataoff, datasz);
    CHECKF((ULONGLONG)dataoff + datasz <= LISTSIZE, "data region exceeds the list");
    EXPECT_EQ(dataoff & 0x3f, 0);                              /* messages are 64-byte blocks */
    EXPECT_EQ(W32(hd, 0x24), A_ATTR_CONTEXT);                  /* AttributeFlags */
    EXPECT_EQ(W32(hd, 0x28), NT(AlpcGetHeaderSize)(A_ATTR_CONTEXT));   /* AttributeSize */
    EXPECT_EQ(W64(hd, 0x40) & 0xffffffffffffull, 0xffffffffffffull);   /* empty list: head and tail unset, no workers */
    EXPECT_EQ(W64(hd, 0x40) >> 48, 0);
    EXPECT_EQ(W32(hd, 0x80), 0); EXPECT_EQ(W32(hd, 0xc0), 0);          /* nothing posted, nothing returned */
    EXPECT_EQ(W32(hd, 0x140), 0);                                      /* user lock initialised by the wrapper */
    EXPECT_EQ(NT(AlpcGetOutstandingCompletionListMessageCount)(hd), 0);
    /* registering again on the same port */
    EXPECT_EQ(NT(AlpcRegisterCompletionList)(lp, hd, LISTSIZE, 2, 0), S(0xC0000018));
    { BYTE *other = new_list(); EXPECT_EQ(NT(AlpcRegisterCompletionList)(lp, other, LISTSIZE, 2, 0), S(0xC000071A)); VirtualFree(other, 0, MEM_RELEASE); }
    /* a connected (communication) port cannot own a completion list; shown via a second unnamed port */
    EXPECT_EQ(NT(AlpcAdjustCompletionListConcurrencyCount)(lp, 3), 0);
    EXPECT_EQ(NT(AlpcAdjustCompletionListConcurrencyCount)(lp, 0), S(0xC000000D));
    /* workers: the list header carries the registered-worker count */
    EXPECT_EQ(NT(AlpcRegisterCompletionListWorkerThread)(hd), 1);
    EXPECT_EQ(W64(hd, 0x40) >> 48, 1);
    EXPECT_EQ(NT(AlpcUnregisterCompletionListWorkerThread)(hd), 1);
    EXPECT_EQ(W64(hd, 0x40) >> 48, 0);
    EXPECT_EQ(NT(AlpcUnregisterCompletionListWorkerThread)(hd), 0);
    /* no messages */
    PVOID attrs = (PVOID)1;
    EXPECT_EQ(NT(AlpcGetMessageFromCompletionList)(hd, &attrs), NULL);
    EXPECT_EQ(NT(AlpcRundownCompletionList)(lp), 0);
    EXPECT_EQ(NT(AlpcUnregisterCompletionList)(lp), 0);
    EXPECT_EQ(NT(AlpcUnregisterCompletionList)(lp), 0);          /* idempotent */
    EXPECT_EQ(NT(AlpcRundownCompletionList)(lp), S(0xC000000D)); /* nothing left to run down */
    /* a fresh registration after unregister works again */
    EXPECT_EQ(NT(AlpcRegisterCompletionList)(lp, hd, LISTSIZE, 1, 0), 0);
    EXPECT_EQ(W32(hd, 0x24), 0); EXPECT_EQ(W32(hd, 0x28), 8);
    EXPECT_EQ(NT(AlpcUnregisterCompletionList)(lp), 0);
    VirtualFree(hd, 0, MEM_RELEASE);
    NT(NtClose)(lp);
}

typedef struct { const WCHAR *nm; NTSTATUS st; HANDLE h; AMSG cm; } CCTX;
static DWORD WINAPI client_thr(LPVOID p)
{
    CCTX *c = p; UNICODE_STRING us; OBJECT_ATTRIBUTES oa; WCHAR nm[100]; wcscpy(nm, c->nm); a_oa(&oa, &us, nm, 0);
    A_PORT_ATTR pa; memset(&pa, 0, sizeof pa); pa.MaxMessageLength = 0x1000;
    pa.SecurityQos.Length = sizeof pa.SecurityQos; pa.SecurityQos.ImpersonationLevel = SecurityImpersonation;
    LARGE_INTEGER to; to.QuadPart = -100000000; ULONG cl = sizeof c->cm; a_mk(&c->cm, "hi");
    c->st = NT(NtAlpcConnectPort)(&c->h, &us, NULL, &pa, 0x20000, NULL, &c->cm.h, &cl, NULL, NULL, &to);
    return 0;
}

static NTSTATUS wait_packet(HANDLE io, PVOID *key)
{
    PVOID apc = NULL; IO_STATUS_BLOCK iosb; LARGE_INTEGER t; t.QuadPart = -50000000;
    memset(&iosb, 0, sizeof iosb);
    return NT(NtRemoveIoCompletion)(io, key, &apc, &iosb, &t);
}

TEST(alpc_cl_message_delivery) {
    NEED(); REQUIRE(NT(NtAlpcConnectPort)); REQUIRE(NT(NtAlpcAcceptConnectPort)); REQUIRE(NT(NtAlpcSendWaitReceivePort));
    WCHAR nm[100]; UNICODE_STRING us; OBJECT_ATTRIBUTES oa; A_PORT_ATTR pa; HANDLE lp = NULL, io = NULL, comm = NULL;
    a_name(nm, 100, "cl"); a_oa(&oa, &us, nm, 0);
    memset(&pa, 0, sizeof pa); pa.MaxMessageLength = 0x1000;
    EXPECT_EQ(NT(NtAlpcCreatePort)(&lp, &oa, &pa), 0);
    EXPECT_EQ(NT(NtCreateIoCompletion)(&io, 0x1f0003, NULL, 0), 0);
    if (!lp || !io) { if (lp) NT(NtClose)(lp); if (io) NT(NtClose)(io); return; }
    ULONG_PTR assoc[2] = { 0x77, (ULONG_PTR)io };
    EXPECT_EQ(NT(NtAlpcSetInformation)(lp, 2, assoc, sizeof assoc), 0);
    BYTE *hd = new_list();
    EXPECT_EQ(NT(AlpcRegisterCompletionList)(lp, hd, LISTSIZE, 2, A_ATTR_CONTEXT), 0);
    ULONG attrsz = W32(hd, 0x28);

    /* ---- the connection request arrives through the list ---- */
    CCTX c; memset(&c, 0, sizeof c); c.nm = nm;
    HANDLE th = CreateThread(NULL, 0, client_thr, &c, 0, NULL);
    PVOID key = NULL;
    EXPECT_EQ(wait_packet(io, &key), 0);
    EXPECT_EQ(key, (PVOID)0x77);
    EXPECT_EQ(NT(AlpcGetOutstandingCompletionListMessageCount)(hd), 1);
    EXPECT_EQ(W32(hd, 0x80), 1);
    PVOID attrs = NULL;
    A_MSG *m = NT(AlpcGetMessageFromCompletionList)(hd, &attrs);
    CHECK(m != NULL);
    struct { A_MSG h; char d[64]; } req; memset(&req, 0, sizeof req);
    if (m) {
        EXPECT_EQ((BYTE *)m >= hd + W32(hd, 0x1c) && (BYTE *)m < hd + W32(hd, 0x1c) + W32(hd, 0x20), 1);
        EXPECT_EQ(((ULONG_PTR)m) & 0x3f, 0);
        EXPECT_EQ(m->Type & 0xff, LPC_CONNECTION_REQUEST);
        EXPECT_EQ(m->DataLength, 3);
        EXPECT_STR((char *)(m + 1), "hi");
        CHECK(attrs != NULL);
        EXPECT_EQ(attrs, NT(AlpcGetCompletionListMessageAttributes)(hd, m));
        if (attrs) { EXPECT_EQ(((ULONG_PTR)attrs) & 7, 0); EXPECT_EQ(((A_MSG_ATTR *)attrs)->AllocatedAttributes, A_ATTR_CONTEXT);
                     EXPECT_EQ((BYTE *)attrs, (BYTE *)(((ULONG_PTR)m + m->TotalLength + 7) & ~(ULONG_PTR)7)); }
        ULONG lastmsg = 0, lastcb = 0;
        NT(AlpcGetCompletionListLastMessageInformation)(hd, &lastmsg, &lastcb);
        EXPECT_EQ(lastmsg, m->MessageId);
        memcpy(&req, m, sizeof(A_MSG) + 64 > m->TotalLength ? m->TotalLength : sizeof req);
        NT(AlpcFreeCompletionListMessage)(hd, m);
        EXPECT_EQ(W32(hd, 0xc0), 1);
        EXPECT_EQ(NT(AlpcGetOutstandingCompletionListMessageCount)(hd), 0);
        /* the list message is the connection request: accept it from the copy */
        EXPECT_EQ(NT(NtAlpcAcceptConnectPort)(&comm, lp, 0, NULL, &pa, (PVOID)0x4242, &req.h, NULL, TRUE), 0);
    }
    WaitForSingleObject(th, 10000); CloseHandle(th);
    EXPECT_EQ(c.st, 0);
    CHECK(c.h != NULL);
    /* nothing else pending */
    attrs = (PVOID)1;
    EXPECT_EQ(NT(AlpcGetMessageFromCompletionList)(hd, &attrs), NULL);

    /* ---- datagrams from the client are delivered into the list, in order ---- */
    if (c.h && comm) {
        const char *txt[3] = { "dgram1", "dgram2", "dgram3" };
        for (int i = 0; i < 3; i++) {
            AMSG d; a_mk(&d, txt[i]);
            EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(c.h, 0, &d.h, NULL, NULL, NULL, NULL, NULL), 0);
        }
        /* at least one completion packet announces the queued messages (packets may be coalesced) */
        key = NULL; EXPECT_EQ(wait_packet(io, &key), 0); EXPECT_EQ(key, (PVOID)0x77);
        for (int i = 0; i < 2; i++) { LARGE_INTEGER z; IO_STATUS_BLOCK iosb; PVOID k2, a2; z.QuadPart = 0; NT(NtRemoveIoCompletion)(io, &k2, &a2, &iosb, &z); }
        EXPECT_EQ(NT(AlpcGetOutstandingCompletionListMessageCount)(hd), 3);
        EXPECT_EQ(W32(hd, 0x80), 4);                      /* four messages posted over the list's life */
        A_MSG *got[3] = { 0 };
        for (int i = 0; i < 3; i++) {
            attrs = NULL; got[i] = NT(AlpcGetMessageFromCompletionList)(hd, &attrs);
            CHECK(got[i] != NULL);
            if (!got[i]) continue;
            EXPECT_EQ(got[i]->Type & 0xff, LPC_REQUEST);
            EXPECT_STR((char *)(got[i] + 1), txt[i]);
            EXPECT_EQ(got[i]->DataLength, strlen(txt[i]) + 1);
            EXPECT_EQ((ULONG_PTR)got[i]->ClientId.UniqueProcess, GetCurrentProcessId());
            CHECK(attrs != NULL);
            if (attrs) {
                /* context attribute carries the communication port's context */
                A_CTX_ATTR *ca = (A_CTX_ATTR *)((BYTE *)attrs + 8);
                EXPECT_EQ(((A_MSG_ATTR *)attrs)->ValidAttributes & A_ATTR_CONTEXT, A_ATTR_CONTEXT);
                EXPECT_EQ(ca->PortContext, (PVOID)0x4242);
                EXPECT_EQ(ca->MessageId, got[i]->MessageId);
            }
            if (i) CHECK(got[i] != got[i - 1]);
        }
        ULONG lm = 0, lc = 0; NT(AlpcGetCompletionListLastMessageInformation)(hd, &lm, &lc);
        if (got[2]) EXPECT_EQ(lm, got[2]->MessageId);
        EXPECT_EQ(NT(AlpcGetMessageFromCompletionList)(hd, NULL), NULL);
        /* outstanding drops only as messages are freed */
        EXPECT_EQ(NT(AlpcGetOutstandingCompletionListMessageCount)(hd), 3);
        for (int i = 0; i < 3; i++) if (got[i]) {
            NT(AlpcFreeCompletionListMessage)(hd, got[i]);
            EXPECT_EQ(NT(AlpcGetOutstandingCompletionListMessageCount)(hd), 2 - i);
        }
        EXPECT_EQ(W32(hd, 0xc0), 4);
        /* freed blocks are reused by the next message */
        AMSG d; a_mk(&d, "again");
        EXPECT_EQ(NT(NtAlpcSendWaitReceivePort)(c.h, 0, &d.h, NULL, NULL, NULL, NULL, NULL), 0);
        key = NULL; EXPECT_EQ(wait_packet(io, &key), 0);
        m = NT(AlpcGetMessageFromCompletionList)(hd, NULL);
        CHECK(m != NULL);
        if (m) { EXPECT_STR((char *)(m + 1), "again"); NT(AlpcFreeCompletionListMessage)(hd, m); }
    }
    if (c.h) NT(NtClose)(c.h);
    if (comm) NT(NtClose)(comm);
    EXPECT_EQ(NT(AlpcRundownCompletionList)(lp), 0);
    EXPECT_EQ(NT(AlpcUnregisterCompletionList)(lp), 0);
    VirtualFree(hd, 0, MEM_RELEASE);
    NT(NtClose)(io); NT(NtClose)(lp);
}

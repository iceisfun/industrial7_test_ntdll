/* ALPC user-mode helpers that operate on caller-supplied memory only:
 *   AlpcGetHeaderSize, AlpcInitializeMessageAttribute, AlpcGetMessageAttribute,
 *   AlpcMaxAllowedMessageLength  (message attribute buffer layout)
 *   AlpcRegisterCompletionListWorkerThread / AlpcUnregisterCompletionListWorkerThread,
 *   AlpcGetOutstandingCompletionListMessageCount, AlpcGetCompletionListLastMessageInformation,
 *   AlpcGetCompletionListMessageAttributes, AlpcGetMessageFromCompletionList,
 *   AlpcFreeCompletionListMessage   (completion list header / ring / bitmap bookkeeping, driven on a
 *                                    hand-built header in private memory)
 * See EVIDENCE.md for the sources of every expected value.
 */
#include "t.h"

UDECL(ULONG, AlpcGetHeaderSize, (ULONG));
UDECL(NTSTATUS, AlpcInitializeMessageAttribute, (ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(PVOID, AlpcGetMessageAttribute, (PVOID, ULONG));
UDECL(ULONG, AlpcMaxAllowedMessageLength, (void));
UDECL(BOOLEAN, AlpcRegisterCompletionListWorkerThread, (PVOID));
UDECL(BOOLEAN, AlpcUnregisterCompletionListWorkerThread, (PVOID));
UDECL(ULONG, AlpcGetOutstandingCompletionListMessageCount, (PVOID));
UDECL(VOID, AlpcGetCompletionListLastMessageInformation, (PVOID, PULONG, PULONG));
UDECL(PVOID, AlpcGetCompletionListMessageAttributes, (PVOID, PVOID));
UDECL(PVOID, AlpcGetMessageFromCompletionList, (PVOID, PVOID *));
UDECL(VOID, AlpcFreeCompletionListMessage, (PVOID, PVOID));

#define A_SECURITY  0x80000000u
#define A_DATAVIEW  0x40000000u
#define A_CONTEXT   0x20000000u
#define A_HANDLE    0x10000000u
#define A_TOKEN     0x08000000u
#define A_DIRECT    0x04000000u
#define A_BEHALF    0x02000000u
#define S(x) ((NTSTATUS)(x))

static const struct { ULONG bit, size; } attr_sizes[] = {
    { A_SECURITY, 0x18 }, { A_DATAVIEW, 0x20 }, { A_CONTEXT, 0x20 }, { A_HANDLE, 0x18 },
    { A_TOKEN, 0x18 }, { A_DIRECT, 8 }, { A_BEHALF, 8 },
};

TEST(alpc_attr_header_size) {
    REQUIRE(UN(AlpcGetHeaderSize));
    ULONG (WINAPI *f)(ULONG) = UN(AlpcGetHeaderSize);
    EXPECT_EQ(f(0), 8);                      /* the ALPC_MESSAGE_ATTRIBUTES header alone */
    for (int i = 0; i < 7; i++)
        EXPECT_EQ(f(attr_sizes[i].bit), 8 + attr_sizes[i].size);
    EXPECT_EQ(f(A_SECURITY | A_DATAVIEW), 8 + 0x18 + 0x20);
    EXPECT_EQ(f(0xfe000000u), 8 + 0x18 + 0x20 + 0x20 + 0x18 + 0x18 + 8 + 8);
    /* every subset: size is 8 plus the sum of the selected attribute sizes */
    for (ULONG m = 0; m < 128; m++) {
        ULONG flags = 0, want = 8;
        for (int i = 0; i < 7; i++) if (m & (1u << i)) { flags |= attr_sizes[i].bit; want += attr_sizes[i].size; }
        EXPECT_EQ(f(flags), want);
    }
    /* bits below the attribute range contribute nothing */
    EXPECT_EQ(f(0x01ffffffu), 8);
    EXPECT_EQ(f(0xffffffffu), f(0xfe000000u));
}

TEST(alpc_attr_initialize) {
    REQUIRE(UN(AlpcInitializeMessageAttribute)); REQUIRE(UN(AlpcGetHeaderSize));
    ULONG buf[64];
    SIZE_T need = 0x1234;
    memset(buf, 0xcc, sizeof buf);
    NTSTATUS st = UN(AlpcInitializeMessageAttribute)(A_SECURITY | A_DATAVIEW, buf, sizeof buf, &need);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(need, 8 + 0x18 + 0x20);
    EXPECT_EQ(buf[0], A_SECURITY | A_DATAVIEW);   /* AllocatedAttributes */
    EXPECT_EQ(buf[1], 0);                         /* ValidAttributes cleared */
    EXPECT_EQ(buf[2], 0xcccccccc);                /* rest untouched */

    /* exact fit */
    memset(buf, 0xcc, sizeof buf); need = 0;
    st = UN(AlpcInitializeMessageAttribute)(A_CONTEXT, buf, 8 + 0x20, &need);
    EXPECT_EQ(st, 0); EXPECT_EQ(need, 8 + 0x20); EXPECT_EQ(buf[0], A_CONTEXT);

    /* one byte short: STATUS_BUFFER_TOO_SMALL, required size reported, buffer untouched */
    memset(buf, 0xcc, sizeof buf); need = 0;
    st = UN(AlpcInitializeMessageAttribute)(A_CONTEXT, buf, 8 + 0x20 - 1, &need);
    EXPECT_EQ(st, S(0xC0000023)); EXPECT_EQ(need, 8 + 0x20); EXPECT_EQ(buf[0], 0xcccccccc);

    /* NULL buffer with sufficient claimed size is accepted (size query form) */
    need = 0;
    st = UN(AlpcInitializeMessageAttribute)(A_HANDLE | A_TOKEN, NULL, 0x100, &need);
    EXPECT_EQ(st, 0); EXPECT_EQ(need, 8 + 0x18 + 0x18);
    need = 0;
    st = UN(AlpcInitializeMessageAttribute)(A_HANDLE, NULL, 0, &need);
    EXPECT_EQ(st, S(0xC0000023)); EXPECT_EQ(need, 8 + 0x18);

    /* no attributes: 8-byte header */
    memset(buf, 0xcc, sizeof buf);
    st = UN(AlpcInitializeMessageAttribute)(0, buf, 8, &need);
    EXPECT_EQ(st, 0); EXPECT_EQ(need, 8); EXPECT_EQ(buf[0], 0); EXPECT_EQ(buf[1], 0);
}

TEST(alpc_attr_get_attribute) {
    REQUIRE(UN(AlpcGetMessageAttribute)); REQUIRE(UN(AlpcInitializeMessageAttribute));
    BYTE buf[256]; SIZE_T need;
    ULONG all = A_SECURITY | A_DATAVIEW | A_CONTEXT | A_HANDLE | A_TOKEN | A_DIRECT | A_BEHALF;
    EXPECT_EQ(UN(AlpcInitializeMessageAttribute)(all, buf, sizeof buf, &need), 0);
    /* attributes are laid out after the 8-byte header in descending bit order */
    ULONG off = 8;
    for (int i = 0; i < 7; i++) {
        PVOID p = UN(AlpcGetMessageAttribute)(buf, attr_sizes[i].bit);
        EXPECT_EQ((BYTE *)p - buf, off);
        off += attr_sizes[i].size;
    }
    EXPECT_EQ(off, need);
    /* not allocated -> NULL */
    EXPECT_EQ(UN(AlpcInitializeMessageAttribute)(A_SECURITY | A_CONTEXT, buf, sizeof buf, &need), 0);
    EXPECT_EQ(UN(AlpcGetMessageAttribute)(buf, A_SECURITY), buf + 8);
    EXPECT_EQ(UN(AlpcGetMessageAttribute)(buf, A_CONTEXT), buf + 8 + 0x18);
    EXPECT_EQ(UN(AlpcGetMessageAttribute)(buf, A_DATAVIEW), NULL);
    EXPECT_EQ(UN(AlpcGetMessageAttribute)(buf, A_TOKEN), NULL);
    /* not exactly one bit -> NULL */
    EXPECT_EQ(UN(AlpcGetMessageAttribute)(buf, 0), NULL);
    EXPECT_EQ(UN(AlpcGetMessageAttribute)(buf, A_SECURITY | A_CONTEXT), NULL);
    /* bit outside the allocated set is NULL even when valid-looking */
    EXPECT_EQ(UN(AlpcGetMessageAttribute)(buf, 1), NULL);
    /* only AllocatedAttributes (first dword) matters, not ValidAttributes */
    ((ULONG *)buf)[1] = 0xffffffffu;
    EXPECT_EQ(UN(AlpcGetMessageAttribute)(buf, A_CONTEXT), buf + 8 + 0x18);
}

TEST(alpc_attr_max_message_length) {
    REQUIRE(UN(AlpcMaxAllowedMessageLength));
    EXPECT_EQ(UN(AlpcMaxAllowedMessageLength)(), 0xffff);
}

/* ---- completion list header driven on private memory ---- */
#define H_LISTOFF   0x0c
#define H_LISTSIZE  0x10
#define H_BITOFF    0x14
#define H_BITSIZE   0x18
#define H_DATAOFF   0x1c
#define H_DATASIZE  0x20
#define H_ATTRFLAGS 0x24
#define H_ATTRSIZE  0x28
#define H_STATE     0x40
#define H_LASTMSG   0x48
#define H_LASTCB    0x4c
#define H_POST      0x80
#define H_RETURN    0xc0
#define W32(b, o) (*(volatile ULONG *)((BYTE *)(b) + (o)))
#define W64(b, o) (*(volatile ULONGLONG *)((BYTE *)(b) + (o)))

static BYTE *new_header(void)
{
    return VirtualAlloc(NULL, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

TEST(alpc_cl_worker_thread_count) {
    REQUIRE(UN(AlpcRegisterCompletionListWorkerThread)); REQUIRE(UN(AlpcUnregisterCompletionListWorkerThread));
    BYTE *h = new_header(); CHECK(h);
    if (!h) return;
    /* unregister with no registered workers fails */
    EXPECT_EQ(UN(AlpcUnregisterCompletionListWorkerThread)(h), 0);
    /* count lives in the top 16 bits of the state qword at +0x40 */
    W64(h, H_STATE) = 0x0000ffffffffffffull;   /* count 0, head/tail empty marker */
    EXPECT_EQ(UN(AlpcRegisterCompletionListWorkerThread)(h), 1);
    EXPECT_EQ(W64(h, H_STATE), 0x0001ffffffffffffull);
    EXPECT_EQ(UN(AlpcRegisterCompletionListWorkerThread)(h), 1);
    EXPECT_EQ(W64(h, H_STATE), 0x0002ffffffffffffull);
    /* unregister only when the head index is the empty marker (low 24 bits all ones) */
    EXPECT_EQ(UN(AlpcUnregisterCompletionListWorkerThread)(h), 1);
    EXPECT_EQ(W64(h, H_STATE), 0x0001ffffffffffffull);
    W64(h, H_STATE) = 0x0001000000000005ull;   /* non-empty list */
    EXPECT_EQ(UN(AlpcUnregisterCompletionListWorkerThread)(h), 0);
    EXPECT_EQ(W64(h, H_STATE), 0x0001000000000005ull);
    /* register preserves the low 48 bits */
    EXPECT_EQ(UN(AlpcRegisterCompletionListWorkerThread)(h), 1);
    EXPECT_EQ(W64(h, H_STATE), 0x0002000000000005ull);
    /* upper limit: 0xffff workers */
    W64(h, H_STATE) = 0xfffe000000000000ull;
    EXPECT_EQ(UN(AlpcRegisterCompletionListWorkerThread)(h), 1);
    EXPECT_EQ(W64(h, H_STATE), 0xffff000000000000ull);
    EXPECT_EQ(UN(AlpcRegisterCompletionListWorkerThread)(h), 0);
    EXPECT_EQ(W64(h, H_STATE), 0xffff000000000000ull);
    VirtualFree(h, 0, MEM_RELEASE);
}

TEST(alpc_cl_counters_and_last_message) {
    REQUIRE(UN(AlpcGetOutstandingCompletionListMessageCount));
    REQUIRE(UN(AlpcGetCompletionListLastMessageInformation));
    BYTE *h = new_header(); CHECK(h);
    if (!h) return;
    W32(h, H_POST) = 10; W32(h, H_RETURN) = 4;
    EXPECT_EQ(UN(AlpcGetOutstandingCompletionListMessageCount)(h), 6);
    W32(h, H_POST) = 7; W32(h, H_RETURN) = 7;
    EXPECT_EQ(UN(AlpcGetOutstandingCompletionListMessageCount)(h), 0);
    W32(h, H_POST) = 0; W32(h, H_RETURN) = 0;
    EXPECT_EQ(UN(AlpcGetOutstandingCompletionListMessageCount)(h), 0);
    W32(h, H_POST) = 0x100; W32(h, H_RETURN) = 0xff;
    EXPECT_EQ(UN(AlpcGetOutstandingCompletionListMessageCount)(h), 1);

    ULONG a = 1, b = 2;
    W32(h, H_LASTMSG) = 0x11223344; W32(h, H_LASTCB) = 0x55667788;
    UN(AlpcGetCompletionListLastMessageInformation)(h, &a, &b);
    EXPECT_EQ(a, 0x11223344); EXPECT_EQ(b, 0x55667788);
    W32(h, H_LASTMSG) = 0; W32(h, H_LASTCB) = 0xffffffff;
    UN(AlpcGetCompletionListLastMessageInformation)(h, &a, &b);
    EXPECT_EQ(a, 0); EXPECT_EQ(b, 0xffffffff);
    VirtualFree(h, 0, MEM_RELEASE);
}

TEST(alpc_cl_message_attributes_pointer) {
    REQUIRE(UN(AlpcGetCompletionListMessageAttributes));
    BYTE *h = new_header(); CHECK(h);
    if (!h) return;
    BYTE *msg = h + 0x1000;
    *(USHORT *)(msg + 2) = 0x2d;                  /* PORT_MESSAGE.TotalLength */
    /* no attribute space configured -> NULL */
    W32(h, H_ATTRFLAGS) = 0;
    EXPECT_EQ(UN(AlpcGetCompletionListMessageAttributes)(h, msg), NULL);
    W32(h, H_ATTRFLAGS) = A_SECURITY;
    /* attributes follow the message, rounded up to an 8-byte boundary */
    EXPECT_EQ(UN(AlpcGetCompletionListMessageAttributes)(h, msg), msg + 0x30);
    *(USHORT *)(msg + 2) = 0x28;
    EXPECT_EQ(UN(AlpcGetCompletionListMessageAttributes)(h, msg), msg + 0x28);
    *(USHORT *)(msg + 2) = 0x29;
    EXPECT_EQ(UN(AlpcGetCompletionListMessageAttributes)(h, msg), msg + 0x30);
    *(USHORT *)(msg + 2) = 0x2f;
    EXPECT_EQ(UN(AlpcGetCompletionListMessageAttributes)(h, msg), msg + 0x30);
    VirtualFree(h, 0, MEM_RELEASE);
}

/* list: 4 entries at +0x200, bitmap at +0x300, data at +0x400 (0x400 bytes = 16 blocks of 64) */
static void setup_ring(BYTE *h)
{
    memset(h, 0, 0x2000);
    W32(h, H_LISTOFF) = 0x200; W32(h, H_LISTSIZE) = 16;
    W32(h, H_BITOFF) = 0x300;  W32(h, H_BITSIZE) = 8;
    W32(h, H_DATAOFF) = 0x400; W32(h, H_DATASIZE) = 0x400;
    W32(h, H_ATTRFLAGS) = 0;   W32(h, H_ATTRSIZE) = 0;
    ((ULONG *)(h + 0x200))[0] = 0x000;
    ((ULONG *)(h + 0x200))[1] = 0x040;
    ((ULONG *)(h + 0x200))[2] = 0x100;
    ((ULONG *)(h + 0x200))[3] = 0x200;
    W64(h, H_STATE) = 0x0003000000000000ull;      /* head 0, tail 0 placeholder set by caller */
}

TEST(alpc_cl_get_message) {
    REQUIRE(UN(AlpcGetMessageFromCompletionList));
    BYTE *h = new_header(); CHECK(h);
    if (!h) return;
    PVOID attrs = (PVOID)(ULONG_PTR)0x1234;
    setup_ring(h);
    /* empty marker in head -> NULL, state untouched */
    W64(h, H_STATE) = 0x0002ffffffffffffull;
    EXPECT_EQ(UN(AlpcGetMessageFromCompletionList)(h, &attrs), NULL);
    EXPECT_EQ(W64(h, H_STATE), 0x0002ffffffffffffull);
    EXPECT_EQ(attrs, (PVOID)(ULONG_PTR)0x1234);
    /* head 0, tail 2: three messages (head..tail inclusive) */
    W64(h, H_STATE) = 0x0002000002000000ull;
    attrs = (PVOID)(ULONG_PTR)0x1234;
    PVOID m = UN(AlpcGetMessageFromCompletionList)(h, &attrs);
    EXPECT_EQ(m, h + 0x400 + 0x000);
    EXPECT_EQ(attrs, NULL);                        /* no attribute space configured */
    EXPECT_EQ(W64(h, H_STATE), 0x0002000002000001ull);
    m = UN(AlpcGetMessageFromCompletionList)(h, NULL);   /* attribute out-pointer is optional */
    EXPECT_EQ(m, h + 0x400 + 0x040);
    EXPECT_EQ(W64(h, H_STATE), 0x0002000002000002ull);
    /* last entry: head == tail, list becomes empty (head and tail set to the empty marker) */
    *(USHORT *)(h + 0x400 + 0x100 + 2) = 0x30;
    W32(h, H_ATTRFLAGS) = A_SECURITY;
    attrs = NULL;
    m = UN(AlpcGetMessageFromCompletionList)(h, &attrs);
    EXPECT_EQ(m, h + 0x400 + 0x100);
    EXPECT_EQ(attrs, (PVOID)(h + 0x400 + 0x100 + 0x30));
    EXPECT_EQ(W64(h, H_STATE), 0x0002ffffffffffffull);
    EXPECT_EQ(UN(AlpcGetMessageFromCompletionList)(h, &attrs), NULL);
    /* wrap-around: head 3, tail 1 */
    W32(h, H_ATTRFLAGS) = 0;
    W64(h, H_STATE) = 0x0001000001000003ull;
    m = UN(AlpcGetMessageFromCompletionList)(h, NULL);
    EXPECT_EQ(m, h + 0x400 + 0x200);
    EXPECT_EQ(W64(h, H_STATE), 0x0001000001000000ull);
    /* out-of-range indices (>= entry count 4) -> NULL */
    W64(h, H_STATE) = 0x0001000000000004ull;
    EXPECT_EQ(UN(AlpcGetMessageFromCompletionList)(h, NULL), NULL);
    W64(h, H_STATE) = 0x0001000004000000ull;
    EXPECT_EQ(UN(AlpcGetMessageFromCompletionList)(h, NULL), NULL);
    VirtualFree(h, 0, MEM_RELEASE);
}

static ULONG bitmap_word(BYTE *h, int i) { return ((ULONG *)(h + 0x300))[i]; }

TEST(alpc_cl_free_message) {
    REQUIRE(UN(AlpcFreeCompletionListMessage));
    BYTE *h = new_header(); CHECK(h);
    if (!h) return;
    setup_ring(h);
    BYTE *data = h + 0x400;
    ((ULONG *)(h + 0x300))[0] = 0xffffffffu;
    ((ULONG *)(h + 0x300))[1] = 0xffffffffu;
    /* one 64-byte block at block index 1 */
    *(USHORT *)(data + 0x40 + 2) = 0x30;
    UN(AlpcFreeCompletionListMessage)(h, data + 0x40);
    EXPECT_EQ(bitmap_word(h, 0), 0xfffffffdu);
    EXPECT_EQ(W32(h, H_RETURN), 1);
    /* a 0x100-byte message spans four blocks (2..5) */
    *(USHORT *)(data + 0x80 + 2) = 0x100;
    UN(AlpcFreeCompletionListMessage)(h, data + 0x80);
    EXPECT_EQ(bitmap_word(h, 0), 0xffffffc1u);
    EXPECT_EQ(W32(h, H_RETURN), 2);
    /* block count rounds up: 0x41 bytes -> two blocks (8, 9) */
    *(USHORT *)(data + 0x200 + 2) = 0x41;
    UN(AlpcFreeCompletionListMessage)(h, data + 0x200);
    EXPECT_EQ(bitmap_word(h, 0) & 0x00000300u, 0);
    EXPECT_EQ(bitmap_word(h, 0) & 0x00000400u, 0x400);
    EXPECT_EQ(W32(h, H_RETURN), 3);
    ULONG before = bitmap_word(h, 0);
    /* rejected: not 64-byte aligned */
    *(USHORT *)(data + 0x300 + 2) = 0x20;
    UN(AlpcFreeCompletionListMessage)(h, data + 0x300 + 0x20);
    EXPECT_EQ(bitmap_word(h, 0), before); EXPECT_EQ(W32(h, H_RETURN), 3);
    /* rejected: before the data area */
    *(USHORT *)(h + 0x3c0 + 2) = 0x20;
    UN(AlpcFreeCompletionListMessage)(h, h + 0x3c0);
    EXPECT_EQ(W32(h, H_RETURN), 3);
    /* rejected: runs past the end of the data area */
    *(USHORT *)(data + 0x3c0 + 2) = 0x80;
    UN(AlpcFreeCompletionListMessage)(h, data + 0x3c0);
    EXPECT_EQ(W32(h, H_RETURN), 3);
    EXPECT_EQ(bitmap_word(h, 0), before);
    /* rejected: zero total length (end not above start) */
    *(USHORT *)(data + 0x340 + 2) = 0;
    UN(AlpcFreeCompletionListMessage)(h, data + 0x340);
    EXPECT_EQ(W32(h, H_RETURN), 3);
    /* last block of the data area is accepted exactly at the boundary */
    *(USHORT *)(data + 0x3c0 + 2) = 0x40;
    UN(AlpcFreeCompletionListMessage)(h, data + 0x3c0);
    EXPECT_EQ(W32(h, H_RETURN), 4);
    EXPECT_EQ(bitmap_word(h, 0) & 0x00008000u, 0);
    /* with attribute space: the attribute area is freed together with the message */
    W32(h, H_ATTRFLAGS) = A_SECURITY; W32(h, H_ATTRSIZE) = 0x40;
    ((ULONG *)(h + 0x300))[0] = 0xffffffffu;
    *(USHORT *)(data + 0x100 + 2) = 0x30;       /* 0x30 aligned to 8, + 0x40 = 0x70 -> 2 blocks */
    UN(AlpcFreeCompletionListMessage)(h, data + 0x100);
    EXPECT_EQ(bitmap_word(h, 0), 0xffffffffu & ~0x30u);
    EXPECT_EQ(W32(h, H_RETURN), 5);
    VirtualFree(h, 0, MEM_RELEASE);
}

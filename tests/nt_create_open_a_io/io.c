/* NtCreateMailslotFile and NtCreateNamedPipeFile (Zw twins are the same RVA).
 * Success paths are verified by talking through the created objects with ordinary Win32 file calls;
 * the parameter-validation outcomes were observed on Windows 10 22H2 (see EVIDENCE.md). */
#include "oa.h"

#define NEED_MS()   do { REQUIRE(UN(NtCreateMailslotFile)); REQUIRE(UN(NtClose)); } while (0)
#define NEED_NP()   do { REQUIRE(UN(NtCreateNamedPipeFile)); REQUIRE(UN(NtClose)); } while (0)
#define MS_ACCESS   (GENERIC_READ | SYNCHRONIZE | 0x100 /* WRITE_ATTRIBUTES */)
#define NP_ACCESS   (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE)
#define SYNC_NONALERT 0x20

static unsigned g_serial;
static void uniq(WCHAR *out, size_t cap, const WCHAR *prefix, const WCHAR *leaf)
{
    wsprintfW(out, L"%s%s_%lu_%u", prefix, leaf, GetCurrentProcessId(), ++g_serial);
}
TEST(mailslot_create_and_message_roundtrip)
{
    WCHAR nt[128], w32[160]; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; LARGE_INTEGER to; HANDLE srv = NULL, cli;
    char buf[64]; DWORD n = 0; NEED_MS();
    uniq(nt, 128, L"\\Device\\Mailslot\\", L"oa_ms"); oa_init(&oa, nt, OBJ_CI);
    to.QuadPart = -10000000;
    memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtCreateMailslotFile)(&srv, MS_ACCESS, &oa, &io, SYNC_NONALERT, 0, 0x100, &to), ST_SUCCESS);
    if (!srv) return;
    EXPECT_EQ(io.Status, ST_SUCCESS);
    EXPECT_EQ(io.Information, 2 /* FILE_CREATED */);
    wsprintfW(w32, L"\\\\.\\mailslot\\%s", nt + lstrlenW(L"\\Device\\Mailslot\\"));
    cli = CreateFileW(w32, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(cli != INVALID_HANDLE_VALUE);
    if (cli != INVALID_HANDLE_VALUE) {
        CHECK(WriteFile(cli, "hello", 5, &n, NULL)); EXPECT_EQ(n, 5);
        memset(buf, 0, sizeof buf);
        /* the mailslot is a message queue: one read returns one message */
        DWORD avail = 0, msgs = 0;
        CHECK(GetMailslotInfo(srv, NULL, &avail, &msgs, NULL));
        EXPECT_EQ(msgs, 1); EXPECT_EQ(avail, 5);
        CHECK(ReadFile(srv, buf, sizeof buf, &n, NULL)); EXPECT_EQ(n, 5);
        CHECK(!memcmp(buf, "hello", 5));
        /* a message larger than the maximum is rejected at write time */
        char big[0x200]; memset(big, 'x', sizeof big);
        SetLastError(0);
        CHECK(!WriteFile(cli, big, sizeof big, &n, NULL));
        CloseHandle(cli);
    }
    UN(NtClose)(srv);
}

TEST(mailslot_create_collision_and_reuse)
{
    WCHAR nt[128]; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; LARGE_INTEGER to; HANDLE a = NULL, b = NULL; NEED_MS();
    uniq(nt, 128, L"\\Device\\Mailslot\\", L"oa_ms2"); oa_init(&oa, nt, OBJ_CI);
    to.QuadPart = -10000000;
    EXPECT_EQ(UN(NtCreateMailslotFile)(&a, MS_ACCESS, &oa, &io, SYNC_NONALERT, 0, 0x100, &to), ST_SUCCESS);
    memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtCreateMailslotFile)(&b, MS_ACCESS, &oa, &io, SYNC_NONALERT, 0, 0x100, &to), ST_NAME_COLLISION);
    CHECK(b == NULL);
    if (a) UN(NtClose)(a);
    /* once the only server handle is closed the name is free again */
    EXPECT_EQ(UN(NtCreateMailslotFile)(&b, MS_ACCESS, &oa, &io, SYNC_NONALERT, 0, 0x100, &to), ST_SUCCESS);
    if (b) UN(NtClose)(b);
}

TEST(mailslot_parameter_variants)
{
    WCHAR nt[128]; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; LARGE_INTEGER to; HANDLE h = NULL; NEED_MS();
    to.QuadPart = -10000000;
    uniq(nt, 128, L"\\Device\\Mailslot\\", L"oa_ms3"); oa_init(&oa, nt, OBJ_CI);
    /* no read timeout: defaults to "wait forever" semantics, the create still succeeds */
    EXPECT_EQ(UN(NtCreateMailslotFile)(&h, MS_ACCESS, &oa, &io, SYNC_NONALERT, 0, 0x100, NULL), ST_SUCCESS);
    if (h) { UN(NtClose)(h); h = NULL; }
    /* quota and max message size of 0 / 0xffffffff are accepted */
    EXPECT_EQ(UN(NtCreateMailslotFile)(&h, MS_ACCESS, &oa, &io, SYNC_NONALERT, 0x1000, 0, &to), ST_SUCCESS);
    if (h) { UN(NtClose)(h); h = NULL; }
    EXPECT_EQ(UN(NtCreateMailslotFile)(&h, MS_ACCESS, &oa, &io, SYNC_NONALERT, 0, 0xffffffffu, &to), ST_SUCCESS);
    if (h) { UN(NtClose)(h); h = NULL; }
}

TEST(mailslot_invalid_arguments)
{
    WCHAR nt[128]; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; LARGE_INTEGER to; HANDLE h = NULL; NEED_MS();
    to.QuadPart = -10000000;
    uniq(nt, 128, L"\\Device\\Mailslot\\", L"oa_ms4"); oa_init(&oa, nt, OBJ_CI);
    /* no ObjectAttributes: the name is mandatory */
    EXPECT_EQ(UN(NtCreateMailslotFile)(&h, MS_ACCESS, NULL, &io, SYNC_NONALERT, 0, 0x100, &to), ST_INVALID_PARAMETER);
    CHECK(h == NULL);
    /* an unwritable IO_STATUS_BLOCK pointer is reported, not raised */
    EXPECT_EQ(UN(NtCreateMailslotFile)(&h, MS_ACCESS, &oa, NULL, SYNC_NONALERT, 0, 0x100, &to), ST_ACCESS_VIOLATION);
    CHECK(h == NULL);
}

/* ---- named pipes ------------------------------------------------------- */

TEST(pipe_create_and_data_roundtrip)
{
    WCHAR nt[128], w32[160]; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; LARGE_INTEGER to; HANDLE srv = NULL, cli; NEED_NP();
    char buf[16]; DWORD n = 0;
    uniq(nt, 128, L"\\Device\\NamedPipe\\", L"oa_np"); oa_init(&oa, nt, OBJ_CI);
    to.QuadPart = -500000;
    memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&srv, NP_ACCESS, &oa, &io, 3, 2 /* FILE_CREATE */, SYNC_NONALERT, 0, 0, 0, 4, 0x1000, 0x1000, &to), ST_SUCCESS);
    if (!srv) return;
    EXPECT_EQ(io.Status, ST_SUCCESS);
    EXPECT_EQ(io.Information, 2 /* FILE_CREATED */);
    wsprintfW(w32, L"\\\\.\\pipe\\%s", nt + lstrlenW(L"\\Device\\NamedPipe\\"));
    cli = CreateFileW(w32, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(cli != INVALID_HANDLE_VALUE);
    if (cli != INVALID_HANDLE_VALUE) {
        CHECK(WriteFile(cli, "ping", 4, &n, NULL)); EXPECT_EQ(n, 4);
        memset(buf, 0, sizeof buf);
        CHECK(ReadFile(srv, buf, sizeof buf, &n, NULL)); EXPECT_EQ(n, 4);
        CHECK(!memcmp(buf, "ping", 4));
        CHECK(WriteFile(srv, "pong!", 5, &n, NULL)); EXPECT_EQ(n, 5);
        memset(buf, 0, sizeof buf);
        CHECK(ReadFile(cli, buf, sizeof buf, &n, NULL)); EXPECT_EQ(n, 5);
        CHECK(!memcmp(buf, "pong!", 5));
        CloseHandle(cli);
    }
    UN(NtClose)(srv);
}

TEST(pipe_second_instance_dispositions)
{
    WCHAR nt[128]; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; LARGE_INTEGER to; HANDLE a = NULL, b = NULL; NEED_NP();
    uniq(nt, 128, L"\\Device\\NamedPipe\\", L"oa_np2"); oa_init(&oa, nt, OBJ_CI);
    to.QuadPart = -500000;
    /* FILE_OPEN on a pipe name that does not exist */
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&a, NP_ACCESS, &oa, &io, 3, 1 /* FILE_OPEN */, SYNC_NONALERT, 0, 0, 0, 4, 0x1000, 0x1000, &to), ST_NAME_NOT_FOUND);
    CHECK(a == NULL);
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&a, NP_ACCESS, &oa, &io, 3, 3 /* FILE_OPEN_IF */, SYNC_NONALERT, 0, 0, 0, 4, 0x1000, 0x1000, &to), ST_SUCCESS);
    EXPECT_EQ(io.Information, 2 /* FILE_CREATED: first instance */);
    /* a further instance of an existing pipe is reported as FILE_OPENED */
    memset(&io, 0xcc, sizeof io);
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&b, NP_ACCESS, &oa, &io, 3, 3, SYNC_NONALERT, 0, 0, 0, 4, 0x1000, 0x1000, &to), ST_SUCCESS);
    EXPECT_EQ(io.Information, 1 /* FILE_OPENED */);
    CHECK(a != NULL && b != NULL && a != b);
    if (b) UN(NtClose)(b);
    /* FILE_CREATE on an existing pipe is refused */
    b = NULL;
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&b, NP_ACCESS, &oa, &io, 3, 2, SYNC_NONALERT, 0, 0, 0, 4, 0x1000, 0x1000, &to), ST_ACCESS_DENIED);
    CHECK(b == NULL);
    if (a) UN(NtClose)(a);
}

TEST(pipe_message_mode_creation)
{
    WCHAR nt[128]; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; LARGE_INTEGER to; HANDLE h = NULL; NEED_NP();
    uniq(nt, 128, L"\\Device\\NamedPipe\\", L"oa_np3"); oa_init(&oa, nt, OBJ_CI);
    to.QuadPart = -500000;
    /* message type + message read mode, unlimited instances (0xffffffff) */
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, &oa, &io, 3, 2, SYNC_NONALERT, 1, 1, 0, 0xffffffffu, 0, 0, &to), ST_SUCCESS);
    if (h) UN(NtClose)(h);
    /* byte-type pipe cannot use message read mode */
    h = NULL;
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, &oa, &io, 3, 2, SYNC_NONALERT, 0, 1, 0, 1, 0, 0, &to), ST_INVALID_PARAMETER);
    CHECK(h == NULL);
}

TEST(pipe_invalid_arguments)
{
    WCHAR nt[128]; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; LARGE_INTEGER to; HANDLE h = NULL; NEED_NP();
    uniq(nt, 128, L"\\Device\\NamedPipe\\", L"oa_np4"); oa_init(&oa, nt, OBJ_CI);
    to.QuadPart = -500000;
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, &oa, &io, 3, 2, SYNC_NONALERT, 0, 2, 0, 1, 0, 0, &to), ST_INVALID_PARAMETER);   /* read mode 2 */
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, &oa, &io, 3, 2, SYNC_NONALERT, 0, 0, 2, 1, 0, 0, &to), ST_INVALID_PARAMETER);   /* completion mode 2 */
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, &oa, &io, 3, 2, SYNC_NONALERT, 0, 0, 0, 0, 0, 0, &to), ST_INVALID_PARAMETER);   /* zero instances */
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, &oa, &io, 3, 0 /* FILE_SUPERSEDE */, SYNC_NONALERT, 0, 0, 0, 1, 0, 0, &to), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, &oa, &io, 0, 2, SYNC_NONALERT, 0, 0, 0, 1, 0, 0, &to), ST_INVALID_PARAMETER);   /* no sharing */
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, &oa, &io, 7, 2, SYNC_NONALERT, 0, 0, 0, 1, 0, 0, &to), ST_INVALID_PARAMETER);   /* delete share */
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, &oa, &io, 3, 2, SYNC_NONALERT, 0, 0, 0, 1, 0, 0, NULL), ST_INVALID_PARAMETER);  /* no default timeout */
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, NULL, &io, 3, 2, SYNC_NONALERT, 0, 0, 0, 1, 0, 0, &to), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateNamedPipeFile)(&h, NP_ACCESS, &oa, NULL, 3, 2, SYNC_NONALERT, 0, 0, 0, 1, 0, 0, &to), ST_ACCESS_VIOLATION);
    CHECK(h == NULL);
}

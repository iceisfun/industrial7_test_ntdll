/* NtCancelSynchronousIoFile / NtCancelIoFile / NtCancelIoFileEx.
 *
 * Synchronous side: a thread blocked in NtReadFile on a synchronous anonymous-pipe handle is cancelled
 * from another thread. Asynchronous side: pending overlapped reads on a named-pipe server end are
 * cancelled one at a time, all at once, and from a thread other than the issuer.
 *
 * Expectations come from the public CancelSynchronousIo / CancelIo / CancelIoEx documentation and the
 * native status codes behind them. Status mapping used here:
 *   STATUS_SUCCESS 0, STATUS_PENDING 0x103, STATUS_CANCELLED 0xC0000120, STATUS_NOT_FOUND 0xC0000225,
 *   STATUS_INVALID_HANDLE 0xC0000008, STATUS_OBJECT_TYPE_MISMATCH 0xC0000024, STATUS_ACCESS_DENIED 0xC0000022.
 * NtCancelSynchronousIoFile(ThreadHandle, IoRequestToCancel OPTIONAL, IoStatusBlock)
 * NtCancelIoFile(FileHandle, IoStatusBlock)
 * NtCancelIoFileEx(FileHandle, IoRequestToCancel OPTIONAL, IoStatusBlock)
 * A thread that races the reader (not yet blocked) is handled by retrying until a deadline.
 */
#include "t.h"

UDECL(NTSTATUS, NtCancelSynchronousIoFile, (HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtCancelIoFile, (HANDLE, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtCancelIoFileEx, (HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK));
UDECL(NTSTATUS, NtReadFile, (HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));

#define S(x)           ((NTSTATUS)(x))
#define ST_SUCCESS     S(0)
#define ST_PENDING     S(0x103)
#define ST_CANCELLED   S(0xC0000120)
#define ST_NOT_FOUND   S(0xC0000225)
#define ST_INV_HANDLE  S(0xC0000008)
#define ST_TYPE_MISM   S(0xC0000024)
#define ST_DENIED      S(0xC0000022)
#define NT_CURRENT_THREAD ((HANDLE)(LONG_PTR)-2)

#define NEED_SYNC()  do { REQUIRE(UN(NtCancelSynchronousIoFile)); REQUIRE(UN(NtReadFile)); } while (0)
#define NEED_ASYNC() do { REQUIRE(UN(NtCancelIoFile)); REQUIRE(UN(NtCancelIoFileEx)); REQUIRE(UN(NtReadFile)); } while (0)

#define WAIT_MS 5000

/* ---- synchronous side ------------------------------------------------- */

typedef struct {
    HANDLE h;                       /* synchronous pipe read end */
    IO_STATUS_BLOCK io;
    NTSTATUS st;
    volatile LONG started;
    BYTE buf[16];
} sync_reader;

static DWORD WINAPI sync_reader_main(LPVOID p)
{
    sync_reader *r = (sync_reader *)p;
    memset(&r->io, 0xcc, sizeof r->io);
    InterlockedExchange(&r->started, 1);
    r->st = UN(NtReadFile)(r->h, NULL, NULL, NULL, &r->io, r->buf, sizeof r->buf, NULL, NULL);
    return 0;
}

/* Start a reader blocked (or about to block) in a synchronous read on an empty pipe. */
static BOOL sync_reader_start(sync_reader *r, HANDLE *wr, HANDLE *th)
{
    memset(r, 0, sizeof *r);
    if (!CreatePipe(&r->h, wr, NULL, 0)) return FALSE;
    *th = CreateThread(NULL, 0, sync_reader_main, r, 0, NULL);
    if (!*th) return FALSE;
    for (int i = 0; i < 500 && !r->started; i++) Sleep(10);
    return r->started != 0;
}

/* Retry until the reader is really blocked in the kernel and the cancel finds it. */
static NTSTATUS cancel_sync_until(HANDLE th, PIO_STATUS_BLOCK target, IO_STATUS_BLOCK *out, DWORD ms)
{
    NTSTATUS st = ST_NOT_FOUND;
    DWORD t0 = GetTickCount();
    do {
        memset(out, 0xcc, sizeof *out);
        st = UN(NtCancelSynchronousIoFile)(th, target, out);
        if (st != ST_NOT_FOUND) break;
        Sleep(10);
    } while (GetTickCount() - t0 < ms);
    return st;
}

static void sync_reader_end(sync_reader *r, HANDLE wr, HANDLE th)
{
    if (th) { WaitForSingleObject(th, WAIT_MS); CloseHandle(th); }
    if (r->h) CloseHandle(r->h);
    if (wr) CloseHandle(wr);
}

TEST(nt_cancel_sync_blocked_read)
{
    sync_reader r; HANDLE wr = NULL, th = NULL; IO_STATUS_BLOCK out; NEED_SYNC();
    CHECK(sync_reader_start(&r, &wr, &th));
    if (!th) return;
    EXPECT_EQ(cancel_sync_until(th, NULL, &out, WAIT_MS), ST_SUCCESS);
    EXPECT_EQ(out.Status, ST_SUCCESS);
    t_note("NtCancelSynchronousIoFile IoStatusBlock on success: Status=%08lx Information=%llu",
           (unsigned long)out.Status, (unsigned long long)out.Information);
    EXPECT_EQ(WaitForSingleObject(th, WAIT_MS), WAIT_OBJECT_0);
    EXPECT_EQ(r.st, ST_CANCELLED);
    EXPECT_EQ(r.io.Status, ST_CANCELLED);
    EXPECT_EQ(r.io.Information, 0);
    sync_reader_end(&r, wr, th);
}

TEST(nt_cancel_sync_matching_iosb)
{
    sync_reader r; HANDLE wr = NULL, th = NULL; IO_STATUS_BLOCK out; NEED_SYNC();
    CHECK(sync_reader_start(&r, &wr, &th));
    if (!th) return;
    /* IoRequestToCancel names the reader's own IO_STATUS_BLOCK: that request is the one cancelled. */
    EXPECT_EQ(cancel_sync_until(th, &r.io, &out, WAIT_MS), ST_SUCCESS);
    EXPECT_EQ(WaitForSingleObject(th, WAIT_MS), WAIT_OBJECT_0);
    EXPECT_EQ(r.st, ST_CANCELLED);
    EXPECT_EQ(r.io.Status, ST_CANCELLED);
    sync_reader_end(&r, wr, th);
}

TEST(nt_cancel_sync_nonmatching_iosb_leaves_read_blocked)
{
    sync_reader r; HANDLE wr = NULL, th = NULL; IO_STATUS_BLOCK out, other; NEED_SYNC();
    CHECK(sync_reader_start(&r, &wr, &th));
    if (!th) return;
    Sleep(100); /* let the reader reach the kernel wait */
    for (int i = 0; i < 10; i++) {
        memset(&out, 0xcc, sizeof out);
        EXPECT_EQ(UN(NtCancelSynchronousIoFile)(th, &other, &out), ST_NOT_FOUND);
    }
    EXPECT_EQ(WaitForSingleObject(th, 100), WAIT_TIMEOUT);   /* still blocked */
    EXPECT_EQ(cancel_sync_until(th, NULL, &out, WAIT_MS), ST_SUCCESS);
    EXPECT_EQ(WaitForSingleObject(th, WAIT_MS), WAIT_OBJECT_0);
    EXPECT_EQ(r.st, ST_CANCELLED);
    sync_reader_end(&r, wr, th);
}

TEST(nt_cancel_sync_second_cancel_not_found)
{
    sync_reader r; HANDLE wr = NULL, th = NULL; IO_STATUS_BLOCK out; NEED_SYNC();
    CHECK(sync_reader_start(&r, &wr, &th));
    if (!th) return;
    EXPECT_EQ(cancel_sync_until(th, NULL, &out, WAIT_MS), ST_SUCCESS);
    EXPECT_EQ(WaitForSingleObject(th, WAIT_MS), WAIT_OBJECT_0);
    /* The thread has exited: nothing left to cancel. The handle is still a valid thread handle. */
    memset(&out, 0xcc, sizeof out);
    EXPECT_EQ(UN(NtCancelSynchronousIoFile)(th, NULL, &out), ST_NOT_FOUND);
    t_note("not-found IoStatusBlock: Status=%08lx Information=%llu",
           (unsigned long)out.Status, (unsigned long long)out.Information);
    sync_reader_end(&r, wr, th);
}

static DWORD WINAPI wait_event_main(LPVOID p)
{
    WaitForSingleObject((HANDLE)p, WAIT_MS);
    return 0;
}

TEST(nt_cancel_sync_thread_without_io_not_found)
{
    HANDLE ev, th; IO_STATUS_BLOCK out; NEED_SYNC();
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, wait_event_main, ev, 0, NULL);
    CHECK(ev && th);
    if (th) {
        Sleep(50);   /* a plain wait is not I/O */
        memset(&out, 0xcc, sizeof out);
        EXPECT_EQ(UN(NtCancelSynchronousIoFile)(th, NULL, &out), ST_NOT_FOUND);
        SetEvent(ev); WaitForSingleObject(th, WAIT_MS); CloseHandle(th);
    }
    if (ev) CloseHandle(ev);
}

TEST(nt_cancel_sync_own_thread_not_found)
{
    IO_STATUS_BLOCK out; NEED_SYNC();
    memset(&out, 0xcc, sizeof out);
    EXPECT_EQ(UN(NtCancelSynchronousIoFile)(NT_CURRENT_THREAD, NULL, &out), ST_NOT_FOUND);
}

TEST(nt_cancel_sync_bad_handles)
{
    IO_STATUS_BLOCK out; HANDLE ev, th, dup = NULL; NEED_SYNC();
    EXPECT_EQ(UN(NtCancelSynchronousIoFile)(NULL, NULL, &out), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCancelSynchronousIoFile)((HANDLE)(ULONG_PTR)0x7ffc, NULL, &out), ST_INV_HANDLE);
    /* The current-process pseudo handle (-1) and an event are valid handles of the wrong type. */
    EXPECT_EQ(UN(NtCancelSynchronousIoFile)(INVALID_HANDLE_VALUE, NULL, &out), ST_TYPE_MISM);
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev) { EXPECT_EQ(UN(NtCancelSynchronousIoFile)(ev, NULL, &out), ST_TYPE_MISM); CloseHandle(ev); }
    /* A thread handle without THREAD_TERMINATE access is refused. */
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, wait_event_main, ev, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        CHECK(DuplicateHandle(GetCurrentProcess(), th, GetCurrentProcess(), &dup,
                              THREAD_QUERY_LIMITED_INFORMATION, FALSE, 0));
        if (dup) { EXPECT_EQ(UN(NtCancelSynchronousIoFile)(dup, NULL, &out), ST_DENIED); CloseHandle(dup); }
        SetEvent(ev); WaitForSingleObject(th, WAIT_MS); CloseHandle(th);
    }
    if (ev) CloseHandle(ev);
}

/* ---- asynchronous side ------------------------------------------------- */

static int g_pipe_seq;

/* Overlapped named-pipe server end (read side) plus a connected client end. */
static BOOL make_async_pipe(HANDLE *srv, HANDLE *cli)
{
    WCHAR name[96];
    wsprintfW(name, L"\\\\.\\pipe\\i7_cancel_io_%lu_%d", GetCurrentProcessId(), ++g_pipe_seq);
    *srv = CreateNamedPipeW(name, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                            PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
    if (*srv == INVALID_HANDLE_VALUE) { *srv = NULL; return FALSE; }
    *cli = CreateFileW(name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (*cli == INVALID_HANDLE_VALUE) { *cli = NULL; return FALSE; }
    return TRUE;
}

typedef struct { HANDLE ev; IO_STATUS_BLOCK io; BYTE buf[16]; } areq;

static NTSTATUS areq_start(HANDLE srv, areq *q)
{
    memset(q, 0, sizeof *q);
    q->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&q->io, 0xcc, sizeof q->io);
    return UN(NtReadFile)(srv, q->ev, NULL, NULL, &q->io, q->buf, sizeof q->buf, NULL, NULL);
}

static void areq_check_cancelled(areq *q)
{
    EXPECT_EQ(WaitForSingleObject(q->ev, WAIT_MS), WAIT_OBJECT_0);
    EXPECT_EQ(q->io.Status, ST_CANCELLED);
    EXPECT_EQ(q->io.Information, 0);
}

static void areq_drain(HANDLE srv, areq *q)
{
    IO_STATUS_BLOCK c;
    if (WaitForSingleObject(q->ev, 0) != WAIT_OBJECT_0) { UN(NtCancelIoFileEx)(srv, NULL, &c); WaitForSingleObject(q->ev, WAIT_MS); }
    if (q->ev) CloseHandle(q->ev);
}

TEST(nt_cancel_io_file_pending_read)
{
    HANDLE srv, cli; areq q; IO_STATUS_BLOCK c; NEED_ASYNC();
    CHECK(make_async_pipe(&srv, &cli));
    if (!srv || !cli) return;
    EXPECT_EQ(areq_start(srv, &q), ST_PENDING);
    memset(&c, 0xcc, sizeof c);
    EXPECT_EQ(UN(NtCancelIoFile)(srv, &c), ST_SUCCESS);
    EXPECT_EQ(c.Status, ST_SUCCESS);
    areq_check_cancelled(&q);
    areq_drain(srv, &q);
    CloseHandle(cli); CloseHandle(srv);
}

TEST(nt_cancel_io_file_idle_succeeds)
{
    HANDLE srv, cli; IO_STATUS_BLOCK c; NEED_ASYNC();
    CHECK(make_async_pipe(&srv, &cli));
    if (!srv || !cli) return;
    memset(&c, 0xcc, sizeof c);
    EXPECT_EQ(UN(NtCancelIoFile)(srv, &c), ST_SUCCESS);   /* CancelIo with nothing pending still succeeds */
    EXPECT_EQ(c.Status, ST_SUCCESS);
    CloseHandle(cli); CloseHandle(srv);
}

TEST(nt_cancel_io_file_ex_idle_not_found)
{
    HANDLE srv, cli; IO_STATUS_BLOCK c; NEED_ASYNC();
    CHECK(make_async_pipe(&srv, &cli));
    if (!srv || !cli) return;
    memset(&c, 0xcc, sizeof c);
    EXPECT_EQ(UN(NtCancelIoFileEx)(srv, NULL, &c), ST_NOT_FOUND);   /* CancelIoEx: ERROR_NOT_FOUND */
    t_note("NtCancelIoFileEx idle IoStatusBlock: Status=%08lx", (unsigned long)c.Status);
    CloseHandle(cli); CloseHandle(srv);
}

TEST(nt_cancel_io_file_ex_one_request_only)
{
    HANDLE srv, cli; areq q1, q2; IO_STATUS_BLOCK c; NEED_ASYNC();
    CHECK(make_async_pipe(&srv, &cli));
    if (!srv || !cli) return;
    EXPECT_EQ(areq_start(srv, &q1), ST_PENDING);
    EXPECT_EQ(areq_start(srv, &q2), ST_PENDING);
    memset(&c, 0xcc, sizeof c);
    EXPECT_EQ(UN(NtCancelIoFileEx)(srv, &q1.io, &c), ST_SUCCESS);
    EXPECT_EQ(c.Status, ST_SUCCESS);
    areq_check_cancelled(&q1);
    EXPECT_EQ(WaitForSingleObject(q2.ev, 50), WAIT_TIMEOUT);   /* the other request is untouched */
    t_note("second pending request IoStatusBlock.Status=%08lx (not asserted)", (unsigned long)q2.io.Status);
    /* IoRequestToCancel == NULL cancels everything still pending on the handle. */
    EXPECT_EQ(UN(NtCancelIoFileEx)(srv, NULL, &c), ST_SUCCESS);
    areq_check_cancelled(&q2);
    areq_drain(srv, &q1); areq_drain(srv, &q2);
    CloseHandle(cli); CloseHandle(srv);
}

TEST(nt_cancel_io_file_ex_nonmatching_iosb)
{
    HANDLE srv, cli; areq q; IO_STATUS_BLOCK c, other; NEED_ASYNC();
    CHECK(make_async_pipe(&srv, &cli));
    if (!srv || !cli) return;
    EXPECT_EQ(areq_start(srv, &q), ST_PENDING);
    memset(&c, 0xcc, sizeof c);
    EXPECT_EQ(UN(NtCancelIoFileEx)(srv, &other, &c), ST_NOT_FOUND);
    EXPECT_EQ(WaitForSingleObject(q.ev, 50), WAIT_TIMEOUT);
    t_note("pending request IoStatusBlock.Status=%08lx before cancel (not asserted: the native call need not initialise it)", (unsigned long)q.io.Status);
    areq_drain(srv, &q);
    CloseHandle(cli); CloseHandle(srv);
}

typedef struct { HANDLE h; int ex; NTSTATUS st; IO_STATUS_BLOCK io; } cancel_job;

static DWORD WINAPI cancel_job_main(LPVOID p)
{
    cancel_job *j = (cancel_job *)p;
    memset(&j->io, 0xcc, sizeof j->io);
    j->st = j->ex ? UN(NtCancelIoFileEx)(j->h, NULL, &j->io) : UN(NtCancelIoFile)(j->h, &j->io);
    return 0;
}

static void run_cancel_job(cancel_job *j)
{
    HANDLE th = CreateThread(NULL, 0, cancel_job_main, j, 0, NULL);
    CHECK(th != NULL);
    if (th) { WaitForSingleObject(th, WAIT_MS); CloseHandle(th); }
}

TEST(nt_cancel_io_from_other_thread)
{
    HANDLE srv, cli; areq q; cancel_job j; NEED_ASYNC();
    CHECK(make_async_pipe(&srv, &cli));
    if (!srv || !cli) return;
    EXPECT_EQ(areq_start(srv, &q), ST_PENDING);
    /* CancelIo only cancels requests issued by the calling thread: success, nothing cancelled. */
    memset(&j, 0, sizeof j); j.h = srv; j.ex = 0;
    run_cancel_job(&j);
    EXPECT_EQ(j.st, ST_SUCCESS);
    EXPECT_EQ(WaitForSingleObject(q.ev, 100), WAIT_TIMEOUT);
    t_note("pending request IoStatusBlock.Status=%08lx before cancel (not asserted: the native call need not initialise it)", (unsigned long)q.io.Status);
    /* CancelIoEx cancels requests regardless of the issuing thread. */
    memset(&j, 0, sizeof j); j.h = srv; j.ex = 1;
    run_cancel_job(&j);
    EXPECT_EQ(j.st, ST_SUCCESS);
    areq_check_cancelled(&q);
    areq_drain(srv, &q);
    CloseHandle(cli); CloseHandle(srv);
}

TEST(nt_cancel_io_sync_cancel_does_not_touch_overlapped)
{
    HANDLE srv, cli; areq q; IO_STATUS_BLOCK out, c; NEED_SYNC(); NEED_ASYNC();
    CHECK(make_async_pipe(&srv, &cli));
    if (!srv || !cli) return;
    EXPECT_EQ(areq_start(srv, &q), ST_PENDING);
    /* NtCancelSynchronousIoFile cancels synchronous I/O only; a pending overlapped read is not one. */
    memset(&out, 0xcc, sizeof out);
    EXPECT_EQ(UN(NtCancelSynchronousIoFile)(NT_CURRENT_THREAD, NULL, &out), ST_NOT_FOUND);
    EXPECT_EQ(WaitForSingleObject(q.ev, 50), WAIT_TIMEOUT);
    t_note("pending request IoStatusBlock.Status=%08lx before cancel (not asserted: the native call need not initialise it)", (unsigned long)q.io.Status);
    EXPECT_EQ(UN(NtCancelIoFile)(srv, &c), ST_SUCCESS);
    areq_check_cancelled(&q);
    areq_drain(srv, &q);
    CloseHandle(cli); CloseHandle(srv);
}

TEST(nt_cancel_io_bad_handles)
{
    IO_STATUS_BLOCK c; HANDLE ev; NEED_ASYNC();
    EXPECT_EQ(UN(NtCancelIoFile)(NULL, &c), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCancelIoFile)((HANDLE)(ULONG_PTR)0x7ffc, &c), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCancelIoFileEx)(NULL, NULL, &c), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCancelIoFileEx)((HANDLE)(ULONG_PTR)0x7ffc, NULL, &c), ST_INV_HANDLE);
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev) {
        EXPECT_EQ(UN(NtCancelIoFile)(ev, &c), ST_TYPE_MISM);
        EXPECT_EQ(UN(NtCancelIoFileEx)(ev, NULL, &c), ST_TYPE_MISM);
        CloseHandle(ev);
    }
}

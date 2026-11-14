/* Preferred-UI-language setters, RtlSetTimer and RtlSetIoCompletionCallback. */
#include "t.h"
#include <stdlib.h>
#include <wchar.h>

UDECL(NTSTATUS, RtlSetThreadPreferredUILanguages, (ULONG, PCZZWSTR, PULONG));
UDECL(NTSTATUS, RtlSetThreadPreferredUILanguages2, (ULONG, PCZZWSTR, PULONG, PHANDLE));
UDECL(BOOLEAN, RtlRestoreThreadPreferredUILanguages, (PVOID));
UDECL(NTSTATUS, RtlSetProcessPreferredUILanguages, (ULONG, PCZZWSTR, PULONG));
UDECL(NTSTATUS, RtlGetThreadPreferredUILanguages, (ULONG, ULONG *, PWSTR, ULONG *));
UDECL(NTSTATUS, RtlGetProcessPreferredUILanguages, (ULONG, ULONG *, PWSTR, ULONG *));
UDECL(NTSTATUS, RtlCreateTimerQueue, (PHANDLE));
UDECL(NTSTATUS, RtlDeleteTimerQueueEx, (HANDLE, HANDLE));
UDECL(NTSTATUS, RtlSetTimer, (HANDLE, PHANDLE, PVOID, PVOID, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, RtlDeleteTimer, (HANDLE, HANDLE, HANDLE));
UDECL(NTSTATUS, RtlSetIoCompletionCallback, (HANDLE, PVOID, ULONG));

#define S(x) ((NTSTATUS)(x))
#define ST_INVPARAM S(0xC000000D)
#define MUI_ID 4
#define MUI_NAME 8

static BOOL first_is(NTSTATUS (*get)(ULONG, ULONG *, PWSTR, ULONG *), ULONG flags, const WCHAR *want, ULONG *count) {
    WCHAR buf[256]; ULONG c = 0, sz = 256; memset(buf, 0, sizeof buf);
    if (get(flags, &c, buf, &sz) < 0) return FALSE;
    if (count) *count = c;
    return !wcscmp(buf, want);
}
static NTSTATUS tget(ULONG f, ULONG *c, PWSTR b, ULONG *s) { return UN(RtlGetThreadPreferredUILanguages)(f, c, b, s); }
static NTSTATUS pget(ULONG f, ULONG *c, PWSTR b, ULONG *s) { return UN(RtlGetProcessPreferredUILanguages)(f, c, b, s); }

TEST(rtl_set_thread_preferred_ui_languages) {
    REQUIRE(UN(RtlSetThreadPreferredUILanguages)); REQUIRE(UN(RtlGetThreadPreferredUILanguages));
    ULONG cnt = 0xdead;
    /* validation of flags: unknown bits, both name+id, both merge flags */
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(0x2, NULL, &cnt), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(0xc, NULL, &cnt), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(0x80000000u, NULL, &cnt), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(0x300 | MUI_NAME, NULL, &cnt), ST_INVPARAM);
    EXPECT_EQ(cnt, 0xdead);
    /* set by name, read back from the thread list */
    static const WCHAR names[] = L"fr-FR\0de-DE\0";           /* + implicit second NUL */
    cnt = 0;
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, names, &cnt), 0);
    EXPECT_EQ(cnt, 2);
    {
        WCHAR buf[128]; ULONG c = 0, sz = 128; memset(buf, 0, sizeof buf);
        EXPECT_EQ(tget(MUI_NAME, &c, buf, &sz), 0);
        /* the thread list is followed by the fallback languages */
        CHECK(c >= 2); CHECK(sz >= 13);
        CHECK(!wcscmp(buf, L"fr-FR")); CHECK(!wcscmp(buf + 6, L"de-DE"));
    }
    /* replacing, flags 0 default to names */
    static const WCHAR one[] = L"es-ES\0";
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(0, one, &cnt), 0); EXPECT_EQ(cnt, 1);
    CHECK(first_is(tget, MUI_NAME, L"es-ES", &cnt)); CHECK(cnt >= 1);
    /* language ids */
    static const WCHAR ids[] = L"0407\0";
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(MUI_ID, ids, &cnt), 0); EXPECT_EQ(cnt, 1);
    CHECK(first_is(tget, MUI_NAME, L"de-DE", &cnt));
    /* a NULL list resets the thread list; the thread getter then follows the process/user/system lists */
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, NULL, NULL), 0);
    { WCHAR buf[128]; ULONG c = 0, sz = 128; EXPECT_EQ(tget(MUI_NAME, &c, buf, &sz), 0); CHECK(wcscmp(buf, L"es-ES") != 0 && wcscmp(buf, L"fr-FR") != 0); }
    /* the empty multi-string also resets */
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, names, &cnt), 0);
    static const WCHAR empty[] = L"\0";
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, empty, &cnt), 0);
    { WCHAR buf[128]; ULONG c = 0, sz = 128; EXPECT_EQ(tget(MUI_NAME, &c, buf, &sz), 0); CHECK(wcscmp(buf, L"fr-FR") != 0); }
    /* an invalid language tag is refused and leaves the list alone */
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, one, &cnt), 0);
    static const WCHAR bad[] = L"zz-notalanguage-ZZ-ZZ-ZZ\0";
    NTSTATUS s = UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, bad, &cnt);
    EXPECT_EQ(s, S(0xC0000001));
    CHECK(first_is(tget, MUI_NAME, L"es-ES", NULL));
    UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, NULL, NULL);
}

TEST(rtl_set_thread_preferred_ui_languages2_restore) {
    REQUIRE(UN(RtlSetThreadPreferredUILanguages2)); REQUIRE(UN(RtlSetThreadPreferredUILanguages)); REQUIRE(UN(RtlGetThreadPreferredUILanguages));
    REQUIRE(UN(RtlRestoreThreadPreferredUILanguages));
    static const WCHAR a[] = L"fr-FR\0", b[] = L"it-IT\0";
    ULONG cnt = 0; HANDLE snap = NULL;
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, a, &cnt), 0);
    /* the Ex form returns a snapshot of the previous state while installing the new one */
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages2)(MUI_NAME, b, &cnt, &snap), 0);
    EXPECT_EQ(cnt, 1); CHECK(snap != NULL);
    CHECK(first_is(tget, MUI_NAME, L"it-IT", NULL));
    if (snap) {
        EXPECT_EQ(UN(RtlRestoreThreadPreferredUILanguages)(snap), TRUE);
        CHECK(first_is(tget, MUI_NAME, L"fr-FR", NULL));          /* previous list is back */
    }
    /* with a NULL snapshot pointer it behaves like the plain setter */
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages2)(MUI_NAME, b, &cnt, NULL), 0);
    CHECK(first_is(tget, MUI_NAME, L"it-IT", NULL));
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages2)(0x2, a, &cnt, &snap), ST_INVPARAM);
    UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, NULL, NULL);
}

TEST(rtl_set_process_preferred_ui_languages) {
    REQUIRE(UN(RtlSetProcessPreferredUILanguages)); REQUIRE(UN(RtlGetProcessPreferredUILanguages)); REQUIRE(UN(RtlSetThreadPreferredUILanguages));
    ULONG cnt = 0xdead;
    EXPECT_EQ(UN(RtlSetProcessPreferredUILanguages)(0x2, NULL, &cnt), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetProcessPreferredUILanguages)(0xc, NULL, &cnt), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetProcessPreferredUILanguages)(0x10, NULL, &cnt), ST_INVPARAM);
    EXPECT_EQ(UN(RtlSetProcessPreferredUILanguages)(0x100, NULL, &cnt), ST_INVPARAM);
    EXPECT_EQ(cnt, 0xdead);
    static const WCHAR names[] = L"ja-JP\0en-GB\0";
    EXPECT_EQ(UN(RtlSetProcessPreferredUILanguages)(MUI_NAME, names, &cnt), 0); EXPECT_EQ(cnt, 2);
    {
        WCHAR buf[128]; ULONG c = 0, sz = 128; memset(buf, 0, sizeof buf);
        EXPECT_EQ(pget(MUI_NAME, &c, buf, &sz), 0);
        EXPECT_EQ(c, 2); EXPECT_EQ(sz, 6 + 6 + 1); CHECK(!wcscmp(buf, L"ja-JP")); CHECK(!wcscmp(buf + 6, L"en-GB"));
    }
    /* a thread list overrides the process list for that thread only */
    static const WCHAR t1[] = L"ko-KR\0";
    EXPECT_EQ(UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, t1, &cnt), 0);
    CHECK(first_is(tget, MUI_NAME, L"ko-KR", NULL));
    CHECK(first_is(pget, MUI_NAME, L"ja-JP", NULL));
    UN(RtlSetThreadPreferredUILanguages)(MUI_NAME, NULL, NULL);
    /* ids and flag 0 (names) */
    static const WCHAR ids[] = L"0409\0";
    EXPECT_EQ(UN(RtlSetProcessPreferredUILanguages)(MUI_ID, ids, &cnt), 0); EXPECT_EQ(cnt, 1);
    CHECK(first_is(pget, MUI_NAME, L"en-US", NULL));
    EXPECT_EQ(UN(RtlSetProcessPreferredUILanguages)(0, names, &cnt), 0); EXPECT_EQ(cnt, 2);
    /* reset */
    EXPECT_EQ(UN(RtlSetProcessPreferredUILanguages)(MUI_NAME, NULL, NULL), 0);
    CHECK(!first_is(pget, MUI_NAME, L"ja-JP", NULL));
}

/* ---- timers ---- */
static HANDLE g_ev; static volatile LONG g_fired; static PVOID g_ctx; static volatile LONG g_flag;
static void NTAPI timer_cb(PVOID ctx, BOOLEAN fired) { g_ctx = ctx; g_flag = fired; InterlockedIncrement(&g_fired); SetEvent(g_ev); }

TEST(rtl_set_timer) {
    REQUIRE(UN(RtlSetTimer)); REQUIRE(UN(RtlCreateTimerQueue)); REQUIRE(UN(RtlDeleteTimerQueueEx)); REQUIRE(UN(RtlDeleteTimer));
    g_ev = CreateEventW(NULL, FALSE, FALSE, NULL); g_fired = 0;
    HANDLE q = NULL, tm = (HANDLE)0xdead;
    EXPECT_EQ(UN(RtlCreateTimerQueue)(&q), 0);
    /* one-shot timer, due in 30ms (flags 0) */
    NTSTATUS s = UN(RtlSetTimer)(q, &tm, timer_cb, (PVOID)0xc0de, 30, 0, 0);
    EXPECT_EQ(s, 0);
    CHECK(tm != (HANDLE)0xdead && tm != NULL);
    if (s >= 0) {
        EXPECT_EQ(WaitForSingleObject(g_ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(g_fired, 1); EXPECT_EQ(g_ctx, (PVOID)0xc0de); EXPECT_EQ(g_flag, 1);   /* TimerOrWaitFired = TRUE */
        EXPECT_EQ(WaitForSingleObject(g_ev, 150), WAIT_TIMEOUT);                          /* does not repeat */
        EXPECT_EQ(g_fired, 1);
        EXPECT_EQ(UN(RtlDeleteTimer)(q, tm, INVALID_HANDLE_VALUE), 0);
    }
    /* periodic timer fires repeatedly until deleted */
    g_fired = 0; tm = NULL;
    s = UN(RtlSetTimer)(q, &tm, timer_cb, (PVOID)0xbeef, 20, 20, 0);
    EXPECT_EQ(s, 0);
    if (s >= 0) {
        for (int i = 0; i < 3; i++) EXPECT_EQ(WaitForSingleObject(g_ev, 5000), WAIT_OBJECT_0);
        CHECK(g_fired >= 3); EXPECT_EQ(g_ctx, (PVOID)0xbeef);
        EXPECT_EQ(UN(RtlDeleteTimer)(q, tm, INVALID_HANDLE_VALUE), 0);
        LONG after = g_fired; Sleep(120); EXPECT_EQ(g_fired, after);                     /* stopped */
    }
    /* far-future timer deleted before it fires never runs */
    g_fired = 0; tm = NULL;
    s = UN(RtlSetTimer)(q, &tm, timer_cb, (PVOID)1, 60000, 0, 0);
    EXPECT_EQ(s, 0);
    if (s >= 0) { EXPECT_EQ(UN(RtlDeleteTimer)(q, tm, INVALID_HANDLE_VALUE), 0); EXPECT_EQ(g_fired, 0); }
    /* a NULL callback is not validated at creation (observed); the far-future timer is deleted before it can fire */
    { HANDLE t2 = (HANDLE)0xdead;
      EXPECT_EQ(UN(RtlSetTimer)(q, &t2, NULL, NULL, 60000, 0, 0), 0);
      CHECK(t2 != (HANDLE)0xdead && t2 != NULL);
      EXPECT_EQ(UN(RtlDeleteTimer)(q, t2, INVALID_HANDLE_VALUE), 0); }
    EXPECT_EQ(UN(RtlDeleteTimerQueueEx)(q, INVALID_HANDLE_VALUE), 0);
    CloseHandle(g_ev);
}

/* ---- I/O completion callback ---- */
static volatile LONG g_io_n; static PVOID g_io_a[3];
static void NTAPI io_cb(PVOID a, PVOID b, PVOID c) { g_io_a[0] = a; g_io_a[1] = b; g_io_a[2] = c; InterlockedIncrement(&g_io_n); SetEvent(g_ev); }

TEST(rtl_set_io_completion_callback) {
    REQUIRE(UN(RtlSetIoCompletionCallback));
    EXPECT_EQ(UN(RtlSetIoCompletionCallback)(NULL, io_cb, 0), ST_INVPARAM);          /* NULL handle */
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "iocb.bin");
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("cannot create overlapped file"); return; }
    EXPECT_EQ(UN(RtlSetIoCompletionCallback)(h, io_cb, 1), ST_INVPARAM);            /* flags must be 0 */
    EXPECT_EQ(UN(RtlSetIoCompletionCallback)(h, io_cb, 0x80), ST_INVPARAM);
    g_ev = CreateEventW(NULL, FALSE, FALSE, NULL); g_io_n = 0;
    NTSTATUS s = UN(RtlSetIoCompletionCallback)(h, io_cb, 0);
    EXPECT_EQ(s, 0);
    if (s >= 0) {
        static OVERLAPPED ov; static char data[512]; memset(&ov, 0, sizeof ov); memset(data, 'x', sizeof data);
        DWORD n = 0;
        BOOL ok = WriteFile(h, data, sizeof data, &n, &ov);
        if (!ok) EXPECT_EQ(GetLastError(), ERROR_IO_PENDING);
        EXPECT_EQ(WaitForSingleObject(g_ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(g_io_n, 1);
        /* BindIoCompletionCallback-style routine: (error code, bytes transferred, OVERLAPPED *) */
        EXPECT_EQ(g_io_a[0], NULL); EXPECT_EQ(g_io_a[1], (PVOID)sizeof data); EXPECT_EQ(g_io_a[2], (PVOID)&ov);
        EXPECT_EQ(ov.InternalHigh, sizeof data);
        /* a second overlapped read also reaches the callback */
        static OVERLAPPED ov2; static char rb[512]; memset(&ov2, 0, sizeof ov2); g_io_n = 0;
        ok = ReadFile(h, rb, sizeof rb, &n, &ov2);
        if (!ok) EXPECT_EQ(GetLastError(), ERROR_IO_PENDING);
        EXPECT_EQ(WaitForSingleObject(g_ev, 5000), WAIT_OBJECT_0);
        EXPECT_EQ(g_io_n, 1); EXPECT_EQ(rb[0], 'x');
    }
    CloseHandle(h); CloseHandle(g_ev);
    DeleteFileA(path);
}

#include "t.h"
#include <stdlib.h>

CHILD(assertion_failure_probe) {
    DWORD expected = 0x12345677;
    freopen("NUL", "w", stdout);
    SET_ERR(0x12345678);
    CHECK(0);
    if (GetLastError() != 0x12345678) return 1;
    EXPECT_ERR(++expected);
    if (expected != 0x12345678 || GetLastError() != 0x12345678) return 2;
    return 0;
}

CHILD(scratch_invalid_leaf) {
    static const char *leaves[] = {"..\\escape", "../escape", "C:escape", "..", ".. ", ""};
    char path[MAX_PATH];
    unsigned index = argc > 1 ? (unsigned)atoi(argv[1]) : 0;
    if (index >= sizeof leaves / sizeof leaves[0]) return 3;
    t_tmpfile(path, sizeof path, leaves[index]);
    return 0;
}

CHILD(scratch_truncation) {
    char path[2];
    t_tmpfile(path, sizeof path, "file");
    return 0;
}

CHILD(timeout_probe) { Sleep(INFINITE); return 0; }

CHILD(scratch_reparse_probe) {
    char root[MAX_PATH], link[MAX_PATH];
    if (argc < 3) return 2;
    snprintf(root, sizeof root, "%s", t_tmpdir());
    root[strlen(root) - 1] = 0;
    if (!strcmp(argv[2], "root")) {
        if (!RemoveDirectoryA(root)) return 3;
        snprintf(link, sizeof link, "%s", root);
    } else t_tmpfile(link, sizeof link, "outside");
    /* Lack of symlink privilege is an environmental skip, not a harness failure. */
    if (!CreateSymbolicLinkA(link, argv[1], SYMBOLIC_LINK_FLAG_DIRECTORY | 2) &&
        !CreateSymbolicLinkA(link, argv[1], SYMBOLIC_LINK_FLAG_DIRECTORY)) return 77;
    return 0;
}

static DWORD WINAPI worker_exception(void *unused) {
    RaiseException(0xC0000005, 0, 0, NULL);
    return 0;
}

TEST(harness_checks_exception_probe) {
    char mode[16];
    if (!GetEnvironmentVariableA("NTDLL_HARNESS_EXCEPTION_PROBE", mode, sizeof mode)) {
        t_skip("exception probe runs only in an isolated child"); return;
    }
    if (!strcmp(mode, "main")) RaiseException(0xC0000005, 0, 0, NULL);
    HANDLE thread = CreateThread(NULL, 0, worker_exception, NULL, 0, NULL);
    CHECK(thread != NULL);
    if (thread) { WaitForSingleObject(thread, 5000); CloseHandle(thread); }
}

CHILD(exception_guard) {
    char cmd[4096];
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE sink = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    if (sink == INVALID_HANDLE_VALUE) return 2;
    si.cb = sizeof si; si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = sink;
    const char *mode = argc > 1 ? argv[1] : "worker";
    SetEnvironmentVariableA("NTDLL_HARNESS_EXCEPTION_PROBE", mode);
    snprintf(cmd, sizeof cmd, "\"%s\" harness_checks_exception_probe", t_self_path());
    BOOL started = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    CloseHandle(sink);
    if (!started) return 3;
    DWORD code = 0;
    if (WaitForSingleObject(pi.hProcess, 10000) != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 4); WaitForSingleObject(pi.hProcess, 5000); code = 4;
    } else GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return code == (!strcmp(mode, "main") ? 1 : 0xC0000005) ? 0 : 5;
}

TEST(harness_checks_expect_eq_evaluates_once) {
    unsigned value = 0;
    EXPECT_EQ(++value, 1);
    EXPECT_EQ(value, 1);
}
TEST(harness_checks_expect_ne_evaluates_once) {
    unsigned value = 0;
    EXPECT_NE(++value, 2);
    EXPECT_EQ(value, 1);
}
TEST(harness_checks_resolution_preserves_last_error) {
    SET_ERR(0x12345678);
    FARPROC p = t_proc_in("ntdll.dll", "NtClose");
    EXPECT_ERR(0x12345678);
    CHECK(p != NULL);
    SET_ERR(0x12345678);
    p = t_proc_in("ntdll.dll", "ntdll_no_such_export");
    EXPECT_ERR(0x12345678);
    CHECK(p == NULL);
}
TEST(harness_checks_module_lookup_preserves_last_error) {
    SET_ERR(0x12345678);
    HMODULE m = t_module("ntdll.dll");
    EXPECT_ERR(0x12345678);
    CHECK(m != NULL);
}
TEST(harness_checks_assertion_preserves_last_error) {
    SET_ERR(0x12345678);
    CHECK(1);
    EXPECT_ERR(0x12345678);
}

TEST(harness_checks_string_assertions_evaluate_once) {
    const char *strings[] = {"same", "same", "same"};
    const WCHAR *wide[] = {L"same", L"same", L"same"};
    unsigned a = 0, b = 0;
    SET_ERR(0x12345678);
    EXPECT_STR(strings[a++], strings[b++]);
    EXPECT_ERR(0x12345678);
    EXPECT_EQ(a, 1); EXPECT_EQ(b, 1);
    a = b = 0;
    SET_ERR(0x12345678);
    EXPECT_WSTR(wide[a++], wide[b++]);
    EXPECT_ERR(0x12345678);
    EXPECT_EQ(a, 1); EXPECT_EQ(b, 1);
    EXPECT_EQ(t_run_child("assertion_failure_probe", NULL, 10000), 0);
}

TEST(harness_checks_scratch_paths) {
    char path[MAX_PATH];
    const char *dir = t_tmpdir();
    CHECK(GetFileAttributesA(dir) & FILE_ATTRIBUTE_DIRECTORY);
    t_tmpfile(path, sizeof path, "safe.txt");
    CHECK(!strncmp(path, dir, strlen(dir)));
    for (unsigned i = 0; i < 6; i++) {
        char arg[16]; snprintf(arg, sizeof arg, "%u", i);
        EXPECT_EQ(t_run_child("scratch_invalid_leaf", arg, 10000), 2);
    }
    EXPECT_EQ(t_run_child("scratch_truncation", NULL, 10000), 2);
}

TEST(harness_checks_child_timeout) {
    EXPECT_EQ(t_run_child("timeout_probe", NULL, 100), 0xDEAD0001);
}

TEST(harness_checks_cleanup_does_not_follow_reparse_points) {
    char marker[MAX_PATH], target[MAX_PATH], args[MAX_PATH + 32];
    t_tmpfile(marker, sizeof marker, "keep.txt");
    HANDLE file = CreateFileA(marker, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    CHECK(file != INVALID_HANDLE_VALUE);
    if (file == INVALID_HANDLE_VALUE) return;
    CloseHandle(file);
    snprintf(target, sizeof target, "%s", t_tmpdir());
    target[strlen(target) - 1] = 0;
    const char *modes[] = {"nested", "root"};
    for (unsigned i = 0; i < 2; i++) {
        snprintf(args, sizeof args, "\"%s\" %s", target, modes[i]);
        DWORD code = t_run_child("scratch_reparse_probe", args, 10000);
        if (code == 77) t_note("%s symlink cleanup probe unavailable (privilege/platform)", modes[i]);
        else EXPECT_EQ(code, 0);
        EXPECT_NE(GetFileAttributesA(marker), INVALID_FILE_ATTRIBUTES);
    }
    CHECK(DeleteFileA(marker));
}

TEST(harness_checks_exception_thread_guard) {
    EXPECT_EQ(t_run_child("exception_guard", "main", 20000), 0);
    EXPECT_EQ(t_run_child("exception_guard", "worker", 20000), 0);
}

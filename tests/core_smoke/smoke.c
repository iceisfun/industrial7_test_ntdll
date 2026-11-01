#include "t.h"
/* Smallest possible corpus test: load, resolve, invoke, check. */
TEST(smoke_module_loads) { CHECK(t_module("ntdll.dll") != NULL); }
TEST(smoke_getprocaddress_negative) {
    /* Documented failure: GetProcAddress for an absent export returns NULL with ERROR_PROC_NOT_FOUND. */
    SET_ERR(0);
    FARPROC p = GetProcAddress(t_module("kernel32.dll"), "NoSuchExport_xyz");
    CHECK(p == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
CHILD(echo) { return argc > 1 ? atoi(argv[1]) : 7; }
TEST(smoke_child_roundtrip) { EXPECT_EQ(t_run_child("echo", "42", 20000), 42); }

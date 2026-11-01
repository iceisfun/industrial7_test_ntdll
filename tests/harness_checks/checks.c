#include "t.h"

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

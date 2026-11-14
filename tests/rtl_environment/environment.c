#include "t.h"
#include <wchar.h>

UDECL(NTSTATUS, RtlCreateEnvironment, (BOOLEAN, PVOID *));
UDECL(NTSTATUS, RtlDestroyEnvironment, (PVOID));
UDECL(NTSTATUS, RtlSetEnvironmentVariable, (PVOID *, PUNICODE_STRING, PUNICODE_STRING));
UDECL(NTSTATUS, RtlQueryEnvironmentVariable_U, (PVOID, PUNICODE_STRING, PUNICODE_STRING));
UDECL(NTSTATUS, RtlExpandEnvironmentStrings_U, (PVOID, PUNICODE_STRING, PUNICODE_STRING, PULONG));

#define RE_SMALL ((NTSTATUS)0xc0000023)
#define RE_MISSING ((NTSTATUS)0xc0000100)
#define RE_REQUIRE() do { \
    REQUIRE(UN(RtlCreateEnvironment)); \
    REQUIRE(UN(RtlDestroyEnvironment)); \
    REQUIRE(UN(RtlSetEnvironmentVariable)); \
    REQUIRE(UN(RtlQueryEnvironmentVariable_U)); \
} while (0)

static UNICODE_STRING re_string(const WCHAR *s)
{
    UNICODE_STRING u;
    u.Length = (USHORT)(wcslen(s) * sizeof(WCHAR));
    u.MaximumLength = u.Length + sizeof(WCHAR);
    u.Buffer = (PWSTR)s;
    return u;
}

static NTSTATUS re_set(PVOID *env, const WCHAR *name, const WCHAR *value)
{
    UNICODE_STRING n = re_string(name), v;
    if (!value) return UN(RtlSetEnvironmentVariable)(env, &n, NULL);
    v = re_string(value);
    return UN(RtlSetEnvironmentVariable)(env, &n, &v);
}

static void re_expect(PVOID env, const WCHAR *name, const WCHAR *expected)
{
    WCHAR buffer[512];
    UNICODE_STRING n = re_string(name), v = {0, sizeof(buffer), buffer};
    NTSTATUS s;
    memset(buffer, 0xa5, sizeof(buffer));
    s = UN(RtlQueryEnvironmentVariable_U)(env, &n, &v);
    EXPECT_EQ(s, expected ? 0 : RE_MISSING);
    if (expected && !s) {
        size_t bytes = wcslen(expected) * sizeof(WCHAR);
        EXPECT_EQ(v.Length, bytes);
        CHECK(bytes < sizeof(buffer));
        if (bytes >= sizeof(buffer)) return;
        CHECK(!memcmp(buffer, expected, bytes));
        EXPECT_EQ(buffer[bytes / sizeof(WCHAR)], 0);
    }
}

static void re_query(const WCHAR *name, const WCHAR *value, const WCHAR *lookup,
                     USHORT capacity, BOOL null_buffer)
{
    PVOID env = NULL;
    WCHAR buffer[128];
    UNICODE_STRING n = re_string(lookup), v = {0xbeef, capacity, null_buffer ? NULL : buffer};
    NTSTATUS s, expected;
    ULONG bytes = (ULONG)(wcslen(value) * 2);
    RE_REQUIRE();
    CHECK(capacity + 1u < sizeof(buffer) && bytes < sizeof(buffer));
    if (capacity + 1u >= sizeof(buffer) || bytes >= sizeof(buffer)) return;
    s = UN(RtlCreateEnvironment)(FALSE, &env);
    EXPECT_EQ(s, 0); CHECK(env != NULL); if (s || !env) return;
    s = re_set(&env, name, value); EXPECT_EQ(s, 0); if (s) goto done;
    memset(buffer, 0xa5, sizeof(buffer));
    s = UN(RtlQueryEnvironmentVariable_U)(env, &n, &v);
    /* The buffer must have room for the terminator as well as the value. */
    expected = !null_buffer && capacity / 2 > bytes / 2 ? 0 : RE_SMALL;
    EXPECT_EQ(s, expected);
    EXPECT_EQ(v.Length, bytes);
    EXPECT_EQ(v.MaximumLength, capacity);
    CHECK(v.Buffer == (null_buffer ? NULL : buffer));
    if (!s && !expected && !null_buffer) {
        CHECK(!memcmp(buffer, value, bytes));
        EXPECT_EQ(buffer[bytes / 2], 0);
    }
    /* On a nonzero-capacity failure the first WCHAR of the buffer is cleared. */
    if (s == RE_SMALL && !null_buffer && capacity >= 2) EXPECT_EQ(buffer[0], 0);
    if (!null_buffer) {
        EXPECT_EQ(((BYTE *)buffer)[capacity], 0xa5);
        EXPECT_EQ(((BYTE *)buffer)[capacity + 1], 0xa5);
    }
done:
    EXPECT_EQ(UN(RtlDestroyEnvironment)(env), 0);
}

static void re_expand(const WCHAR *source, const WCHAR *expected, USHORT capacity,
                      BOOL required_pointer)
{
    PVOID env = NULL;
    WCHAR buffer[512];
    UNICODE_STRING src = re_string(source), dst = {0xbeef, capacity, buffer};
    ULONG required = 0xdeadbeef, bytes = (ULONG)(wcslen(expected) * 2);
    NTSTATUS s;
    RE_REQUIRE(); REQUIRE(UN(RtlExpandEnvironmentStrings_U));
    CHECK(capacity + 1u < sizeof(buffer) && bytes < sizeof(buffer));
    if (capacity + 1u >= sizeof(buffer) || bytes >= sizeof(buffer)) return;
    s = UN(RtlCreateEnvironment)(FALSE, &env);
    EXPECT_EQ(s, 0); CHECK(env != NULL); if (s || !env) return;
    s = re_set(&env, L"rtl_environment_A", L"Alpha"); EXPECT_EQ(s, 0); if (s) goto done;
    s = re_set(&env, L"rtl_environment_B", L"Beta"); EXPECT_EQ(s, 0); if (s) goto done;
    s = re_set(&env, L"rtl_environment_Empty", L""); EXPECT_EQ(s, 0); if (s) goto done;
    s = re_set(&env, L"rtl_environment_Nested", L"%rtl_environment_A%"); EXPECT_EQ(s, 0); if (s) goto done;
    memset(buffer, 0xa5, sizeof(buffer));
    s = UN(RtlExpandEnvironmentStrings_U)(env, &src, &dst, required_pointer ? &required : NULL);
    EXPECT_EQ(s, capacity / 2 > bytes / 2 ? 0 : RE_SMALL);
    if (required_pointer) EXPECT_EQ(required, bytes + 2);
    EXPECT_EQ(dst.MaximumLength, capacity); CHECK(dst.Buffer == buffer);
    if (!s) {
        EXPECT_EQ(dst.Length, bytes);
        CHECK(!memcmp(buffer, expected, bytes)); EXPECT_EQ(buffer[bytes / 2], 0);
    } else {
        /* Length is only assigned on success. */
        EXPECT_EQ(dst.Length, 0xbeef);
    }
    EXPECT_EQ(((BYTE *)buffer)[capacity], 0xa5);
    EXPECT_EQ(((BYTE *)buffer)[capacity + 1], 0xa5);
done:
    EXPECT_EQ(UN(RtlDestroyEnvironment)(env), 0);
}

static void re_update(unsigned mode)
{
    PVOID env = NULL;
    WCHAR long_value[301];
    const WCHAR *replacement = mode == 0 ? L"longer replacement value" :
                               mode == 1 ? L"x" : mode == 2 ? L"other" :
                               mode == 3 ? L"" : mode == 4 ? NULL : L"Alpha";
    NTSTATUS s;
    RE_REQUIRE();
    s = UN(RtlCreateEnvironment)(FALSE, &env);
    EXPECT_EQ(s, 0); CHECK(env != NULL); if (s || !env) return;
    s = re_set(&env, L"rtl_environment_First", L"left"); EXPECT_EQ(s, 0); if (s) goto done;
    s = re_set(&env, L"rtl_environment_Middle", L"Alpha"); EXPECT_EQ(s, 0); if (s) goto done;
    s = re_set(&env, L"rtl_environment_Last", L"right"); EXPECT_EQ(s, 0); if (s) goto done;
    if (mode == 6) {
        for (unsigned i = 0; i < 300; ++i) long_value[i] = (WCHAR)(L'a' + i % 26);
        long_value[300] = 0; replacement = long_value;
    }
    if (mode == 7 || mode == 8) {
        const WCHAR *target = mode == 7 ? L"rtl_environment_First" : L"rtl_environment_Last";
        EXPECT_EQ(re_set(&env, target, NULL), 0);
        re_expect(env, target, NULL);
        re_expect(env, L"rtl_environment_Middle", L"Alpha");
    } else {
        s = re_set(&env, mode == 5 ? L"RTL_ENVIRONMENT_MIDDLE" : L"rtl_environment_Middle", replacement);
        EXPECT_EQ(s, 0);
        if (!s) re_expect(env, L"rtl_environment_middle", replacement);
        re_expect(env, L"rtl_environment_First", L"left");
        re_expect(env, L"rtl_environment_Last", L"right");
    }
done:
    EXPECT_EQ(UN(RtlDestroyEnvironment)(env), 0);
}

TEST(rtl_environment_create_empty)
{
    PVOID env = NULL;
    NTSTATUS s;
    RE_REQUIRE();
    s = UN(RtlCreateEnvironment)(FALSE, &env);
    EXPECT_EQ(s, 0); CHECK(env != NULL); if (s || !env) return;
    EXPECT_EQ(((WCHAR *)env)[0], 0); EXPECT_EQ(((WCHAR *)env)[1], 0);
    re_expect(env, L"rtl_environment_absent", NULL);
    EXPECT_EQ(UN(RtlDestroyEnvironment)(env), 0);
}

TEST(rtl_environment_independent_blocks)
{
    PVOID a = NULL, b = NULL;
    NTSTATUS s;
    RE_REQUIRE();
    s = UN(RtlCreateEnvironment)(FALSE, &a); EXPECT_EQ(s, 0); CHECK(a != NULL); if (s || !a) return;
    s = UN(RtlCreateEnvironment)(FALSE, &b); EXPECT_EQ(s, 0); CHECK(b != NULL);
    if (!s && b) {
        CHECK(a != b);
        s = re_set(&a, L"rtl_environment_Isolated", L"one"); EXPECT_EQ(s, 0);
        if (!s) re_expect(a, L"rtl_environment_Isolated", L"one");
        re_expect(b, L"rtl_environment_Isolated", NULL);
        s = re_set(&b, L"rtl_environment_Isolated", L"two"); EXPECT_EQ(s, 0);
        if (!s) re_expect(b, L"rtl_environment_Isolated", L"two");
        re_expect(a, L"rtl_environment_Isolated", L"one");
        EXPECT_EQ(UN(RtlDestroyEnvironment)(b), 0);
    }
    EXPECT_EQ(UN(RtlDestroyEnvironment)(a), 0);
}

TEST(rtl_environment_query_name_boundary)
{
    PVOID env = NULL;
    NTSTATUS s;
    RE_REQUIRE();
    s = UN(RtlCreateEnvironment)(FALSE, &env);
    EXPECT_EQ(s, 0); CHECK(env != NULL); if (s || !env) return;
    s = re_set(&env, L"rtl_environment_PrefixSuffix", L"long name");
    EXPECT_EQ(s, 0);
    if (!s) {
        re_expect(env, L"rtl_environment_Prefix", NULL);
        s = re_set(&env, L"rtl_environment_Prefix", L"short name");
        EXPECT_EQ(s, 0);
        if (!s) re_expect(env, L"rtl_environment_Prefix", L"short name");
        re_expect(env, L"rtl_environment_PrefixSuffix", L"long name");
    }
    EXPECT_EQ(UN(RtlDestroyEnvironment)(env), 0);
}

TEST(rtl_environment_query_zero) { re_query(L"rtl_environment_Q", L"Alpha", L"rtl_environment_Q", 0, FALSE); }
TEST(rtl_environment_query_one_byte) { re_query(L"rtl_environment_Q", L"Alpha", L"rtl_environment_Q", 1, FALSE); }
TEST(rtl_environment_query_one_char) { re_query(L"rtl_environment_Q", L"Alpha", L"rtl_environment_Q", 2, FALSE); }
TEST(rtl_environment_query_short) { re_query(L"rtl_environment_Q", L"Alpha", L"rtl_environment_Q", 8, FALSE); }
TEST(rtl_environment_query_exact_payload) { re_query(L"rtl_environment_Q", L"Alpha", L"rtl_environment_Q", 10, FALSE); }
TEST(rtl_environment_query_exact_terminated) { re_query(L"rtl_environment_Q", L"Alpha", L"rtl_environment_Q", 12, FALSE); }
TEST(rtl_environment_query_spare) { re_query(L"rtl_environment_Q", L"Alpha", L"rtl_environment_Q", 64, FALSE); }
TEST(rtl_environment_query_odd_capacity) { re_query(L"rtl_environment_Q", L"Alpha", L"rtl_environment_Q", 11, FALSE); }
TEST(rtl_environment_query_null_size) { re_query(L"rtl_environment_Q", L"Alpha", L"rtl_environment_Q", 0, TRUE); }
TEST(rtl_environment_query_case) { re_query(L"rtl_environment_Mixed", L"Alpha", L"RTL_ENVIRONMENT_MIXED", 64, FALSE); }
TEST(rtl_environment_query_empty_zero) { re_query(L"rtl_environment_Q", L"", L"rtl_environment_Q", 0, FALSE); }
TEST(rtl_environment_query_empty_terminated) { re_query(L"rtl_environment_Q", L"", L"rtl_environment_Q", 2, FALSE); }
TEST(rtl_environment_query_unicode_value) { re_query(L"rtl_environment_Q", L"\x03a9\x4e2d\x00e9", L"rtl_environment_Q", 64, FALSE); }
TEST(rtl_environment_query_equals_value) { re_query(L"rtl_environment_Q", L"a=b=c", L"rtl_environment_Q", 64, FALSE); }
TEST(rtl_environment_query_literal_percent) { re_query(L"rtl_environment_Q", L"%unchanged%", L"rtl_environment_Q", 64, FALSE); }
TEST(rtl_environment_replace_grow) { re_update(0); }
TEST(rtl_environment_replace_shrink) { re_update(1); }
TEST(rtl_environment_replace_same_length) { re_update(2); }
TEST(rtl_environment_replace_empty) { re_update(3); }
TEST(rtl_environment_delete_middle) { re_update(4); }
TEST(rtl_environment_replace_case) { re_update(5); }
TEST(rtl_environment_replace_large) { re_update(6); }
TEST(rtl_environment_delete_first) { re_update(7); }
TEST(rtl_environment_delete_last) { re_update(8); }
TEST(rtl_environment_expand_literal) { re_expand(L"literal", L"literal", 64, TRUE); }
TEST(rtl_environment_expand_empty) { re_expand(L"", L"", 2, TRUE); }
TEST(rtl_environment_expand_variable) { re_expand(L"%rtl_environment_A%", L"Alpha", 64, TRUE); }
TEST(rtl_environment_expand_case) { re_expand(L"%RTL_ENVIRONMENT_A%", L"Alpha", 64, TRUE); }
TEST(rtl_environment_expand_affixes) { re_expand(L"[%rtl_environment_A%]", L"[Alpha]", 64, TRUE); }
TEST(rtl_environment_expand_adjacent) { re_expand(L"%rtl_environment_A%%rtl_environment_B%", L"AlphaBeta", 64, TRUE); }
TEST(rtl_environment_expand_repeated) { re_expand(L"%rtl_environment_A%:%rtl_environment_A%", L"Alpha:Alpha", 64, TRUE); }
TEST(rtl_environment_expand_unknown) { re_expand(L"%rtl_environment_Unknown%", L"%rtl_environment_Unknown%", 128, TRUE); }
TEST(rtl_environment_expand_unclosed) { re_expand(L"%rtl_environment_A", L"%rtl_environment_A", 128, TRUE); }
TEST(rtl_environment_expand_percent) { re_expand(L"%", L"%", 64, TRUE); }
TEST(rtl_environment_expand_double_percent) { re_expand(L"%%", L"%%", 64, TRUE); }
TEST(rtl_environment_expand_empty_variable) { re_expand(L"a%rtl_environment_Empty%b", L"ab", 64, TRUE); }
TEST(rtl_environment_expand_nonrecursive) { re_expand(L"%rtl_environment_Nested%", L"%rtl_environment_A%", 128, TRUE); }
TEST(rtl_environment_expand_zero_capacity) { re_expand(L"%rtl_environment_A%", L"Alpha", 0, TRUE); }
TEST(rtl_environment_expand_one_byte) { re_expand(L"%rtl_environment_A%", L"Alpha", 1, TRUE); }
TEST(rtl_environment_expand_short) { re_expand(L"%rtl_environment_A%", L"Alpha", 8, TRUE); }
TEST(rtl_environment_expand_exact_payload) { re_expand(L"%rtl_environment_A%", L"Alpha", 10, TRUE); }
TEST(rtl_environment_expand_exact_terminated) { re_expand(L"%rtl_environment_A%", L"Alpha", 12, TRUE); }
TEST(rtl_environment_expand_no_required) { re_expand(L"%rtl_environment_A%", L"Alpha", 64, FALSE); }

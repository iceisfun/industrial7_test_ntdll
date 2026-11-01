#include "t.h"

UDECL(ULONG, RtlDetermineDosPathNameType_U, (PCWSTR));
UDECL(ULONG, RtlIsDosDeviceName_U, (PCWSTR));
UDECL(BOOLEAN, RtlDosPathNameToNtPathName_U, (PCWSTR, PUNICODE_STRING, PWSTR *, PVOID));
UDECL(NTSTATUS, RtlDosPathNameToNtPathName_U_WithStatus, (PCWSTR, PUNICODE_STRING, PWSTR *, PVOID));
UDECL(ULONG, RtlGetFullPathName_U, (PCWSTR, ULONG, PWSTR, PWSTR *));
UDECL(ULONG, RtlGetCurrentDirectory_U, (ULONG, PWSTR));

static void rtl_path_type(PCWSTR path, ULONG type)
{
    REQUIRE(UN(RtlDetermineDosPathNameType_U));
    EXPECT_EQ(UN(RtlDetermineDosPathNameType_U)(path), type);
}
#define TYPE_CASE(n,p,t) TEST(rtl_path_type_##n) { rtl_path_type(p,t); }
TYPE_CASE(empty, L"", 5)
TYPE_CASE(relative, L"leaf.txt", 5)
TYPE_CASE(dot, L".", 5)
TYPE_CASE(parent, L"..\\leaf", 5)
TYPE_CASE(drive, L"C:", 3)
TYPE_CASE(drive_relative, L"C:leaf", 3)
TYPE_CASE(drive_absolute, L"C:\\leaf", 2)
TYPE_CASE(drive_forward, L"c:/leaf", 2)
TYPE_CASE(root, L"\\", 4)
TYPE_CASE(root_leaf, L"\\leaf", 4)
TYPE_CASE(root_forward, L"/leaf", 4)
TYPE_CASE(unc, L"\\\\server\\share\\leaf", 1)
TYPE_CASE(unc_forward, L"//server/share/leaf", 1)
TYPE_CASE(unc_empty, L"\\\\", 1)
TYPE_CASE(local_dot, L"\\\\.\\NUL", 6)
TYPE_CASE(local_question, L"\\\\?\\C:\\leaf", 6)
TYPE_CASE(local_forward, L"//?/C:/leaf", 6)
TYPE_CASE(root_local_dot, L"\\\\.", 7)
TYPE_CASE(root_local_question, L"\\\\?", 7)
TYPE_CASE(unc_question_suffix, L"\\\\?suffix", 1)
TYPE_CASE(unc_dot_suffix, L"\\\\.suffix", 1)
TYPE_CASE(nonletter_drive_syntax, L"1:\\leaf", 2)

static void rtl_path_device(PCWSTR path, ULONG offset, ULONG bytes)
{
    REQUIRE(UN(RtlIsDosDeviceName_U));
    EXPECT_EQ(UN(RtlIsDosDeviceName_U)(path), (offset << 16) | bytes);
}
#define DEVICE_CASE(n,p,o,b) TEST(rtl_path_device_##n) { rtl_path_device(p,o,b); }
DEVICE_CASE(nul, L"NUL", 0, 6)
DEVICE_CASE(nul_case, L"nul", 0, 6)
DEVICE_CASE(con, L"CON", 0, 6)
DEVICE_CASE(aux, L"AUX", 0, 6)
DEVICE_CASE(prn, L"PRN", 0, 6)
DEVICE_CASE(com1, L"COM1", 0, 8)
DEVICE_CASE(lpt9, L"LPT9", 0, 8)
DEVICE_CASE(com0, L"COM0", 0, 0)
DEVICE_CASE(com10, L"COM10", 0, 0)
DEVICE_CASE(extension, L"NUL.txt", 0, 6)
DEVICE_CASE(colon, L"NUL:", 0, 6)
DEVICE_CASE(trailing, L"NUL. ", 0, 6)
DEVICE_CASE(drive_prefix, L"C:\\NUL", 6, 6)
DEVICE_CASE(relative_prefix, L"dir\\AUX.txt", 8, 6)
DEVICE_CASE(ordinary, L"normal.txt", 0, 0)
DEVICE_CASE(unc, L"\\\\server\\share\\NUL", 0, 0)
DEVICE_CASE(conin, L"CONIN$", 0, 12)
DEVICE_CASE(conout, L"CONOUT$", 0, 14)

static void rtl_path_convert(PCWSTR in, PCWSTR expected, PCWSTR leaf, int status)
{
    UNICODE_STRING out = {0};
    PWSTR part = NULL;
    int success;
    REQUIRE(U(RtlFreeUnicodeString));
    if (status) {
        NTSTATUS s;
        REQUIRE(UN(RtlDosPathNameToNtPathName_U_WithStatus));
        s = UN(RtlDosPathNameToNtPathName_U_WithStatus)(in, &out, &part, NULL);
        EXPECT_EQ(s, 0); success = s >= 0;
    } else {
        REQUIRE(UN(RtlDosPathNameToNtPathName_U));
        success = UN(RtlDosPathNameToNtPathName_U)(in, &out, &part, NULL);
        CHECK(success);
    }
    if (!success || !out.Buffer) {
        CHECK(out.Buffer != NULL);
        if (out.Buffer) U(RtlFreeUnicodeString)(&out);
        return;
    }
    EXPECT_EQ(out.Length, lstrlenW(expected) * 2);
    CHECK(out.MaximumLength >= out.Length + 2);
    if (out.Length == lstrlenW(expected) * 2) {
        CHECK(!memcmp(out.Buffer, expected, out.Length));
        EXPECT_EQ(out.Buffer[out.Length / 2], 0);
    }
    if (leaf) {
        CHECK(part != NULL);
        if (part) {
            EXPECT_EQ(part, out.Buffer + lstrlenW(expected) - lstrlenW(leaf));
            /* Dereference only after proving this is inside the owned string. */
            if ((ULONG_PTR)part >= (ULONG_PTR)out.Buffer &&
                (ULONG_PTR)part <= (ULONG_PTR)out.Buffer + out.Length)
                EXPECT_WSTR(part, leaf);
        }
    } else EXPECT_EQ(part, NULL);
    U(RtlFreeUnicodeString)(&out);
}
#define CONVERT_CASE(n,p,e,l,s) TEST(rtl_path_convert_##n) { rtl_path_convert(p,e,l,s); }
CONVERT_CASE(drive, L"C:\\alpha\\file.txt", L"\\??\\C:\\alpha\\file.txt", L"file.txt", 0)
CONVERT_CASE(drive_status, L"C:\\alpha\\file.txt", L"\\??\\C:\\alpha\\file.txt", L"file.txt", 1)
CONVERT_CASE(unc, L"\\\\server\\share\\file", L"\\??\\UNC\\server\\share\\file", L"file", 0)
CONVERT_CASE(unc_status, L"\\\\server\\share\\file", L"\\??\\UNC\\server\\share\\file", L"file", 1)
CONVERT_CASE(extended, L"\\\\?\\C:\\alpha\\file", L"\\??\\C:\\alpha\\file", L"file", 0)
CONVERT_CASE(extended_status, L"\\\\?\\C:\\alpha\\file", L"\\??\\C:\\alpha\\file", L"file", 1)
CONVERT_CASE(dot, L"C:\\alpha\\.\\file", L"\\??\\C:\\alpha\\file", L"file", 0)
CONVERT_CASE(parent, L"C:\\alpha\\..\\file", L"\\??\\C:\\file", L"file", 1)
CONVERT_CASE(root, L"C:\\", L"\\??\\C:\\", NULL, 0)
CONVERT_CASE(unicode, L"C:\\alpha\\\x03a9.txt", L"\\??\\C:\\alpha\\\x03a9.txt", L"\x03a9.txt", 1)

static void rtl_path_full(PCWSTR in, PCWSTR expected, PCWSTR leaf)
{
    struct { WCHAR before; WCHAR text[260]; WCHAR after; } b;
    PWSTR part = NULL;
    ULONG n;
    REQUIRE(UN(RtlGetFullPathName_U));
    b.before = b.after = 0x5555;
    n = UN(RtlGetFullPathName_U)(in, sizeof(b.text), b.text, &part);
    EXPECT_EQ(n, lstrlenW(expected) * 2);
    EXPECT_EQ(b.before, 0x5555); EXPECT_EQ(b.after, 0x5555);
    if (n && n < sizeof(b.text)) EXPECT_WSTR(b.text, expected);
    EXPECT_EQ(part, leaf ? b.text + lstrlenW(expected) - lstrlenW(leaf) : NULL);
}
#define FULL_CASE(n,p,e,l) TEST(rtl_path_full_##n) { rtl_path_full(p,e,l); }
FULL_CASE(absolute, L"C:\\alpha\\file", L"C:\\alpha\\file", L"file")
FULL_CASE(forward, L"C:/alpha/file", L"C:\\alpha\\file", L"file")
FULL_CASE(dot, L"C:\\alpha\\.\\file", L"C:\\alpha\\file", L"file")
FULL_CASE(parent, L"C:\\alpha\\..\\file", L"C:\\file", L"file")
FULL_CASE(root, L"C:\\", L"C:\\", NULL)
FULL_CASE(trailing_separator, L"C:\\alpha\\", L"C:\\alpha\\", NULL)
FULL_CASE(unc, L"\\\\server\\share\\file", L"\\\\server\\share\\file", L"file")
FULL_CASE(unicode, L"C:\\alpha\\\x03a9.txt", L"C:\\alpha\\\x03a9.txt", L"\x03a9.txt")

static void rtl_path_full_buffer(ULONG bytes)
{
    WCHAR b[64]; PWSTR part = NULL; ULONG n;
    REQUIRE(UN(RtlGetFullPathName_U));
    memset(b, 0x55, sizeof(b));
    n = UN(RtlGetFullPathName_U)(L"C:\\leaf", bytes, b, &part);
    EXPECT_EQ(n, bytes < 16 ? 16 : 14);
    EXPECT_EQ(b[bytes / 2], 0x5555);
    if (bytes >= 16) { EXPECT_WSTR(b, L"C:\\leaf"); EXPECT_EQ(part, b + 3); }
    else EXPECT_EQ(part, NULL);
}
TEST(rtl_path_full_buffer_zero) { rtl_path_full_buffer(0); }
TEST(rtl_path_full_buffer_one_wchar) { rtl_path_full_buffer(2); }
TEST(rtl_path_full_buffer_without_nul) { rtl_path_full_buffer(14); }
TEST(rtl_path_full_buffer_exact) { rtl_path_full_buffer(16); }

static void rtl_path_current(unsigned mode)
{
    WCHAR b[512], small[512]; ULONG n, required, capacity;
    REQUIRE(UN(RtlGetCurrentDirectory_U));
    n = UN(RtlGetCurrentDirectory_U)(sizeof(b), b);
    CHECK(n > 0 && n < sizeof(b)); if (!n || n >= sizeof(b)) return;
    EXPECT_EQ(n, lstrlenW(b) * 2);
    required = n + 2;
    capacity = mode == 0 ? 0 : mode == 1 ? 2 : mode == 2 ? n : required;
    memset(small, 0x55, sizeof(small));
    EXPECT_EQ(UN(RtlGetCurrentDirectory_U)(capacity, small), capacity < required ? required : n);
    if (capacity < required) EXPECT_EQ(small[0], 0x5555);
    else EXPECT_WSTR(small, b);
    EXPECT_EQ(small[capacity / 2], 0x5555);
}
TEST(rtl_path_current_query) { rtl_path_current(0); }
TEST(rtl_path_current_short) { rtl_path_current(1); }
TEST(rtl_path_current_without_nul) { rtl_path_current(2); }
TEST(rtl_path_current_exact) { rtl_path_current(3); }

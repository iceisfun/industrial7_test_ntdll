/* NtSetInformationKey on a private subkey of the current user's hive (created and deleted by each test).
 * KEY_SET_INFORMATION_CLASS: 0 KeyWriteTimeInformation (8 bytes), 1 KeyWow64FlagsInformation (4),
 * 2 KeyControlFlagsInformation (4), 3 KeySetVirtualizationInformation (4), 4 KeySetDebugInformation (4),
 * 5 KeySetHandleTagsInformation (4).
 */
#include "t.h"

UDECL(NTSTATUS, NtSetInformationKey, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtQueryKey, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtCreateKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG));
UDECL(NTSTATUS, NtOpenKey, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtDeleteKey, (HANDLE));
UDECL(NTSTATUS, NtClose, (HANDLE));
UDECL(NTSTATUS, RtlOpenCurrentUser, (ACCESS_MASK, PHANDLE));

#define S(x)            ((NTSTATUS)(x))
#define ST_BAD_CLASS    S(0xC0000003)
#define ST_BAD_LENGTH   S(0xC0000004)
#define ST_INV_HANDLE   S(0xC0000008)
#define ST_DENIED       S(0xC0000022)
#define ST_TYPE_MISM    S(0xC0000024)

typedef struct { HANDLE root, key; WCHAR name[80]; } kfix;

static BOOL kfix_open(kfix *k)
{
    OBJECT_ATTRIBUTES oa; UNICODE_STRING us; ULONG disp = 0; NTSTATUS st;
    memset(k, 0, sizeof *k);
    if (!UN(RtlOpenCurrentUser) || !UN(NtCreateKey) || !UN(NtDeleteKey)) return FALSE;
    if (UN(RtlOpenCurrentUser)(KEY_ALL_ACCESS, &k->root) != 0) return FALSE;
    swprintf(k->name, 80, L"Software\\ntdllt_setinfo_%lu_%lu", GetCurrentProcessId(), GetTickCount());
    us.Buffer = k->name; us.Length = (USHORT)(wcslen(k->name) * 2); us.MaximumLength = us.Length + 2;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, k->root, NULL);
    st = UN(NtCreateKey)(&k->key, KEY_ALL_ACCESS, &oa, 0, NULL, 0, &disp);
    return st == 0 && k->key;
}

static void kfix_close(kfix *k)
{
    if (k->key) { UN(NtDeleteKey)(k->key); UN(NtClose)(k->key); }
    if (k->root) UN(NtClose)(k->root);
    memset(k, 0, sizeof *k);
}

TEST(set_key_alias_pair)
{
    EXPECT_EQ(t_proc("NtSetInformationKey"), t_proc("ZwSetInformationKey"));
}

TEST(set_key_wow64_flags)
{
    kfix k; ULONG v, rl = 0; BYTE buf[64]; NTSTATUS st;
    REQUIRE(UN(NtSetInformationKey)); REQUIRE(UN(NtQueryKey));
    CHECK(kfix_open(&k)); if (!k.key) { kfix_close(&k); return; }
    /* KeyFlagsInformation (12 bytes) starts with the Wow64 flags: only the low values 0..8 are accepted */
    v = 4;
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 1, &v, sizeof v), 0);
    memset(buf, 0xCC, sizeof buf);
    st = UN(NtQueryKey)(k.key, 5, buf, sizeof buf, &rl);
    EXPECT_EQ(st, 0); EXPECT_EQ(rl, 12);
    EXPECT_EQ(*(ULONG *)buf, 4);
    v = 8;
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 1, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryKey)(k.key, 5, buf, sizeof buf, &rl), 0);
    EXPECT_EQ(*(ULONG *)buf, 8);
    v = 0x100;
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 1, &v, sizeof v), S(0xC000000D));
    v = 0x10;
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 1, &v, sizeof v), S(0xC000000D));
    EXPECT_EQ(UN(NtQueryKey)(k.key, 5, buf, sizeof buf, &rl), 0);
    EXPECT_EQ(*(ULONG *)buf, 8);                    /* rejected values leave the flags alone */
    v = 0;
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 1, &v, sizeof v), 0);
    EXPECT_EQ(UN(NtQueryKey)(k.key, 5, buf, sizeof buf, &rl), 0);
    EXPECT_EQ(*(ULONG *)buf, 0);
    kfix_close(&k);
}

TEST(set_key_write_time)
{
    kfix k; LARGE_INTEGER t8, got; BYTE buf[128]; ULONG rl = 0;
    REQUIRE(UN(NtSetInformationKey)); REQUIRE(UN(NtQueryKey));
    CHECK(kfix_open(&k)); if (!k.key) { kfix_close(&k); return; }
    t8.QuadPart = 0x01d0000000000000LL;
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 0, &t8, sizeof t8), 0);
    memset(buf, 0, sizeof buf);
    EXPECT_EQ(UN(NtQueryKey)(k.key, 0 /* KeyBasicInformation */, buf, sizeof buf, &rl), 0);
    got.QuadPart = *(LONGLONG *)buf;                /* KEY_BASIC_INFORMATION.LastWriteTime */
    EXPECT_EQ(got.QuadPart, t8.QuadPart);
    kfix_close(&k);
}

TEST(set_key_other_classes_accept_zero)
{
    kfix k; ULONG v = 0, c;
    REQUIRE(UN(NtSetInformationKey));
    CHECK(kfix_open(&k)); if (!k.key) { kfix_close(&k); return; }
    for (c = 2; c <= 5; c++)         /* control flags, virtualization, debug, handle tags */
        EXPECT_EQ(UN(NtSetInformationKey)(k.key, c, &v, sizeof v), 0);
    kfix_close(&k);
}

TEST(set_key_errors)
{
    kfix k; HANDLE ro = NULL, ev; ULONG v = 0; LARGE_INTEGER t8; OBJECT_ATTRIBUTES oa; UNICODE_STRING us;
    REQUIRE(UN(NtSetInformationKey)); REQUIRE(UN(NtOpenKey));
    CHECK(kfix_open(&k)); if (!k.key) { kfix_close(&k); return; }
    t8.QuadPart = 0;
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 0x7f, &v, sizeof v), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 6, &v, sizeof v), ST_BAD_CLASS);
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 1, &v, 2), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 1, &t8, 8), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationKey)(k.key, 0, &v, 4), ST_BAD_LENGTH);
    EXPECT_EQ(UN(NtSetInformationKey)((HANDLE)(ULONG_PTR)0xdeadbee4, 1, &v, sizeof v), ST_INV_HANDLE);
    ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev) { EXPECT_EQ(UN(NtSetInformationKey)(ev, 1, &v, sizeof v), ST_TYPE_MISM); CloseHandle(ev); }
    /* a handle opened for reading only has no KEY_SET_VALUE */
    us.Buffer = k.name; us.Length = (USHORT)(wcslen(k.name) * 2); us.MaximumLength = us.Length + 2;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, k.root, NULL);
    if (UN(NtOpenKey)(&ro, KEY_READ, &oa) == 0 && ro) {
        EXPECT_EQ(UN(NtSetInformationKey)(ro, 1, &v, sizeof v), ST_DENIED);
        UN(NtClose)(ro);
    } else CHECK(0);
    kfix_close(&k);
}

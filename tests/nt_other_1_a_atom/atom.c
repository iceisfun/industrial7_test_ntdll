/* Global atom table native services: NtAddAtom, NtAddAtomEx, NtFindAtom, NtDeleteAtom.
 * Cross-checked against the documented Win32 global atom API (GlobalAddAtomW family), which is a thin
 * layer over these services. Atom names are unique per run (process id + tick count). */
#include "t.h"

UDECL(NTSTATUS, NtAddAtom, (PWSTR, ULONG, PUSHORT));
UDECL(NTSTATUS, NtAddAtomEx, (PWSTR, ULONG, PUSHORT, ULONG));
UDECL(NTSTATUS, NtFindAtom, (PWSTR, ULONG, PUSHORT));
UDECL(NTSTATUS, NtDeleteAtom, (USHORT));

#define ST_SUCCESS   ((NTSTATUS)0)
#define ST_NOTFOUND  ((NTSTATUS)0xC0000034)  /* STATUS_OBJECT_NAME_NOT_FOUND */
#define ST_NAMEINV   ((NTSTATUS)0xC0000033)  /* STATUS_OBJECT_NAME_INVALID */
#define ST_INVHANDLE ((NTSTATUS)0xC0000008)
#define ST_INVPARAM  ((NTSTATUS)0xC000000D)

#define NEED() do { REQUIRE(UN(NtAddAtom)); REQUIRE(UN(NtAddAtomEx)); REQUIRE(UN(NtFindAtom)); REQUIRE(UN(NtDeleteAtom)); } while (0)

static void uname(WCHAR *out, size_t cap, const char *tag)
{
    static int n;
    swprintf(out, cap, L"nt1a_%hs_%lu_%lu_%d", tag, GetCurrentProcessId(), GetTickCount(), ++n);
}
#define BYTES(w) ((ULONG)(lstrlenW(w) * sizeof(WCHAR)))

TEST(atom_alias)
{
    NEED();
    CHECK(t_proc("NtAddAtom") == t_proc("ZwAddAtom"));
    CHECK(t_proc("NtAddAtomEx") == t_proc("ZwAddAtomEx"));
    CHECK(t_proc("NtFindAtom") == t_proc("ZwFindAtom"));
    CHECK(t_proc("NtDeleteAtom") == t_proc("ZwDeleteAtom"));
}

TEST(atom_add_find_delete)
{
    WCHAR nm[64], upper[64]; USHORT a = 0, b = 0, c = 0; NTSTATUS s; WCHAR back[64]; UINT n;
    NEED();
    uname(nm, 64, "afd");
    s = UN(NtFindAtom)(nm, BYTES(nm), &c);
    EXPECT_EQ(s, ST_NOTFOUND);
    s = UN(NtAddAtom)(nm, BYTES(nm), &a);
    EXPECT_EQ(s, ST_SUCCESS);
    CHECK(a >= 0xC000);                        /* string atoms live in 0xC000..0xFFFF */
    s = UN(NtFindAtom)(nm, BYTES(nm), &c);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(c, a);
    /* Win32 layer sees the same atom and name */
    EXPECT_EQ(GlobalFindAtomW(nm), a);
    memset(back, 0, sizeof back);
    n = GlobalGetAtomNameW(a, back, 64);
    EXPECT_EQ(n, lstrlenW(nm)); EXPECT_WSTR(back, nm);
    /* lookup is case-insensitive and yields the same atom; adding again bumps the reference count */
    lstrcpyW(upper, nm); CharUpperW(upper);
    c = 0; s = UN(NtFindAtom)(upper, BYTES(upper), &c);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(c, a);
    s = UN(NtAddAtom)(upper, BYTES(upper), &b);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(b, a);
    /* two references: first delete keeps it, second removes it, third fails */
    EXPECT_EQ(UN(NtDeleteAtom)(a), ST_SUCCESS);
    c = 0; EXPECT_EQ(UN(NtFindAtom)(nm, BYTES(nm), &c), ST_SUCCESS); EXPECT_EQ(c, a);
    EXPECT_EQ(UN(NtDeleteAtom)(a), ST_SUCCESS);
    EXPECT_EQ(UN(NtFindAtom)(nm, BYTES(nm), &c), ST_NOTFOUND);
    EXPECT_EQ(UN(NtDeleteAtom)(a), ST_INVHANDLE);
}

TEST(atom_distinct_names)
{
    WCHAR n1[64], n2[64]; USHORT a = 0, b = 0;
    NEED();
    uname(n1, 64, "d1"); uname(n2, 64, "d2");
    EXPECT_EQ(UN(NtAddAtom)(n1, BYTES(n1), &a), ST_SUCCESS);
    EXPECT_EQ(UN(NtAddAtom)(n2, BYTES(n2), &b), ST_SUCCESS);
    CHECK(a != b);
    EXPECT_EQ(UN(NtDeleteAtom)(a), ST_SUCCESS);
    EXPECT_EQ(UN(NtDeleteAtom)(b), ST_SUCCESS);
}

TEST(atom_integer_names)
{
    WCHAR nm[] = L"#1234"; USHORT a = 0, c = 0; NTSTATUS s;
    NEED();
    /* "#nnn" names denote integer atoms: the value is returned and nothing is stored in the table */
    s = UN(NtAddAtom)(nm, BYTES(nm), &a);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(a, 1234);
    s = UN(NtFindAtom)(nm, BYTES(nm), &c);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(c, 1234);
    /* deleting an integer atom is a successful no-op */
    s = UN(NtDeleteAtom)(1234);
    EXPECT_EQ(s, ST_SUCCESS);
}

TEST(atom_name_validation)
{
    WCHAR nm[64], longn[300]; USHORT a = 0x5555; NTSTATUS s; int i;
    NEED();
    uname(nm, 64, "val");
    /* empty name */
    s = UN(NtAddAtom)(nm, 0, &a);
    EXPECT_EQ(s, ST_NAMEINV);
    s = UN(NtFindAtom)(nm, 0, &a);
    EXPECT_EQ(s, ST_NAMEINV);
    /* 255 characters is the maximum, 256 is rejected */
    for (i = 0; i < 299; i++) longn[i] = L'a' + (i % 26);
    longn[299] = 0;
    wsprintfW(longn, L"nt1a_len_%lu_%lu_", GetCurrentProcessId(), GetTickCount());
    for (i = lstrlenW(longn); i < 255; i++) longn[i] = L'z';
    longn[255] = 0;
    a = 0; s = UN(NtAddAtom)(longn, 255 * 2, &a);
    EXPECT_EQ(s, ST_SUCCESS);
    if (s == ST_SUCCESS) { CHECK(a >= 0xC000); EXPECT_EQ(UN(NtDeleteAtom)(a), ST_SUCCESS); }
    longn[255] = L'z'; longn[256] = 0;
    s = UN(NtAddAtom)(longn, 256 * 2, &a);
    EXPECT_EQ(s, ST_INVPARAM);
    /* odd byte length is accepted (the trailing byte is dropped); remove whatever was added */
    a = 0;
    s = UN(NtAddAtom)(nm, 3, &a);
    EXPECT_EQ(s, ST_SUCCESS);
    if (s == ST_SUCCESS) { CHECK(a >= 0xC000); EXPECT_EQ(UN(NtDeleteAtom)(a), ST_SUCCESS); }
    /* NULL name pointer with non-zero length */
    s = UN(NtAddAtom)(NULL, 4, &a);
    EXPECT_EQ(s, ST_INVPARAM);
    s = UN(NtFindAtom)(NULL, 4, &a);
    EXPECT_EQ(s, ST_INVPARAM);
}

TEST(atom_ex_flags)
{
    WCHAR nm[64]; USHORT a = 0, b = 0; NTSTATUS s;
    NEED();
    uname(nm, 64, "ex");
    s = UN(NtAddAtomEx)(nm, BYTES(nm), &a, 0);
    EXPECT_EQ(s, ST_SUCCESS); CHECK(a >= 0xC000);
    s = UN(NtAddAtomEx)(nm, BYTES(nm), &b, 0);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(b, a);
    EXPECT_EQ(UN(NtDeleteAtom)(a), ST_SUCCESS);
    EXPECT_EQ(UN(NtDeleteAtom)(a), ST_SUCCESS);
    EXPECT_EQ(UN(NtFindAtom)(nm, BYTES(nm), &b), ST_NOTFOUND);
    s = UN(NtAddAtomEx)(nm, BYTES(nm), &b, 0x80000000);
    EXPECT_EQ(s, ST_INVPARAM);
    s = UN(NtAddAtomEx)(nm, BYTES(nm), &b, 1);
    EXPECT_EQ(s, ST_INVPARAM);
}

TEST(atom_delete_invalid)
{
    NEED();
    EXPECT_EQ(UN(NtDeleteAtom)(0), ST_INVHANDLE);
    EXPECT_EQ(UN(NtDeleteAtom)(0xBFFF), ST_SUCCESS);   /* integer-atom range: no-op success */
    EXPECT_EQ(UN(NtDeleteAtom)(0xFFFF), ST_INVHANDLE);  /* string-atom range, not present */
}

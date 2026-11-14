/* Atom tables: private (Rtl*AtomTable) and global (Nt*Atom). Global atoms use
 * names unique to this process and are always deleted again. */
#include "t.h"

typedef USHORT xa_atom;
UDECL(NTSTATUS, RtlCreateAtomTable, (ULONG, PVOID *));
UDECL(NTSTATUS, RtlDestroyAtomTable, (PVOID));
UDECL(NTSTATUS, RtlEmptyAtomTable, (PVOID, BOOLEAN));
UDECL(NTSTATUS, RtlAddAtomToAtomTable, (PVOID, PWSTR, xa_atom *));
UDECL(NTSTATUS, RtlLookupAtomInAtomTable, (PVOID, PWSTR, xa_atom *));
UDECL(NTSTATUS, RtlDeleteAtomFromAtomTable, (PVOID, xa_atom));
UDECL(NTSTATUS, RtlPinAtomInAtomTable, (PVOID, xa_atom));
UDECL(NTSTATUS, RtlQueryAtomInAtomTable, (PVOID, xa_atom, PULONG, PULONG, PWSTR, PULONG));
UDECL(NTSTATUS, NtAddAtom, (PWSTR, ULONG, xa_atom *));
UDECL(NTSTATUS, NtFindAtom, (PWSTR, ULONG, xa_atom *));
UDECL(NTSTATUS, NtDeleteAtom, (xa_atom));
UDECL(NTSTATUS, NtQueryInformationAtom, (xa_atom, ULONG, PVOID, ULONG, PULONG));

#define XS(x) ((NTSTATUS)(x))
#define XOK(s) ((NTSTATUS)(s) >= 0)
#define XA_NEED() do { REQUIRE(UN(RtlCreateAtomTable)); REQUIRE(UN(RtlDestroyAtomTable)); REQUIRE(UN(RtlAddAtomToAtomTable)); \
    REQUIRE(UN(RtlLookupAtomInAtomTable)); REQUIRE(UN(RtlDeleteAtomFromAtomTable)); REQUIRE(UN(RtlQueryAtomInAtomTable)); REQUIRE(UN(RtlPinAtomInAtomTable)); } while (0)
#define XA_TABLE(t) PVOID t = NULL; XA_NEED(); if (!XOK(UN(RtlCreateAtomTable)(37, &t)) || !t) { t_skip("atom table"); return; }
#define XA_INT(n) ((PWSTR)(ULONG_PTR)(n))

TEST(rtl_tables_x_atom_add_lookup_basic)
{
    xa_atom a = 0, b = 0, c = 0; XA_TABLE(t);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"First", &a), 0);
    CHECK(a >= 0xC000);                                           /* string atoms start at 0xC000 */
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"Second", &b), 0);
    CHECK(b >= 0xC000 && b != a);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"First", &c), 0); EXPECT_EQ(c, a);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"Second", &c), 0); EXPECT_EQ(c, b);
    c = 0x1234;
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"Missing", &c), XS(0xC0000034));
    EXPECT_EQ(UN(RtlDestroyAtomTable)(t), 0);
}
TEST(rtl_tables_x_atom_case_insensitive_and_refcount)
{
    xa_atom a = 0, b = 0, c = 0; WCHAR name[32]; ULONG ref = 0, pin = 0, len; XA_TABLE(t);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"MixedCase", &a), 0);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"mixedcase", &b), 0);
    EXPECT_EQ(b, a);                                              /* same atom, reference count incremented */
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"MIXEDCASE", &c), 0); EXPECT_EQ(c, a);
    len = sizeof name; memset(name, 0, sizeof name);
    EXPECT_EQ(UN(RtlQueryAtomInAtomTable)(t, a, &ref, &pin, name, &len), 0);
    EXPECT_EQ(ref, 2); EXPECT_EQ(pin, 0);
    EXPECT_EQ(len, 18);                                           /* bytes, without terminator */
    CHECK(!memcmp(name, L"MixedCase", 18));                       /* the first spelling is kept */
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(t, a), 0);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"MixedCase", &c), 0);   /* still referenced once */
    len = sizeof name;
    EXPECT_EQ(UN(RtlQueryAtomInAtomTable)(t, a, &ref, &pin, NULL, NULL), 0); EXPECT_EQ(ref, 1);
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(t, a), 0);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"MixedCase", &c), XS(0xC0000034));
    EXPECT_EQ(UN(RtlDeleteAtomFromAtomTable)(t, a), XS(0xC0000008));   /* already gone */
    UN(RtlDestroyAtomTable)(t);
}
TEST(rtl_tables_x_atom_integer_atoms)
{
    xa_atom a = 0; WCHAR name[32]; ULONG ref = 0, pin = 0, len; NTSTATUS s; XA_TABLE(t);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, XA_INT(0x123), &a), 0); EXPECT_EQ(a, 0x123);
    a = 0;
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"#291", &a), 0); EXPECT_EQ(a, 291);      /* "#decimal" is an integer atom */
    a = 0;
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, XA_INT(0x123), &a), 0); EXPECT_EQ(a, 0x123);
    a = 0xffff;
    s = UN(RtlAddAtomToAtomTable)(t, XA_INT(0), &a);
    CHECK(!XOK(s)); t_note("integer atom 0 status=%08lx", s);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, XA_INT(0xBFFF), &a), 0); EXPECT_EQ(a, 0xBFFF);   /* the largest integer atom; 0xC000 and above are string atoms */
    len = sizeof name; memset(name, 0, sizeof name);
    s = UN(RtlQueryAtomInAtomTable)(t, 0x123, &ref, &pin, name, &len);
    if (XOK(s)) { CHECK(len >= 8); CHECK(!lstrcmpW(name, L"#291")); t_note("integer atom query: ref=%lu pin=%lu", ref, pin); }
    else t_note("integer atom query status=%08lx", s);
    UN(RtlDestroyAtomTable)(t);
}
TEST(rtl_tables_x_atom_name_length_limits)
{
    WCHAR name[300]; xa_atom a = 0; NTSTATUS s; XA_TABLE(t);
    for (int i = 0; i < 299; i++) name[i] = L'a' + (i % 26);
    name[255] = 0;
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, name, &a), 0);            /* 255 characters is the longest name */
    name[255] = L'q'; name[256] = 0;
    s = UN(RtlAddAtomToAtomTable)(t, name, &a);
    CHECK(!XOK(s)); t_note("256-character name status=%08lx", s);
    s = UN(RtlAddAtomToAtomTable)(t, L"", &a);
    CHECK(!XOK(s)); t_note("empty name status=%08lx", s);
    UN(RtlDestroyAtomTable)(t);
}
TEST(rtl_tables_x_atom_query_buffer_protocol)
{
    xa_atom a = 0; WCHAR name[16]; ULONG ref, pin, len; NTSTATUS s; XA_TABLE(t);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"Twelve", &a), 0);
    len = 4; memset(name, 0xcc, sizeof name);
    s = UN(RtlQueryAtomInAtomTable)(t, a, &ref, &pin, name, &len);
    /* A short buffer receives a truncated, terminated name (one character plus the terminator here). */
    EXPECT_EQ(s, 0); EXPECT_EQ(len, 2); EXPECT_EQ(name[0], L'T'); EXPECT_EQ(name[1], 0);
    len = 12; memset(name, 0xcc, sizeof name);
    s = UN(RtlQueryAtomInAtomTable)(t, a, &ref, &pin, name, &len);
    t_note("exact-size buffer status=%08lx length=%lu", s, len);
    len = sizeof name;
    s = UN(RtlQueryAtomInAtomTable)(t, a, &ref, &pin, name, &len);
    EXPECT_EQ(s, 0); EXPECT_EQ(len, 12); EXPECT_EQ(name[6], 0);        /* a terminator is written when there is room */
    EXPECT_EQ(UN(RtlQueryAtomInAtomTable)(t, 0xC123, &ref, &pin, name, &len), XS(0xC0000008));
    UN(RtlDestroyAtomTable)(t);
}
TEST(rtl_tables_x_atom_pin_survives_delete)
{
    xa_atom a = 0, c = 0; ULONG ref = 0, pin = 9; NTSTATUS s; XA_TABLE(t);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"Pinned", &a), 0);
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(t, a), 0);
    EXPECT_EQ(UN(RtlQueryAtomInAtomTable)(t, a, &ref, &pin, NULL, NULL), 0); EXPECT_EQ(pin, 1);
    s = UN(RtlDeleteAtomFromAtomTable)(t, a);
    t_note("delete of a pinned atom status=%08lx", s);
    s = UN(RtlDeleteAtomFromAtomTable)(t, a);
    t_note("second delete of a pinned atom status=%08lx", s);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"Pinned", &c), 0);       /* a pinned atom cannot be removed */
    EXPECT_EQ(c, a);
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(t, 0xC555), XS(0xC0000008));
    UN(RtlDestroyAtomTable)(t);
}
TEST(rtl_tables_x_atom_empty_table)
{
    xa_atom a = 0, b = 0, c = 0; XA_TABLE(t); REQUIRE(UN(RtlEmptyAtomTable));
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"Gone1", &a), 0);
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"Kept", &b), 0);
    EXPECT_EQ(UN(RtlPinAtomInAtomTable)(t, b), 0);
    EXPECT_EQ(UN(RtlEmptyAtomTable)(t, FALSE), 0);                       /* pinned atoms stay */
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"Gone1", &c), XS(0xC0000034));
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"Kept", &c), 0);
    EXPECT_EQ(UN(RtlEmptyAtomTable)(t, TRUE), 0);                        /* everything goes */
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"Kept", &c), XS(0xC0000034));
    UN(RtlDestroyAtomTable)(t);
}
TEST(rtl_tables_x_atom_create_table_reuses_existing)
{
    PVOID t = NULL, again; xa_atom a = 0, c = 0; XA_NEED();
    if (!XOK(UN(RtlCreateAtomTable)(17, &t)) || !t) { t_skip("atom table"); return; }
    EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, L"Persist", &a), 0);
    again = t;
    EXPECT_EQ(UN(RtlCreateAtomTable)(17, &again), 0);                   /* an existing table pointer is kept */
    EXPECT_EQ(again, t);
    EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, L"Persist", &c), 0);
    UN(RtlDestroyAtomTable)(t);
}
TEST(rtl_tables_x_atom_many_names)
{
    xa_atom atoms[64], back; WCHAR name[24]; int distinct = 1; XA_TABLE(t);
    for (int i = 0; i < 64; i++) { wsprintfW(name, L"Atom_%03d", i); EXPECT_EQ(UN(RtlAddAtomToAtomTable)(t, name, &atoms[i]), 0); }
    for (int i = 1; i < 64; i++) { int dup = 0; for (int j = 0; j < i; j++) if (atoms[j] == atoms[i]) dup = 1; if (!dup) distinct++; }
    EXPECT_EQ(distinct, 64);
    for (int i = 0; i < 64; i++) { wsprintfW(name, L"ATOM_%03d", i); back = 0; EXPECT_EQ(UN(RtlLookupAtomInAtomTable)(t, name, &back), 0); EXPECT_EQ(back, atoms[i]); }
    UN(RtlDestroyAtomTable)(t);
}

/* ---- global atoms --------------------------------------------------------- */
typedef struct { USHORT usage, flags, name_bytes; WCHAR name[40]; } xa_basic;
static void xa_gname(WCHAR *out, const WCHAR *tag) { wsprintfW(out, L"NtdllConf_%lu_%s", GetCurrentProcessId(), tag); }
#define XA_GNEED() do { REQUIRE(UN(NtAddAtom)); REQUIRE(UN(NtFindAtom)); REQUIRE(UN(NtDeleteAtom)); REQUIRE(UN(NtQueryInformationAtom)); } while (0)
TEST(rtl_tables_x_global_atom_lifecycle)
{
    WCHAR name[48]; xa_atom a = 0, b = 0, c = 0; XA_GNEED();
    xa_gname(name, L"life");
    EXPECT_EQ(UN(NtFindAtom)(name, lstrlenW(name) * 2, &c), XS(0xC0000034));
    EXPECT_EQ(UN(NtAddAtom)(name, lstrlenW(name) * 2, &a), 0); CHECK(a >= 0xC000);
    EXPECT_EQ(UN(NtAddAtom)(name, lstrlenW(name) * 2, &b), 0); EXPECT_EQ(b, a);
    EXPECT_EQ(UN(NtFindAtom)(name, lstrlenW(name) * 2, &c), 0); EXPECT_EQ(c, a);
    { xa_basic info; ULONG got = 0; memset(&info, 0, sizeof info);
      EXPECT_EQ(UN(NtQueryInformationAtom)(a, 0, &info, sizeof info, &got), 0);
      EXPECT_EQ(info.usage, 2); EXPECT_EQ(info.name_bytes, lstrlenW(name) * 2); CHECK(!memcmp(info.name, name, info.name_bytes));
      t_note("basic information length=%lu", got); }
    EXPECT_EQ(UN(NtDeleteAtom)(a), 0);
    EXPECT_EQ(UN(NtFindAtom)(name, lstrlenW(name) * 2, &c), 0);        /* one reference left */
    EXPECT_EQ(UN(NtDeleteAtom)(a), 0);
    EXPECT_EQ(UN(NtFindAtom)(name, lstrlenW(name) * 2, &c), XS(0xC0000034));
    EXPECT_EQ(UN(NtDeleteAtom)(a), XS(0xC0000008));
}
TEST(rtl_tables_x_global_atom_case_insensitive)
{
    WCHAR name[48], upper[48]; xa_atom a = 0, b = 0; XA_GNEED();
    xa_gname(name, L"CaseTest"); xa_gname(upper, L"CASETEST");
    EXPECT_EQ(UN(NtAddAtom)(name, lstrlenW(name) * 2, &a), 0);
    EXPECT_EQ(UN(NtFindAtom)(upper, lstrlenW(upper) * 2, &b), 0); EXPECT_EQ(b, a);
    EXPECT_EQ(UN(NtDeleteAtom)(a), 0);
}
TEST(rtl_tables_x_global_atom_length_is_bytes)
{
    WCHAR name[48]; xa_atom a = 0, b = 0, c = 0; XA_GNEED();
    xa_gname(name, L"LenBytes");
    EXPECT_EQ(UN(NtAddAtom)(name, 2 * 8, &a), 0);                       /* only the first 8 characters count */
    CHECK(a >= 0xC000);
    { WCHAR prefix[9]; memcpy(prefix, name, 16); prefix[8] = 0;
      EXPECT_EQ(UN(NtFindAtom)(prefix, 16, &b), 0); EXPECT_EQ(b, a);
      EXPECT_EQ(UN(NtFindAtom)(name, lstrlenW(name) * 2, &c), XS(0xC0000034)); }
    EXPECT_EQ(UN(NtDeleteAtom)(a), 0);
}
TEST(rtl_tables_x_global_atom_invalid_arguments)
{
    WCHAR name[48]; xa_atom a = 0; NTSTATUS s; XA_GNEED();
    xa_gname(name, L"Invalid");
    s = UN(NtAddAtom)(name, 0, &a);
    CHECK(!XOK(s)); t_note("zero length status=%08lx", s);
    s = UN(NtAddAtom)(name, 3, &a);
    t_note("odd byte length status=%08lx", s);
    if (XOK(s)) UN(NtDeleteAtom)(a);
    EXPECT_EQ(UN(NtDeleteAtom)(0), XS(0xC0000008));
    EXPECT_EQ(UN(NtDeleteAtom)(0xC7FF), XS(0xC0000008));
}
TEST(rtl_tables_x_global_atom_query_information)
{
    WCHAR name[48]; xa_atom a = 0; xa_basic info; ULONG got = 0; NTSTATUS s; XA_GNEED();
    xa_gname(name, L"QueryInfo");
    EXPECT_EQ(UN(NtAddAtom)(name, lstrlenW(name) * 2, &a), 0);
    s = UN(NtQueryInformationAtom)(a, 0, &info, 4, &got);
    CHECK(!XOK(s)); t_note("short basic buffer status=%08lx", s);
    s = UN(NtQueryInformationAtom)(a, 0x7f, &info, sizeof info, &got);
    EXPECT_EQ(s, XS(0xC0000003));
    s = UN(NtQueryInformationAtom)(a, 1 /* table information */, &info, sizeof info, &got);
    t_note("table information status=%08lx length=%lu", s, got);
    EXPECT_EQ(UN(NtQueryInformationAtom)(0xC7FE, 0, &info, sizeof info, &got), XS(0xC0000008));
    EXPECT_EQ(UN(NtDeleteAtom)(a), 0);
}

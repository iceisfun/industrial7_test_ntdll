/* Create/open services for namespace objects: symbolic links, directory objects,
 * private namespaces, sections and job objects. */
#include "cob.h"

UDECL(NTSTATUS, ZwCreateSymbolicLinkObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING));
UDECL(NTSTATUS, ZwOpenSymbolicLinkObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtQuerySymbolicLinkObject, (HANDLE, PUNICODE_STRING, PULONG));
UDECL(NTSTATUS, ZwOpenDirectoryObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateDirectoryObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwCreatePrivateNamespace, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, ZwOpenPrivateNamespace, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID));
UDECL(NTSTATUS, NtDeletePrivateNamespace, (HANDLE));
UDECL(PVOID, RtlCreateBoundaryDescriptor, (PUNICODE_STRING, ULONG));
UDECL(NTSTATUS, RtlAddSIDToBoundaryDescriptor, (PVOID *, PSID));
UDECL(VOID, RtlDeleteBoundaryDescriptor, (PVOID));
UDECL(NTSTATUS, ZwCreateSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE));
UDECL(NTSTATUS, ZwCreateSectionEx, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE, PVOID, ULONG));
UDECL(NTSTATUS, ZwOpenSection, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtQuerySection, (HANDLE, ULONG, PVOID, SIZE_T, PSIZE_T));
UDECL(NTSTATUS, NtMapViewOfSection, (HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG));
UDECL(NTSTATUS, NtUnmapViewOfSection, (HANDLE, PVOID));
UDECL(NTSTATUS, ZwCreateJobObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwOpenJobObject, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtAssignProcessToJobObject, (HANDLE, HANDLE));
UDECL(NTSTATUS, NtQueryInformationJobObject, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, ZwCreateJobSet, (ULONG, PVOID, ULONG));
UDECL(NTSTATUS, ZwCreatePartition, (HANDLE, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG));
UDECL(NTSTATUS, ZwOpenPartition, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtCreateEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN));
UDECL(NTSTATUS, NtOpenEvent, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, ZwOpenSession, (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES));

typedef NTSTATUS (WINAPI *open_fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
static void open_errors(open_fn op, const char *tag, ACCESS_MASK acc)
{
    HANDLE h = (HANDLE)0x1234; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200];
    cob_name(name, 200, tag); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    EXPECT_EQ(op(&h, acc, &oa), S_NOTFOUND);
    { WCHAR deep[260]; UNICODE_STRING d; lstrcpyW(deep, name); lstrcatW(deep, L"\\child"); cob_us(&d, deep); cob_oa(&oa, &d, 0, NULL);
      h = (HANDLE)0x1234; EXPECT_EQ(op(&h, acc, &oa), S_PATHNF); }
    h = (HANDLE)0x1234; EXPECT_EQ(op(&h, acc, NULL), S_INVPARAM);
    cob_oa(&oa, NULL, 0, NULL); h = (HANDLE)0x1234; EXPECT_EQ(op(&h, acc, &oa), S_PATHSYN);
    cob_us(&u, name); cob_oa(&oa, &u, 0, NULL); oa.Length = 8; h = (HANDLE)0x1234; EXPECT_EQ(op(&h, acc, &oa), S_INVPARAM);
    cob_oa(&oa, &u, 0, NULL); EXPECT_EQ(op(NULL, acc, &oa), S_AV);
    { UNICODE_STRING r; cob_us(&r, L"x"); cob_oa(&oa, &r, 0, (HANDLE)(ULONG_PTR)0x7ffffff0); h = (HANDLE)0x1234; EXPECT_EQ(op(&h, acc, &oa), S_INVHANDLE); }
}
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 1
#endif
#ifndef DIRECTORY_ALL_ACCESS
#define DIRECTORY_ALL_ACCESS 0xF000F
#endif
#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 1
#endif
#ifndef SYMBOLIC_LINK_ALL_ACCESS
#define SYMBOLIC_LINK_ALL_ACCESS 0xF0001
#endif
#define NEED(x) do { REQUIRE(UN(x)); REQUIRE(UN(NtClose)); REQUIRE(UN(NtQueryObject)); } while (0)

TEST(nt_create_open_b_symlink)
{
    HANDLE h = NULL, h2 = NULL, o = NULL; UNICODE_STRING u, target, q; OBJECT_ATTRIBUTES oa; WCHAR name[200], tn[40], qb[100]; NTSTATUS s; ULONG ret = 0;
    NEED(ZwCreateSymbolicLinkObject); REQUIRE(UN(ZwOpenSymbolicLinkObject)); REQUIRE(UN(NtQuerySymbolicLinkObject));
    COB_ALIAS("CreateSymbolicLinkObject"); COB_ALIAS("OpenSymbolicLinkObject");
    cob_name(name, 200, "sl"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    cob_us(&target, L"\\Device\\Null");
    s = UN(ZwCreateSymbolicLinkObject)(&h, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target);
    EXPECT_EQ(s, S_OK_); if (s != S_OK_) return;
    CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"SymbolicLink");
    /* query the target */
    q.Buffer = qb; q.Length = 0; q.MaximumLength = sizeof qb; ret = 0;
    EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(h, &q, &ret), S_OK_);
    EXPECT_EQ(q.Length, target.Length); EXPECT_EQ(ret, target.Length);
    CHECK(!memcmp(qb, L"\\Device\\Null", target.Length));
    /* too small buffer reports the needed length */
    q.Buffer = qb; q.Length = 0; q.MaximumLength = 8; ret = 0;
    EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(h, &q, &ret), S_BUFSMALL); EXPECT_EQ(ret, target.Length);
    /* duplicate name */
    h2 = (HANDLE)0x1234; EXPECT_EQ(UN(ZwCreateSymbolicLinkObject)(&h2, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target), S_COLLIDE);
    /* open it back */
    EXPECT_EQ(UN(ZwOpenSymbolicLinkObject)(&o, SYMBOLIC_LINK_QUERY, &oa), S_OK_);
    if (o) { q.Buffer = qb; q.Length = 0; q.MaximumLength = sizeof qb; EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(o, &q, &ret), S_OK_); EXPECT_EQ(q.Length, target.Length); cob_close(o); }
    /* error paths on create */
    cob_oa(&oa, NULL, 0, NULL);
    h2 = NULL; EXPECT_EQ(UN(ZwCreateSymbolicLinkObject)(&h2, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target), S_OK_); cob_close(h2);   /* unnamed link */
    cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    { UNICODE_STRING e = {0, 0, NULL}; WCHAR n2[200]; UNICODE_STRING u2; OBJECT_ATTRIBUTES oa2; cob_name(n2, 200, "sl2"); cob_us(&u2, n2); cob_oa(&oa2, &u2, 0, NULL);
      EXPECT_EQ(UN(ZwCreateSymbolicLinkObject)(&h2, SYMBOLIC_LINK_ALL_ACCESS, &oa2, &e), S_INVPARAM);
      EXPECT_EQ(UN(ZwCreateSymbolicLinkObject)(&h2, SYMBOLIC_LINK_ALL_ACCESS, &oa2, NULL), S_AV); }
    EXPECT_EQ(UN(ZwCreateSymbolicLinkObject)(NULL, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target), S_AV);
    cob_close(h);
    /* the object is gone when the last handle of a non-permanent link closes */
    EXPECT_EQ(UN(ZwOpenSymbolicLinkObject)(&o, SYMBOLIC_LINK_QUERY, &oa), S_NOTFOUND);
    { UNICODE_STRING nf; WCHAR n3[200]; cob_name(n3, 200, "sl3"); cob_us(&nf, n3); cob_oa(&oa, &nf, 0, NULL);
      EXPECT_EQ(UN(ZwOpenSymbolicLinkObject)(&o, SYMBOLIC_LINK_QUERY, &oa), S_NOTFOUND);
      EXPECT_EQ(UN(ZwOpenSymbolicLinkObject)(&o, SYMBOLIC_LINK_QUERY, NULL), S_INVPARAM); }
    /* type mismatch: open a directory as a symlink */
    { WCHAR bno[96]; UNICODE_STRING bu; OBJECT_ATTRIBUTES boa; cob_bno(bno, 96); cob_us(&bu, bno); cob_oa(&boa, &bu, 0, NULL);
      EXPECT_EQ(UN(ZwOpenSymbolicLinkObject)(&o, SYMBOLIC_LINK_QUERY, &boa), S_TYPEMM); }
}

TEST(nt_create_open_b_symlink_resolves_lookup)
{
    HANDLE h = NULL, ev = NULL, via = NULL; UNICODE_STRING u, target, lu; OBJECT_ATTRIBUTES oa; WCHAR name[200], evn[200]; NTSTATUS s;
    NEED(ZwCreateSymbolicLinkObject); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtOpenEvent));
    cob_name(evn, 200, "slev"); cob_us(&u, evn); cob_oa(&oa, &u, 0, NULL);
    EXPECT_EQ(UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, &oa, 0, FALSE), S_OK_); if (!ev) return;
    cob_name(name, 200, "sllink"); cob_us(&lu, name); cob_us(&target, evn);
    cob_oa(&oa, &lu, 0, NULL);
    s = UN(ZwCreateSymbolicLinkObject)(&h, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target); EXPECT_EQ(s, S_OK_);
    if (s == S_OK_) {
        /* opening through the link name reaches the event */
        EXPECT_EQ(UN(NtOpenEvent)(&via, EVENT_QUERY_STATE, &oa), S_OK_);
        if (via) { WCHAR tn[40]; CHECK(cob_typename(via, tn, 40)); EXPECT_WSTR(tn, L"Event"); cob_close(via); }
        /* OBJ_OPENLINK is not a valid attribute for the link-open service itself */
        via = NULL; oa.Attributes = 0x100;
        EXPECT_EQ(UN(ZwOpenSymbolicLinkObject)(&via, SYMBOLIC_LINK_QUERY, &oa), S_INVPARAM); cob_close(via);
        cob_close(h);
    }
    cob_close(ev);
}

TEST(nt_create_open_b_directory_open)
{
    HANDLE h = NULL, d = NULL, o = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR bno[96], tn[40], sub[200]; ULONG g = 0;
    NEED(ZwOpenDirectoryObject); REQUIRE(UN(NtCreateDirectoryObject));
    COB_ALIAS("OpenDirectoryObject");
    cob_bno(bno, 96); cob_us(&u, bno); cob_oa(&oa, &u, 0, NULL);
    EXPECT_EQ(UN(ZwOpenDirectoryObject)(&h, DIRECTORY_QUERY, &oa), S_OK_);
    if (h) { CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"Directory"); CHECK(cob_granted(h, &g)); EXPECT_EQ(g & 0x1f, DIRECTORY_QUERY); }
    /* open a sub-object relative to the directory handle */
    cob_name(sub, 200, "dirsub"); cob_us(&u, sub); cob_oa(&oa, &u, 0, NULL);
    EXPECT_EQ(UN(NtCreateDirectoryObject)(&d, DIRECTORY_ALL_ACCESS, &oa), S_OK_);
    if (d) {
        UNICODE_STRING rel; WCHAR *leaf = wcsrchr(sub, L'\\') + 1; OBJECT_ATTRIBUTES roa; cob_us(&rel, leaf); cob_oa(&roa, &rel, 0, h);
        EXPECT_EQ(UN(ZwOpenDirectoryObject)(&o, DIRECTORY_QUERY, &roa), S_OK_); cob_close(o);
        o = NULL; cob_oa(&roa, &rel, 0, d);   /* the child does not exist inside itself */
        EXPECT_EQ(UN(ZwOpenDirectoryObject)(&o, DIRECTORY_QUERY, &roa), S_NOTFOUND);
        cob_close(d);
    }
    cob_close(h);
    /* root of the namespace */
    { UNICODE_STRING r; OBJECT_ATTRIBUTES ro; cob_us(&r, L"\\"); cob_oa(&ro, &r, 0, NULL); o = NULL;
      EXPECT_EQ(UN(ZwOpenDirectoryObject)(&o, DIRECTORY_QUERY, &ro), S_OK_); cob_close(o); }
    /* \Device exists but is not writable by users */
    { UNICODE_STRING r; OBJECT_ATTRIBUTES ro; cob_us(&r, L"\\Device"); cob_oa(&ro, &r, 0, NULL); o = NULL;
      EXPECT_EQ(UN(ZwOpenDirectoryObject)(&o, DIRECTORY_QUERY, &ro), S_OK_); cob_close(o); }
    open_errors(UN(ZwOpenDirectoryObject), "dirx", DIRECTORY_QUERY);
}

TEST(nt_create_open_b_private_namespace)
{
    HANDLE bnoh = NULL, ns = NULL, ns2 = NULL, o = NULL; UNICODE_STRING u, bn; OBJECT_ATTRIBUTES oa; WCHAR bno[96], leaf[64], tn[40]; PVOID bd = NULL; NTSTATUS s;
    BYTE sid[12] = {1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};   /* S-1-1-0 (Everyone) */
    NEED(ZwCreatePrivateNamespace); REQUIRE(UN(ZwOpenPrivateNamespace)); REQUIRE(UN(NtDeletePrivateNamespace)); REQUIRE(UN(ZwOpenDirectoryObject));
    REQUIRE(UN(RtlCreateBoundaryDescriptor)); REQUIRE(UN(RtlAddSIDToBoundaryDescriptor)); REQUIRE(UN(RtlDeleteBoundaryDescriptor));
    COB_ALIAS("CreatePrivateNamespace"); COB_ALIAS("OpenPrivateNamespace");
    cob_bno(bno, 96); cob_us(&u, bno); cob_oa(&oa, &u, 0, NULL);
    EXPECT_EQ(UN(ZwOpenDirectoryObject)(&bnoh, DIRECTORY_ALL_ACCESS, &oa), S_OK_);
    if (!bnoh) return;
    wsprintfW(leaf, L"cobns_%lu", (unsigned long)GetCurrentProcessId());
    cob_us(&bn, L"cobbd"); bd = UN(RtlCreateBoundaryDescriptor)(&bn, 0); CHECK(bd != NULL);
    if (!bd) { cob_close(bnoh); return; }
    EXPECT_EQ(UN(RtlAddSIDToBoundaryDescriptor)(&bd, sid), S_OK_);
    cob_oa(&oa, NULL, 0, NULL);
    s = UN(ZwCreatePrivateNamespace)(&ns, DIRECTORY_ALL_ACCESS, &oa, bd);
    EXPECT_EQ(s, S_OK_);
    if (s == S_OK_) {
        CHECK(cob_typename(ns, tn, 40)); EXPECT_WSTR(tn, L"Directory");
        ns2 = (HANDLE)0x1234; EXPECT_EQ(UN(ZwCreatePrivateNamespace)(&ns2, DIRECTORY_ALL_ACCESS, &oa, bd), S_COLLIDE);
        EXPECT_EQ(UN(ZwOpenPrivateNamespace)(&o, DIRECTORY_QUERY, &oa, bd), S_OK_);
        if (o) { CHECK(cob_typename(o, tn, 40)); EXPECT_WSTR(tn, L"Directory"); cob_close(o); o = NULL; }
        /* NULL boundary descriptor is probed as a pointer */
        EXPECT_EQ(UN(ZwOpenPrivateNamespace)(&o, DIRECTORY_QUERY, &oa, NULL), S_AV);
        EXPECT_EQ(UN(NtDeletePrivateNamespace)(ns), S_OK_);
        cob_close(ns);
    }
    { PVOID bd2 = NULL; UNICODE_STRING b2; cob_us(&b2, L"cobbd2"); bd2 = UN(RtlCreateBoundaryDescriptor)(&b2, 0);
      if (bd2) { UN(RtlAddSIDToBoundaryDescriptor)(&bd2, sid);
        cob_oa(&oa, NULL, 0, NULL); o = (HANDLE)0x1234; s = UN(ZwOpenPrivateNamespace)(&o, DIRECTORY_QUERY, &oa, bd2); CHECK(s < 0); t_note("open missing private namespace: 0x%08lx", (unsigned long)s);
        UN(RtlDeleteBoundaryDescriptor)(bd2); }
      EXPECT_EQ(UN(ZwCreatePrivateNamespace)(&ns2, DIRECTORY_ALL_ACCESS, &oa, NULL), S_AV);
      EXPECT_EQ(UN(ZwCreatePrivateNamespace)(NULL, DIRECTORY_ALL_ACCESS, &oa, bd), S_AV); }
    UN(RtlDeleteBoundaryDescriptor)(bd);
    cob_close(bnoh);
}

#define S_INVPARAM4 ((NTSTATUS)0xC00000F2)
#define S_INVPARAM6 ((NTSTATUS)0xC00000F4)
#define S_NOTMZ ((NTSTATUS)0xC000012F)
#define S_PAGEPROT ((NTSTATUS)0xC0000045)
#define JOB_OBJECT_ALL_ACCESS_ 0x1F001F
#define SEC_COMMIT_ 0x8000000
#define SEC_RESERVE_ 0x4000000
TEST(nt_create_open_b_section)
{
    HANDLE h = NULL, h2 = NULL, o = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200], tn[40]; NTSTATUS s; LARGE_INTEGER sz; ULONG g = 0;
    struct { PVOID base; ULONG attr; LARGE_INTEGER size; } bi; SIZE_T ret = 0;
    NEED(ZwCreateSection); REQUIRE(UN(ZwOpenSection)); REQUIRE(UN(NtQuerySection));
    COB_ALIAS("CreateSection"); COB_ALIAS("OpenSection");
    cob_name(name, 200, "sec"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    sz.QuadPart = 0x12000;
    s = UN(ZwCreateSection)(&h, SECTION_ALL_ACCESS, &oa, &sz, PAGE_READWRITE, SEC_COMMIT_, NULL);
    EXPECT_EQ(s, S_OK_); if (!h) return;
    CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"Section");
    memset(&bi, 0xcc, sizeof bi);
    EXPECT_EQ(UN(NtQuerySection)(h, 0, &bi, sizeof bi, &ret), S_OK_);
    EXPECT_EQ(ret, sizeof bi); EXPECT_EQ(bi.size.QuadPart, 0x12000); EXPECT_EQ(bi.attr & SEC_COMMIT_, SEC_COMMIT_);
    EXPECT_EQ(UN(ZwCreateSection)(&h2, SECTION_ALL_ACCESS, &oa, &sz, PAGE_READWRITE, SEC_COMMIT_, NULL), S_COLLIDE);
    EXPECT_EQ(UN(ZwOpenSection)(&o, SECTION_QUERY | SECTION_MAP_READ, &oa), S_OK_);
    if (o) { CHECK(cob_granted(o, &g)); EXPECT_EQ(g & SECTION_ALL_ACCESS, SECTION_QUERY | SECTION_MAP_READ);
        memset(&bi, 0, sizeof bi); EXPECT_EQ(UN(NtQuerySection)(o, 0, &bi, sizeof bi, &ret), S_OK_); EXPECT_EQ(bi.size.QuadPart, 0x12000); cob_close(o); }
    /* a view of the opened section sees writes made through the creator's view */
    if (UN(NtMapViewOfSection) && UN(NtUnmapViewOfSection)) {
        PVOID v1 = NULL, v2 = NULL; SIZE_T vs1 = 0, vs2 = 0; HANDLE self = GetCurrentProcess(); o = NULL;
        EXPECT_EQ(UN(ZwOpenSection)(&o, SECTION_MAP_READ | SECTION_MAP_WRITE, &oa), S_OK_);
        if (o && UN(NtMapViewOfSection)(h, self, &v1, 0, 0, NULL, &vs1, 2, 0, PAGE_READWRITE) == 0) {
            EXPECT_EQ(vs1, 0x12000);
            if (UN(NtMapViewOfSection)(o, self, &v2, 0, 0, NULL, &vs2, 2, 0, PAGE_READWRITE) == 0) {
                *(volatile DWORD *)v1 = 0xC0FFEE42; EXPECT_EQ(*(volatile DWORD *)v2, 0xC0FFEE42);
                UN(NtUnmapViewOfSection)(self, v2);
            }
            UN(NtUnmapViewOfSection)(self, v1);
        }
        cob_close(o);
    }
    cob_close(h);
    /* parameter validation, unnamed */
    h2 = NULL; sz.QuadPart = 0;
    EXPECT_EQ(UN(ZwCreateSection)(&h2, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT_, NULL), S_INVPARAM4);
    EXPECT_EQ(UN(ZwCreateSection)(&h2, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READWRITE, SEC_COMMIT_, NULL), S_INVPARAM4);
    sz.QuadPart = 0x1000;
    EXPECT_EQ(UN(ZwCreateSection)(&h2, SECTION_ALL_ACCESS, NULL, &sz, 0x3, SEC_COMMIT_, NULL), S_PAGEPROT);
    EXPECT_EQ(UN(ZwCreateSection)(&h2, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, 0, NULL), S_INVPARAM6);
    EXPECT_EQ(UN(ZwCreateSection)(&h2, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT_ | SEC_RESERVE_, NULL), S_INVPARAM6);
    EXPECT_EQ(UN(ZwCreateSection)(&h2, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT_, (HANDLE)(ULONG_PTR)0x7ffffff0), S_INVHANDLE);
    EXPECT_EQ(UN(ZwCreateSection)(NULL, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT_, NULL), S_AV);
    EXPECT_EQ(UN(ZwCreateSection)(&h2, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT_, NULL), S_OK_); cob_close(h2);
    open_errors(UN(ZwOpenSection), "secx", SECTION_QUERY);
}

TEST(nt_create_open_b_section_file_backed)
{
    HANDLE f, h = NULL; char path[300]; LARGE_INTEGER sz; struct { PVOID base; ULONG attr; LARGE_INTEGER size; } bi; SIZE_T ret; DWORD wr; NTSTATUS s;
    NEED(ZwCreateSection); REQUIRE(UN(NtQuerySection));
    t_tmpfile(path, sizeof path, "cob_sec.bin");
    f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(f != INVALID_HANDLE_VALUE); if (f == INVALID_HANDLE_VALUE) return;
    { char buf[5000]; memset(buf, 'q', sizeof buf); WriteFile(f, buf, sizeof buf, &wr, NULL); }
    sz.QuadPart = 0;
    s = UN(ZwCreateSection)(&h, SECTION_MAP_READ | SECTION_QUERY, NULL, &sz, PAGE_READONLY, SEC_COMMIT_, f);
    EXPECT_EQ(s, S_OK_);
    if (h) { memset(&bi, 0, sizeof bi); EXPECT_EQ(UN(NtQuerySection)(h, 0, &bi, sizeof bi, &ret), S_OK_); EXPECT_EQ(bi.size.QuadPart, 5000); cob_close(h); h = NULL; }
    /* NULL size: size taken from the file */
    s = UN(ZwCreateSection)(&h, SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, SEC_COMMIT_, f);
    EXPECT_EQ(s, S_OK_);
    if (h) { memset(&bi, 0, sizeof bi); EXPECT_EQ(UN(NtQuerySection)(h, 0, &bi, sizeof bi, &ret), S_OK_); EXPECT_EQ(bi.size.QuadPart, 5000); cob_close(h); h = NULL; }
    /* a file that is not an image */
    s = UN(ZwCreateSection)(&h, SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, 0x1000000 /* SEC_IMAGE */, f);
    EXPECT_EQ(s, S_NOTMZ); cob_close(h);
    CloseHandle(f); DeleteFileA(path);
}

TEST(nt_create_open_b_section_ex)
{
    HANDLE h = NULL, o = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200]; NTSTATUS s; LARGE_INTEGER sz; SIZE_T ret;
    struct { PVOID base; ULONG attr; LARGE_INTEGER size; } bi;
    NEED(ZwCreateSectionEx); REQUIRE(UN(ZwOpenSection)); REQUIRE(UN(NtQuerySection));
    COB_ALIAS("CreateSectionEx");
    cob_name(name, 200, "secex"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    sz.QuadPart = 0x4000;
    s = UN(ZwCreateSectionEx)(&h, SECTION_ALL_ACCESS, &oa, &sz, PAGE_READWRITE, SEC_COMMIT_, NULL, NULL, 0);
    EXPECT_EQ(s, S_OK_);
    if (h) { memset(&bi, 0, sizeof bi); EXPECT_EQ(UN(NtQuerySection)(h, 0, &bi, sizeof bi, &ret), S_OK_); EXPECT_EQ(bi.size.QuadPart, 0x4000);
        EXPECT_EQ(UN(ZwOpenSection)(&o, SECTION_QUERY, &oa), S_OK_); cob_close(o); }
    cob_close(h); h = NULL;
    EXPECT_EQ(UN(ZwCreateSectionEx)(&h, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT_, NULL, NULL, 1), S_INVPARAM);
    EXPECT_EQ(UN(ZwCreateSectionEx)(&h, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT_, NULL, (PVOID)(ULONG_PTR)8, 1), S_AV);
    sz.QuadPart = 0;
    EXPECT_EQ(UN(ZwCreateSectionEx)(&h, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT_, NULL, NULL, 0), S_INVPARAM4);
    EXPECT_EQ(UN(ZwCreateSectionEx)(NULL, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT_, NULL, NULL, 0), S_AV);
}

TEST(nt_create_open_b_job_object)
{
    HANDLE h = NULL, h2 = NULL, o = NULL; UNICODE_STRING u; OBJECT_ATTRIBUTES oa; WCHAR name[200], tn[40]; NTSTATUS s; ULONG g = 0;
    struct { LARGE_INTEGER a, b, c, d; ULONG e, f, g, h, i, j; } bi; ULONG ret;
    NEED(ZwCreateJobObject); REQUIRE(UN(ZwOpenJobObject));
    COB_ALIAS("CreateJobObject"); COB_ALIAS("OpenJobObject");
    cob_name(name, 200, "job"); cob_us(&u, name); cob_oa(&oa, &u, 0, NULL);
    s = UN(ZwCreateJobObject)(&h, JOB_OBJECT_ALL_ACCESS_, &oa); EXPECT_EQ(s, S_OK_); if (!h) return;
    CHECK(cob_typename(h, tn, 40)); EXPECT_WSTR(tn, L"Job");
    CHECK(cob_granted(h, &g)); EXPECT_EQ(g & JOB_OBJECT_ALL_ACCESS_, JOB_OBJECT_ALL_ACCESS_);
    h2 = (HANDLE)0x1234; EXPECT_EQ(UN(ZwCreateJobObject)(&h2, JOB_OBJECT_ALL_ACCESS_, &oa), S_COLLIDE);
    EXPECT_EQ(UN(ZwOpenJobObject)(&o, 0x4 /* JOB_OBJECT_QUERY */, &oa), S_OK_);
    if (o) { CHECK(cob_granted(o, &g)); EXPECT_EQ(g & JOB_OBJECT_ALL_ACCESS_, 4);
        if (UN(NtQueryInformationJobObject)) { ULONG cnt[2] = {0xcc, 0xcc}; ret = 0;
          /* JobObjectBasicAccountingInformation (1) is 0x30 bytes */
          BYTE big[0x30]; memset(big, 0xcc, sizeof big);
          EXPECT_EQ(UN(NtQueryInformationJobObject)(o, 1, big, sizeof big, &ret), S_OK_); EXPECT_EQ(ret, 0x30); } cob_close(o); }
    /* unnamed */
    cob_oa(&oa, NULL, 0, NULL);
    EXPECT_EQ(UN(ZwCreateJobObject)(&h2, JOB_OBJECT_ALL_ACCESS_, &oa), S_OK_); cob_close(h2);
    EXPECT_EQ(UN(ZwCreateJobObject)(&h2, JOB_OBJECT_ALL_ACCESS_, NULL), S_OK_); cob_close(h2);
    EXPECT_EQ(UN(ZwCreateJobObject)(NULL, JOB_OBJECT_ALL_ACCESS_, NULL), S_AV);
    cob_close(h);
    open_errors(UN(ZwOpenJobObject), "jobx", 4);
}

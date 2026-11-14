/* Object-manager style creators and openers: directory objects, symbolic links, keyed events,
 * job objects, sections, timers, debug objects, LPC ports, private namespaces, event pairs.
 * Expectations were observed on Windows 10 22H2 (see EVIDENCE.md). */
#include "oa.h"

#define DIR_RIGHTS 0x0F  /* QUERY | TRAVERSE | CREATE_OBJECT | CREATE_SUBDIRECTORY */

TEST(zw_aliases_share_nt_entry)
{
    static const char *names[] = {"CreateCrossVmEvent", "CreateCrossVmMutant", "CreateDebugObject", "CreateDirectoryObject",
        "CreateDirectoryObjectEx", "CreateEnclave", "CreateEnlistment", "CreateEvent", "CreateEventPair"};
    char nt[64], zw[64];
    REQUIRE(t_proc("NtCreateEvent"));
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        wsprintfA(nt, "Nt%s", names[i]); wsprintfA(zw, "Zw%s", names[i]);
        CHECKF(t_proc(nt) != NULL && t_proc(nt) == t_proc(zw), "%s", names[i]);
    }
}

TEST(zw_create_event_behaves_as_event)
{
    HANDLE h = NULL; WCHAR nm[96]; OBJECT_ATTRIBUTES oa; HANDLE o = NULL; REQUIRE(UN(ZwCreateEvent)); REQUIRE(UN(NtOpenEvent)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_zwev"); oa_init(&oa, nm, OBJ_CI);
    /* notification event, initially signalled */
    EXPECT_EQ(UN(ZwCreateEvent)(&h, EVENT_ALL_ACCESS, &oa, 0, TRUE), ST_SUCCESS);
    CHECK(h != NULL);
    if (h) {
        EXPECT_EQ(WaitForSingleObject(h, 0), WAIT_OBJECT_0);
        EXPECT_EQ(WaitForSingleObject(h, 0), WAIT_OBJECT_0); /* notification: stays signalled */
        EXPECT_EQ(UN(NtOpenEvent)(&o, SYNCHRONIZE, &oa), ST_SUCCESS);
        CLOSE(o);
    }
    CLOSE(h);
    EXPECT_EQ(UN(NtOpenEvent)(&o, SYNCHRONIZE, &oa), ST_NAME_NOT_FOUND);
    CHECK(o == NULL);
    /* event type 2 is not valid */
    EXPECT_EQ(UN(ZwCreateEvent)(&h, EVENT_ALL_ACCESS, NULL, 2, FALSE), ST_INVALID_PARAMETER);
}

/* ---- directory objects ------------------------------------------------- */

TEST(directory_create_open_and_contents)
{
    HANDLE d = NULL, d2 = NULL, ev = NULL, ev2 = NULL; WCHAR nm[96], child[160]; OBJECT_ATTRIBUTES oa, co;
    REQUIRE(UN(NtCreateDirectoryObject)); REQUIRE(UN(NtOpenDirectoryObject)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtOpenEvent)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_dir"); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreateDirectoryObject)(&d, DIR_RIGHTS | 0x20000, &oa), ST_SUCCESS);
    CHECK(d != NULL);
    /* same name again */
    EXPECT_EQ(UN(NtCreateDirectoryObject)(&d2, DIR_RIGHTS, &oa), ST_NAME_COLLISION);
    CHECK(d2 == NULL);
    EXPECT_EQ(UN(NtOpenDirectoryObject)(&d2, 3 /* QUERY|TRAVERSE */, &oa), ST_SUCCESS);
    CLOSE(d2);
    if (d) {
        /* an object created relative to the directory is visible by its full path */
        memset(&co, 0, sizeof co); co.Length = sizeof co; co.RootDirectory = d; co.ObjectName = oa_us(L"child_event"); co.Attributes = OBJ_CI;
        EXPECT_EQ(UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, &co, 1, FALSE), ST_SUCCESS);
        wsprintfW(child, L"%s\\child_event", nm); oa_init(&co, child, OBJ_CI);
        EXPECT_EQ(UN(NtOpenEvent)(&ev2, SYNCHRONIZE, &co), ST_SUCCESS);
        CLOSE(ev2); CLOSE(ev);
    }
    CLOSE(d);
    /* the directory was not permanent: gone when the last handle closes */
    EXPECT_EQ(UN(NtOpenDirectoryObject)(&d2, 3, &oa), ST_NAME_NOT_FOUND);
    CHECK(d2 == NULL);
}

TEST(directory_open_root_and_errors)
{
    HANDLE h = NULL; OBJECT_ATTRIBUTES oa; REQUIRE(UN(NtOpenDirectoryObject)); REQUIRE(UN(NtCreateDirectoryObject)); REQUIRE(UN(NtClose));
    oa_init(&oa, L"\\", 0);
    EXPECT_EQ(UN(NtOpenDirectoryObject)(&h, 1 /* DIRECTORY_QUERY */, &oa), ST_SUCCESS);
    CLOSE(h);
    oa_init(&oa, L"\\NoSuchDirectoryZZ", 0);
    EXPECT_EQ(UN(NtOpenDirectoryObject)(&h, 1, &oa), ST_NAME_NOT_FOUND);
    CHECK(h == NULL);
    /* NULL output handle pointer is reported, not raised */
    WCHAR nm[96]; bno_name(nm, L"oa_dirnull"); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreateDirectoryObject)(NULL, DIR_RIGHTS, &oa), ST_ACCESS_VIOLATION);
    /* unnamed directory with zero access is allowed */
    EXPECT_EQ(UN(NtCreateDirectoryObject)(&h, 0, NULL), ST_SUCCESS);
    CLOSE(h);
}

TEST(directory_ex_flags_and_shadow)
{
    HANDLE d = NULL, s = NULL, sh = NULL; WCHAR nm[96]; OBJECT_ATTRIBUTES oa;
    REQUIRE(UN(NtCreateDirectoryObjectEx)); REQUIRE(UN(NtCreateDirectoryObject)); REQUIRE(UN(NtOpenDirectoryObject)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_dirx"); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreateDirectoryObjectEx)(&d, DIR_RIGHTS, &oa, NULL, 0), ST_SUCCESS);
    CHECK(d != NULL);
    HANDLE o = NULL;
    EXPECT_EQ(UN(NtOpenDirectoryObject)(&o, 3, &oa), ST_SUCCESS);
    CLOSE(o);
    EXPECT_EQ(UN(NtCreateDirectoryObjectEx)(&o, DIR_RIGHTS, &oa, NULL, 0), ST_NAME_COLLISION);
    CHECK(o == NULL);
    CLOSE(d);
    /* flag 1 (shadow-cloning request) is accepted; 2 and 4 are rejected as the fifth parameter */
    EXPECT_EQ(UN(NtCreateDirectoryObjectEx)(&s, DIR_RIGHTS, NULL, NULL, 1), ST_SUCCESS);
    CLOSE(s);
    EXPECT_EQ(UN(NtCreateDirectoryObjectEx)(&s, DIR_RIGHTS, NULL, NULL, 2), ST(0xC00000F3));
    EXPECT_EQ(UN(NtCreateDirectoryObjectEx)(&s, DIR_RIGHTS, NULL, NULL, 4), ST(0xC00000F3));
    CHECK(s == NULL);
    /* shadow directory handle: a valid directory works, a bogus handle is rejected */
    EXPECT_EQ(UN(NtCreateDirectoryObject)(&sh, DIR_RIGHTS, NULL), ST_SUCCESS);
    EXPECT_EQ(UN(NtCreateDirectoryObjectEx)(&s, DIR_RIGHTS, NULL, sh, 0), ST_SUCCESS);
    CLOSE(s);
    EXPECT_EQ(UN(NtCreateDirectoryObjectEx)(&s, DIR_RIGHTS, NULL, (HANDLE)(ULONG_PTR)0x1234, 0), ST_INV_HANDLE);
    CHECK(s == NULL);
    CLOSE(sh);
}

/* ---- symbolic links ---------------------------------------------------- */

TEST(symlink_create_open_query)
{
    HANDLE l = NULL, l2 = NULL; WCHAR nm[96], tgt[] = L"\\BaseNamedObjects"; OBJECT_ATTRIBUTES oa; UNICODE_STRING t; WCHAR out[128]; UNICODE_STRING q; ULONG need = 0;
    REQUIRE(UN(NtCreateSymbolicLinkObject)); REQUIRE(UN(NtOpenSymbolicLinkObject)); REQUIRE(UN(NtQuerySymbolicLinkObject)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_sym"); oa_init(&oa, nm, OBJ_CI);
    t.Buffer = tgt; t.Length = sizeof tgt - 2; t.MaximumLength = sizeof tgt;
    EXPECT_EQ(UN(NtCreateSymbolicLinkObject)(&l, 0x20001 /* READ_CONTROL|QUERY */, &oa, &t), ST_SUCCESS);
    CHECK(l != NULL);
    HANDLE d = NULL;
    EXPECT_EQ(UN(NtCreateSymbolicLinkObject)(&d, 0x20001, &oa, &t), ST_NAME_COLLISION);
    CHECK(d == NULL);
    EXPECT_EQ(UN(NtOpenSymbolicLinkObject)(&l2, 1, &oa), ST_SUCCESS);
    if (l2) {
        q.Buffer = out; q.Length = 0; q.MaximumLength = sizeof out; need = 0;
        EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(l2, &q, &need), ST_SUCCESS);
        EXPECT_EQ(q.Length, sizeof tgt - 2);
        CHECK(q.Length == sizeof tgt - 2 && !memcmp(out, tgt, q.Length));
        q.MaximumLength = 8; need = 0;
        EXPECT_EQ(UN(NtQuerySymbolicLinkObject)(l2, &q, &need), ST(0xC0000023) /* BUFFER_TOO_SMALL */);
        EXPECT_EQ(need, sizeof tgt);
    }
    CLOSE(l2); CLOSE(l);
    /* temporary link: gone once its last handle is closed */
    EXPECT_EQ(UN(NtOpenSymbolicLinkObject)(&l2, 1, &oa), ST_NAME_NOT_FOUND);
    CHECK(l2 == NULL);
}

TEST(symlink_invalid_arguments)
{
    HANDLE l = NULL; WCHAR nm[96], tgt[] = L"\\BaseNamedObjects"; OBJECT_ATTRIBUTES oa; UNICODE_STRING t;
    REQUIRE(UN(NtCreateSymbolicLinkObject)); REQUIRE(UN(NtOpenSymbolicLinkObject)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_sym2"); oa_init(&oa, nm, OBJ_CI);
    t.Buffer = tgt; t.Length = sizeof tgt - 2; t.MaximumLength = sizeof tgt;
    EXPECT_EQ(UN(NtCreateSymbolicLinkObject)(&l, 0x20001, &oa, NULL), ST_ACCESS_VIOLATION);
    CHECK(l == NULL);
    EXPECT_EQ(UN(NtOpenSymbolicLinkObject)(&l, 1, &oa), ST_NAME_NOT_FOUND);
    CHECK(l == NULL);
}

/* ---- keyed events ------------------------------------------------------ */

TEST(keyed_event_create_open_access)
{
    HANDLE k = NULL, o = NULL; WCHAR nm[96]; OBJECT_ATTRIBUTES oa;
    REQUIRE(UN(NtCreateKeyedEvent)); REQUIRE(UN(NtOpenKeyedEvent)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_ke"); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreateKeyedEvent)(&k, 0x1F0003, &oa, 0), ST_SUCCESS);
    CHECK(k != NULL);
    EXPECT_EQ(UN(NtOpenKeyedEvent)(&o, 3 /* WAIT|WAKE */, &oa), ST_SUCCESS); CLOSE(o);
    EXPECT_EQ(UN(NtOpenKeyedEvent)(&o, 1, &oa), ST_SUCCESS); CLOSE(o);
    EXPECT_EQ(UN(NtOpenKeyedEvent)(&o, 0x02000000 /* MAXIMUM_ALLOWED */, &oa), ST_SUCCESS); CLOSE(o);
    /* only WAIT/WAKE and the standard rights that do not include SYNCHRONIZE are grantable */
    EXPECT_EQ(UN(NtOpenKeyedEvent)(&o, 0x100000 /* SYNCHRONIZE */, &oa), ST_ACCESS_DENIED);
    CHECK(o == NULL);
    CLOSE(k);
    EXPECT_EQ(UN(NtOpenKeyedEvent)(&o, 3, &oa), ST_NAME_NOT_FOUND);
    CHECK(o == NULL);
}

TEST(keyed_event_flags_validation)
{
    HANDLE k = NULL; REQUIRE(UN(NtCreateKeyedEvent)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateKeyedEvent)(&k, 0x1F0003, NULL, 0), ST_SUCCESS); CLOSE(k);
    EXPECT_EQ(UN(NtCreateKeyedEvent)(&k, 0x1F0003, NULL, 1), ST_PARAM4);
    EXPECT_EQ(UN(NtCreateKeyedEvent)(&k, 0x1F0003, NULL, 0x80000000u), ST_PARAM4);
    CHECK(k == NULL);
}

/* ---- job objects ------------------------------------------------------- */

TEST(job_create_open_shares_state)
{
    HANDLE j = NULL, j2 = NULL; WCHAR nm[96]; OBJECT_ATTRIBUTES oa;
    REQUIRE(UN(NtCreateJobObject)); REQUIRE(UN(NtOpenJobObject)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_job"); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreateJobObject)(&j, JOB_OBJECT_ALL_ACCESS, &oa), ST_SUCCESS);
    CHECK(j != NULL);
    EXPECT_EQ(UN(NtCreateJobObject)(&j2, JOB_OBJECT_ALL_ACCESS, &oa), ST_NAME_COLLISION);
    CHECK(j2 == NULL);
    EXPECT_EQ(UN(NtOpenJobObject)(&j2, JOB_OBJECT_ALL_ACCESS, &oa), ST_SUCCESS);
    if (j && j2) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION in, out; DWORD ret = 0;
        memset(&in, 0, sizeof in);
        in.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        in.BasicLimitInformation.ActiveProcessLimit = 7;
        CHECK(SetInformationJobObject(j, JobObjectExtendedLimitInformation, &in, sizeof in));
        memset(&out, 0, sizeof out);
        CHECK(QueryInformationJobObject(j2, JobObjectExtendedLimitInformation, &out, sizeof out, &ret));
        EXPECT_EQ(out.BasicLimitInformation.ActiveProcessLimit, 7);
        EXPECT_EQ(out.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_ACTIVE_PROCESS);
    }
    CLOSE(j2); CLOSE(j);
    EXPECT_EQ(UN(NtOpenJobObject)(&j2, JOB_OBJECT_ALL_ACCESS, &oa), ST_NAME_NOT_FOUND);
    CHECK(j2 == NULL);
}

TEST(job_set_is_not_supported)
{
    HANDLE j = NULL; struct { HANDLE job; ULONG level, flags; } set[1];
    REQUIRE(UN(NtCreateJobSet)); REQUIRE(UN(NtCreateJobObject)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateJobObject)(&j, JOB_OBJECT_ALL_ACCESS, NULL), ST_SUCCESS);
    set[0].job = j; set[0].level = 0; set[0].flags = 0;
    EXPECT_EQ(UN(NtCreateJobSet)(1, set, 0), ST_NOT_SUPP);
    EXPECT_EQ(UN(NtCreateJobSet)(0, set, 0), ST_NOT_SUPP);
    EXPECT_EQ(UN(NtCreateJobSet)(1, NULL, 0), ST_NOT_SUPP);
    set[0].job = (HANDLE)(ULONG_PTR)0x1234;
    EXPECT_EQ(UN(NtCreateJobSet)(1, set, 0), ST_NOT_SUPP);
    CLOSE(j);
}

/* ---- sections ---------------------------------------------------------- */

TEST(section_ex_create_open_map)
{
    HANDLE s = NULL, s2 = NULL; WCHAR nm[96]; OBJECT_ATTRIBUTES oa; LARGE_INTEGER sz; BYTE *v1, *v2;
    REQUIRE(UN(NtCreateSectionEx)); REQUIRE(UN(NtOpenSection)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_sec"); oa_init(&oa, nm, OBJ_CI);
    sz.QuadPart = 0x2000;
    EXPECT_EQ(UN(NtCreateSectionEx)(&s, SECTION_ALL_ACCESS, &oa, &sz, PAGE_READWRITE, SEC_COMMIT, NULL, NULL, 0), ST_SUCCESS);
    CHECK(s != NULL);
    EXPECT_EQ(UN(NtCreateSectionEx)(&s2, SECTION_ALL_ACCESS, &oa, &sz, PAGE_READWRITE, SEC_COMMIT, NULL, NULL, 0), ST_NAME_COLLISION);
    CHECK(s2 == NULL);
    EXPECT_EQ(UN(NtOpenSection)(&s2, SECTION_MAP_READ | SECTION_MAP_WRITE, &oa), ST_SUCCESS);
    if (s && s2) {
        v1 = MapViewOfFile(s, FILE_MAP_WRITE, 0, 0, 0x2000);
        v2 = MapViewOfFile(s2, FILE_MAP_READ, 0, 0, 0x2000);
        CHECK(v1 != NULL && v2 != NULL);
        if (v1 && v2) {
            EXPECT_EQ(v1[0], 0); EXPECT_EQ(v1[0x1fff], 0); /* committed pages are zero */
            memcpy(v1 + 0x1000, "section ex", 10);
            CHECK(!memcmp(v2 + 0x1000, "section ex", 10)); /* both handles name the same section */
        }
        if (v1) UnmapViewOfFile(v1);
        if (v2) UnmapViewOfFile(v2);
        /* size is page-rounded and reported by NtQuerySection */
        if (UN(NtQuerySection)) {
            struct { PVOID base; ULONG attr; LARGE_INTEGER size; } bi; SIZE_T ret = 0;
            memset(&bi, 0, sizeof bi);
            EXPECT_EQ(UN(NtQuerySection)(s, 0, &bi, sizeof bi, &ret), ST_SUCCESS);
            EXPECT_EQ(bi.size.QuadPart, 0x2000);
        }
    }
    CLOSE(s2); CLOSE(s);
    EXPECT_EQ(UN(NtOpenSection)(&s2, SECTION_MAP_READ, &oa), ST_NAME_NOT_FOUND);
    CHECK(s2 == NULL);
}

TEST(section_ex_invalid_arguments)
{
    HANDLE s = NULL; LARGE_INTEGER sz; REQUIRE(UN(NtCreateSectionEx)); REQUIRE(UN(NtClose));
    sz.QuadPart = 0x1000;
    /* no maximum size and no file */
    EXPECT_EQ(UN(NtCreateSectionEx)(&s, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READWRITE, SEC_COMMIT, NULL, NULL, 0), ST_PARAM4);
    sz.QuadPart = 0;
    EXPECT_EQ(UN(NtCreateSectionEx)(&s, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT, NULL, NULL, 0), ST_PARAM4);
    sz.QuadPart = 0x1000;
    /* bogus page protection */
    EXPECT_EQ(UN(NtCreateSectionEx)(&s, SECTION_ALL_ACCESS, NULL, &sz, 0x1234, SEC_COMMIT, NULL, NULL, 0), ST(0xC0000045));
    /* allocation attributes must name a backing: none given */
    EXPECT_EQ(UN(NtCreateSectionEx)(&s, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, 0, NULL, NULL, 0), ST(0xC00000F4));
    /* extended-parameter count without a pointer */
    EXPECT_EQ(UN(NtCreateSectionEx)(&s, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT, NULL, NULL, 1), ST_INVALID_PARAMETER);
    /* bogus file handle */
    EXPECT_EQ(UN(NtCreateSectionEx)(&s, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_COMMIT, (HANDLE)(ULONG_PTR)0x1234, NULL, 0), ST_INV_HANDLE);
    CHECK(s == NULL);
    /* SEC_RESERVE and executable page-file sections are fine */
    EXPECT_EQ(UN(NtCreateSectionEx)(&s, SECTION_ALL_ACCESS, NULL, &sz, PAGE_READWRITE, SEC_RESERVE, NULL, NULL, 0), ST_SUCCESS); CLOSE(s);
    EXPECT_EQ(UN(NtCreateSectionEx)(&s, SECTION_ALL_ACCESS, NULL, &sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL, NULL, 0), ST_SUCCESS); CLOSE(s);
}

/* ---- timers ------------------------------------------------------------ */

TEST(timer2_attribute_validation)
{
    HANDLE h = NULL; WCHAR tn[64]; REQUIRE(UN(NtCreateTimer2)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateTimer2)(&h, NULL, NULL, 0, TIMER_ALL_ACCESS), ST_SUCCESS);
    CHECK(h != NULL);
    if (h && type_name(h, tn, 64)) CHECKF(!lstrcmpW(tn, L"IRTimer"), "type %ls", tn);
    CLOSE(h);
    EXPECT_EQ(UN(NtCreateTimer2)(&h, NULL, NULL, 4, TIMER_ALL_ACCESS), ST_SUCCESS); CLOSE(h);
    EXPECT_EQ(UN(NtCreateTimer2)(&h, NULL, NULL, 8, TIMER_ALL_ACCESS), ST_SUCCESS); CLOSE(h);
    /* attribute bits 1, 0x10, 0x20, 0x40, 0x80, 0x100 and combinations are not valid */
    ULONG bad[] = {1, 3, 12, 0x10, 0x20, 0x40, 0x80, 0x100};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        EXPECT_EQ(UN(NtCreateTimer2)(&h, NULL, NULL, bad[i], TIMER_ALL_ACCESS), ST_PARAM4);
        CHECK(h == NULL);
    }
}

TEST(timer2_other_argument_validation)
{
    HANDLE h = NULL; OBJECT_ATTRIBUTES oa; REQUIRE(UN(NtCreateTimer2)); REQUIRE(UN(NtClose));
    oa_init(&oa, L"\\BaseNamedObjects\\oa_t2_never", 0);
    /* a Timer2 cannot be named: the third parameter must be NULL */
    EXPECT_EQ(UN(NtCreateTimer2)(&h, NULL, &oa, 0, TIMER_ALL_ACCESS), ST(0xC00000F1));
    /* the second parameter is only for IR timers (attribute bit 2) */
    EXPECT_EQ(UN(NtCreateTimer2)(&h, (PVOID)(ULONG_PTR)1, NULL, 0, TIMER_ALL_ACCESS), ST(0xC00000F0));
    CHECK(h == NULL);
    EXPECT_EQ(UN(NtCreateTimer2)(NULL, NULL, NULL, 0, TIMER_ALL_ACCESS), ST_ACCESS_VIOLATION);
    EXPECT_EQ(UN(NtCreateTimer2)(&h, NULL, NULL, 0, 0), ST_SUCCESS); /* access 0 is a valid (useless) handle */
    CLOSE(h);
}

TEST(ir_timer_rejects_unprivileged_or_invalid_use)
{
    HANDLE h = NULL; ULONG v = 0; REQUIRE(UN(NtCreateIRTimer)); REQUIRE(UN(NtClose));
    NTSTATUS st = UN(NtCreateIRTimer)(&h, NULL, TIMER_ALL_ACCESS);
    EXPECT_EQ(st, ST_INVALID_PARAMETER);
    CHECK(h == NULL);
    v = 1;
    st = UN(NtCreateIRTimer)(&h, &v, TIMER_ALL_ACCESS);
    EXPECT_EQ(st, ST_ACCESS_DENIED);
    CHECK(h == NULL);
}

/* ---- debug objects ----------------------------------------------------- */

TEST(debug_object_create_flags_and_names)
{
    HANDLE d = NULL, d2 = NULL; WCHAR nm[96], tn[64]; OBJECT_ATTRIBUTES oa; REQUIRE(UN(NtCreateDebugObject)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_dbg"); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreateDebugObject)(&d, 0x1F000F, &oa, 0), ST_SUCCESS);
    CHECK(d != NULL);
    if (d && type_name(d, tn, 64)) CHECKF(!lstrcmpW(tn, L"DebugObject"), "type %ls", tn);
    EXPECT_EQ(UN(NtCreateDebugObject)(&d2, 0x1F000F, &oa, 0), ST_NAME_COLLISION);
    CHECK(d2 == NULL);
    CLOSE(d);
    EXPECT_EQ(UN(NtCreateDebugObject)(&d, 0x1F000F, NULL, 0), ST_SUCCESS); CLOSE(d);
    EXPECT_EQ(UN(NtCreateDebugObject)(&d, 0x1F000F, NULL, 1 /* kill-on-close */), ST_SUCCESS); CLOSE(d);
    EXPECT_EQ(UN(NtCreateDebugObject)(&d, 0x1F000F, NULL, 2), ST_INVALID_PARAMETER);
    CHECK(d == NULL);
}

/* ---- LPC ports --------------------------------------------------------- */

TEST(port_create_variants)
{
    HANDLE p = NULL, p2 = NULL; WCHAR nm[96], tn[64]; OBJECT_ATTRIBUTES oa; REQUIRE(UN(NtCreatePort)); REQUIRE(UN(NtCreateWaitablePort)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_port"); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreatePort)(&p, &oa, 0, 0x100, 0), ST_SUCCESS);
    CHECK(p != NULL);
    if (p && type_name(p, tn, 64)) CHECKF(!lstrcmpW(tn, L"ALPC Port"), "type %ls", tn);
    EXPECT_EQ(UN(NtCreatePort)(&p2, &oa, 0, 0x100, 0), ST_NAME_COLLISION);
    CHECK(p2 == NULL);
    CLOSE(p);
    EXPECT_EQ(UN(NtCreatePort)(&p, NULL, 0, 0x100, 0), ST_SUCCESS); CLOSE(p);
    /* message length above the LPC maximum */
    EXPECT_EQ(UN(NtCreatePort)(&p, NULL, 0, 0x10000, 0), ST_INVALID_PARAMETER);
    CHECK(p == NULL);
    bno_name(nm, L"oa_wport"); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreateWaitablePort)(&p, &oa, 0, 0x100, 0), ST_SUCCESS);
    CHECK(p != NULL);
    if (p && type_name(p, tn, 64)) CHECKF(!lstrcmpW(tn, L"ALPC Port"), "type %ls", tn);
    CLOSE(p);
    EXPECT_EQ(UN(NtCreateWaitablePort)(&p, NULL, 0, 0x10000, 0), ST_INVALID_PARAMETER);
}

/* ---- private namespaces ------------------------------------------------ */

TEST(private_namespace_create_open_delete)
{
    PVOID bd; BYTE sid[12] = {1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}; /* S-1-1-0 */
    HANDLE ns = NULL, o = NULL, ns2 = NULL; WCHAR nm[64]; NTSTATUS st;
    REQUIRE(UN(NtCreatePrivateNamespace)); REQUIRE(UN(NtOpenPrivateNamespace)); REQUIRE(UN(NtDeletePrivateNamespace)); REQUIRE(UN(RtlCreateBoundaryDescriptor));
    REQUIRE(UN(RtlAddSIDToBoundaryDescriptor)); REQUIRE(UN(RtlDeleteBoundaryDescriptor)); REQUIRE(UN(NtClose));
    wsprintfW(nm, L"oa_boundary_%lu_%u", GetCurrentProcessId(), ++g_serial);
    bd = UN(RtlCreateBoundaryDescriptor)(oa_us(nm), 0);
    CHECK(bd != NULL); if (!bd) return;
    EXPECT_EQ(UN(RtlAddSIDToBoundaryDescriptor)(&bd, sid), ST_SUCCESS);
    /* the namespace is identified by the boundary descriptor, not by an object name */
    st = UN(NtCreatePrivateNamespace)(&ns, 0xF0001, NULL, bd);
    if (st == ST_ACCESS_DENIED || st == ST(0xC0000061)) { t_skip("private namespaces cannot be created by this account (%08lx)", (unsigned long)st); UN(RtlDeleteBoundaryDescriptor)(bd); return; }
    EXPECT_EQ(st, ST_SUCCESS);
    CHECK(ns != NULL);
    if (st >= 0) {
        EXPECT_EQ(UN(NtOpenPrivateNamespace)(&o, 0xF0001, NULL, bd), ST_SUCCESS);
        CHECK(o != NULL && o != ns);
        CLOSE(o);
        st = UN(NtCreatePrivateNamespace)(&ns2, 0xF0001, NULL, bd);
        EXPECT_EQ(st, ST_NAME_COLLISION);
        CLOSE(ns2);
        EXPECT_EQ(UN(NtDeletePrivateNamespace)(ns), ST_SUCCESS);
    }
    CLOSE(ns);
    EXPECT_EQ(UN(NtOpenPrivateNamespace)(&o, 0xF0001, NULL, bd), ST(0xC000003A));
    CHECK(o == NULL);
    /* an object name is rejected (a name needs a root directory that this call does not accept here) */
    { OBJECT_ATTRIBUTES oa; oa_init(&oa, L"oa_unrooted_name", 0);
      EXPECT_EQ(UN(NtCreatePrivateNamespace)(&ns, 0xF0001, &oa, bd), ST(0xC0000033)); CHECK(ns == NULL); }
    /* a buffer that is not a boundary descriptor */
    { BYTE junk[64] = {0}; EXPECT_EQ(UN(NtCreatePrivateNamespace)(&ns, 0xF0001, NULL, junk), ST_INVALID_PARAMETER); }
    EXPECT_EQ(UN(NtCreatePrivateNamespace)(&ns, 0xF0001, NULL, NULL), ST_ACCESS_VIOLATION);
    CHECK(ns == NULL);
    UN(RtlDeleteBoundaryDescriptor)(bd);
}

TEST(event_pair_is_not_implemented)
{
    HANDLE h = NULL; WCHAR nm[96]; OBJECT_ATTRIBUTES oa; REQUIRE(UN(NtCreateEventPair)); REQUIRE(UN(NtOpenEventPair));
    bno_name(nm, L"oa_ep"); oa_init(&oa, nm, OBJ_CI);
    EXPECT_EQ(UN(NtCreateEventPair)(&h, 0x1F0003, &oa), ST_NOT_IMPL);
    EXPECT_EQ(UN(NtCreateEventPair)(&h, 0x1F0003, NULL), ST_NOT_IMPL);
    EXPECT_EQ(UN(NtOpenEventPair)(&h, 0x100000, &oa), ST_NOT_IMPL);
    CHECK(h == NULL);
}

TEST(open_missing_null_and_type_mismatch)
{
    HANDLE h = NULL, ev = NULL; OBJECT_ATTRIBUTES oa; WCHAR nm[96];
    REQUIRE(UN(NtOpenSection)); REQUIRE(UN(NtOpenJobObject)); REQUIRE(UN(NtOpenDirectoryObject)); REQUIRE(UN(NtOpenSymbolicLinkObject));
    REQUIRE(UN(NtOpenKeyedEvent)); REQUIRE(UN(NtCreateEvent)); REQUIRE(UN(NtClose));
    bno_name(nm, L"oa_openerr"); oa_init(&oa, nm, OBJ_CI);
    /* nothing of that name exists */
    EXPECT_EQ(UN(NtOpenSection)(&h, SECTION_MAP_READ, &oa), ST_NAME_NOT_FOUND);
    EXPECT_EQ(UN(NtOpenJobObject)(&h, JOB_OBJECT_ALL_ACCESS, &oa), ST_NAME_NOT_FOUND);
    /* the name is mandatory */
    EXPECT_EQ(UN(NtOpenSection)(&h, SECTION_MAP_READ, NULL), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtOpenJobObject)(&h, JOB_OBJECT_ALL_ACCESS, NULL), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtOpenDirectoryObject)(&h, 1, NULL), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtOpenSymbolicLinkObject)(&h, 1, NULL), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtOpenKeyedEvent)(&h, 3, NULL), ST_INVALID_PARAMETER);
    CHECK(h == NULL);
    /* an existing object of another type */
    EXPECT_EQ(UN(NtCreateEvent)(&ev, EVENT_ALL_ACCESS, &oa, 1, FALSE), ST_SUCCESS);
    if (ev) {
        EXPECT_EQ(UN(NtOpenSection)(&h, SECTION_MAP_READ, &oa), ST(0xC0000024));
        EXPECT_EQ(UN(NtOpenJobObject)(&h, JOB_OBJECT_ALL_ACCESS, &oa), ST(0xC0000024));
        EXPECT_EQ(UN(NtOpenDirectoryObject)(&h, 1, &oa), ST(0xC0000024));
        EXPECT_EQ(UN(NtOpenSymbolicLinkObject)(&h, 1, &oa), ST(0xC0000024));
        EXPECT_EQ(UN(NtOpenKeyedEvent)(&h, 3, &oa), ST(0xC0000024));
        CHECK(h == NULL);
    }
    CLOSE(ev);
}

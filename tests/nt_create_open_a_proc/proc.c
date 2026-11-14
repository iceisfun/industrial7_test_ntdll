/* Process, thread and token creation/opening: NtCreateProcess, NtCreateProcessEx, NtCreateThread,
 * NtCreateThreadEx, NtCreateUserProcess, NtOpenProcessTokenEx, NtOpenThreadTokenEx.
 * Expectations were observed on Windows 10 22H2 (see EVIDENCE.md). */
#include "oa.h"

/* ---- NtCreateProcess / NtCreateProcessEx -------------------------------- */

static void reap_process(HANDLE p, NTSTATUS code)
{
    if (!p) return;
    UN(NtTerminateProcess)(p, code);
}

TEST(process_create_no_section_object)
{
    HANDLE p = NULL; pbi_t pbi; ULONG ret = 0; DWORD ec = 0;
    REQUIRE(UN(NtCreateProcess)); REQUIRE(UN(NtQueryInformationProcess)); REQUIRE(UN(NtTerminateProcess)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateProcess)(&p, PROCESS_ALL_ACCESS, NULL, NT_CUR_PROC, FALSE, NULL, NULL, NULL), ST_SUCCESS);
    CHECK(p != NULL);
    if (p) {
        memset(&pbi, 0, sizeof pbi);
        EXPECT_EQ(UN(NtQueryInformationProcess)(p, 0, &pbi, sizeof pbi, &ret), ST_SUCCESS);
        EXPECT_EQ(pbi.parent, GetCurrentProcessId());
        CHECK(pbi.pid != 0 && pbi.pid != GetCurrentProcessId());
        EXPECT_EQ(GetProcessId(p), pbi.pid);
        EXPECT_EQ(pbi.exit, 0x103 /* STILL_ACTIVE */);
        { NTSTATUS tst = UN(NtTerminateProcess)(p, 0x55); CHECK(tst >= 0); t_note("terminate of an empty process -> %08lx", (unsigned long)tst); }
    }
    CLOSE(p);
}

TEST(process_ex_create_variants)
{
    HANDLE p = NULL; pbi_t pbi; ULONG ret = 0;
    REQUIRE(UN(NtCreateProcessEx)); REQUIRE(UN(NtQueryInformationProcess)); REQUIRE(UN(NtTerminateProcess)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateProcessEx)(&p, PROCESS_ALL_ACCESS, NULL, NT_CUR_PROC, 0, NULL, NULL, NULL, 0), ST_SUCCESS);
    if (p) { memset(&pbi, 0, sizeof pbi); UN(NtQueryInformationProcess)(p, 0, &pbi, sizeof pbi, &ret); EXPECT_EQ(pbi.parent, GetCurrentProcessId()); }
    reap_process(p, 0); CLOSE(p);
    /* PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT (4) */
    EXPECT_EQ(UN(NtCreateProcessEx)(&p, PROCESS_ALL_ACCESS, NULL, NT_CUR_PROC, 4, NULL, NULL, NULL, 0), ST_SUCCESS);
    reap_process(p, 0); CLOSE(p);
}

TEST(process_create_invalid_arguments)
{
    HANDLE p = NULL; REQUIRE(UN(NtCreateProcess)); REQUIRE(UN(NtCreateProcessEx)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateProcess)(&p, PROCESS_ALL_ACCESS, NULL, (HANDLE)(ULONG_PTR)0x1234, FALSE, NULL, NULL, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCreateProcess)(&p, PROCESS_ALL_ACCESS, NULL, NULL, FALSE, NULL, NULL, NULL), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateProcessEx)(&p, PROCESS_ALL_ACCESS, NULL, (HANDLE)(ULONG_PTR)0x1234, 0, NULL, NULL, NULL, 0), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCreateProcessEx)(&p, PROCESS_ALL_ACCESS, NULL, NULL, 0, NULL, NULL, NULL, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateProcessEx)(&p, PROCESS_ALL_ACCESS, NULL, NT_CUR_PROC, 0x80000000u, NULL, NULL, NULL, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateProcessEx)(&p, 0, NULL, NT_CUR_PROC, 0, NULL, NULL, NULL, 0), ST_ACCESS_DENIED);
    EXPECT_EQ(UN(NtCreateProcessEx)(&p, PROCESS_ALL_ACCESS, NULL, NT_CUR_PROC, 0, (HANDLE)(ULONG_PTR)0x1234, NULL, NULL, 0), ST_INV_HANDLE);
    CHECK(p == NULL);
}

/* ---- NtCreateThreadEx --------------------------------------------------- */

static DWORD WINAPI ret_arg(LPVOID a) { return (DWORD)(ULONG_PTR)a + 1; }

TEST(thread_ex_runs_start_routine)
{
    HANDLE t = NULL; DWORD ec = 0; CLIENT_ID cid; ULONG ret = 0;
    REQUIRE(UN(NtCreateThreadEx)); REQUIRE(UN(NtQueryInformationThread)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateThreadEx)(&t, THREAD_ALL_ACCESS, NULL, NT_CUR_PROC, (PVOID)ret_arg, (PVOID)(ULONG_PTR)41, 0, 0, 0, 0, NULL), ST_SUCCESS);
    CHECK(t != NULL);
    if (t) {
        EXPECT_EQ(WaitForSingleObject(t, 10000), WAIT_OBJECT_0);
        CHECK(GetExitCodeThread(t, &ec)); EXPECT_EQ(ec, 42);
        CHECK(GetThreadId(t) != 0 && GetThreadId(t) != GetCurrentThreadId());
    }
    CLOSE(t);
}

TEST(thread_ex_create_suspended)
{
    HANDLE t = NULL; DWORD ec = 0; REQUIRE(UN(NtCreateThreadEx)); REQUIRE(UN(NtResumeThread)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateThreadEx)(&t, THREAD_ALL_ACCESS, NULL, NT_CUR_PROC, (PVOID)ret_arg, (PVOID)(ULONG_PTR)6, 1 /* CREATE_SUSPENDED */, 0, 0, 0, NULL), ST_SUCCESS);
    if (t) {
        EXPECT_EQ(WaitForSingleObject(t, 100), WAIT_TIMEOUT);
        ULONG prev = 99;
        EXPECT_EQ(UN(NtResumeThread)(t, &prev), ST_SUCCESS);
        EXPECT_EQ(prev, 1);
        EXPECT_EQ(WaitForSingleObject(t, 10000), WAIT_OBJECT_0);
        CHECK(GetExitCodeThread(t, &ec)); EXPECT_EQ(ec, 7);
    }
    CLOSE(t);
}

TEST(thread_ex_invalid_arguments)
{
    HANDLE t = NULL; REQUIRE(UN(NtCreateThreadEx)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtCreateThreadEx)(&t, THREAD_ALL_ACCESS, NULL, (HANDLE)(ULONG_PTR)0x1234, (PVOID)ret_arg, NULL, 0, 0, 0, 0, NULL), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtCreateThreadEx)(&t, THREAD_ALL_ACCESS, NULL, NT_CUR_PROC, (PVOID)ret_arg, NULL, 0x80000000u, 0, 0, 0, NULL), ST(0xC00000F5));
    EXPECT_EQ(UN(NtCreateThreadEx)(&t, THREAD_ALL_ACCESS, NULL, NT_CUR_PROC, (PVOID)ret_arg, NULL, 1, 0, 0, 0x7FFFFFFFFFFFull, NULL), ST_INVALID_PARAMETER);
    CHECK(t == NULL);
    /* a thread handle is not a process handle */
    EXPECT_EQ(UN(NtCreateThreadEx)(&t, THREAD_ALL_ACCESS, NULL, NT_CUR_THREAD, (PVOID)ret_arg, NULL, 0, 0, 0, 0, NULL), ST_TYPE_MISMATCH);
    CHECK(t == NULL);
}

/* ---- NtCreateThread (legacy, caller supplies stack and context) --------- */

TEST(thread_legacy_create_with_context)
{
    HANDLE t = NULL; CLIENT_ID cid; PVOID stack; struct { PVOID old_base, old_limit, base, limit, alloc_base; } teb;
    CONTEXT *ctx; DWORD ec = 0; BYTE ctxbuf[sizeof(CONTEXT) + 16];
    REQUIRE(UN(NtCreateThread)); REQUIRE(UN(NtClose));
    stack = VirtualAlloc(NULL, 0x40000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(stack != NULL); if (!stack) return;
    ctx = (CONTEXT *)(((ULONG_PTR)ctxbuf + 15) & ~(ULONG_PTR)15);
    memset(ctx, 0, sizeof *ctx);
    ctx->ContextFlags = CONTEXT_FULL;
    ctx->SegCs = 0x33; ctx->SegSs = 0x2b; ctx->EFlags = 0x200; ctx->MxCsr = 0x1f80;
    ctx->Rip = (DWORD64)(ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
    ctx->Rcx = 0x2A;
    ctx->Rsp = (DWORD64)((ULONG_PTR)stack + 0x40000 - 0x100);
    memset(&teb, 0, sizeof teb);
    teb.base = (BYTE *)stack + 0x40000; teb.limit = stack; teb.alloc_base = stack;
    memset(&cid, 0, sizeof cid);
    NTSTATUS st = UN(NtCreateThread)(&t, THREAD_ALL_ACCESS, NULL, NT_CUR_PROC, &cid, ctx, &teb, FALSE);
    EXPECT_EQ(st, ST_SUCCESS);
    if (st >= 0) {
        CHECK(cid.UniqueThread != 0);
        EXPECT_EQ((ULONG_PTR)cid.UniqueProcess, GetCurrentProcessId());
        EXPECT_EQ(WaitForSingleObject(t, 10000), WAIT_OBJECT_0);
        CHECK(GetExitCodeThread(t, &ec)); EXPECT_EQ(ec, 0x2A);
        EXPECT_EQ(GetThreadId(t), (ULONG_PTR)cid.UniqueThread);
    }
    CLOSE(t);
    VirtualFree(stack, 0, MEM_RELEASE);
}

TEST(thread_legacy_invalid_arguments)
{
    HANDLE t = NULL; CLIENT_ID cid; CONTEXT ctx; struct { PVOID a, b, c, d, e; } teb; PVOID stack;
    REQUIRE(UN(NtCreateThread)); REQUIRE(UN(NtClose));
    memset(&ctx, 0, sizeof ctx); memset(&teb, 0, sizeof teb);
    stack = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    teb.c = (BYTE *)stack + 0x10000; teb.d = stack; teb.e = stack;
    /* no context */
    EXPECT_EQ(UN(NtCreateThread)(&t, THREAD_ALL_ACCESS, NULL, NT_CUR_PROC, &cid, NULL, &teb, TRUE), ST_INVALID_PARAMETER);
    /* no initial TEB: the service faults and reports an access violation */
    EXPECT_EQ(UN(NtCreateThread)(&t, THREAD_ALL_ACCESS, NULL, NT_CUR_PROC, &cid, &ctx, NULL, TRUE), ST_ACCESS_VIOLATION);
    /* the CLIENT_ID output is optional */
    EXPECT_EQ(UN(NtCreateThread)(&t, THREAD_ALL_ACCESS, NULL, NT_CUR_PROC, NULL, &ctx, &teb, TRUE), ST_SUCCESS);
    CHECK(t != NULL);
    if (t) { UN(NtTerminateThread)(t, 0); CLOSE(t); }
    if (stack) VirtualFree(stack, 0, MEM_RELEASE);
}

/* ---- tokens ------------------------------------------------------------- */

TEST(open_process_token_ex_basic)
{
    HANDLE a = NULL, b = NULL; LUID ia, ib; REQUIRE(UN(NtOpenProcessTokenEx)); REQUIRE(UN(NtQueryInformationToken)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtOpenProcessTokenEx)(NT_CUR_PROC, TOKEN_QUERY, 0, &a), ST_SUCCESS);
    EXPECT_EQ(UN(NtOpenProcessTokenEx)(NT_CUR_PROC, TOKEN_QUERY | TOKEN_DUPLICATE, 0, &b), ST_SUCCESS);
    CHECK(a != NULL && b != NULL && a != b);
    if (a && b) {
        CHECK(token_id(a, &ia) && token_id(b, &ib));
        CHECK(ia.LowPart == ib.LowPart && ia.HighPart == ib.HighPart);
    }
    CLOSE(a); CLOSE(b);
}

TEST(open_process_token_ex_handle_attributes)
{
    HANDLE h = NULL; DWORD fl = 0; REQUIRE(UN(NtOpenProcessTokenEx)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtOpenProcessTokenEx)(NT_CUR_PROC, TOKEN_QUERY, 0, &h), ST_SUCCESS);
    if (h) { CHECK(GetHandleInformation(h, &fl)); EXPECT_EQ(fl & HANDLE_FLAG_INHERIT, 0); }
    CLOSE(h);
    EXPECT_EQ(UN(NtOpenProcessTokenEx)(NT_CUR_PROC, TOKEN_QUERY, 2 /* OBJ_INHERIT */, &h), ST_SUCCESS);
    if (h) { CHECK(GetHandleInformation(h, &fl)); EXPECT_EQ(fl & HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT); }
    CLOSE(h);
}

TEST(open_process_token_ex_errors)
{
    HANDLE h = NULL; REQUIRE(UN(NtOpenProcessTokenEx)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtOpenProcessTokenEx)((HANDLE)(ULONG_PTR)0x1234, TOKEN_QUERY, 0, &h), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtOpenProcessTokenEx)(NT_CUR_THREAD, TOKEN_QUERY, 0, &h), ST_TYPE_MISMATCH);
    EXPECT_EQ(UN(NtOpenProcessTokenEx)(NT_CUR_PROC, 0, 0, &h), ST_ACCESS_DENIED);
    CHECK(h == NULL);
}

TEST(open_thread_token_ex_no_token_and_errors)
{
    HANDLE h = NULL; REQUIRE(UN(NtOpenThreadTokenEx)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtOpenThreadTokenEx)(NT_CUR_THREAD, TOKEN_QUERY, FALSE, 0, &h), ST(0xC000007C) /* STATUS_NO_TOKEN */);
    EXPECT_EQ(UN(NtOpenThreadTokenEx)(NT_CUR_THREAD, TOKEN_QUERY, TRUE, 0, &h), ST(0xC000007C));
    EXPECT_EQ(UN(NtOpenThreadTokenEx)((HANDLE)(ULONG_PTR)0x1234, TOKEN_QUERY, TRUE, 0, &h), ST_INV_HANDLE);
    EXPECT_EQ(UN(NtOpenThreadTokenEx)(NT_CUR_PROC, TOKEN_QUERY, TRUE, 0, &h), ST_TYPE_MISMATCH);
    CHECK(h == NULL);
}

TEST(open_thread_token_ex_impersonating)
{
    HANDLE ptok = NULL, imp = NULL, tt = NULL; LUID iid, tid; NTSTATUS st; OBJECT_ATTRIBUTES oa; SECURITY_QUALITY_OF_SERVICE q; HANDLE null_tok = NULL;
    REQUIRE(UN(NtOpenThreadTokenEx)); REQUIRE(UN(NtOpenProcessTokenEx)); REQUIRE(UN(NtDuplicateToken)); REQUIRE(UN(NtSetInformationThread)); REQUIRE(UN(NtClose));
    EXPECT_EQ(UN(NtOpenProcessTokenEx)(NT_CUR_PROC, TOKEN_DUPLICATE | TOKEN_QUERY, 0, &ptok), ST_SUCCESS);
    if (!ptok) return;
    memset(&q, 0, sizeof q); q.Length = sizeof q; q.ImpersonationLevel = SecurityImpersonation; q.EffectiveOnly = FALSE;
    memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.SecurityQualityOfService = &q;
    st = UN(NtDuplicateToken)(ptok, TOKEN_ALL_ACCESS, &oa, FALSE, 2 /* TokenImpersonation */, &imp);
    EXPECT_EQ(st, ST_SUCCESS);
    if (st >= 0) {
        EXPECT_EQ(UN(NtSetInformationThread)(NT_CUR_THREAD, 5 /* ThreadImpersonationToken */, &imp, sizeof imp), ST_SUCCESS);
        EXPECT_EQ(UN(NtOpenThreadTokenEx)(NT_CUR_THREAD, TOKEN_QUERY, TRUE, 0, &tt), ST_SUCCESS);
        if (tt) {
            CHECK(token_id(imp, &iid) && token_id(tt, &tid));
            CHECK(iid.LowPart == tid.LowPart && iid.HighPart == tid.HighPart);
        }
        CLOSE(tt);
        EXPECT_EQ(UN(NtOpenThreadTokenEx)(NT_CUR_THREAD, TOKEN_QUERY, FALSE, 0, &tt), ST_SUCCESS);
        CLOSE(tt);
        /* revert */
        EXPECT_EQ(UN(NtSetInformationThread)(NT_CUR_THREAD, 5, &null_tok, sizeof null_tok), ST_SUCCESS);
        EXPECT_EQ(UN(NtOpenThreadTokenEx)(NT_CUR_THREAD, TOKEN_QUERY, TRUE, 0, &tt), ST(0xC000007C));
    }
    CLOSE(imp); CLOSE(ptok);
}

/* ---- NtCreateUserProcess ------------------------------------------------ */

typedef struct { ULONG_PTR Attribute; SIZE_T Size; ULONG_PTR Value; SIZE_T *ReturnLength; } ps_attr;
typedef struct { SIZE_T TotalLength; ps_attr A[1]; } ps_attr_list;
#define PS_ATTRIBUTE_IMAGE_NAME 0x20005

static const WCHAR k_image_nt[] = L"\\??\\C:\\Windows\\System32\\cmd.exe";
static const WCHAR k_image_win[] = L"C:\\Windows\\System32\\cmd.exe";
static const WCHAR k_cwd[] = L"C:\\Windows\\System32";

static PVOID make_params(const WCHAR *cmdline)
{
    PVOID pp = NULL;
    if (UN(RtlCreateProcessParametersEx)(&pp, oa_us(k_image_win), NULL, oa_us(k_cwd), oa_us(cmdline), NULL, NULL, NULL, NULL, NULL, 1 /* normalized */) < 0) return NULL;
    return pp;
}
static void init_attrs(ps_attr_list *al, const WCHAR *img)
{
    memset(al, 0, sizeof *al);
    al->TotalLength = sizeof(SIZE_T) + sizeof(ps_attr);
    al->A[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    al->A[0].Size = lstrlenW(img) * sizeof(WCHAR);
    al->A[0].Value = (ULONG_PTR)img;
}

TEST(user_process_runs_image_and_returns_handles)
{
    HANDLE hp = NULL, ht = NULL; PVOID pp; BYTE ci[0x58]; ps_attr_list al; DWORD ec = 0; pbi_t pbi; ULONG ret = 0;
    REQUIRE(UN(NtCreateUserProcess)); REQUIRE(UN(RtlCreateProcessParametersEx)); REQUIRE(UN(RtlDestroyProcessParameters)); REQUIRE(UN(NtQueryInformationProcess));
    if (GetFileAttributesW(k_image_win) == INVALID_FILE_ATTRIBUTES) { t_skip("cmd.exe not present"); return; }
    pp = make_params(L"cmd.exe /c exit 7"); CHECK(pp != NULL); if (!pp) return;
    memset(ci, 0, sizeof ci); *(SIZE_T *)ci = sizeof ci;
    init_attrs(&al, k_image_nt);
    NTSTATUS st = UN(NtCreateUserProcess)(&hp, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, pp, ci, &al);
    EXPECT_EQ(st, ST_SUCCESS);
    if (st >= 0) {
        CHECK(hp != NULL && ht != NULL);
        memset(&pbi, 0, sizeof pbi);
        EXPECT_EQ(UN(NtQueryInformationProcess)(hp, 0, &pbi, sizeof pbi, &ret), ST_SUCCESS);
        EXPECT_EQ(pbi.parent, GetCurrentProcessId());
        EXPECT_EQ(GetProcessId(hp), pbi.pid);
        CHECK(GetThreadId(ht) != 0);
        EXPECT_EQ(GetProcessIdOfThread(ht), pbi.pid);
        EXPECT_EQ(WaitForSingleObject(hp, 15000), WAIT_OBJECT_0);
        CHECK(GetExitCodeProcess(hp, &ec)); EXPECT_EQ(ec, 7);
    }
    if (hp && WaitForSingleObject(hp, 0) != WAIT_OBJECT_0) TerminateProcess(hp, 1);
    CLOSE(hp); CLOSE(ht);
    UN(RtlDestroyProcessParameters)(pp);
}

TEST(user_process_invalid_arguments)
{
    HANDLE hp = NULL, ht = NULL; PVOID pp; BYTE ci[0x58], ci_small[0x58]; ps_attr_list al; static const WCHAR missing[] = L"\\??\\C:\\Windows\\System32\\oa_no_such_image.exe";
    REQUIRE(UN(NtCreateUserProcess)); REQUIRE(UN(RtlCreateProcessParametersEx)); REQUIRE(UN(RtlDestroyProcessParameters));
    pp = make_params(L"cmd.exe /c exit 7"); CHECK(pp != NULL); if (!pp) return;
    memset(ci, 0, sizeof ci); *(SIZE_T *)ci = sizeof ci;
    memcpy(ci_small, ci, sizeof ci); *(SIZE_T *)ci_small = 0x50;
    init_attrs(&al, k_image_nt);
    EXPECT_EQ(UN(NtCreateUserProcess)(&hp, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, pp, ci, NULL), ST_INVALID_PARAMETER);    /* no attribute list */
    EXPECT_EQ(UN(NtCreateUserProcess)(&hp, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, NULL, ci, &al), ST_ACCESS_VIOLATION);   /* no parameters */
    EXPECT_EQ(UN(NtCreateUserProcess)(&hp, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, pp, ci_small, &al), ST_INVALID_PARAMETER); /* bad create-info size */
    EXPECT_EQ(UN(NtCreateUserProcess)(&hp, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0x80000000u, 0, pp, ci, &al), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateUserProcess)(&hp, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0x80000000u, pp, ci, &al), ST_INVALID_PARAMETER);
    EXPECT_EQ(UN(NtCreateUserProcess)(NULL, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, pp, ci, &al), ST_ACCESS_VIOLATION);
    EXPECT_EQ(UN(NtCreateUserProcess)(&hp, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, pp, NULL, &al), ST_ACCESS_VIOLATION);
    al.A[0].Size = 0;
    EXPECT_EQ(UN(NtCreateUserProcess)(&hp, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, pp, ci, &al), ST_INVALID_PARAMETER);    /* empty image name */
    init_attrs(&al, missing);
    EXPECT_EQ(UN(NtCreateUserProcess)(&hp, &ht, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, pp, ci, &al), ST_NAME_NOT_FOUND);
    CHECK(hp == NULL && ht == NULL);
    UN(RtlDestroyProcessParameters)(pp);
}

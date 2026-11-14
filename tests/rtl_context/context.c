#include "t.h"
#include <stdlib.h>
#include <xmmintrin.h>

UDECL(VOID, RtlRaiseException, (PEXCEPTION_RECORD));
_Static_assert(sizeof(CONTEXT) == 1232, "Win10 x64 CONTEXT");
_Static_assert(_Alignof(CONTEXT) >= 16, "FXSAVE alignment");
_Static_assert(offsetof(CONTEXT, ContextFlags) == 48, "flags");
_Static_assert(offsetof(CONTEXT, Rsp) == 152, "stack");
_Static_assert(offsetof(CONTEXT, Rip) == 248, "pc");
_Static_assert(offsetof(CONTEXT, FltSave) == 256, "floating state");

static void capture_case(int kind)
{
    struct { BYTE before[16]; CONTEXT c; BYTE after[16]; } box;
    MEMORY_BASIC_INFORMATION stack, here;
    PVOID base = NULL;
    DWORD mxcsr = _mm_getcsr();
    REQUIRE(U(RtlCaptureContext));
    _Static_assert(offsetof(__typeof__(box), c) % 16 == 0, "embedded CONTEXT alignment");
    memset(&box, 0xa5, sizeof(box));
    U(RtlCaptureContext)(&box.c);
    switch (kind) {
    case 0: EXPECT_EQ(box.c.ContextFlags, CONTEXT_FULL | CONTEXT_SEGMENTS); break;
    case 1:
        CHECK(box.c.Rsp != 0);
        EXPECT_EQ(box.c.Rsp & 15, 0);
        break;
    case 2:
        REQUIRE(U(RtlPcToFileHeader));
        EXPECT_EQ(U(RtlPcToFileHeader)((PVOID)box.c.Rip, &base), GetModuleHandleW(NULL));
        EXPECT_EQ(base, GetModuleHandleW(NULL));
        break;
    case 3: EXPECT_EQ(box.c.Rcx, &box.c); break;
    case 4:
        CHECK(box.c.SegCs != 0); CHECK(box.c.SegSs != 0);
        EXPECT_EQ(box.c.SegCs & 3, 3); EXPECT_EQ(box.c.SegSs & 3, 3);
        break;
    case 5:
        EXPECT_EQ(box.c.MxCsr, mxcsr);
        EXPECT_EQ(box.c.FltSave.MxCsr, mxcsr);
        break;
    case 6:
        for (unsigned i = 0; i < 16; i++) {
            EXPECT_EQ(box.before[i], 0xa5); EXPECT_EQ(box.after[i], 0xa5);
        }
        break;
    case 7:
        CHECK(VirtualQuery((PVOID)box.c.Rsp, &stack, sizeof(stack)) == sizeof(stack));
        CHECK(VirtualQuery(&box, &here, sizeof(here)) == sizeof(here));
        if (!VirtualQuery((PVOID)box.c.Rsp, &stack, sizeof(stack)) ||
            !VirtualQuery(&box, &here, sizeof(here))) { t_skip("cannot query stack mapping"); return; }
        EXPECT_EQ(stack.State, MEM_COMMIT);
        EXPECT_EQ(stack.AllocationBase, here.AllocationBase);
        break;
    }
}
TEST(rtl_context_capture_flags) { capture_case(0); }
TEST(rtl_context_capture_stack_alignment) { capture_case(1); }
TEST(rtl_context_capture_return_image) { capture_case(2); }
TEST(rtl_context_capture_argument_register) { capture_case(3); }
TEST(rtl_context_capture_user_segments) { capture_case(4); }
TEST(rtl_context_capture_mxcsr) { capture_case(5); }
TEST(rtl_context_capture_buffer_guards) { capture_case(6); }
TEST(rtl_context_capture_stack_mapping) { capture_case(7); }

/* Real compiler-generated frames only; volatile post-call use prevents a tail
 * call, and recursion makes skip/capture independent of harness stack depth. */
static __attribute__((noinline)) USHORT trace_frames(unsigned depth, ULONG skip,
                                                     ULONG cap, PVOID *out, DWORD *hash)
{
    volatile ULONG frame = depth;
    USHORT n;
    if (depth) n = trace_frames(depth - 1, skip, cap, out, hash);
    else n = U(RtlCaptureStackBackTrace)(skip, cap, out, hash);
    if (frame == 0xffffffff) puts("unreachable fixture depth");
    return n;
}
static void trace_case(int kind)
{
    struct { PVOID frames[16]; ULONG_PTR guard; } box;
    DWORD hash = 0xdeadbeef, sum = 0;
    ULONG cap = kind == 0 ? 1 : 8, skip = kind == 4 ? 2 : 0;
    USHORT n;
    REQUIRE(U(RtlCaptureStackBackTrace));
    memset(&box, 0, sizeof(box)); box.guard = 0x123456789abcdef0ULL;
    if (kind == 5) {
        /* A skip count of 255 or more is rejected before the stack is walked. */
        n = U(RtlCaptureStackBackTrace)(255, 8, box.frames, &hash);
        EXPECT_EQ(n, 0); EXPECT_EQ(hash, 0xdeadbeef);
        for (int i = 0; i < 16; i++) EXPECT_EQ(box.frames[i], NULL);
    } else {
        n = trace_frames(12, skip, cap, box.frames, kind == 3 ? NULL : &hash);
        EXPECT_EQ(n, cap);
        if (n > cap) { t_skip("capture count exceeds fixture capacity"); return; }
        for (USHORT i = 0; i < n; i++) {
            CHECK(box.frames[i] != NULL);
            sum += (DWORD)(ULONG_PTR)box.frames[i];
        }
        if (kind != 3) EXPECT_EQ(hash, sum);
        for (unsigned i = cap; i < 16; i++) EXPECT_EQ(box.frames[i], NULL);
        if (kind == 2 || kind == 4) {
            REQUIRE(U(RtlPcToFileHeader));
            for (USHORT i = 0; i < n; i++) {
                PVOID base = NULL;
                EXPECT_EQ(U(RtlPcToFileHeader)(box.frames[i], &base), GetModuleHandleW(NULL));
            }
        }
    }
    EXPECT_EQ(box.guard, 0x123456789abcdef0ULL);
}
TEST(rtl_context_backtrace_one_frame) { trace_case(0); }
TEST(rtl_context_backtrace_eight_frames) { trace_case(1); }
TEST(rtl_context_backtrace_hash_and_images) { trace_case(2); }
TEST(rtl_context_backtrace_optional_hash) { trace_case(3); }
TEST(rtl_context_backtrace_skip_real_frames) { trace_case(4); }
TEST(rtl_context_backtrace_skip_limit) { trace_case(5); }

TEST(rtl_context_backtrace_skip_matches_suffix)
{
    PVOID full[10] = {0}, skipped[8] = {0};
    USHORT n, m;
    REQUIRE(U(RtlCaptureStackBackTrace));
    n = trace_frames(12, 0, 10, full, NULL);
    m = trace_frames(12, 2, 8, skipped, NULL);
    EXPECT_EQ(n, 10); EXPECT_EQ(m, 8);
    if (n != 10 || m != 8) { t_skip("incomplete recursive backtrace fixture"); return; }
    for (unsigned i = 0; i < 8; i++) EXPECT_EQ(skipped[i], full[i + 2]);
}

static __attribute__((noinline)) DWORD lookup_probe(void)
{
    volatile DWORD value = GetCurrentThreadId();
    return value + 1;
}
/* Inspect only the known loaded image, never headers at a DUT-returned base. */
static int image_readable(HMODULE module, const void *p, SIZE_T bytes)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)module;
    const IMAGE_NT_HEADERS *nt;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR offset;
    if (!module || (ULONG_PTR)p < (ULONG_PTR)module) return 0;
    nt = (const IMAGE_NT_HEADERS *)((const BYTE *)module + dos->e_lfanew);
    offset = (ULONG_PTR)p - (ULONG_PTR)module;
    if (offset > nt->OptionalHeader.SizeOfImage ||
        bytes > nt->OptionalHeader.SizeOfImage - offset) return 0;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return 0;
    return mbi.AllocationBase == module && mbi.State == MEM_COMMIT &&
        !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
        (ULONG_PTR)p - (ULONG_PTR)mbi.BaseAddress <= mbi.RegionSize &&
        bytes <= mbi.RegionSize - ((ULONG_PTR)p - (ULONG_PTR)mbi.BaseAddress);
}
static void lookup_case(int kind)
{
    DWORD64 image = 0, image2 = 0;
    DWORD64 pc;
    PRUNTIME_FUNCTION entry, again;
    UNWIND_HISTORY_TABLE history;
    HMODULE expected = kind == 1 ? t_module("ntdll.dll") : GetModuleHandleW(NULL);
    int valid;
    REQUIRE(U(RtlLookupFunctionEntry));
    pc = (DWORD64)(ULONG_PTR)(kind == 1 ? (PVOID)U(RtlLookupFunctionEntry) : (PVOID)lookup_probe);
    memset(&history, 0, sizeof(history));
    history.LowAddress = ~(DWORD64)0;
    if (kind == 5) {
        PVOID region = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!region) { t_skip("cannot allocate non-image PC fixture"); return; }
        entry = U(RtlLookupFunctionEntry)((DWORD64)(ULONG_PTR)region, &image, NULL);
        CHECK(entry == NULL);
        VirtualFree(region, 0, MEM_RELEASE);
        return;
    }
    entry = U(RtlLookupFunctionEntry)(pc, &image, kind == 2 ? &history : NULL);
    CHECK(entry != NULL);
    if (!entry) { t_skip("expected non-leaf function has no runtime entry"); return; }
    EXPECT_EQ(image, expected);
    valid = image == (DWORD64)(ULONG_PTR)expected && image_readable(expected, entry, sizeof(*entry));
    CHECK(valid);
    if (!valid) { t_skip("runtime entry is outside readable expected image"); return; }
    CHECK(entry->BeginAddress < entry->EndAddress);
    valid = entry->BeginAddress < entry->EndAddress &&
        image_readable(expected, (PVOID)(ULONG_PTR)(image + entry->BeginAddress), 1) &&
        image_readable(expected, (PVOID)(ULONG_PTR)(image + entry->EndAddress - 1), 1) &&
        entry->UnwindData != 0 &&
        image_readable(expected, (PVOID)(ULONG_PTR)(image + entry->UnwindData), 4);
    CHECK(valid);
    if (!valid) { t_skip("runtime entry has invalid code/unwind ranges"); return; }
    CHECK(image + entry->BeginAddress <= pc && pc < image + entry->EndAddress);
    if (kind == 2) {
        again = U(RtlLookupFunctionEntry)(pc, &image2, &history);
        EXPECT_EQ(again, entry); EXPECT_EQ(image2, image);
        CHECK(history.Count <= UNWIND_HISTORY_TABLE_SIZE);
    } else if (kind == 3 || kind == 4) {
        DWORD64 inside = image + (kind == 3 ? entry->BeginAddress : entry->EndAddress - 1);
        again = U(RtlLookupFunctionEntry)(inside, &image2, NULL);
        EXPECT_EQ(again, entry); EXPECT_EQ(image2, image);
    }
}
TEST(rtl_context_lookup_own_nonleaf) { lookup_case(0); }
TEST(rtl_context_lookup_ntdll_nonleaf) { lookup_case(1); }
TEST(rtl_context_lookup_history_repeat) { lookup_case(2); }
TEST(rtl_context_lookup_begin_inclusive) { lookup_case(3); }
TEST(rtl_context_lookup_last_byte) { lookup_case(4); }
TEST(rtl_context_lookup_private_allocation) { lookup_case(5); }

TEST(rtl_context_pc_to_self_image)
{
    PVOID base = NULL;
    REQUIRE(U(RtlPcToFileHeader));
    EXPECT_EQ(U(RtlPcToFileHeader)((PVOID)lookup_probe, &base), GetModuleHandleW(NULL));
    EXPECT_EQ(base, GetModuleHandleW(NULL));
}
TEST(rtl_context_pc_to_ntdll_image)
{
    PVOID base = NULL;
    REQUIRE(U(RtlPcToFileHeader));
    EXPECT_EQ(U(RtlPcToFileHeader)((PVOID)U(RtlPcToFileHeader), &base), t_module("ntdll.dll"));
    EXPECT_EQ(base, t_module("ntdll.dll"));
}

static volatile LONG exception_calls, exception_bad;
static ULONG exception_count;
static LONG CALLBACK own_exception(PEXCEPTION_POINTERS p)
{
    EXCEPTION_RECORD *e = p->ExceptionRecord;
    if (e->ExceptionCode != 0xe0421234) return EXCEPTION_CONTINUE_SEARCH;
    if (e->ExceptionFlags != 0 || e->NumberParameters != exception_count ||
        !e->ExceptionAddress || !p->ContextRecord ||
        !p->ContextRecord->Rip || !p->ContextRecord->Rsp)
        InterlockedIncrement(&exception_bad);
    for (ULONG i = 0; i < e->NumberParameters && i < EXCEPTION_MAXIMUM_PARAMETERS; i++)
        if (e->ExceptionInformation[i] != (ULONG_PTR)0x1000 + i)
            InterlockedIncrement(&exception_bad);
    InterlockedIncrement(&exception_calls);
    return EXCEPTION_CONTINUE_EXECUTION;
}
CHILD(rtl_context_raise)
{
    EXCEPTION_RECORD record;
    PVOID handler;
    exception_count = argc > 1 && atoi(argv[1]) ? EXCEPTION_MAXIMUM_PARAMETERS : 0;
    memset(&record, 0, sizeof(record));
    record.ExceptionCode = 0xe0421234;
    record.NumberParameters = exception_count;
    for (ULONG i = 0; i < exception_count; i++) record.ExceptionInformation[i] = 0x1000 + i;
    handler = AddVectoredExceptionHandler(1, own_exception);
    if (!handler) return 77;
    UN(RtlRaiseException)(&record);
    if (!RemoveVectoredExceptionHandler(handler)) return 2;
    return exception_calls == 1 && exception_bad == 0 ? 0 : 3;
}
static void raise_case(const char *arg)
{
    DWORD result;
    REQUIRE(UN(RtlRaiseException));
    result = t_run_child("rtl_context_raise", arg, 10000);
    if (result == 77) { t_skip("cannot install private child VEH"); return; }
    EXPECT_EQ(result, 0);
}
TEST(rtl_context_raise_continuable_empty) { raise_case("0"); }
TEST(rtl_context_raise_continuable_full_payload) { raise_case("1"); }

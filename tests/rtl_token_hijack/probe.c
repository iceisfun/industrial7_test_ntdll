#include "t.h"

UDECL(NTSTATUS, RtlFreeNonVolatileToken, (PVOID));
UDECL(VOID, RtlRaiseExceptionForReturnAddressHijack, (void));
UDECL(PVOID, RtlAddVectoredExceptionHandler, (ULONG, PVECTORED_EXCEPTION_HANDLER));

TEST(free_non_volatile_token_low_bit) {
    static const ULONG_PTR values[] = {
        0, 1, 2, 3, 4, 0xff, 0x100, 0x101,
        0x100000000ULL, 0x100000001ULL, ~(ULONG_PTR)1, ~(ULONG_PTR)0
    };
    size_t i;
    REQUIRE(UN(RtlFreeNonVolatileToken));
    for (i = 0; i < sizeof values / sizeof values[0]; i++) {
        NTSTATUS s = UN(RtlFreeNonVolatileToken)((PVOID)values[i]);
        CHECKF(s == ((values[i] & 1) ? 0 : (NTSTATUS)0xc000000d),
               "token %p: got %08lx", (PVOID)values[i], (ULONG)s);
    }
}

/* The kernel-style entry has RSP aligned to 16, with the eventual return
 * address one slot BELOW entry RSP. A C call supplies neither property. */
extern void hijack_entry(RtlRaiseExceptionForReturnAddressHijack_pfn fn);
__asm__(
    ".text\n"
    "hijack_entry:\n"
    "subq $0x28, %rsp\n"
    "leaq 1f(%rip), %rax\n"
    "movq %rax, -8(%rsp)\n"
    "jmp *%rcx\n"
    "1: addq $0x28, %rsp\n"
    "ret\n"
);

static volatile LONG seen;
static EXCEPTION_RECORD record;
static LONG CALLBACK hijack_veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != 0x80000033)
        return EXCEPTION_CONTINUE_SEARCH;
    record = *ep->ExceptionRecord;
    if (++seen != 1) ExitProcess(3);
    return EXCEPTION_CONTINUE_EXECUTION;
}

CHILD(hijack_frame) {
    if (!UN(RtlRaiseExceptionForReturnAddressHijack) ||
        !UN(RtlAddVectoredExceptionHandler)) return 2;
    if (!UN(RtlAddVectoredExceptionHandler)(1, hijack_veh)) return 2;
    hijack_entry(UN(RtlRaiseExceptionForReturnAddressHijack));
    if (seen != 1 || record.ExceptionCode != 0x80000033 ||
        record.ExceptionFlags != 0 || record.NumberParameters != 0 ||
        record.ExceptionRecord != NULL) return 4;
    return 0;
}

TEST(raise_exception_for_return_address_hijack) {
    REQUIRE(UN(RtlRaiseExceptionForReturnAddressHijack));
    REQUIRE(UN(RtlAddVectoredExceptionHandler));
    EXPECT_EQ(t_run_child("hijack_frame", NULL, 10000), 0);
}

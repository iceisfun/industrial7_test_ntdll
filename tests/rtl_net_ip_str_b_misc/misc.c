#include "t.h"

#define INVP ((NTSTATUS)0xC000000D)
#define EXPECT_ST(a, b) EXPECT_EQ((ULONG)(a), (ULONG)(b))

typedef struct { ULONG64 Size; ULONG64 *Buffer; } BITMAP_EX;
typedef struct { ULONG Size; ULONG pad; PULONG Buffer; } BITMAP_T;   /* RTL_BITMAP: ULONG + PULONG (8-aligned) */

UDECL(ULONG64, RtlNumberOfSetBitsEx, (const BITMAP_EX *));
UDECL(ULONG64, RtlNumberOfClearBitsEx, (const BITMAP_EX *));
UDECL(ULONG, RtlNumberOfSetBitsInRange, (const void *, ULONG, ULONG));
UDECL(ULONG, RtlNumberOfClearBitsInRange, (const void *, ULONG, ULONG));
UDECL(ULONG_PTR, RtlNumberOfSetBitsUlongPtr, (ULONG_PTR));
UDECL(BOOLEAN, RtlIsZeroMemory, (const void *, SIZE_T));
UDECL(UCHAR, RtlUpperChar, (UCHAR));
UDECL(VOID, RtlUpperString, (void *, const void *));
UDECL(BOOLEAN, RtlIsElevatedRid, (const SID_AND_ATTRIBUTES *));
UDECL(BOOLEAN, RtlIsCapabilitySid, (PSID));
UDECL(BOOLEAN, RtlIsPackageSid, (PSID));
UDECL(BOOLEAN, RtlIsValidProcessTrustLabelSid, (PSID));
UDECL(BOOLEAN, RtlIsParentOfChildAppContainer, (PSID, PSID));
UDECL(BOOLEAN, RtlIsCurrentProcess, (HANDLE));
UDECL(BOOLEAN, RtlIsCurrentThread, (HANDLE));
UDECL(BOOLEAN, RtlIsProcessorFeaturePresent, (ULONG));
UDECL(BOOLEAN, RtlIsThreadWithinLoaderCallout, (void));
UDECL(BOOLEAN, RtlIsCurrentThreadAttachExempt, (void));
UDECL(BOOLEAN, RtlIsActivationContextActive, (HANDLE));
UDECL(BOOLEAN, RtlIsCloudFilesPlaceholder, (ULONG, ULONG));
UDECL(BOOLEAN, RtlIsPartialPlaceholder, (ULONG));
UDECL(NTSTATUS, RtlIsPartialPlaceholderFileHandle, (HANDLE, BOOLEAN *));
UDECL(NTSTATUS, RtlIsPartialPlaceholderFileInfo, (const void *, ULONG, BOOLEAN *));
UDECL(BOOLEAN, RtlIsNonEmptyDirectoryReparsePointAllowed, (ULONG));
UDECL(BOOLEAN, RtlIsMultiSessionSku, (void));
UDECL(BOOLEAN, RtlIsMultiUsersInSessionSku, (void));
UDECL(BOOLEAN, RtlIsStateSeparationEnabled, (void));
UDECL(BOOLEAN, RtlIsValidLocaleName, (PCWSTR, ULONG));
UDECL(BOOLEAN, RtlValidProcessProtection, (UCHAR));
UDECL(NTSTATUS, RtlValidateCorrelationVector, (const void *));
UDECL(NTSTATUS, RtlValidateUnicodeString, (ULONG, const UNICODE_STRING *));
UDECL(BOOLEAN, RtlValidAcl, (PACL));
UDECL(BOOLEAN, RtlValidRelativeSecurityDescriptor, (PSECURITY_DESCRIPTOR, ULONG, ULONG));
UDECL(BOOLEAN, RtlValidateProcessHeaps, (void));
UDECL(BOOLEAN, RtlIsNameInExpression, (const UNICODE_STRING *, const UNICODE_STRING *, BOOLEAN, PWCH));
UDECL(BOOLEAN, RtlIsNameInUnUpcasedExpression, (const UNICODE_STRING *, const UNICODE_STRING *, BOOLEAN, PWCH));
UDECL(BOOLEAN, RtlIsNameLegalDOS8Dot3, (const UNICODE_STRING *, void *, BOOLEAN *));
UDECL(BOOLEAN, RtlIsTextUnicode, (const void *, ULONG, PULONG));
UDECL(NTSTATUS, RtlIsNormalizedString, (ULONG, PCWSTR, LONG, BOOLEAN *));
UDECL(NTSTATUS, RtlIsUntrustedObject, (HANDLE, PVOID, BOOLEAN *));
UDECL(VOID, RtlInitializeHandleTable, (ULONG, ULONG, void *));
UDECL(BOOLEAN, RtlIsValidHandle, (void *, void *));
UDECL(BOOLEAN, RtlIsValidIndexHandle, (void *, ULONG, void **));
UDECL(void *, RtlAllocateHandle, (void *, PULONG));
UDECL(BOOLEAN, RtlFreeHandle, (void *, void *));
UDECL(NTSTATUS, RtlDestroyHandleTable, (void *));
UDECL(NTSTATUS, RtlInitializeSidEx, (PSID, PSID_IDENTIFIER_AUTHORITY, UCHAR, ...));
UDECL(VOID, RtlInitializeSListHead, (PSLIST_HEADER));
UDECL(ULONG, RtlMultipleAllocateHeap, (HANDLE, ULONG, SIZE_T, ULONG, PVOID *));
UDECL(ULONG, RtlMultipleFreeHeap, (HANDLE, ULONG, ULONG, PVOID *));
UDECL(NTSTATUS, RtlTimeToElapsedTimeFields, (const LARGE_INTEGER *, PVOID));

TEST(rtl_net_ip_str_b_misc_aliases) {
    CHECK(t_proc("RtlUnicodeStringToAnsiSize") != NULL);
    CHECK(t_proc("RtlUnicodeStringToOemSize") == t_proc("RtlUnicodeStringToAnsiSize"));
    CHECK(t_proc("RtlOemStringToUnicodeSize") != NULL);
}

static void bm_set(ULONG64 *b, unsigned i) { b[i / 64] |= 1ULL << (i % 64); }

TEST(rtl_net_ip_str_b_misc_bit_counts_ex) {
    REQUIRE(UN(RtlNumberOfSetBitsEx)); REQUIRE(UN(RtlNumberOfClearBitsEx));
    ULONG64 buf[4] = {0};
    BITMAP_EX bm = { 200, buf };
    EXPECT_EQ(UN(RtlNumberOfSetBitsEx)(&bm), 0);
    EXPECT_EQ(UN(RtlNumberOfClearBitsEx)(&bm), 200);
    bm_set(buf, 0); bm_set(buf, 63); bm_set(buf, 64); bm_set(buf, 100); bm_set(buf, 199);
    EXPECT_EQ(UN(RtlNumberOfSetBitsEx)(&bm), 5);
    EXPECT_EQ(UN(RtlNumberOfClearBitsEx)(&bm), 195);
    /* bits beyond SizeOfBitMap are not counted */
    buf[3] = ~0ULL; buf[2] = ~0ULL;
    bm.Size = 130; buf[0] = buf[1] = 0; buf[2] = 0;
    bm_set(buf, 129); buf[2] |= 0xfcULL;     /* bits 128.. : 129 plus bits 130..135 outside */
    EXPECT_EQ(UN(RtlNumberOfSetBitsEx)(&bm), 1);
    EXPECT_EQ(UN(RtlNumberOfClearBitsEx)(&bm), 129);
    /* all ones, odd sizes */
    memset(buf, 0xff, sizeof buf);
    for (ULONG64 n = 0; n <= 256; n += 37) {
        bm.Size = n;
        EXPECT_EQ(UN(RtlNumberOfSetBitsEx)(&bm), n);
        EXPECT_EQ(UN(RtlNumberOfClearBitsEx)(&bm), 0);
    }
    bm.Size = 0;
    EXPECT_EQ(UN(RtlNumberOfSetBitsEx)(&bm), 0);
}

TEST(rtl_net_ip_str_b_misc_bit_counts_range) {
    REQUIRE(UN(RtlNumberOfSetBitsInRange)); REQUIRE(UN(RtlNumberOfClearBitsInRange)); REQUIRE(UN(RtlNumberOfSetBitsUlongPtr));
    ULONG buf[8] = {0};
    BITMAP_T bm = { 256, 0, buf };
    ULONG64 *b64 = (ULONG64 *)buf;
    bm_set(b64, 0); bm_set(b64, 5); bm_set(b64, 63); bm_set(b64, 64); bm_set(b64, 70); bm_set(b64, 200); bm_set(b64, 255);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 0, 256), 7);
    EXPECT_EQ(UN(RtlNumberOfClearBitsInRange)(&bm, 0, 256), 249);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 0, 6), 2);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 6, 57), 0);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 6, 58), 1);     /* includes bit 63 */
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 63, 2), 2);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 64, 64), 2);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 71, 130), 1);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 200, 1), 1);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 201, 1), 0);
    EXPECT_EQ(UN(RtlNumberOfClearBitsInRange)(&bm, 200, 1), 0);
    EXPECT_EQ(UN(RtlNumberOfClearBitsInRange)(&bm, 201, 1), 1);
    EXPECT_EQ(UN(RtlNumberOfClearBitsInRange)(&bm, 64, 64), 62);
    /* range errors return 0xffffffff */
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 256, 1), 0xffffffff);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 0, 257), 0xffffffff);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 255, 2), 0xffffffff);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 0, 0), 0xffffffff);
    EXPECT_EQ(UN(RtlNumberOfClearBitsInRange)(&bm, 256, 1), 0xffffffff);
    EXPECT_EQ(UN(RtlNumberOfClearBitsInRange)(&bm, 0, 0), 0xffffffff);
    EXPECT_EQ(UN(RtlNumberOfSetBitsInRange)(&bm, 0xffffffff, 2), 0xffffffff);
    /* popcount */
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(0), 0);
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(1), 1);
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(0xff), 8);
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(0x8000000000000001ULL), 2);
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(~(ULONG_PTR)0), 64);
    EXPECT_EQ(UN(RtlNumberOfSetBitsUlongPtr)(0x5555555555555555ULL), 32);
}

TEST(rtl_net_ip_str_b_misc_is_zero_memory) {
    REQUIRE(UN(RtlIsZeroMemory));
    BYTE b[64] __attribute__((aligned(8))); memset(b, 0, sizeof b);
    EXPECT_EQ(UN(RtlIsZeroMemory)(b, 64), 1);
    EXPECT_EQ(UN(RtlIsZeroMemory)(b, 0), 1);
    EXPECT_EQ(UN(RtlIsZeroMemory)(b + 1, 63), 1);
    for (int i = 0; i < 64; i += 7) {       /* single nonzero byte at head, body, tail, unaligned starts */
        b[i] = 1;
        EXPECT_EQ(UN(RtlIsZeroMemory)(b, 64), 0);
        EXPECT_EQ(UN(RtlIsZeroMemory)(b + 3, 61 ) , i >= 3 ? 0 : 1);
        EXPECT_EQ(UN(RtlIsZeroMemory)(b, i), 1);          /* excludes the nonzero byte */
        EXPECT_EQ(UN(RtlIsZeroMemory)(b, i + 1), 0);
        b[i] = 0;
    }
}

TEST(rtl_net_ip_str_b_misc_upper_char_string) {
    REQUIRE(UN(RtlUpperChar));
    EXPECT_EQ(UN(RtlUpperChar)('a'), 'A');
    EXPECT_EQ(UN(RtlUpperChar)('z'), 'Z');
    EXPECT_EQ(UN(RtlUpperChar)('A'), 'A');
    EXPECT_EQ(UN(RtlUpperChar)('0'), '0');
    EXPECT_EQ(UN(RtlUpperChar)('{'), '{');
    EXPECT_EQ(UN(RtlUpperChar)('`'), '`');
    EXPECT_EQ(UN(RtlUpperChar)('@'), '@');
    EXPECT_EQ(UN(RtlUpperChar)(0), 0);
    typedef struct { USHORT Length, Max; PCHAR Buffer; } S8;
    REQUIRE(UN(RtlUpperString));
    char src[] = "Hello, World-123 az"; char dst[40]; memset(dst, '#', sizeof dst);
    S8 s = { 19, 19, src }, d = { 0, 40, dst };
    UN(RtlUpperString)(&d, &s);
    CHECK(!memcmp(dst, "HELLO, WORLD-123 AZ", 19));
    EXPECT_EQ(dst[19], '#');
    EXPECT_EQ(d.Length, 19);
    /* destination limits the copy */
    memset(dst, '#', sizeof dst); d.Length = 0; d.Max = 5;
    UN(RtlUpperString)(&d, &s);
    CHECK(!memcmp(dst, "HELLO#", 6));
    EXPECT_EQ(d.Length, 5);
    /* empty source */
    memset(dst, '#', sizeof dst); d.Max = 40; s.Length = 0;
    UN(RtlUpperString)(&d, &s);
    EXPECT_EQ(dst[0], '#'); EXPECT_EQ(d.Length, 0);
}

static void mksid(BYTE *sid, BYTE nsub, const BYTE *auth, const ULONG *subs) {
    sid[0] = 1; sid[1] = nsub; memcpy(sid + 2, auth, 6);
    for (int i = 0; i < nsub; i++) memcpy(sid + 8 + 4 * i, &subs[i], 4);
}

TEST(rtl_net_ip_str_b_misc_sid_predicates) {
    REQUIRE(UN(RtlIsCapabilitySid)); REQUIRE(UN(RtlIsPackageSid)); REQUIRE(UN(RtlIsValidProcessTrustLabelSid)); REQUIRE(UN(RtlIsElevatedRid));
    static const BYTE app[6] = {0,0,0,0,0,15}, nt[6] = {0,0,0,0,0,5}, trust[6] = {0,0,0,0,0,0x13};
    BYTE sid[64];
    ULONG s3[] = {3, 1, 2, 3, 4, 5, 6, 7}, s2[] = {2, 1, 2, 3, 4, 5, 6, 7};
    mksid(sid, 2, app, s3); EXPECT_EQ(UN(RtlIsCapabilitySid)(sid), 1); EXPECT_EQ(UN(RtlIsPackageSid)(sid), 0);
    mksid(sid, 8, app, s3); EXPECT_EQ(UN(RtlIsCapabilitySid)(sid), 1);
    mksid(sid, 2, app, s2); EXPECT_EQ(UN(RtlIsPackageSid)(sid), 1); EXPECT_EQ(UN(RtlIsCapabilitySid)(sid), 0);
    mksid(sid, 8, app, s2); EXPECT_EQ(UN(RtlIsPackageSid)(sid), 1);
    mksid(sid, 1, app, s2); EXPECT_EQ(UN(RtlIsPackageSid)(sid), 0);        /* needs more than one sub-authority */
    mksid(sid, 1, app, s3); EXPECT_EQ(UN(RtlIsCapabilitySid)(sid), 0);
    mksid(sid, 2, nt, s2); EXPECT_EQ(UN(RtlIsPackageSid)(sid), 0);         /* wrong authority */
    mksid(sid, 2, nt, s3); EXPECT_EQ(UN(RtlIsCapabilitySid)(sid), 0);
    ULONG s9[] = {9, 1}; mksid(sid, 2, app, s9);
    EXPECT_EQ(UN(RtlIsPackageSid)(sid), 0); EXPECT_EQ(UN(RtlIsCapabilitySid)(sid), 0);
    mksid(sid, 2, app, s2); sid[0] = 2;                                    /* bad revision */
    EXPECT_EQ(UN(RtlIsPackageSid)(sid), 0);
    /* process trust label sid */
    ULONG t1[] = {0x2000, 0x2000}, t2[] = {0, 0}, t3[] = {0, 5}, t4[] = {5, 0}, t5[] = {5, 0x2000};
    mksid(sid, 2, trust, t1); EXPECT_EQ(UN(RtlIsValidProcessTrustLabelSid)(sid), 1);
    mksid(sid, 2, trust, t2); EXPECT_EQ(UN(RtlIsValidProcessTrustLabelSid)(sid), 1);
    mksid(sid, 2, trust, t3); EXPECT_EQ(UN(RtlIsValidProcessTrustLabelSid)(sid), 0);
    mksid(sid, 2, trust, t4); EXPECT_EQ(UN(RtlIsValidProcessTrustLabelSid)(sid), 1);
    mksid(sid, 2, trust, t5); EXPECT_EQ(UN(RtlIsValidProcessTrustLabelSid)(sid), 1);
    mksid(sid, 1, trust, t1); EXPECT_EQ(UN(RtlIsValidProcessTrustLabelSid)(sid), 0);
    mksid(sid, 3, trust, t1); EXPECT_EQ(UN(RtlIsValidProcessTrustLabelSid)(sid), 0);
    mksid(sid, 2, nt, t1); EXPECT_EQ(UN(RtlIsValidProcessTrustLabelSid)(sid), 0);
    mksid(sid, 2, trust, t1); sid[0] = 2; EXPECT_EQ(UN(RtlIsValidProcessTrustLabelSid)(sid), 0);
    /* elevated rid: enabled group whose last sub-authority is an administrative RID */
    ULONG adm[] = {32, 544}, usr[] = {32, 545};
    BYTE sid2[32]; mksid(sid2, 2, nt, adm);
    SID_AND_ATTRIBUTES sa = { sid2, SE_GROUP_ENABLED };
    EXPECT_EQ(UN(RtlIsElevatedRid)(&sa), 1);
    sa.Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    EXPECT_EQ(UN(RtlIsElevatedRid)(&sa), 1);
    sa.Attributes = SE_GROUP_USE_FOR_DENY_ONLY | SE_GROUP_ENABLED;
    EXPECT_EQ(UN(RtlIsElevatedRid)(&sa), 0);
    sa.Attributes = SE_GROUP_INTEGRITY | SE_GROUP_ENABLED;
    EXPECT_EQ(UN(RtlIsElevatedRid)(&sa), 0);
    mksid(sid2, 2, nt, usr); sa.Attributes = SE_GROUP_ENABLED;
    EXPECT_EQ(UN(RtlIsElevatedRid)(&sa), 0);
    EXPECT_EQ(UN(RtlIsElevatedRid)(NULL), 0);
}

TEST(rtl_net_ip_str_b_misc_current_process_thread) {
    REQUIRE(UN(RtlIsCurrentProcess)); REQUIRE(UN(RtlIsCurrentThread));
    EXPECT_EQ(UN(RtlIsCurrentProcess)((HANDLE)-1), 1);
    EXPECT_EQ(UN(RtlIsCurrentThread)((HANDLE)-2), 1);
    EXPECT_EQ(UN(RtlIsCurrentProcess)((HANDLE)-2), 0);
    EXPECT_EQ(UN(RtlIsCurrentThread)((HANDLE)-1), 0);
    EXPECT_EQ(UN(RtlIsCurrentProcess)(NULL), 0);
    EXPECT_EQ(UN(RtlIsCurrentThread)(NULL), 0);
    EXPECT_EQ(UN(RtlIsCurrentProcess)((HANDLE)(ULONG_PTR)0x7777776c), 0);   /* not a handle */
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    CHECK(hp != NULL);
    if (hp) { EXPECT_EQ(UN(RtlIsCurrentProcess)(hp), 1); EXPECT_EQ(UN(RtlIsCurrentThread)(hp), 0); CloseHandle(hp); }
    HANDLE ht = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
    CHECK(ht != NULL);
    if (ht) { EXPECT_EQ(UN(RtlIsCurrentThread)(ht), 1); EXPECT_EQ(UN(RtlIsCurrentProcess)(ht), 0); CloseHandle(ht); }
    /* a different process */
    STARTUPINFOA si = { sizeof si }; PROCESS_INFORMATION pi;
    char cmd[] = "cmd.exe /c pause"; char sysdir[MAX_PATH], full[MAX_PATH + 32];
    GetSystemDirectoryA(sysdir, sizeof sysdir); wsprintfA(full, "%s\\cmd.exe", sysdir);
    if (CreateProcessA(full, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        EXPECT_EQ(UN(RtlIsCurrentProcess)(pi.hProcess), 0);
        EXPECT_EQ(UN(RtlIsCurrentThread)(pi.hThread), 0);
        TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    } else t_note("CreateProcess for a foreign process handle failed: %lu", GetLastError());
    /* a thread in this process that is not the caller */
    EXPECT_EQ(UN(RtlIsCurrentThread)(GetCurrentThread()), 1);
}

TEST(rtl_net_ip_str_b_misc_processor_feature) {
    REQUIRE(UN(RtlIsProcessorFeaturePresent));
    for (ULONG i = 0; i < 64; i++)
        CHECKF(!!UN(RtlIsProcessorFeaturePresent)(i) == !!IsProcessorFeaturePresent(i), "feature %lu", i);
    EXPECT_EQ(UN(RtlIsProcessorFeaturePresent)(64), 0);
    EXPECT_EQ(UN(RtlIsProcessorFeaturePresent)(0x1000), 0);
    EXPECT_EQ(UN(RtlIsProcessorFeaturePresent)(0xffffffff), 0);
    EXPECT_EQ(UN(RtlIsProcessorFeaturePresent)(PF_FLOATING_POINT_PRECISION_ERRATA), 0);
    EXPECT_EQ(UN(RtlIsProcessorFeaturePresent)(PF_NX_ENABLED), 1);   /* 64-bit Windows 10 always has NX */
    EXPECT_EQ(UN(RtlIsProcessorFeaturePresent)(PF_COMPARE_EXCHANGE_DOUBLE), 1);
}

TEST(rtl_net_ip_str_b_misc_state_predicates) {
    REQUIRE(UN(RtlIsThreadWithinLoaderCallout)); REQUIRE(UN(RtlIsCurrentThreadAttachExempt));
    EXPECT_EQ(UN(RtlIsThreadWithinLoaderCallout)(), 0);   /* test code runs outside DllMain */
    EXPECT_EQ(UN(RtlIsCurrentThreadAttachExempt)(), 0);
    REQUIRE(UN(RtlIsMultiSessionSku)); REQUIRE(UN(RtlIsMultiUsersInSessionSku)); REQUIRE(UN(RtlIsStateSeparationEnabled));
    /* bits of KUSER_SHARED_DATA.SharedDataFlags at 0x7ffe02f0 */
    ULONG flags = *(volatile ULONG *)0x7ffe02f0;
    BOOLEAN a = UN(RtlIsMultiUsersInSessionSku)(), b = UN(RtlIsStateSeparationEnabled)();
    EXPECT_EQ(a, (flags >> 9) & 1);
    EXPECT_EQ(b, (flags >> 10) & 1);
    BOOLEAN m = UN(RtlIsMultiSessionSku)();
    {   /* with the service session id 0 the answer is bit 8 of SharedDataFlags */
        ULONG (WINAPI *sid)(void) = (void *)t_proc("RtlGetCurrentServiceSessionId");
        if (sid && sid() == 0) EXPECT_EQ(m, (flags >> 8) & 1);
        else CHECK(m == 0 || m == 1);
    }
    t_note("multi-session=%d multiuser-in-session=%d state-separation=%d", m, a, b);
}

TEST(rtl_net_ip_str_b_misc_activation_context_active) {
    REQUIRE(UN(RtlIsActivationContextActive));
    EXPECT_EQ(UN(RtlIsActivationContextActive)((HANDLE)(ULONG_PTR)0x12345670), 0);
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "act.manifest");
    static const char xml[] = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n"
        "<assemblyIdentity type=\"win32\" name=\"ntdll.conf.test\" version=\"1.0.0.0\"/>\r\n</assembly>\r\n";
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create manifest"); return; }
    DWORD w; WriteFile(f, xml, sizeof xml - 1, &w, NULL); CloseHandle(f);
    ACTCTXA ac = { sizeof ac }; ac.lpSource = path;
    HANDLE h = CreateActCtxA(&ac);
    if (h == INVALID_HANDLE_VALUE) { t_skip("CreateActCtx failed %lu", GetLastError()); DeleteFileA(path); return; }
    EXPECT_EQ(UN(RtlIsActivationContextActive)(h), 0);   /* created but not activated */
    ULONG_PTR cookie = 0;
    CHECK(ActivateActCtx(h, &cookie));
    EXPECT_EQ(UN(RtlIsActivationContextActive)(h), 1);
    EXPECT_EQ(UN(RtlIsActivationContextActive)((HANDLE)(ULONG_PTR)0x12345670), 0);
    CHECK(DeactivateActCtx(0, cookie));
    EXPECT_EQ(UN(RtlIsActivationContextActive)(h), 0);
    ReleaseActCtx(h); DeleteFileA(path);
}

TEST(rtl_net_ip_str_b_misc_placeholder_predicates) {
    REQUIRE(UN(RtlIsCloudFilesPlaceholder)); REQUIRE(UN(RtlIsPartialPlaceholder)); REQUIRE(UN(RtlIsNonEmptyDirectoryReparsePointAllowed));
    /* needs FILE_ATTRIBUTE_REPARSE_POINT (0x400) and a cloud-files reparse tag 0x9000001a | (n << 12) */
    EXPECT_EQ(UN(RtlIsCloudFilesPlaceholder)(0x400, 0x9000001a), 1);
    EXPECT_EQ(UN(RtlIsCloudFilesPlaceholder)(0x400, 0x9000101a), 1);
    EXPECT_EQ(UN(RtlIsCloudFilesPlaceholder)(0x400, 0x9000f01a), 1);
    EXPECT_EQ(UN(RtlIsCloudFilesPlaceholder)(0x400 | 0x20, 0x9000201a), 1);
    EXPECT_EQ(UN(RtlIsCloudFilesPlaceholder)(0x20, 0x9000001a), 0);
    EXPECT_EQ(UN(RtlIsCloudFilesPlaceholder)(0, 0x9000001a), 0);
    EXPECT_EQ(UN(RtlIsCloudFilesPlaceholder)(0x400, 0x9000001b), 0);
    EXPECT_EQ(UN(RtlIsCloudFilesPlaceholder)(0x400, 0xA000000C), 0);
    EXPECT_EQ(UN(RtlIsCloudFilesPlaceholder)(0x400, 0x8000001a), 0);
    EXPECT_EQ(UN(RtlIsCloudFilesPlaceholder)(0x400, 0x1000001a), 0);
    /* partial placeholder: RECALL_ON_OPEN (0x40000) or RECALL_ON_DATA_ACCESS (0x400000) */
    EXPECT_EQ(UN(RtlIsPartialPlaceholder)(0x40000), 1);
    EXPECT_EQ(UN(RtlIsPartialPlaceholder)(0x400000), 1);
    EXPECT_EQ(UN(RtlIsPartialPlaceholder)(0x440000), 1);
    EXPECT_EQ(UN(RtlIsPartialPlaceholder)(0), 0);
    EXPECT_EQ(UN(RtlIsPartialPlaceholder)(0x20), 0);
    EXPECT_EQ(UN(RtlIsPartialPlaceholder)(0x80000), 0);
    EXPECT_EQ(UN(RtlIsPartialPlaceholder)(0xffffffff), 1);
    /* non-empty directory reparse points: bit 28 of the tag (directory-allowed) or the legacy tag 0x80000018 */
    EXPECT_EQ(UN(RtlIsNonEmptyDirectoryReparsePointAllowed)(0x10000000), 1);
    EXPECT_EQ(UN(RtlIsNonEmptyDirectoryReparsePointAllowed)(0x9000001a), 1);
    EXPECT_EQ(UN(RtlIsNonEmptyDirectoryReparsePointAllowed)(0x80000018), 1);
    EXPECT_EQ(UN(RtlIsNonEmptyDirectoryReparsePointAllowed)(0xA000000C), 0);
    EXPECT_EQ(UN(RtlIsNonEmptyDirectoryReparsePointAllowed)(0), 0);
    EXPECT_EQ(UN(RtlIsNonEmptyDirectoryReparsePointAllowed)(0x80000017), 0);
}

TEST(rtl_net_ip_str_b_misc_placeholder_fileinfo) {
    REQUIRE(UN(RtlIsPartialPlaceholderFileHandle)); REQUIRE(UN(RtlIsPartialPlaceholderFileInfo));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "ph.dat");
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { t_skip("cannot create file"); return; }
    BOOLEAN r = 9;
    EXPECT_EQ(UN(RtlIsPartialPlaceholderFileHandle)(h, &r), 0);
    EXPECT_EQ(r, 0);
    r = 9;
    NTSTATUS s = UN(RtlIsPartialPlaceholderFileHandle)((HANDLE)(ULONG_PTR)0x77777770, &r);
    EXPECT_ST(s, 0xC0000008);                       /* STATUS_INVALID_HANDLE */
    CloseHandle(h); DeleteFileA(path);
    /* info buffers: attributes field position depends on the class */
    static const ULONG classes_off14[] = {2, 3, 0x25, 0x26, 0x3c, 0x3f, 0x44, 0x46};
    ULONG buf[128];
    for (unsigned i = 0; i < sizeof classes_off14 / sizeof *classes_off14; i++) {
        memset(buf, 0, sizeof buf); buf[14] = 0x40000; r = 9;
        CHECKF(UN(RtlIsPartialPlaceholderFileInfo)(buf, classes_off14[i], &r) == 0 && r == 1, "class %lu recall-on-open", classes_off14[i]);
        memset(buf, 0, sizeof buf); buf[14] = 0x20; r = 9;
        CHECKF(UN(RtlIsPartialPlaceholderFileInfo)(buf, classes_off14[i], &r) == 0 && r == 0, "class %lu normal", classes_off14[i]);
        memset(buf, 0, sizeof buf); buf[0] = 0x400000; r = 9;     /* offset 0 is not read for these classes */
        CHECKF(UN(RtlIsPartialPlaceholderFileInfo)(buf, classes_off14[i], &r) == 0 && r == 0, "class %lu offset", classes_off14[i]);
    }
    memset(buf, 0, sizeof buf); buf[0] = 0x400000; r = 9;     /* FileAttributeTagInformation */
    EXPECT_EQ(UN(RtlIsPartialPlaceholderFileInfo)(buf, 0x23, &r), 0); EXPECT_EQ(r, 1);
    buf[0] = 0; r = 9; EXPECT_EQ(UN(RtlIsPartialPlaceholderFileInfo)(buf, 0x23, &r), 0); EXPECT_EQ(r, 0);
    /* unsupported classes */
    EXPECT_ST(UN(RtlIsPartialPlaceholderFileInfo)(buf, 0, &r), 0xC00000BB);
    EXPECT_ST(UN(RtlIsPartialPlaceholderFileInfo)(buf, 1, &r), 0xC00000BB);
    EXPECT_ST(UN(RtlIsPartialPlaceholderFileInfo)(buf, 4, &r), 0xC00000BB);
    EXPECT_ST(UN(RtlIsPartialPlaceholderFileInfo)(buf, 0x24, &r), 0xC00000BB);
    EXPECT_ST(UN(RtlIsPartialPlaceholderFileInfo)(buf, 0x27, &r), 0xC00000BB);
    EXPECT_ST(UN(RtlIsPartialPlaceholderFileInfo)(buf, 0x4b, &r), 0xC00000BB);
    EXPECT_ST(UN(RtlIsPartialPlaceholderFileInfo)(buf, 0x4c, &r), 0xC0000003);
    EXPECT_ST(UN(RtlIsPartialPlaceholderFileInfo)(buf, 0x1000, &r), 0xC0000003);
    EXPECT_ST(UN(RtlIsPartialPlaceholderFileInfo)(buf, 0xffffffff, &r), 0xC00000BB);
}

TEST(rtl_net_ip_str_b_misc_valid_locale_name) {
    REQUIRE(UN(RtlIsValidLocaleName));
    EXPECT_EQ(UN(RtlIsValidLocaleName)(L"en-US", 0), 1);
    EXPECT_EQ(UN(RtlIsValidLocaleName)(L"en-us", 0), 1);        /* case-insensitive */
    EXPECT_EQ(UN(RtlIsValidLocaleName)(L"de-DE", 0), 1);
    EXPECT_EQ(UN(RtlIsValidLocaleName)(L"en-US", 2), 1);
    EXPECT_EQ(UN(RtlIsValidLocaleName)(L"zz-ZZ-nonsense", 0), 0);
    EXPECT_EQ(UN(RtlIsValidLocaleName)(L"", 0), 1);        /* the empty name is the invariant locale */
    EXPECT_EQ(UN(RtlIsValidLocaleName)(NULL, 0), 0);
    EXPECT_EQ(UN(RtlIsValidLocaleName)(L"en-US", 1), 0);        /* only bit 1 (allow neutral/supplemental) is defined */
    EXPECT_EQ(UN(RtlIsValidLocaleName)(L"en-US", 4), 0);
    EXPECT_EQ(UN(RtlIsValidLocaleName)(L"en-US", 0x80000000), 0);
}

TEST(rtl_net_ip_str_b_misc_valid_process_protection) {
    REQUIRE(UN(RtlValidProcessProtection));
    /* PS_PROTECTION: Type (3 bits) | Audit (1) | Signer (4) << 4 */
    static const UCHAR valid[] = {0x00, 0x08, 0x12, 0x21, 0x31, 0x41, 0x51, 0x52, 0x61, 0x62, 0x72, 0x81};
    for (int i = 0; i < 256; i++) {
        int want = 0;
        for (unsigned k = 0; k < sizeof valid; k++) if (valid[k] == i) want = 1;
        CHECKF(UN(RtlValidProcessProtection)((UCHAR)i) == want, "protection 0x%02x want %d", i, want);
    }
}

TEST(rtl_net_ip_str_b_misc_validate_unicode_string) {
    REQUIRE(UN(RtlValidateUnicodeString));
    WCHAR buf[8] = L"abc";
    UNICODE_STRING u = { 6, 16, buf };
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), 0);
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, NULL), 0);
    EXPECT_ST(UN(RtlValidateUnicodeString)(1, &u), INVP);       /* reserved flags */
    EXPECT_ST(UN(RtlValidateUnicodeString)(0x80000000, NULL), INVP);
    UNICODE_STRING e = { 0, 0, NULL };
    EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &e), 0);
    u.Length = 5; EXPECT_ST(UN(RtlValidateUnicodeString)(0, &u), INVP);    /* odd length */
    u.Length = 6; u.MaximumLength = 15; EXPECT_ST(UN(RtlValidateUnicodeString)(0, &u), INVP);   /* odd max */
    u.MaximumLength = 4; EXPECT_ST(UN(RtlValidateUnicodeString)(0, &u), INVP);   /* Length > Max */
    u.MaximumLength = 6; EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), 0);
    u.Length = 0xfffe; u.MaximumLength = 0xffff; EXPECT_ST(UN(RtlValidateUnicodeString)(0, &u), INVP);
    u.MaximumLength = 0xfffe; EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), 0);   /* Max = 0xfffe is fine */
    u.Length = 2; u.MaximumLength = 2; u.Buffer = NULL; EXPECT_ST(UN(RtlValidateUnicodeString)(0, &u), INVP);
    u.Length = 0; u.MaximumLength = 2; EXPECT_ST(UN(RtlValidateUnicodeString)(0, &u), INVP);
    u.Length = 0; u.MaximumLength = 0; EXPECT_EQ(UN(RtlValidateUnicodeString)(0, &u), 0);
}

TEST(rtl_net_ip_str_b_misc_validate_correlation_vector) {
    REQUIRE(UN(RtlValidateCorrelationVector));
    /* CORRELATION_VECTOR: CHAR Version; CHAR Vector[128] */
    struct { CHAR Version; CHAR Vector[128]; } cv;
    #define CVT(ver, text, want) do { memset(&cv, 0, sizeof cv); cv.Version = (ver); strcpy(cv.Vector, text); \
        NTSTATUS s_ = UN(RtlValidateCorrelationVector)(&cv); CHECKF(s_ == (want), "v%d \"%s\" got 0x%lx", (ver), text, (long)s_); } while (0)
    CVT(1, "tul4NUsfs9Cl7mOf.1", 0);
    CVT(1, "tul4NUsfs9Cl7mOf.0", 0);
    CVT(1, "tul4NUsfs9Cl7mOf.1.2.3", 0);
    CVT(1, "tul4NUsfs9Cl7mOf.2147483647", 0);
    CVT(1, "tul4NUsfs9Cl7mOf.2147483648", INVP);
    CVT(1, "tul4NUsfs9Cl7mOf.12345678901", INVP);
    CVT(1, "tul4NUsfs9Cl7mOf.", INVP);
    CVT(1, "tul4NUsfs9Cl7mOf.1.", INVP);
    CVT(1, "tul4NUsfs9Cl7mOf.1x", INVP);
    CVT(1, "tul4NUsfs9Cl7mOf", INVP);                 /* no index */
    CVT(1, "tul4NUsfs9Cl7m.1", INVP);                 /* base too short for v1 (16 chars) */
    CVT(1, "tul4NUsfs9Cl7mOfX.1", INVP);              /* base too long for v1 */
    CVT(2, "tul4NUsfs9Cl7mOfWtvXYZ.1", 0);            /* v2 base is 22 chars */
    CVT(2, "tul4NUsfs9Cl7mOf.1", INVP);
    CVT(2, "tul4NUsfs9Cl7mOfWtvXYZ.1.2", 0);
    CVT(3, "tul4NUsfs9Cl7mOf.1", INVP);               /* unknown version */
    CVT(0, "tul4NUsfs9Cl7mOf.1", INVP);
    EXPECT_ST(UN(RtlValidateCorrelationVector)(NULL), INVP);
}

static UNICODE_STRING us(const WCHAR *s) { UNICODE_STRING u; u.Length = (USHORT)(lstrlenW(s) * 2); u.MaximumLength = u.Length + 2; u.Buffer = (PWSTR)s; return u; }

TEST(rtl_net_ip_str_b_misc_name_in_expression) {
    REQUIRE(UN(RtlIsNameInExpression)); REQUIRE(UN(RtlIsNameInUnUpcasedExpression));
    static const struct { const WCHAR *expr, *name; int match; } c[] = {
        {L"*", L"anything.txt", 1}, {L"*", L"", 0}, {L"*.*", L"file", 0}, {L"*.*", L"a.b", 1},
        {L"*.TXT", L"A.TXT", 1}, {L"*.TXT", L"A.TXT.TXT", 1}, {L"*.TXT", L"A.DOC", 0}, {L"*.TXT", L"A.TXTX", 0},
        {L"A?C", L"ABC", 1}, {L"A?C", L"AC", 0}, {L"A?C", L"ABBC", 0}, {L"???", L"ABC", 1}, {L"???", L"AB", 0},
        {L"A*C", L"AC", 1}, {L"A*C", L"ABBBC", 1}, {L"A*C", L"ABD", 0},
        {L"ABC", L"ABC", 1}, {L"ABC", L"ABCD", 0}, {L"ABC", L"AB", 0},
        {L"A<", L"ABC", 1}, {L"A<.TXT", L"ABC.TXT", 1}, {L"A<.TXT", L"ABC.DOC", 0},   /* DOS_STAR: any run not crossing the last dot */
        {L"ABC>", L"ABC", 1}, {L"ABC>", L"ABCD", 1}, {L"ABC>", L"ABCDE", 0},           /* DOS_QM: zero or one char */
        {L"ABC\"TXT", L"ABC.TXT", 1}, {L"ABC\"", L"ABC.", 1}, {L"ABC\"", L"ABC", 1},   /* DOS_DOT */
        {L"AB>>", L"AB", 1}, {L"AB>>", L"ABCD", 1}, {L"AB>>", L"ABCDE", 0},
        {L"*A*B", L"XAYB", 1}, {L"*A*B", L"XAYC", 0},
        {L"", L"", 1}, {L"", L"A", 0}, {L"A", L"", 0},
    };
    for (unsigned i = 0; i < sizeof c / sizeof *c; i++) {
        UNICODE_STRING e = us(c[i].expr), n = us(c[i].name);
        BOOLEAN r = UN(RtlIsNameInExpression)(&e, &n, FALSE, NULL);
        CHECKF(r == c[i].match, "case-sens expr \"%ls\" name \"%ls\" got %d want %d", c[i].expr, c[i].name, r, c[i].match);
        r = UN(RtlIsNameInExpression)(&e, &n, TRUE, NULL);
        CHECKF(r == c[i].match, "ignore-case expr \"%ls\" name \"%ls\" got %d want %d", c[i].expr, c[i].name, r, c[i].match);
        r = UN(RtlIsNameInUnUpcasedExpression)(&e, &n, FALSE, NULL);
        CHECKF(r == c[i].match, "unupcased cs expr \"%ls\" name \"%ls\" got %d want %d", c[i].expr, c[i].name, r, c[i].match);
        r = UN(RtlIsNameInUnUpcasedExpression)(&e, &n, TRUE, NULL);
        CHECKF(r == c[i].match, "unupcased ic expr \"%ls\" name \"%ls\" got %d want %d", c[i].expr, c[i].name, r, c[i].match);
    }
    /* case: the expression passed to RtlIsNameInExpression must already be upcased when IgnoreCase is set;
       the name is upcased by the routine. The Un-upcased variant upcases both. */
    UNICODE_STRING e = us(L"*.TXT"), n = us(L"file.txt");
    EXPECT_EQ(UN(RtlIsNameInExpression)(&e, &n, TRUE, NULL), 1);
    EXPECT_EQ(UN(RtlIsNameInExpression)(&e, &n, FALSE, NULL), 0);
    UNICODE_STRING el = us(L"*.txt"), nu = us(L"FILE.TXT");
    EXPECT_EQ(UN(RtlIsNameInUnUpcasedExpression)(&el, &nu, TRUE, NULL), 1);
    EXPECT_EQ(UN(RtlIsNameInUnUpcasedExpression)(&el, &nu, FALSE, NULL), 0);
    EXPECT_EQ(UN(RtlIsNameInExpression)(&el, &nu, FALSE, NULL), 0);
    /* wildcard-free fast path is also exact */
    UNICODE_STRING e2 = us(L"ABC"), n2 = us(L"abc");
    EXPECT_EQ(UN(RtlIsNameInExpression)(&e2, &n2, TRUE, NULL), 1);
    EXPECT_EQ(UN(RtlIsNameInExpression)(&e2, &n2, FALSE, NULL), 0);
}

TEST(rtl_net_ip_str_b_misc_dos8dot3) {
    REQUIRE(UN(RtlIsNameLegalDOS8Dot3));
    static const struct { const WCHAR *name; int legal; int spaces; } c[] = {
        {L"FILE.TXT", 1, 0}, {L"file.txt", 1, 0}, {L"A", 1, 0}, {L"ABCDEFGH", 1, 0}, {L"ABCDEFGH.EXT", 1, 0},
        {L"ABCDEFGHI", 0, 0}, {L"ABCDEFGH.EXTX", 0, 0}, {L"A.B.C", 0, 0}, {L".EXT", 0, 0}, {L"A..B", 0, 0},
        {L"A B.TXT", 1, 1}, {L"AB.T X", 1, 1}, {L"A*B", 0, 0}, {L"A?B", 0, 0}, {L"A\"B", 0, 0}, {L"A<B", 0, 0},
        {L"A|B", 0, 0}, {L"A+B", 0, 0}, {L"A,B", 0, 0}, {L"A;B", 0, 0}, {L"A=B", 0, 0}, {L"A[B", 0, 0},
        {L"A$B", 1, 0}, {L"A~1.TXT", 1, 0}, {L"A-B_C.D", 1, 0},
        {L".", 1, 0}, {L"..", 1, 0}, {L"A.", 0, 0}, {L"", 1, 0}, {L"ABC\\D", 0, 0}, {L"A:B", 0, 0},
    };
    for (unsigned i = 0; i < sizeof c / sizeof *c; i++) {
        UNICODE_STRING u = us(c[i].name);
        BOOLEAN sp = 9;
        BOOLEAN r = UN(RtlIsNameLegalDOS8Dot3)(&u, NULL, &sp);
        CHECKF(r == c[i].legal, "\"%ls\" legal got %d want %d", c[i].name, r, c[i].legal);
        if (r) CHECKF(sp == c[i].spaces, "\"%ls\" spaces got %d want %d", c[i].name, sp, c[i].spaces);
        BOOLEAN r2 = UN(RtlIsNameLegalDOS8Dot3)(&u, NULL, NULL);        /* NULL spaces pointer is allowed */
        CHECKF(r2 == r, "\"%ls\" with NULL spaces", c[i].name);
    }
    /* OEM output string receives the upcased counted name */
    UNICODE_STRING u = us(L"abc.txt"); CHAR ob[16]; struct { USHORT L, M; PCHAR B; } o = { 0, sizeof ob, ob };
    BOOLEAN sp;
    EXPECT_EQ(UN(RtlIsNameLegalDOS8Dot3)(&u, &o, &sp), 1);
    EXPECT_EQ(o.L, 7); CHECK(!memcmp(ob, "ABC.TXT", 7));
    /* names over 12 characters are rejected before conversion */
    UNICODE_STRING lng = us(L"abcdefghijklm.txt");
    EXPECT_EQ(UN(RtlIsNameLegalDOS8Dot3)(&lng, NULL, &sp), 0);
}

TEST(rtl_net_ip_str_b_misc_is_text_unicode) {
    REQUIRE(UN(RtlIsTextUnicode));
    ULONG fl;
    static const WCHAR bom[] = { 0xFEFF, 'h', 'i' };
    fl = IS_TEXT_UNICODE_SIGNATURE;
    EXPECT_EQ(UN(RtlIsTextUnicode)(bom, sizeof bom, &fl), 1);
    EXPECT_EQ(fl, IS_TEXT_UNICODE_SIGNATURE);
    fl = 0xffffffff;
    EXPECT_EQ(UN(RtlIsTextUnicode)(bom, sizeof bom, &fl), 1);
    CHECK(fl & IS_TEXT_UNICODE_SIGNATURE);
    static const WCHAR rev[] = { 0xFFFE, 'h', 'i' };
    fl = IS_TEXT_UNICODE_REVERSE_SIGNATURE;
    EXPECT_EQ(UN(RtlIsTextUnicode)(rev, sizeof rev, &fl), 0);   /* reverse BOM: flagged, but not text */
    EXPECT_EQ(fl, IS_TEXT_UNICODE_REVERSE_SIGNATURE);
    fl = IS_TEXT_UNICODE_SIGNATURE;                       /* only signature test asked: reverse BOM does not satisfy it */
    EXPECT_EQ(UN(RtlIsTextUnicode)(rev, sizeof rev, &fl), 0);
    EXPECT_EQ(fl, 0);
    /* plain ASCII bytes */
    const char *asc = "Hello, this is plain ascii text.";
    fl = 0xffffffff;
    EXPECT_EQ(UN(RtlIsTextUnicode)(asc, (ULONG)strlen(asc), &fl), 0);
    /* UTF-16 English text */
    static const WCHAR txt[] = L"Hello, this is plain unicode text.";
    fl = 0xffffffff;
    EXPECT_EQ(UN(RtlIsTextUnicode)(txt, sizeof txt - 2, &fl), 1);
    t_note("ascii16 flags 0x%lx", fl);
    /* odd length can never be unicode */
    fl = IS_TEXT_UNICODE_ODD_LENGTH | IS_TEXT_UNICODE_SIGNATURE;
    EXPECT_EQ(UN(RtlIsTextUnicode)(bom, 5, &fl), 0);
    CHECK(fl & IS_TEXT_UNICODE_ODD_LENGTH);
    /* NULL result pointer is allowed */
    EXPECT_EQ(UN(RtlIsTextUnicode)(bom, sizeof bom, NULL), 1);
    /* embedded NULs make it not text */
    static const WCHAR nul[] = { 'a', 0, 'b', 'c' };
    fl = IS_TEXT_UNICODE_NULL_BYTES;
    UN(RtlIsTextUnicode)(nul, sizeof nul, &fl);
    EXPECT_EQ(fl, IS_TEXT_UNICODE_NULL_BYTES);        /* observed: the NULL_BYTES test result is reported back */
    /* tiny inputs */
    fl = 0xffffffff;
    EXPECT_EQ(UN(RtlIsTextUnicode)(bom, 0, &fl), 0);
    EXPECT_EQ(UN(RtlIsTextUnicode)(bom, 1, &fl), 0);
}

TEST(rtl_net_ip_str_b_misc_is_normalized_string) {
    REQUIRE(UN(RtlIsNormalizedString));
    BOOLEAN r;
    static const WCHAR ascii[] = L"abc", dec[] = { 'e', 0x301, 0 }, pre[] = { 0xe9, 0 };
    r = 9; EXPECT_EQ(UN(RtlIsNormalizedString)(1, ascii, -1, &r), 0); EXPECT_EQ(r, 1);   /* NormalizationC */
    r = 9; EXPECT_EQ(UN(RtlIsNormalizedString)(1, ascii, 3, &r), 0); EXPECT_EQ(r, 1);
    r = 9; EXPECT_EQ(UN(RtlIsNormalizedString)(1, pre, -1, &r), 0); EXPECT_EQ(r, 1);
    r = 9; EXPECT_EQ(UN(RtlIsNormalizedString)(1, dec, -1, &r), 0); EXPECT_EQ(r, 0);    /* e + combining acute is not NFC */
    r = 9; EXPECT_EQ(UN(RtlIsNormalizedString)(2, dec, -1, &r), 0); EXPECT_EQ(r, 1);    /* NormalizationD */
    r = 9; EXPECT_EQ(UN(RtlIsNormalizedString)(2, pre, -1, &r), 0); EXPECT_EQ(r, 0);
    r = 9; EXPECT_EQ(UN(RtlIsNormalizedString)(1, dec, 1, &r), 0); EXPECT_EQ(r, 1);     /* length cuts the sequence */
    r = 9; EXPECT_EQ(UN(RtlIsNormalizedString)(1, dec, 0, &r), 0); EXPECT_EQ(r, 1);     /* empty is normalized */
    EXPECT_ST(UN(RtlIsNormalizedString)(1, NULL, -1, &r), INVP);
    EXPECT_ST(UN(RtlIsNormalizedString)(1, ascii, -1, NULL), INVP);
    EXPECT_ST(UN(RtlIsNormalizedString)(1, ascii, -2, &r), INVP);
    EXPECT_ST(UN(RtlIsNormalizedString)(0, ascii, -1, &r), INVP);
    NTSTATUS s = UN(RtlIsNormalizedString)(0x1234, ascii, -1, &r);
    CHECKF(s < 0, "unknown normalization form rejected, got 0x%lx", (long)s);
}

TEST(rtl_net_ip_str_b_misc_untrusted_object) {
    REQUIRE(UN(RtlIsUntrustedObject));
    BOOLEAN u = 9;
    EXPECT_ST(UN(RtlIsUntrustedObject)(NULL, NULL, &u), INVP); EXPECT_EQ(u, 1);        /* output pre-set to TRUE */
    u = 9; EXPECT_ST(UN(RtlIsUntrustedObject)(GetCurrentProcess(), (PVOID)8, &u), INVP);
    u = 9; EXPECT_ST(UN(RtlIsUntrustedObject)((HANDLE)(ULONG_PTR)0x77777770, NULL, &u), 0xC0000008); EXPECT_EQ(u, 1);
    /* a plain event: no untrusted-integrity ACE, so it is trusted */
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    u = 9; NTSTATUS s = UN(RtlIsUntrustedObject)(ev, NULL, &u);
    EXPECT_EQ(s, 0); EXPECT_EQ(u, 0);
    CloseHandle(ev);
    u = 9; s = UN(RtlIsUntrustedObject)(GetCurrentProcess(), NULL, &u);
    CHECKF(s == 0 || s == (NTSTATUS)0xC0000022, "process object status 0x%lx", (long)s);
    if (s == 0) EXPECT_EQ(u, 0);
}

TEST(rtl_net_ip_str_b_misc_handle_table) {
    REQUIRE(UN(RtlInitializeHandleTable)); REQUIRE(UN(RtlIsValidHandle)); REQUIRE(UN(RtlIsValidIndexHandle));
    REQUIRE(UN(RtlAllocateHandle)); REQUIRE(UN(RtlFreeHandle)); REQUIRE(UN(RtlDestroyHandleTable));
    struct { ULONG Max; ULONG Size; ULONG R[2]; PVOID Free, Comm, Uncomm, MaxRes; } tbl;
    memset(&tbl, 0xcc, sizeof tbl);
    UN(RtlInitializeHandleTable)(100, 32, &tbl);
    EXPECT_EQ(tbl.Max, 100); EXPECT_EQ(tbl.Size, 32);
    EXPECT_EQ(tbl.R[0], 0); EXPECT_EQ(tbl.R[1], 0);
    EXPECT_EQ(tbl.Free, 0); EXPECT_EQ(tbl.Comm, 0); EXPECT_EQ(tbl.Uncomm, 0); EXPECT_EQ(tbl.MaxRes, 0);
    /* the sign bit of the entry size is moved into a flag word */
    memset(&tbl, 0xcc, sizeof tbl);
    UN(RtlInitializeHandleTable)(50, 0x80000040, &tbl);
    EXPECT_EQ(tbl.Max, 50); EXPECT_EQ(tbl.Size, 0x40); EXPECT_EQ(tbl.R[0], 1);
    memset(&tbl, 0xcc, sizeof tbl);
    UN(RtlInitializeHandleTable)(100, 32, &tbl);
    /* use it */
    ULONG idx = 0xdead; BYTE *e0 = UN(RtlAllocateHandle)(&tbl, &idx);
    if (!e0) { t_skip("RtlAllocateHandle failed"); return; }
    EXPECT_EQ(idx, 0);
    EXPECT_EQ(UN(RtlIsValidHandle)(&tbl, e0), 0);        /* allocated but not marked valid (bit 0 of first dword) */
    *(ULONG *)e0 |= 1;
    EXPECT_EQ(UN(RtlIsValidHandle)(&tbl, e0), 1);
    EXPECT_EQ(UN(RtlIsValidHandle)(&tbl, NULL), 0);
    EXPECT_EQ(UN(RtlIsValidHandle)(&tbl, e0 + 1), 0);    /* misaligned */
    EXPECT_EQ(UN(RtlIsValidHandle)(&tbl, e0 - 32), 0);   /* below the committed range */
    EXPECT_EQ(UN(RtlIsValidHandle)(&tbl, (BYTE *)tbl.Uncomm), 0);   /* at/after uncommitted limit */
    void *out = NULL;
    EXPECT_EQ(UN(RtlIsValidIndexHandle)(&tbl, 0, &out), 1); EXPECT_EQ(out, e0);
    out = NULL; EXPECT_EQ(UN(RtlIsValidIndexHandle)(&tbl, 1, &out), 0); EXPECT_EQ(out, NULL);
    ULONG idx1; BYTE *e1 = UN(RtlAllocateHandle)(&tbl, &idx1);
    if (e1) {
        EXPECT_EQ(idx1, 1); EXPECT_EQ(e1, e0 + 32);
        *(ULONG *)e1 |= 1;
        out = NULL; EXPECT_EQ(UN(RtlIsValidIndexHandle)(&tbl, 1, &out), 1); EXPECT_EQ(out, e1);
        *(ULONG *)e1 &= ~1u;
        UN(RtlFreeHandle)(&tbl, e1);
    }
    *(ULONG *)e0 &= ~1u;
    UN(RtlFreeHandle)(&tbl, e0);
    UN(RtlDestroyHandleTable)(&tbl);
}

TEST(rtl_net_ip_str_b_misc_initialize_sid_ex) {
    REQUIRE(UN(RtlInitializeSidEx));
    SID_IDENTIFIER_AUTHORITY nt = { {0,0,0,0,0,5} };
    union { SID s; BYTE b[64]; } u;
    memset(&u, 0xcc, sizeof u);
    EXPECT_EQ(UN(RtlInitializeSidEx)(&u.s, &nt, 0), 0);
    EXPECT_EQ(u.b[0], 1); EXPECT_EQ(u.b[1], 0); CHECK(!memcmp(u.b + 2, nt.Value, 6));
    memset(&u, 0xcc, sizeof u);
    EXPECT_EQ(UN(RtlInitializeSidEx)(&u.s, &nt, 2, 32, 544), 0);
    EXPECT_EQ(u.b[1], 2); EXPECT_EQ(*(ULONG *)(u.b + 8), 32); EXPECT_EQ(*(ULONG *)(u.b + 12), 544);
    EXPECT_EQ(IsValidSid(&u.s), 1);
    PSTR str = NULL;
    memset(&u, 0xcc, sizeof u);
    EXPECT_EQ(UN(RtlInitializeSidEx)(&u.s, &nt, 5, 1, 2, 3, 4, 5), 0);
    EXPECT_EQ(u.b[1], 5);
    for (int i = 0; i < 5; i++) EXPECT_EQ(*(ULONG *)(u.b + 8 + 4 * i), i + 1);
    (void)str;
    memset(&u, 0xcc, sizeof u);
    EXPECT_EQ(UN(RtlInitializeSidEx)(&u.s, &nt, 15, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15), 0);
    EXPECT_EQ(*(ULONG *)(u.b + 8 + 4 * 14), 15);
    NTSTATUS s = UN(RtlInitializeSidEx)(&u.s, &nt, 16, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16);
        EXPECT_ST(s, INVP);
}

TEST(rtl_net_ip_str_b_misc_slist_head) {
    REQUIRE(UN(RtlInitializeSListHead));
    SLIST_HEADER *h = _aligned_malloc(sizeof *h, 16);
    memset(h, 0xcc, sizeof *h);
    UN(RtlInitializeSListHead)(h);
    BYTE *b = (BYTE *)h; int z = 1;
    for (unsigned i = 0; i < sizeof *h; i++) if (b[i]) z = 0;
    CHECK(z);
    SLIST_ENTRY *e = _aligned_malloc(16, 16);
    e->Next = NULL;
    CHECK(InterlockedPushEntrySList(h, e) == NULL);
    CHECK(QueryDepthSList(h) == 1);
    CHECK(InterlockedPopEntrySList(h) == e);
    UN(RtlInitializeSListHead)(h);
    CHECK(QueryDepthSList(h) == 0);
    _aligned_free(e); _aligned_free(h);
}

TEST(rtl_net_ip_str_b_misc_multiple_heap) {
    REQUIRE(UN(RtlMultipleAllocateHeap)); REQUIRE(UN(RtlMultipleFreeHeap));
    HANDLE heap = HeapCreate(0, 0, 0);
    PVOID arr[8];
    memset(arr, 0, sizeof arr);
    EXPECT_EQ(UN(RtlMultipleAllocateHeap)(heap, HEAP_ZERO_MEMORY, 64, 8, arr), 8);
    for (int i = 0; i < 8; i++) {
        CHECK(arr[i] != NULL);
        CHECK(HeapSize(heap, 0, arr[i]) >= 64);
        for (int j = 0; j < 8; j++) if (i != j) CHECK(arr[i] != arr[j]);
        CHECK(*(ULONG64 *)arr[i] == 0);
    }
    EXPECT_EQ(UN(RtlMultipleFreeHeap)(heap, 0, 8, arr), 8);
    EXPECT_EQ(UN(RtlMultipleAllocateHeap)(heap, 0, 16, 0, arr), 0);
    EXPECT_EQ(UN(RtlMultipleFreeHeap)(heap, 0, 0, arr), 0);
    /* allocation failure stops early: a fixed-size heap cannot satisfy every request */
    HANDLE small = HeapCreate(HEAP_NO_SERIALIZE, 0x10000, 0x10000);
    if (small) {
        PVOID big[8]; memset(big, 0, sizeof big);
        ULONG n = UN(RtlMultipleAllocateHeap)(small, 0, 0x6000, 8, big);
        CHECKF(n >= 1 && n < 8, "partial allocation count %lu", n);
        CHECK(big[n] == NULL);
        EXPECT_EQ(UN(RtlMultipleFreeHeap)(small, 0, n, big), n);
        HeapDestroy(small);
    }
    HeapDestroy(heap);
}

TEST(rtl_net_ip_str_b_misc_elapsed_time_fields) {
    REQUIRE(UN(RtlTimeToElapsedTimeFields));
    typedef struct { SHORT Year, Month, Day, Hour, Minute, Second, Milliseconds, Weekday; } TF;
    LARGE_INTEGER t; TF f;
    #define MS(d,h,m,s,ms) (((((LONGLONG)(d) * 24 + (h)) * 60 + (m)) * 60 + (s)) * 1000 + (ms)) * 10000
    t.QuadPart = MS(0, 0, 0, 0, 0); memset(&f, 0x55, sizeof f);
    UN(RtlTimeToElapsedTimeFields)(&t, &f);
    EXPECT_EQ(f.Day, 0); EXPECT_EQ(f.Hour, 0); EXPECT_EQ(f.Minute, 0); EXPECT_EQ(f.Second, 0); EXPECT_EQ(f.Milliseconds, 0);
    t.QuadPart = MS(1, 2, 3, 4, 5); memset(&f, 0x55, sizeof f);
    UN(RtlTimeToElapsedTimeFields)(&t, &f);
    EXPECT_EQ(f.Day, 1); EXPECT_EQ(f.Hour, 2); EXPECT_EQ(f.Minute, 3); EXPECT_EQ(f.Second, 4); EXPECT_EQ(f.Milliseconds, 5);
    t.QuadPart = MS(0, 23, 59, 59, 999) + 9999;   /* sub-millisecond ticks are dropped */
    UN(RtlTimeToElapsedTimeFields)(&t, &f);
    EXPECT_EQ(f.Day, 0); EXPECT_EQ(f.Hour, 23); EXPECT_EQ(f.Minute, 59); EXPECT_EQ(f.Second, 59); EXPECT_EQ(f.Milliseconds, 999);
    t.QuadPart = MS(1000, 12, 30, 15, 250);
    UN(RtlTimeToElapsedTimeFields)(&t, &f);
    EXPECT_EQ(f.Hour, 12); EXPECT_EQ(f.Minute, 30); EXPECT_EQ(f.Second, 15); EXPECT_EQ(f.Milliseconds, 250);
    t.QuadPart = MS(0, 0, 0, 0, 1);
    UN(RtlTimeToElapsedTimeFields)(&t, &f);
    EXPECT_EQ(f.Milliseconds, 1); EXPECT_EQ(f.Second, 0);
    t.QuadPart = 9999;
    UN(RtlTimeToElapsedTimeFields)(&t, &f);
    EXPECT_EQ(f.Milliseconds, 0);
}

TEST(rtl_net_ip_str_b_misc_valid_acl_sd) {
    REQUIRE(UN(RtlValidAcl)); REQUIRE(UN(RtlValidRelativeSecurityDescriptor));
    union { ACL a; BYTE b[256]; } u; memset(&u, 0, sizeof u);
    CHECK(InitializeAcl(&u.a, sizeof u, ACL_REVISION));
    EXPECT_EQ(UN(RtlValidAcl)(&u.a), 1);
    BYTE sidb[16] = {1, 1, 0,0,0,0,0,1, 0,0,0,0};
    CHECK(AddAccessAllowedAce(&u.a, ACL_REVISION, GENERIC_ALL, sidb));
    EXPECT_EQ(UN(RtlValidAcl)(&u.a), 1);
    USHORT orig = u.a.AclSize;
    u.a.AclSize = 9; EXPECT_EQ(UN(RtlValidAcl)(&u.a), 0);          /* too small for its ACE */
    u.a.AclSize = 7; EXPECT_EQ(UN(RtlValidAcl)(&u.a), 0);          /* smaller than header */
    u.a.AclSize = orig;
    u.a.AclRevision = 1; EXPECT_EQ(UN(RtlValidAcl)(&u.a), 0);
    u.a.AclRevision = 5; EXPECT_EQ(UN(RtlValidAcl)(&u.a), 0);
    u.a.AclRevision = ACL_REVISION; u.a.AceCount = 2; EXPECT_EQ(UN(RtlValidAcl)(&u.a), 0);   /* ACE count beyond data */
    u.a.AceCount = 1;
    EXPECT_EQ(UN(RtlValidAcl)(&u.a), 1);
    /* relative security descriptor */
    union { SECURITY_DESCRIPTOR_RELATIVE sd; BYTE b[256]; } r; memset(&r, 0, sizeof r);
    r.sd.Revision = 1; r.sd.Control = SE_SELF_RELATIVE;
    EXPECT_EQ(UN(RtlValidRelativeSecurityDescriptor)(&r.sd, sizeof r.sd, 0), 1);
    EXPECT_EQ(UN(RtlValidRelativeSecurityDescriptor)(&r.sd, sizeof r.sd - 1, 0), 0);
    EXPECT_EQ(UN(RtlValidRelativeSecurityDescriptor)(&r.sd, 0, 0), 0);
    r.sd.Control = 0; EXPECT_EQ(UN(RtlValidRelativeSecurityDescriptor)(&r.sd, sizeof r.sd, 0), 0);   /* not self-relative */
    r.sd.Control = SE_SELF_RELATIVE; r.sd.Revision = 2;
    EXPECT_EQ(UN(RtlValidRelativeSecurityDescriptor)(&r.sd, sizeof r.sd, 0), 0);
    r.sd.Revision = 1;
    /* owner required when OWNER_SECURITY_INFORMATION is asked */
    EXPECT_EQ(UN(RtlValidRelativeSecurityDescriptor)(&r.sd, sizeof r.sd, OWNER_SECURITY_INFORMATION), 0);
    memcpy(r.b + 64, sidb, 12); r.sd.Owner = 64;
    EXPECT_EQ(UN(RtlValidRelativeSecurityDescriptor)(&r.sd, sizeof r.sd + 64, OWNER_SECURITY_INFORMATION), 1);
    r.sd.Owner = 250;                                                     /* SID would run past the buffer */
    EXPECT_EQ(UN(RtlValidRelativeSecurityDescriptor)(&r.sd, 256, 0), 0);
    r.sd.Owner = 65;                                                      /* misaligned offset */
    EXPECT_EQ(UN(RtlValidRelativeSecurityDescriptor)(&r.sd, 256, 0), 0);
}

TEST(rtl_net_ip_str_b_misc_validate_process_heaps) {
    REQUIRE(UN(RtlValidateProcessHeaps));
    EXPECT_EQ(UN(RtlValidateProcessHeaps)(), 1);
    HANDLE heap = HeapCreate(0, 0, 0);
    PVOID p = HeapAlloc(heap, 0, 100);
    EXPECT_EQ(UN(RtlValidateProcessHeaps)(), 1);
    HeapFree(heap, 0, p); HeapDestroy(heap);
    EXPECT_EQ(UN(RtlValidateProcessHeaps)(), 1);
}

TEST(rtl_net_ip_str_b_misc_parent_of_child_appcontainer) {
    REQUIRE(UN(RtlIsParentOfChildAppContainer));
    static const BYTE app[6] = {0,0,0,0,0,15};
    ULONG par[8] = {2, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777};
    ULONG chd[12] = {2, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777,
                     0xa1a1a1a1, 0xb2b2b2b2, 0xc3c3c3c3, 0xd4d4d4d4};
    ULONG oth[12]; memcpy(oth, chd, sizeof oth); oth[3] ^= 1;
    BYTE ps[64], cs[64], os[64], ns[32];
    mksid(ps, 8, app, par); mksid(cs, 12, app, chd); mksid(os, 12, app, oth);
    ULONG nt[2] = {32, 544}; static const BYTE ntauth[6] = {0,0,0,0,0,5}; mksid(ns, 2, ntauth, nt);
    BOOLEAN a = UN(RtlIsParentOfChildAppContainer)(ps, cs);
    BOOLEAN b = UN(RtlIsParentOfChildAppContainer)(cs, ps);
    /* observed on Windows 10: (8-sub-authority parent, 12-sub-authority child) matches, the swapped order does not */
    CHECKF(a == 1 && b == 0, "(parent,child)=%d (child,parent)=%d", a, b);
    EXPECT_EQ(UN(RtlIsParentOfChildAppContainer)(ps, os), 0);       /* different parent hash */
    EXPECT_EQ(UN(RtlIsParentOfChildAppContainer)(ps, ps), 0);
    EXPECT_EQ(UN(RtlIsParentOfChildAppContainer)(cs, cs), 0);
    EXPECT_EQ(UN(RtlIsParentOfChildAppContainer)(ns, cs), 0);
    EXPECT_EQ(UN(RtlIsParentOfChildAppContainer)(ps, ns), 0);
}

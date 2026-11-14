/* Internal Rtlp helpers, string-size helpers, VerSetConditionMask and the ship-assert buffer.
 * See EVIDENCE.md. */
#include "t.h"

typedef struct { SHORT Year, Month, Day, Hour, Minute, Second, Milliseconds, Weekday; } TF;
typedef long long i64;
#define S(x) ((NTSTATUS)(x))

UDECL(VOID, RtlpTimeToTimeFields, (const LARGE_INTEGER *, TF *, const LARGE_INTEGER *));
UDECL(BOOLEAN, RtlpTimeFieldsToTime, (const TF *, LARGE_INTEGER *, const LARGE_INTEGER *));
UDECL(VOID, RtlTimeToTimeFields, (const LARGE_INTEGER *, TF *));
UDECL(BOOLEAN, RtlTimeFieldsToTime, (TF *, LARGE_INTEGER *));
UDECL(ULONG, RtlxAnsiStringToUnicodeSize, (const ANSI_STRING *));
UDECL(ULONG, RtlxOemStringToUnicodeSize, (const ANSI_STRING *));
UDECL(ULONG, RtlxUnicodeStringToAnsiSize, (const UNICODE_STRING *));
UDECL(ULONG, RtlxUnicodeStringToOemSize, (const UNICODE_STRING *));
UDECL(ULONG, RtlAnsiStringToUnicodeSize, (const ANSI_STRING *));
UDECL(ULONG, RtlOemStringToUnicodeSize, (const ANSI_STRING *));
UDECL(ULONGLONG, VerSetConditionMask, (ULONGLONG, ULONG, UCHAR));
UDECL(VOID, ShipAssertGetBufferInfo, (PVOID *, PVOID *));
UDECL(VOID, ShipAssert, (ULONG, ULONG));
UDECL(NTSTATUS, RtlpNtSetValueKey, (HANDLE, ULONG, PVOID, ULONG));
UDECL(VOID, RtlpUnWaitCriticalSection, (CRITICAL_SECTION *));
UDECL(VOID, RtlpWaitForCriticalSection, (CRITICAL_SECTION *));
UDECL(ULONG, RtlpSetInstallLanguage, (ULONG64, const WCHAR *, ULONG64, ULONG64));
UDECL(ULONG, RtlpRefreshCachedUILanguage, (const WCHAR *, ULONG64, ULONG64, ULONG64));

/* ---------------------------------------------------------- time fields */
static i64 days_from_civil(int y, int m, int d) { /* days since 1970-01-01 */
    y -= m <= 2;
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (i64)era * 146097 + (i64)doe - 719468;
}
static i64 ft_of(int y, int mo, int d, int h, int mi, int s, int ms) {
    i64 days = days_from_civil(y, mo, d) + 134774; /* 1601-01-01 .. 1970-01-01 */
    return (((days * 24 + h) * 60 + mi) * 60 + s) * 10000000LL + (i64)ms * 10000;
}
static int weekday_of(int y, int mo, int d) { /* 0 = Sunday */
    i64 z = days_from_civil(y, mo, d) + 4; /* 1970-01-01 was Thursday (4) */
    return (int)(((z % 7) + 7) % 7);
}

static const struct { int y, mo, d, h, mi, s, ms; } tcases[] = {
    { 1601, 1, 1, 0, 0, 0, 0 }, { 1601, 12, 31, 23, 59, 59, 999 }, { 1970, 1, 1, 0, 0, 0, 0 },
    { 1999, 12, 31, 23, 59, 59, 999 }, { 2000, 1, 1, 0, 0, 0, 0 }, { 2000, 2, 29, 12, 34, 56, 789 },
    { 1900, 2, 28, 1, 2, 3, 4 }, { 1900, 3, 1, 0, 0, 0, 0 }, { 2024, 2, 29, 23, 0, 0, 1 },
    { 2100, 3, 1, 0, 0, 1, 0 }, { 2023, 12, 31, 6, 7, 8, 9 }, { 3000, 7, 4, 15, 16, 17, 18 },
    { 9999, 12, 31, 23, 59, 59, 999 }, { 30827, 12, 31, 23, 59, 59, 999 },
};

TEST(time_to_fields) {
    REQUIRE(UN(RtlpTimeToTimeFields)); REQUIRE(UN(RtlTimeToTimeFields));
    for (size_t i = 0; i < sizeof tcases / sizeof tcases[0]; i++) {
        LARGE_INTEGER t; t.QuadPart = ft_of(tcases[i].y, tcases[i].mo, tcases[i].d, tcases[i].h, tcases[i].mi, tcases[i].s, tcases[i].ms);
        TF f, g; memset(&f, 0x77, sizeof f); memset(&g, 0x55, sizeof g);
        UN(RtlpTimeToTimeFields)(&t, &f, NULL);
        EXPECT_EQ(f.Year, tcases[i].y); EXPECT_EQ(f.Month, tcases[i].mo); EXPECT_EQ(f.Day, tcases[i].d);
        EXPECT_EQ(f.Hour, tcases[i].h); EXPECT_EQ(f.Minute, tcases[i].mi); EXPECT_EQ(f.Second, tcases[i].s);
        EXPECT_EQ(f.Milliseconds, tcases[i].ms);
        EXPECT_EQ(f.Weekday, weekday_of(tcases[i].y, tcases[i].mo, tcases[i].d));
        UN(RtlTimeToTimeFields)(&t, &g);
        EXPECT_EQ(memcmp(&f, &g, sizeof f), 0);
        /* sub-millisecond 100ns ticks are dropped */
        LARGE_INTEGER t2; t2.QuadPart = t.QuadPart + 9999;
        UN(RtlpTimeToTimeFields)(&t2, &g, NULL);
        EXPECT_EQ(memcmp(&f, &g, sizeof f), 0);
    }
    LARGE_INTEGER z = { 0 }; TF f;
    UN(RtlpTimeToTimeFields)(&z, &f, NULL);
    EXPECT_EQ(f.Weekday, 1); /* 1601-01-01 was a Monday */
}

TEST(fields_to_time) {
    REQUIRE(UN(RtlpTimeFieldsToTime)); REQUIRE(UN(RtlpTimeToTimeFields)); REQUIRE(UN(RtlTimeFieldsToTime));
    for (size_t i = 0; i < sizeof tcases / sizeof tcases[0]; i++) {
        TF f = { (SHORT)tcases[i].y, (SHORT)tcases[i].mo, (SHORT)tcases[i].d, (SHORT)tcases[i].h, (SHORT)tcases[i].mi, (SHORT)tcases[i].s, (SHORT)tcases[i].ms, 0x1234 /* ignored */ };
        LARGE_INTEGER t, u; t.QuadPart = 0x7777; u.QuadPart = 0x5555;
        EXPECT_EQ(UN(RtlpTimeFieldsToTime)(&f, &t, NULL), 1);
        EXPECT_EQ(t.QuadPart, ft_of(tcases[i].y, tcases[i].mo, tcases[i].d, tcases[i].h, tcases[i].mi, tcases[i].s, tcases[i].ms));
        EXPECT_EQ(UN(RtlTimeFieldsToTime)(&f, &u), 1);
        EXPECT_EQ(t.QuadPart, u.QuadPart);
        TF back; UN(RtlpTimeToTimeFields)(&t, &back, NULL);
        EXPECT_EQ(back.Year, f.Year); EXPECT_EQ(back.Month, f.Month); EXPECT_EQ(back.Day, f.Day);
        EXPECT_EQ(back.Hour, f.Hour); EXPECT_EQ(back.Minute, f.Minute); EXPECT_EQ(back.Second, f.Second); EXPECT_EQ(back.Milliseconds, f.Milliseconds);
    }
}

TEST(fields_to_time_invalid) {
    REQUIRE(UN(RtlpTimeFieldsToTime));
    static const TF bad[] = {
        { 1600, 12, 31, 23, 59, 59, 999, 0 },  /* before the epoch of FILETIME */
        { 2000, 0, 1, 0, 0, 0, 0, 0 }, { 2000, 13, 1, 0, 0, 0, 0, 0 },
        { 2000, 1, 0, 0, 0, 0, 0, 0 }, { 2000, 1, 32, 0, 0, 0, 0, 0 },
        { 2001, 2, 29, 0, 0, 0, 0, 0 },  /* not a leap year */
        { 1900, 2, 29, 0, 0, 0, 0, 0 },  /* century non-leap */
        { 2000, 4, 31, 0, 0, 0, 0, 0 },
        { 2000, 1, 1, 24, 0, 0, 0, 0 }, { 2000, 1, 1, 0, 60, 0, 0, 0 },
        { 2000, 1, 1, 0, 0, 60, 0, 0 }, { 2000, 1, 1, 0, 0, 0, 1000, 0 },
        { 2000, 1, 1, -1, 0, 0, 0, 0 }, { 2000, -1, 1, 0, 0, 0, 0, 0 },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        LARGE_INTEGER t; t.QuadPart = 0x1234;
        EXPECT_EQ(UN(RtlpTimeFieldsToTime)(&bad[i], &t, NULL), 0);
    }
    TF ok = { 2000, 2, 29, 0, 0, 0, 0, 0 }; LARGE_INTEGER t;
    EXPECT_EQ(UN(RtlpTimeFieldsToTime)(&ok, &t, NULL), 1);   /* 2000 is a leap year */
    TF ok2 = { 2000, 12, 31, 23, 59, 59, 999, 0 };
    EXPECT_EQ(UN(RtlpTimeFieldsToTime)(&ok2, &t, NULL), 1);
}

/* ---------------------------------------------------- string size helpers */
TEST(string_size_helpers) {
    REQUIRE(UN(RtlxAnsiStringToUnicodeSize)); REQUIRE(UN(RtlxOemStringToUnicodeSize));
    REQUIRE(UN(RtlxUnicodeStringToAnsiSize)); REQUIRE(UN(RtlxUnicodeStringToOemSize));
    char txt[] = "Hello, world";
    ANSI_STRING a = { 0, sizeof txt, txt };
    UNICODE_STRING u; WCHAR wtxt[] = L"Hello, world"; u.Buffer = wtxt; u.MaximumLength = sizeof wtxt;
    /* the ASCII range is single-byte in every ANSI/OEM code page: n chars <-> 2n bytes (+ terminator) */
    static const USHORT lens[] = { 0, 1, 5, 12 };
    for (size_t i = 0; i < 4; i++) {
        a.Length = lens[i]; u.Length = (USHORT)(lens[i] * 2);
        EXPECT_EQ(UN(RtlxAnsiStringToUnicodeSize)(&a), lens[i] * 2u + 2);
        EXPECT_EQ(UN(RtlxOemStringToUnicodeSize)(&a), lens[i] * 2u + 2);
        EXPECT_EQ(UN(RtlxUnicodeStringToAnsiSize)(&u), lens[i] + 1u);
        EXPECT_EQ(UN(RtlxUnicodeStringToOemSize)(&u), lens[i] + 1u);
    }
    /* Length, not MaximumLength or the terminator, decides the answer */
    a.Length = 3; a.MaximumLength = 12; EXPECT_EQ(UN(RtlxAnsiStringToUnicodeSize)(&a), 8);
    u.Length = 6; u.MaximumLength = 24; EXPECT_EQ(UN(RtlxUnicodeStringToAnsiSize)(&u), 4);
    /* Nt-style aliases share the implementation */
    EXPECT_EQ(t_proc("RtlxAnsiStringToUnicodeSize") == t_proc("RtlxOemStringToUnicodeSize"), 1);
    EXPECT_EQ(t_proc("RtlxAnsiStringToUnicodeSize") == t_proc("RtlAnsiStringToUnicodeSize"), 1);
    EXPECT_EQ(t_proc("RtlxOemStringToUnicodeSize") == t_proc("RtlOemStringToUnicodeSize"), 1);
    EXPECT_EQ(UN(RtlxUnicodeStringToOemSize) != NULL, 1);
    /* embedded non-ASCII Latin-1 text: one wide char per byte in SBCS pages; just check it is bounded */
    char hi[] = { 'a', (char)0xe9, 'b' }; ANSI_STRING h = { 3, 3, hi };
    ULONG n = UN(RtlxAnsiStringToUnicodeSize)(&h);
    CHECK(n >= 4 + 2 && n <= 6 + 2);
}

/* ----------------------------------------------------------- VerSetConditionMask */
TEST(ver_set_condition_mask) {
    REQUIRE(UN(VerSetConditionMask));
    const ULONGLONG TOP = 1ULL << 63;
    /* one bit per field; each field is a 3-bit condition at bit (3 * index of the type bit) */
    static const struct { ULONG type; int idx; } fields[] = {
        { 0x01, 0 }, { 0x02, 1 }, { 0x04, 2 }, { 0x08, 3 }, { 0x10, 4 }, { 0x20, 5 }, { 0x40, 6 }, { 0x80, 7 },
    };
    for (size_t i = 0; i < 8; i++)
        for (UCHAR c = 1; c <= 7; c++) {
            ULONGLONG m = UN(VerSetConditionMask)(0, fields[i].type, c);
            EXPECT_EQ(m, TOP | ((ULONGLONG)c << (3 * fields[i].idx)));
        }
    /* accumulation: later calls OR into the earlier mask */
    ULONGLONG m = 0;
    m = UN(VerSetConditionMask)(m, 0x02, 3); m = UN(VerSetConditionMask)(m, 0x01, 5); m = UN(VerSetConditionMask)(m, 0x20, 2);
    EXPECT_EQ(m, TOP | (3ULL << 3) | 5ULL | (2ULL << 15));
    /* same field again ORs bits rather than replacing them */
    EXPECT_EQ(UN(VerSetConditionMask)(m, 0x01, 2), m | 2ULL);
    /* only the low three bits of the condition are used */
    EXPECT_EQ(UN(VerSetConditionMask)(0, 0x01, 0x0b), TOP | 3ULL);
    EXPECT_EQ(UN(VerSetConditionMask)(0, 0x01, 0), TOP);
    /* an empty type mask yields zero, discarding the incoming mask */
    EXPECT_EQ(UN(VerSetConditionMask)(0x1234, 0, 3), 0);
    EXPECT_EQ(UN(VerSetConditionMask)(TOP | 7, 0, 7), 0);
    /* higher type bits are not rejected */
    EXPECT_EQ(UN(VerSetConditionMask)(0, 0x100, 1), TOP | (1ULL << 24));
    /* when several type bits are given, the highest one selects the field */
    EXPECT_EQ(UN(VerSetConditionMask)(0, 0x03, 1), TOP | (1ULL << 3));
    EXPECT_EQ(UN(VerSetConditionMask)(0, 0x81, 4), TOP | (4ULL << 21));
}

/* ----------------------------------------------------------- ship assert */
TEST(ship_assert_buffer_info) {
    REQUIRE(UN(ShipAssertGetBufferInfo));
    PVOID a = (PVOID)1, b = (PVOID)2;
    UN(ShipAssertGetBufferInfo)(&a, &b);
    CHECK(a != (PVOID)1 && a != NULL); CHECK(b != (PVOID)2 && b != NULL);
    PVOID a2 = NULL, b2 = NULL;
    UN(ShipAssertGetBufferInfo)(&a2, &b2);
    EXPECT_EQ(a2, a); EXPECT_EQ(b2, b);           /* both are fixed addresses inside ntdll */
    EXPECT_EQ(((ULONG_PTR)b) & 3, 0);             /* the counter is a naturally aligned ULONG */
    EXPECT_EQ(IsBadReadPtr(a, 8), 0); EXPECT_EQ(IsBadReadPtr(b, 4), 0);
    PVOID only = NULL;
    UN(ShipAssertGetBufferInfo)(&only, NULL); EXPECT_EQ(only, a);   /* each output is optional */
    only = NULL; UN(ShipAssertGetBufferInfo)(NULL, &only); EXPECT_EQ(only, b);
    UN(ShipAssertGetBufferInfo)(NULL, NULL);
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    CHECK((char *)a > (char *)nt && (char *)a < (char *)nt + 0x400000);
}

TEST(ship_assert_counter) {
    REQUIRE(UN(ShipAssert)); REQUIRE(UN(ShipAssertGetBufferInfo));
    volatile ULONG *cnt = NULL; PVOID buf = NULL;
    UN(ShipAssertGetBufferInfo)(&buf, (PVOID *)&cnt);
    USHORT *flags = (USHORT *)((char *)NtCurrentTeb() + 0x17ee);
    USHORT before = *flags;
    ULONG c0 = *cnt;
    UN(ShipAssert)(0x1111, 0x2222);
    EXPECT_EQ(*flags, before);                    /* the re-entrancy bit is dropped again on return */
    ULONG c1 = *cnt;
    CHECK(c1 == c0 || c1 == c0 + 1);              /* only counted when a record buffer exists */
    if (c1 == c0) t_note("no ship-assert record buffer in this process: counter unchanged");
    else {
        EXPECT_EQ(c1, c0 + 1);                    /* observed: exactly one record per call */
        UN(ShipAssert)(0x3333, 0x4444); EXPECT_EQ(*cnt, c1 + 1);
        c1 = *cnt;
    }
    /* re-entrancy: with the bit set, the assertion is ignored */
    *flags = (USHORT)(before | 0x10);
    ULONG c2 = *cnt; UN(ShipAssert)(1, 2); EXPECT_EQ(*cnt, c2); EXPECT_EQ(*flags, (USHORT)(before | 0x10));
    *flags = before;
}

/* ------------------------------------------------- registry value helper */
TEST(nt_set_value_key) {
    REQUIRE(UN(RtlpNtSetValueKey));
    WCHAR name[80]; wsprintfW(name, L"Software\\ntdllt_nsv_%lu", GetCurrentProcessId());
    HMODULE adv = LoadLibraryA("advapi32.dll"); REQUIRE(adv);
    LONG (WINAPI *create)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD) = (void *)GetProcAddress(adv, "RegCreateKeyExW");
    LONG (WINAPI *open)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY) = (void *)GetProcAddress(adv, "RegOpenKeyExW");
    LONG (WINAPI *query)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD) = (void *)GetProcAddress(adv, "RegQueryValueExW");
    LONG (WINAPI *closek)(HKEY) = (void *)GetProcAddress(adv, "RegCloseKey");
    LONG (WINAPI *delk)(HKEY, LPCWSTR) = (void *)GetProcAddress(adv, "RegDeleteKeyW");
    REQUIRE(create && open && query && closek && delk);
    HKEY k = NULL, ro = NULL;
    if (create(HKEY_CURRENT_USER, name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL)) { t_skip("cannot create a scratch key under HKCU"); return; }
    DWORD v = 0xCAFE1234, type = 0, got = 0, cb = sizeof got;
    EXPECT_EQ(UN(RtlpNtSetValueKey)(k, REG_DWORD, &v, sizeof v), 0);
    EXPECT_EQ(query(k, L"", NULL, &type, (LPBYTE)&got, &cb), 0);        /* sets the unnamed (default) value */
    EXPECT_EQ(type, REG_DWORD); EXPECT_EQ(got, 0xCAFE1234); EXPECT_EQ(cb, 4);
    WCHAR str[] = L"hello"; WCHAR rd[16] = { 0 }; cb = sizeof rd;
    EXPECT_EQ(UN(RtlpNtSetValueKey)(k, REG_SZ, str, sizeof str), 0);    /* replaces the previous value, changing type */
    EXPECT_EQ(query(k, NULL, NULL, &type, (LPBYTE)rd, &cb), 0);
    EXPECT_EQ(type, REG_SZ); EXPECT_EQ(cb, sizeof str); EXPECT_WSTR(rd, L"hello");
    EXPECT_EQ(UN(RtlpNtSetValueKey)(k, REG_BINARY, NULL, 0), 0);        /* empty data */
    cb = 0; type = 0; EXPECT_EQ(query(k, L"", NULL, &type, NULL, &cb), 0); EXPECT_EQ(type, REG_BINARY); EXPECT_EQ(cb, 0);
    /* error paths */
    EXPECT_EQ(UN(RtlpNtSetValueKey)(NULL, REG_DWORD, &v, sizeof v), S(0xC0000008));         /* invalid handle */
    EXPECT_EQ(UN(RtlpNtSetValueKey)((HANDLE)(ULONG_PTR)0x7ffff0, REG_DWORD, &v, 4), S(0xC0000008));
    if (open(HKEY_CURRENT_USER, name, 0, KEY_QUERY_VALUE, &ro) == 0) {
        EXPECT_EQ(UN(RtlpNtSetValueKey)(ro, REG_DWORD, &v, sizeof v), S(0xC0000022));        /* no KEY_SET_VALUE */
        closek(ro);
    }
    closek(k);
    EXPECT_EQ(delk(HKEY_CURRENT_USER, name), 0);
}

/* ----------------------------------------------------- critical section helpers */
UDECL(NTSTATUS, RtlWaitOnAddress, (volatile VOID *, PVOID, SIZE_T, PLARGE_INTEGER));
typedef struct { CRITICAL_SECTION *cs; volatile LONG *started; NTSTATUS st; } WAITER;
static DWORD WINAPI addr_waiter(LPVOID p) {
    WAITER *w = p; LONG cmp = -1; LARGE_INTEGER to; to.QuadPart = -50000000LL; /* 5 s */
    InterlockedExchange(w->started, 1);
    w->st = UN(RtlWaitOnAddress)(&w->cs->LockCount, &cmp, sizeof cmp, &to);
    return 0;
}
TEST(critical_section_event) {
    REQUIRE(UN(RtlpUnWaitCriticalSection)); REQUIRE(UN(RtlpWaitForCriticalSection)); REQUIRE(UN(RtlWaitOnAddress));
    CRITICAL_SECTION cs; InitializeCriticalSection(&cs);
    EXPECT_EQ((ULONG_PTR)cs.LockSemaphore, 0);          /* event is created lazily */
    UN(RtlpWaitForCriticalSection)(&cs);                  /* returns without touching the section */
    EXPECT_EQ((ULONG_PTR)cs.LockSemaphore, 0); EXPECT_EQ(cs.LockCount, -1);
    EXPECT_EQ(t_proc("RtlpWaitForCriticalSection") == t_proc("LdrStandardizeSystemPath"), 1);

    /* Windows 10 wakes the waiter through the address of LockCount and marks the section with -1 */
    volatile LONG started = 0; WAITER w = { &cs, &started, 0x7777 };
    HANDLE th = CreateThread(NULL, 0, addr_waiter, &w, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        while (!started) Sleep(1);
        DWORD r = WAIT_TIMEOUT;
        for (int i = 0; i < 100 && r == WAIT_TIMEOUT; i++) {
            Sleep(30);
            UN(RtlpUnWaitCriticalSection)(&cs);
            r = WaitForSingleObject(th, 0);
        }
        EXPECT_EQ(r, WAIT_OBJECT_0);
        if (r == WAIT_OBJECT_0) EXPECT_EQ(w.st, 0);
        else TerminateThread(th, 0);
        CloseHandle(th);
    }
    HANDLE h = cs.LockSemaphore;
    if (h != (HANDLE)(LONG_PTR)-1) {           /* event-based flavour: the call signals an auto-reset event */
        CHECK(h != NULL);
        if (h) { EXPECT_EQ(WaitForSingleObject(h, 1000), WAIT_OBJECT_0); EXPECT_EQ(WaitForSingleObject(h, 0), WAIT_TIMEOUT); }
    } else t_note("critical section uses address-wait mode (LockSemaphore == -1)");
    DeleteCriticalSection(&cs);
}

/* ----------------------------------------------------- UI language setters */
TEST(ui_language_arg_validation) {
    REQUIRE(UN(RtlpSetInstallLanguage)); REQUIRE(UN(RtlpRefreshCachedUILanguage));
    EXPECT_EQ(UN(RtlpSetInstallLanguage)(4, NULL, 0, 0), 0xC000000Du);
    EXPECT_EQ(UN(RtlpSetInstallLanguage)(8, NULL, 0, 0), 0xC000000Du);
    EXPECT_EQ(UN(RtlpSetInstallLanguage)(0, L"en-US", 0, 0), 0xC000000Du);     /* neither name nor LCID flag */
    EXPECT_EQ(UN(RtlpSetInstallLanguage)(1, L"en-US", 0, 0), 0xC000000Du);
    EXPECT_EQ(UN(RtlpSetInstallLanguage)(8, L"zz-invalid-culture", 0, 0), 0xC000000Du);  /* unknown culture name */
    EXPECT_EQ(UN(RtlpRefreshCachedUILanguage)(NULL, 0, 0, 0), 0xC000000Du);
}

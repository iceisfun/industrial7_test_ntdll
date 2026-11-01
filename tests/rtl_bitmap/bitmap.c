#include "t.h"

typedef struct { ULONG SizeOfBitMap; PULONG Buffer; } BM;
typedef struct { ULONG StartingIndex, NumberOfBits; } RUN;
_Static_assert(sizeof(BM)==16 && offsetof(BM,Buffer)==8, "Win10 x64 bitmap layout");
UDECL(void, RtlInitializeBitMap, (BM *, PULONG, ULONG));
UDECL(void, RtlSetBits, (BM *, ULONG, ULONG));
UDECL(void, RtlClearBits, (BM *, ULONG, ULONG));
UDECL(void, RtlSetAllBits, (BM *));
UDECL(void, RtlClearAllBits, (BM *));
UDECL(BOOLEAN, RtlTestBit, (BM *, ULONG));
UDECL(BOOLEAN, RtlAreBitsSet, (BM *, ULONG, ULONG));
UDECL(BOOLEAN, RtlAreBitsClear, (BM *, ULONG, ULONG));
UDECL(ULONG, RtlFindClearBits, (BM *, ULONG, ULONG));
UDECL(ULONG, RtlFindSetBits, (BM *, ULONG, ULONG));
UDECL(ULONG, RtlFindClearBitsAndSet, (BM *, ULONG, ULONG));
UDECL(ULONG, RtlFindSetBitsAndClear, (BM *, ULONG, ULONG));
UDECL(ULONG, RtlNumberOfClearBits, (BM *));
UDECL(ULONG, RtlNumberOfSetBits, (BM *));
UDECL(ULONG, RtlFindNextForwardRunClear, (BM *, ULONG, PULONG));
UDECL(ULONG, RtlFindLastBackwardRunClear, (BM *, ULONG, PULONG));
UDECL(ULONG, RtlFindLongestRunClear, (BM *, PULONG));
UDECL(ULONG, RtlFindClearRuns, (BM *, RUN *, ULONG, BOOLEAN));

/* Extra words make the Windows implementation's rounded word reads safe. */
typedef struct { ULONG before[2], words[12], after[2]; } STORAGE;
static ULONG bit(const ULONG *p, ULONG i) { return (p[i / 32] >> (i % 32)) & 1; }
static void put(ULONG *p, ULONG i, ULONG v) {
    ULONG m = 1u << (i % 32);
    if (v) p[i / 32] |= m; else p[i / 32] &= ~m;
}
static void storage(STORAGE *s, ULONG value) {
    memset(s, 0xa5, sizeof(*s));
    for (unsigned i = 0; i < 12; ++i) s->words[i] = value;
}
static void guards(const STORAGE *s) {
    for (unsigned i = 0; i < 2; ++i) {
        EXPECT_EQ(s->before[i], 0xa5a5a5a5); EXPECT_EQ(s->after[i], 0xa5a5a5a5);
    }
}

TEST(rtl_bitmap_initialize_fields) {
    REQUIRE(UN(RtlInitializeBitMap));
    static const ULONG sizes[] = {0,1,7,8,31,32,33,63,64,65,255};
    STORAGE s; BM b;
    for (unsigned i = 0; i < sizeof(sizes)/sizeof(*sizes); ++i) {
        UN(RtlInitializeBitMap)(&b, s.words, sizes[i]);
        EXPECT_EQ(b.SizeOfBitMap, sizes[i]); EXPECT_EQ(b.Buffer, s.words);
    }
}
TEST(rtl_bitmap_initialize_preserves_storage) {
    REQUIRE(UN(RtlInitializeBitMap));
    STORAGE s, copy; BM b; storage(&s, 0x9348ac71); copy = s;
    UN(RtlInitializeBitMap)(&b, s.words, 129); CHECK(!memcmp(&s, &copy, sizeof(s)));
}
TEST(rtl_bitmap_initialize_zero_size) {
    REQUIRE(UN(RtlInitializeBitMap));
    BM b; ULONG w = 0x55aa55aa;
    UN(RtlInitializeBitMap)(&b, &w, 0); EXPECT_EQ(b.SizeOfBitMap, 0); EXPECT_EQ(w, 0x55aa55aa);
}
TEST(rtl_bitmap_reinitialize_storage) {
    REQUIRE(UN(RtlInitializeBitMap));
    BM b; ULONG a[2] = {1,2}, c[2] = {3,4};
    UN(RtlInitializeBitMap)(&b, a, 64); UN(RtlInitializeBitMap)(&b, c, 33);
    EXPECT_EQ(b.Buffer, c); EXPECT_EQ(b.SizeOfBitMap, 33); EXPECT_EQ(a[0], 1); EXPECT_EQ(c[1], 4);
}

static void change_range(int set, ULONG start, ULONG count, int overlap, int repeat) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlSetBits)); REQUIRE(UN(RtlClearBits));
    STORAGE s; ULONG model[12]; BM b;
    storage(&s, set ? 0x10204080 : 0xefdfbf7f); memcpy(model, s.words, sizeof(model));
    UN(RtlInitializeBitMap)(&b, s.words, 257);
    for (int pass = 0; pass < 1 + overlap + repeat; ++pass) {
        ULONG first = start + (overlap && pass ? 2 : 0);
        if (set) UN(RtlSetBits)(&b, first, count); else UN(RtlClearBits)(&b, first, count);
        for (ULONG i = first; i < first + count; ++i) put(model, i, set);
        CHECK(!memcmp(model, s.words, sizeof(model))); guards(&s);
    }
}
TEST(rtl_bitmap_set_single_edges) {
    static const ULONG v[] = {0,7,8,31,32,63,64,255,256};
    for (unsigned i=0;i<sizeof(v)/sizeof(*v);++i) change_range(1,v[i],1,0,0);
}
TEST(rtl_bitmap_set_cross_word) {
    static const ULONG v[][2]={{3,29},{31,2},{30,67},{63,130},{128,129}};
    for(unsigned i=0;i<sizeof(v)/sizeof(*v);++i) change_range(1,v[i][0],v[i][1],0,0);
}
TEST(rtl_bitmap_set_overlap) { change_range(1,29,70,1,0); }
TEST(rtl_bitmap_set_full_range) { change_range(1,0,257,0,0); }
TEST(rtl_bitmap_set_zero_length) { change_range(1,17,0,0,0); }
TEST(rtl_bitmap_set_idempotent) { change_range(1,7,193,0,1); }
TEST(rtl_bitmap_clear_single_edges) {
    static const ULONG v[] = {0,7,8,31,32,63,64,255,256};
    for (unsigned i=0;i<sizeof(v)/sizeof(*v);++i) change_range(0,v[i],1,0,0);
}
TEST(rtl_bitmap_clear_cross_word) {
    static const ULONG v[][2]={{3,29},{31,2},{30,67},{63,130},{128,129}};
    for(unsigned i=0;i<sizeof(v)/sizeof(*v);++i) change_range(0,v[i][0],v[i][1],0,0);
}
TEST(rtl_bitmap_clear_overlap) { change_range(0,29,70,1,0); }
TEST(rtl_bitmap_clear_full_range) { change_range(0,0,257,0,0); }
TEST(rtl_bitmap_clear_zero_length) { change_range(0,17,0,0,0); }
TEST(rtl_bitmap_clear_idempotent) { change_range(0,7,193,0,1); }

static void all_bits(int set) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlSetAllBits)); REQUIRE(UN(RtlClearAllBits));
    static const ULONG sizes[]={1,31,32,33,63,64,65,257};
    for(unsigned j=0;j<sizeof(sizes)/sizeof(*sizes);++j) {
        STORAGE s; BM b; storage(&s,0x12345678); UN(RtlInitializeBitMap)(&b,s.words,sizes[j]);
        if(set) UN(RtlSetAllBits)(&b); else UN(RtlClearAllBits)(&b);
        for(ULONG i=0;i<sizes[j];++i) EXPECT_EQ(bit(s.words,i),set);
        /* Set/ClearAll round up to ULONG; do not assert unused tail bits. */
        for(ULONG i=(sizes[j]+31)/32;i<12;++i) EXPECT_EQ(s.words[i],0x12345678);
        guards(&s);
    }
}
TEST(rtl_bitmap_set_all_sizes) { all_bits(1); }
TEST(rtl_bitmap_clear_all_sizes) { all_bits(0); }
TEST(rtl_bitmap_check_bit_patterns) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlTestBit));
    static const ULONG patterns[]={0,~0u,0xaaaaaaaa,0x80000001,0x13579bdf};
    for(unsigned j=0;j<sizeof(patterns)/sizeof(*patterns);++j) {
        STORAGE s; BM b; storage(&s,patterns[j]); UN(RtlInitializeBitMap)(&b,s.words,257);
        for(ULONG i=0;i<257;++i) EXPECT_EQ(UN(RtlTestBit)(&b,i),bit(s.words,i));
    }
}
static void predicates(int set, int kind) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlAreBitsSet)); REQUIRE(UN(RtlAreBitsClear));
    STORAGE s; BM b; storage(&s,set?~0u:0); UN(RtlInitializeBitMap)(&b,s.words,129);
    static const ULONG ranges[][2]={{0,1},{31,2},{3,64},{64,65},{128,1},{0,129}};
    if(!kind) {
        for(unsigned j=0;j<sizeof(ranges)/sizeof(*ranges);++j) {
            ULONG start=ranges[j][0], n=ranges[j][1];
            EXPECT_EQ(set?UN(RtlAreBitsSet)(&b,start,n):UN(RtlAreBitsClear)(&b,start,n),TRUE);
            put(s.words,start+n/2,!set);
            EXPECT_EQ(set?UN(RtlAreBitsSet)(&b,start,n):UN(RtlAreBitsClear)(&b,start,n),FALSE);
            put(s.words,start+n/2,set);
        }
    } else {
        static const ULONG bad[][2]={{129,1},{128,2},{0,130},{130,1}};
        for(unsigned j=0;j<4;++j) {
            ULONG start=kind==1?j*32:bad[j][0], n=kind==1?0:bad[j][1];
            EXPECT_EQ(set?UN(RtlAreBitsSet)(&b,start,n):UN(RtlAreBitsClear)(&b,start,n),FALSE);
        }
    }
}
TEST(rtl_bitmap_are_set_ranges) { predicates(1,0); }
TEST(rtl_bitmap_are_clear_ranges) { predicates(0,0); }
TEST(rtl_bitmap_are_set_zero_length) { predicates(1,1); }
TEST(rtl_bitmap_are_clear_zero_length) { predicates(0,1); }
TEST(rtl_bitmap_are_set_outside_range) { predicates(1,2); }
TEST(rtl_bitmap_are_clear_outside_range) { predicates(0,2); }

static void counts(int kind) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlNumberOfSetBits)); REQUIRE(UN(RtlNumberOfClearBits));
    static const ULONG sizes[]={0,1,7,8,31,32,33,63,64,65,255,257};
    for(unsigned j=0;j<sizeof(sizes)/sizeof(*sizes);++j) {
        STORAGE s; BM b; ULONG n=0; storage(&s,kind==0?0:kind==1?~0u:kind==2?0xaaaaaaaa:0x9348ac71);
        UN(RtlInitializeBitMap)(&b,s.words,sizes[j]);
        for(ULONG i=0;i<sizes[j];++i) n+=bit(s.words,i);
        EXPECT_EQ(UN(RtlNumberOfSetBits)(&b),n); EXPECT_EQ(UN(RtlNumberOfClearBits)(&b),sizes[j]-n);
    }
}
TEST(rtl_bitmap_count_empty) { counts(0); }
TEST(rtl_bitmap_count_full_tail_mask) { counts(1); }
TEST(rtl_bitmap_count_alternating) { counts(2); }
TEST(rtl_bitmap_count_mixed) { counts(3); }

static void searches(int set, int kind) {
    REQUIRE(UN(RtlInitializeBitMap)); REQUIRE(UN(RtlFindSetBits)); REQUIRE(UN(RtlFindClearBits));
    REQUIRE(UN(RtlFindClearBitsAndSet)); REQUIRE(UN(RtlFindSetBitsAndClear));
    STORAGE s; BM b; ULONG original[12]; storage(&s,set?0:~0u);
    UN(RtlInitializeBitMap)(&b,s.words,257);
    if(kind!=2) for(ULONG i=29;i<202;++i) put(s.words,i,set);
    memcpy(original,s.words,sizeof(original));
    if(kind==0) {
        static const ULONG lengths[]={1,2,31,32,63,64,65,128,129,173};
        for(unsigned j=0;j<sizeof(lengths)/sizeof(*lengths);++j)
            EXPECT_EQ(set?UN(RtlFindSetBits)(&b,lengths[j],0):UN(RtlFindClearBits)(&b,lengths[j],0),29);
        CHECK(!memcmp(original,s.words,sizeof(original)));
    } else if(kind==1) {
        static const ULONG hints[]={202,256,257,300};
        for(unsigned j=0;j<4;++j)
            EXPECT_EQ(set?UN(RtlFindSetBits)(&b,10,hints[j]):UN(RtlFindClearBits)(&b,10,hints[j]),29);
        EXPECT_EQ(set?UN(RtlFindSetBits)(&b,10,50):UN(RtlFindClearBits)(&b,10,50),50);
    } else if(kind==2) {
        EXPECT_EQ(set?UN(RtlFindSetBits)(&b,1,0):UN(RtlFindClearBits)(&b,1,0),~0u);
        EXPECT_EQ(set?UN(RtlFindSetBitsAndClear)(&b,1,0):UN(RtlFindClearBitsAndSet)(&b,1,0),~0u);
        EXPECT_EQ(set?UN(RtlFindSetBits)(&b,258,0):UN(RtlFindClearBits)(&b,258,0),~0u);
        CHECK(!memcmp(original,s.words,sizeof(original)));
    } else {
        EXPECT_EQ(set?UN(RtlFindSetBitsAndClear)(&b,65,30):UN(RtlFindClearBitsAndSet)(&b,65,30),30);
        for(ULONG i=30;i<95;++i) put(original,i,!set);
        CHECK(!memcmp(original,s.words,sizeof(original))); guards(&s);
    }
}
TEST(rtl_bitmap_find_clear_lengths) { searches(0,0); }
TEST(rtl_bitmap_find_set_lengths) { searches(1,0); }
TEST(rtl_bitmap_find_clear_hint_wrap) { searches(0,1); }
TEST(rtl_bitmap_find_set_hint_wrap) { searches(1,1); }
TEST(rtl_bitmap_find_clear_failure_unchanged) { searches(0,2); }
TEST(rtl_bitmap_find_set_failure_unchanged) { searches(1,2); }
TEST(rtl_bitmap_find_clear_and_set_exact_range) { searches(0,3); }
TEST(rtl_bitmap_find_set_and_clear_exact_range) { searches(1,3); }

static void run_pattern(BM *b, STORAGE *s) {
    storage(s,~0u); UN(RtlInitializeBitMap)(b,s->words,129);
    for(ULONG i=3;i<8;++i) put(s->words,i,0);
    for(ULONG i=30;i<70;++i) put(s->words,i,0);
    for(ULONG i=120;i<129;++i) put(s->words,i,0);
}
TEST(rtl_bitmap_forward_run_boundaries) {
    REQUIRE(UN(RtlInitializeBitMap));
    REQUIRE(UN(RtlFindNextForwardRunClear));
    BM b; STORAGE s; ULONG start; run_pattern(&b,&s);
    static const ULONG v[][3]={{0,3,5},{5,5,3},{8,30,40},{31,31,39},{70,120,9},{129,129,0}};
    for(unsigned i=0;i<sizeof(v)/sizeof(*v);++i) {
        start=999; EXPECT_EQ(UN(RtlFindNextForwardRunClear)(&b,v[i][0],&start),v[i][2]); EXPECT_EQ(start,v[i][1]);
    }
}
TEST(rtl_bitmap_backward_run_boundaries) {
    REQUIRE(UN(RtlInitializeBitMap));
    REQUIRE(UN(RtlFindLastBackwardRunClear));
    BM b; STORAGE s; ULONG start; run_pattern(&b,&s);
    static const ULONG v[][3]={{128,120,9},{119,30,40},{69,30,40},{35,30,6},{29,3,5},{129,129,0}};
    for(unsigned i=0;i<sizeof(v)/sizeof(*v);++i) {
        start=999; EXPECT_EQ(UN(RtlFindLastBackwardRunClear)(&b,v[i][0],&start),v[i][2]); EXPECT_EQ(start,v[i][1]);
    }
}
TEST(rtl_bitmap_longest_clear_run) {
    REQUIRE(UN(RtlInitializeBitMap));
    REQUIRE(UN(RtlFindLongestRunClear));
    BM b; STORAGE s; ULONG start=999; run_pattern(&b,&s);
    EXPECT_EQ(UN(RtlFindLongestRunClear)(&b,&start),40); EXPECT_EQ(start,30);
}
TEST(rtl_bitmap_clear_runs_capacity_order) {
    REQUIRE(UN(RtlInitializeBitMap));
    REQUIRE(UN(RtlFindClearRuns));
    BM b; STORAGE s; struct {RUN r[4]; ULONG guard;} out; run_pattern(&b,&s);
    memset(&out,0xcc,sizeof(out));
    ULONG n=UN(RtlFindClearRuns)(&b,out.r,4,FALSE); EXPECT_EQ(n,3);
    if(n==3) {
        EXPECT_EQ(out.r[0].StartingIndex,3); EXPECT_EQ(out.r[0].NumberOfBits,5);
        EXPECT_EQ(out.r[1].StartingIndex,30); EXPECT_EQ(out.r[1].NumberOfBits,40);
        EXPECT_EQ(out.r[2].StartingIndex,120); EXPECT_EQ(out.r[2].NumberOfBits,9);
    }
    EXPECT_EQ(out.guard,0xcccccccc);
    n=UN(RtlFindClearRuns)(&b,out.r,1,TRUE); EXPECT_EQ(n,1);
    if(n==1) { EXPECT_EQ(out.r[0].StartingIndex,30); EXPECT_EQ(out.r[0].NumberOfBits,40); }
}

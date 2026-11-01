#include "t.h"
#include <stdlib.h>

/* Layouts and callback prototypes: ntddk.h, checked against Win10 init bodies. */
typedef enum { Less, Greater, Equal } ORDER;
typedef struct SPLAY_LINKS { struct SPLAY_LINKS *Parent, *Left, *Right; } SPLAY_LINKS;
typedef struct AVL_LINKS {
    struct AVL_LINKS *Parent, *Left, *Right;
    CHAR Balance; UCHAR Reserved[3];
} AVL_LINKS;
typedef struct S_TABLE S_TABLE;
typedef struct A_TABLE A_TABLE;
typedef ORDER (WINAPI *S_COMPARE)(S_TABLE *, void *, void *);
typedef void *(WINAPI *S_ALLOC)(S_TABLE *, LONG);
typedef void (WINAPI *S_FREE)(S_TABLE *, void *);
typedef ORDER (WINAPI *A_COMPARE)(A_TABLE *, void *, void *);
typedef void *(WINAPI *A_ALLOC)(A_TABLE *, ULONG);
typedef void (WINAPI *A_FREE)(A_TABLE *, void *);
struct S_TABLE {
    SPLAY_LINKS *Root;
    LIST_ENTRY InsertOrderList;
    LIST_ENTRY *OrderedPointer;
    ULONG WhichOrderedElement, NumberGenericTableElements;
    S_COMPARE Compare; S_ALLOC Allocate; S_FREE Free; void *Context;
};
struct A_TABLE {
    AVL_LINKS Root;
    void *OrderedPointer;
    ULONG WhichOrderedElement, NumberGenericTableElements, DepthOfTree;
    AVL_LINKS *RestartKey;
    ULONG DeleteCount;
    A_COMPARE Compare; A_ALLOC Allocate; A_FREE Free; void *Context;
};
_Static_assert(sizeof(S_TABLE)==0x48 && offsetof(S_TABLE,Compare)==0x28 &&
               offsetof(S_TABLE,Context)==0x40, "Win10 x64 splay table layout");
_Static_assert(sizeof(A_TABLE)==0x68 && offsetof(A_TABLE,Compare)==0x48 &&
               offsetof(A_TABLE,Context)==0x60, "Win10 x64 AVL table layout");
#define DECLARE_TABLE_APIS(suffix, type, compare, alloc, release) \
    UDECL(void, RtlInitializeGenericTable##suffix, (type *, compare, alloc, release, void *)); \
    UDECL(void *, RtlInsertElementGenericTable##suffix, (type *, void *, LONG, BOOLEAN *)); \
    UDECL(void *, RtlLookupElementGenericTable##suffix, (type *, void *)); \
    UDECL(BOOLEAN, RtlDeleteElementGenericTable##suffix, (type *, void *)); \
    UDECL(void *, RtlEnumerateGenericTable##suffix, (type *, BOOLEAN)); \
    UDECL(void *, RtlEnumerateGenericTableWithoutSplaying##suffix, (type *, void **)); \
    UDECL(ULONG, RtlNumberGenericTableElements##suffix, (type *)); \
    UDECL(void *, RtlGetElementGenericTable##suffix, (type *, ULONG)); \
    UDECL(BOOLEAN, RtlIsGenericTableEmpty##suffix, (type *))
DECLARE_TABLE_APIS(, S_TABLE, S_COMPARE, S_ALLOC, S_FREE);
DECLARE_TABLE_APIS(Avl, A_TABLE, A_COMPARE, A_ALLOC, A_FREE);

typedef struct { LONG key; ULONG payload; unsigned char bytes[13]; } ITEM;
typedef struct {
    ULONG magic, calls, allocations, frees, comparisons;
    int fail_next;
    void *live[64];
} TABLE_CONTEXT;
typedef struct {
    union { S_TABLE s; A_TABLE a; } table;
    TABLE_CONTEXT ctx;
    int avl;
    LONG keys[64];
    unsigned nkeys;
} FIXTURE;
static ITEM item(LONG key) {
    ITEM x; memset(&x,0,sizeof(x)); x.key=key; x.payload=(ULONG)key ^ 0x19283746;
    for(unsigned i=0;i<sizeof(x.bytes);++i) x.bytes[i]=(unsigned char)(key+i*7);
    return x;
}
static ORDER compare(TABLE_CONTEXT *c, void *x, void *y) {
    CHECK(c->magic==0x715ac03d); ++c->comparisons;
    LONG a=((ITEM *)x)->key, b=((ITEM *)y)->key;
    return a<b?Less:a>b?Greater:Equal;
}
static void *allocate(TABLE_CONTEXT *c, LONG size) {
    CHECK(c->magic==0x715ac03d); ++c->calls;
    CHECK(size >= (LONG)sizeof(ITEM) && size < 1024);
    if(size < (LONG)sizeof(ITEM) || size >= 1024) return NULL;
    if(c->fail_next) { c->fail_next=0; return NULL; }
    for(unsigned i=0;i<64;++i) if(!c->live[i]) {
        void *p=malloc(size); c->live[i]=p; if(p) ++c->allocations; return p;
    }
    CHECK(0); return NULL;
}
static void release(TABLE_CONTEXT *c, void *p) {
    CHECK(c->magic==0x715ac03d);
    for(unsigned i=0;i<64;++i) if(c->live[i]==p && p) {
        c->live[i]=NULL; ++c->frees; free(p); return;
    }
    CHECKF(0,"free callback received an unowned allocation");
}
static ORDER WINAPI s_compare(S_TABLE *t, void *a, void *b) { return compare(t->Context,a,b); }
static ORDER WINAPI a_compare(A_TABLE *t, void *a, void *b) { return compare(t->Context,a,b); }
static void *WINAPI s_allocate(S_TABLE *t, LONG n) { return allocate(t->Context,n); }
static void *WINAPI a_allocate(A_TABLE *t, ULONG n) { return allocate(t->Context,n); }
static void WINAPI s_release(S_TABLE *t, void *p) { release(t->Context,p); }
static void WINAPI a_release(A_TABLE *t, void *p) { release(t->Context,p); }

/* The adapter uses each API's actual table pointer type, not ABI casts. */
static void setup(FIXTURE *f, int avl, int which, int *ready) {
    memset(f,0,sizeof(*f)); f->avl=avl; f->ctx.magic=0x715ac03d;
#define NEED(n) REQUIRE(UN(n))
#define NEED_SET(suffix) \
    NEED(RtlInitializeGenericTable##suffix); NEED(RtlInsertElementGenericTable##suffix); \
    NEED(RtlLookupElementGenericTable##suffix); \
    NEED(RtlNumberGenericTableElements##suffix)
    if(avl) {
        NEED_SET(Avl);
        if(which==2 || (which>=5 && which<=23)) NEED(RtlDeleteElementGenericTableAvl);
        if(which==5 || which==9 || which==22 || which==24) NEED(RtlIsGenericTableEmptyAvl);
        if(which==4 || which==16 || which==17) NEED(RtlGetElementGenericTableAvl);
        if(which==3 || which==13 || which==14 || which==22) NEED(RtlEnumerateGenericTableAvl);
        if(which==3 || which==15 || which==23) NEED(RtlEnumerateGenericTableWithoutSplayingAvl);
        UN(RtlInitializeGenericTableAvl)(&f->table.a,a_compare,a_allocate,a_release,&f->ctx);
    } else {
        NEED_SET();
        if(which==2 || (which>=5 && which<=23)) NEED(RtlDeleteElementGenericTable);
        if(which==5 || which==9 || which==22 || which==24) NEED(RtlIsGenericTableEmpty);
        if(which==4 || which==16 || which==17) NEED(RtlGetElementGenericTable);
        if(which==3 || which==13 || which==14 || which==22) NEED(RtlEnumerateGenericTable);
        if(which==3 || which==15 || which==23) NEED(RtlEnumerateGenericTableWithoutSplaying);
        UN(RtlInitializeGenericTable)(&f->table.s,s_compare,s_allocate,s_release,&f->ctx);
    }
#undef NEED_SET
#undef NEED
    *ready=1;
}
#define CALL(f,name,...) ((f)->avl ? UN(name##Avl)(&(f)->table.a, __VA_ARGS__) : UN(name)(&(f)->table.s, __VA_ARGS__))
static ITEM *insert(FIXTURE *f, ITEM *x, BOOLEAN *fresh) {
    ITEM *p=CALL(f,RtlInsertElementGenericTable,x,sizeof(*x),fresh);
    if(p) {
        unsigned i;
        for(i=0;i<f->nkeys;++i) if(f->keys[i]==x->key) break;
        if(i==f->nkeys && i<64) f->keys[f->nkeys++]=x->key;
    }
    return p;
}
static ITEM *lookup(FIXTURE *f, LONG key) { ITEM x=item(key); return CALL(f,RtlLookupElementGenericTable,&x); }
static BOOLEAN remove_key(FIXTURE *f, LONG key) { ITEM x=item(key); return CALL(f,RtlDeleteElementGenericTable,&x); }
static ULONG count(FIXTURE *f) {
    return f->avl?UN(RtlNumberGenericTableElementsAvl)(&f->table.a):UN(RtlNumberGenericTableElements)(&f->table.s);
}
static BOOLEAN empty(FIXTURE *f) {
    return f->avl?UN(RtlIsGenericTableEmptyAvl)(&f->table.a):UN(RtlIsGenericTableEmpty)(&f->table.s);
}
static ITEM *enumerate(FIXTURE *f, BOOLEAN restart) { return CALL(f,RtlEnumerateGenericTable,restart); }
static ITEM *cursor(FIXTURE *f, void **key) { return CALL(f,RtlEnumerateGenericTableWithoutSplaying,key); }
static ITEM *get(FIXTURE *f, ULONG index) { return CALL(f,RtlGetElementGenericTable,index); }
static void check_item(ITEM *p, LONG key) {
    ITEM expected=item(key); CHECK(p!=NULL);
    if(p) CHECK(!memcmp(p,&expected,sizeof(expected)));
}
static int seed(FIXTURE *f) {
    static const LONG keys[]={40,10,70,20,60,30,50};
    for(unsigned i=0;i<7;++i) {
        ITEM x=item(keys[i]); BOOLEAN fresh=FALSE; ITEM *p=insert(f,&x,&fresh);
        CHECK(p!=NULL); CHECK(fresh==TRUE);
        if(!p) return 0;
    }
    return 1;
}
static void cleanup(FIXTURE *f) {
    /* Do not make cleanup depend on optional indexed/enumeration exports. */
    for(unsigned i=0;i<f->nkeys;++i) if(lookup(f,f->keys[i])) CHECK(remove_key(f,f->keys[i]));
    EXPECT_EQ(count(f),0); EXPECT_EQ(f->ctx.allocations,f->ctx.frees);
    for(unsigned i=0;i<64;++i) if(f->ctx.live[i]) {
        free(f->ctx.live[i]); f->ctx.live[i]=NULL;
    }
    f->ctx.magic=0;
}

static void table_case(int avl, int which) {
    FIXTURE f; ITEM x=item(40), *p, *q; BOOLEAN fresh=FALSE; void *key=NULL, *key2=NULL;
    int ready=0; setup(&f,avl,which,&ready); if(!ready) return;
    if(which>=10 && which<=23 && !seed(&f)) goto done;
    switch(which) {
    case 0:
        EXPECT_EQ(count(&f),0); EXPECT_EQ(f.ctx.calls,0);
        if(avl) {
            EXPECT_EQ(f.table.a.Context,&f.ctx); EXPECT_EQ(f.table.a.Root.Parent,&f.table.a.Root);
            CHECK(f.table.a.Compare==a_compare); CHECK(f.table.a.Allocate==a_allocate); CHECK(f.table.a.Free==a_release);
        } else {
            EXPECT_EQ(f.table.s.Context,&f.ctx); EXPECT_EQ(f.table.s.Root,NULL);
            EXPECT_EQ(f.table.s.InsertOrderList.Flink,&f.table.s.InsertOrderList);
            EXPECT_EQ(f.table.s.InsertOrderList.Blink,&f.table.s.InsertOrderList);
            CHECK(f.table.s.Compare==s_compare); CHECK(f.table.s.Allocate==s_allocate); CHECK(f.table.s.Free==s_release);
        }
        break;
    case 1: EXPECT_EQ(lookup(&f,40),NULL); EXPECT_EQ(f.ctx.comparisons,0); break;
    case 2: EXPECT_EQ(remove_key(&f,40),FALSE); EXPECT_EQ(f.ctx.frees,0); break;
    case 3: EXPECT_EQ(enumerate(&f,TRUE),NULL); EXPECT_EQ(cursor(&f,&key),NULL); break;
    case 4: EXPECT_EQ(get(&f,0),NULL); EXPECT_EQ(get(&f,~0u),NULL); break;
    case 5:
        p=insert(&f,&x,&fresh); check_item(p,40); EXPECT_EQ(fresh,TRUE);
        EXPECT_EQ(count(&f),1); EXPECT_EQ(empty(&f),FALSE); EXPECT_EQ(f.ctx.allocations,1); break;
    case 6:
        p=insert(&f,&x,&fresh); CHECK(p!=NULL); memset(&x,0xee,sizeof(x));
        check_item(lookup(&f,40),40); break;
    case 7:
        p=insert(&f,&x,NULL); check_item(p,40); EXPECT_EQ(count(&f),1); break;
    case 8:
        p=insert(&f,&x,&fresh); CHECK(p!=NULL); x.payload=123; fresh=TRUE;
        q=insert(&f,&x,&fresh); EXPECT_EQ(q,p); EXPECT_EQ(fresh,FALSE);
        check_item(q,40); EXPECT_EQ(f.ctx.calls,1); EXPECT_EQ(count(&f),1); break;
    case 9:
        f.ctx.fail_next=1; fresh=TRUE; p=insert(&f,&x,&fresh);
        EXPECT_EQ(p,NULL); EXPECT_EQ(fresh,FALSE); EXPECT_EQ(count(&f),0);
        EXPECT_EQ(empty(&f),TRUE); EXPECT_EQ(f.ctx.frees,0);
        p=insert(&f,&x,&fresh); check_item(p,40); EXPECT_EQ(fresh,TRUE); break;
    case 10:
        for(LONG k=10;k<=70;k+=10) check_item(lookup(&f,k),k);
        CHECK(f.ctx.comparisons>0); break;
    case 11: {
        static const LONG missing[]={-1,0,15,35,75,100};
        for(unsigned i=0;i<sizeof(missing)/sizeof(*missing);++i) EXPECT_EQ(lookup(&f,missing[i]),NULL);
        EXPECT_EQ(count(&f),7); EXPECT_EQ(f.ctx.allocations,7); break;
    }
    case 12:
        p=lookup(&f,40); CHECK(p!=NULL);
        for(LONG k=80;k<=120;k+=10) { x=item(k); q=insert(&f,&x,&fresh); CHECK(q!=NULL); }
        EXPECT_EQ(lookup(&f,40),p); check_item(p,40); EXPECT_EQ(count(&f),12); break;
    case 13:
        for(LONG k=10;k<=70;k+=10) check_item(enumerate(&f,k==10),k);
        EXPECT_EQ(enumerate(&f,FALSE),NULL); EXPECT_EQ(count(&f),7); break;
    case 14:
        check_item(enumerate(&f,TRUE),10); check_item(enumerate(&f,FALSE),20);
        check_item(enumerate(&f,TRUE),10); check_item(enumerate(&f,FALSE),20); break;
    case 15:
        for(LONG k=10;k<=70;k+=10) {
            check_item(cursor(&f,&key),k); check_item(cursor(&f,&key2),k);
        }
        EXPECT_EQ(cursor(&f,&key),NULL); EXPECT_EQ(cursor(&f,&key2),NULL); break;
    case 16: {
        static const LONG order[]={40,10,70,20,60,30,50};
        static const ULONG indices[]={0,6,2,5,1,4,3,0,6};
        for(unsigned j=0;j<sizeof(indices)/sizeof(*indices);++j) {
            ULONG i=indices[j]; check_item(get(&f,i),avl?(LONG)(i+1)*10:order[i]);
        }
        break;
    }
    case 17:
        EXPECT_EQ(get(&f,7),NULL); EXPECT_EQ(get(&f,8),NULL); EXPECT_EQ(get(&f,~0u),NULL);
        EXPECT_EQ(count(&f),7); break;
    case 18:
        EXPECT_EQ(remove_key(&f,40),TRUE); EXPECT_EQ(lookup(&f,40),NULL); EXPECT_EQ(count(&f),6);
        EXPECT_EQ(f.ctx.frees,1);
        for(LONG k=10;k<=70;k+=10) if(k!=40) check_item(lookup(&f,k),k);
        break;
    case 19:
        EXPECT_EQ(remove_key(&f,35),FALSE); EXPECT_EQ(count(&f),7); EXPECT_EQ(f.ctx.frees,0);
        check_item(lookup(&f,40),40); break;
    case 20:
        EXPECT_EQ(remove_key(&f,40),TRUE); x=item(40); x.payload=123;
        p=insert(&f,&x,&fresh); CHECK(p!=NULL); EXPECT_EQ(fresh,TRUE);
        if(p) EXPECT_EQ(p->payload,123);
        EXPECT_EQ(count(&f),7); EXPECT_EQ(f.ctx.allocations,8); EXPECT_EQ(f.ctx.frees,1); break;
    case 21:
        f.ctx.fail_next=1; x=item(80); fresh=TRUE;
        EXPECT_EQ(insert(&f,&x,&fresh),NULL); EXPECT_EQ(fresh,FALSE); EXPECT_EQ(count(&f),7);
        for(LONG k=10;k<=70;k+=10) check_item(lookup(&f,k),k);
        EXPECT_EQ(lookup(&f,80),NULL); break;
    case 22:
        for(LONG k=10;k<=70;k+=10) {
            EXPECT_EQ(remove_key(&f,k),TRUE); EXPECT_EQ(count(&f),(70-k)/10);
            EXPECT_EQ(f.ctx.frees,k/10); EXPECT_EQ(empty(&f),k==70);
        }
        EXPECT_EQ(enumerate(&f,TRUE),NULL); EXPECT_EQ(lookup(&f,40),NULL); break;
    case 23:
        /* Deletion invalidates old cursors; restart only with a fresh NULL key. */
        check_item(cursor(&f,&key),10); EXPECT_EQ(remove_key(&f,30),TRUE); key=NULL;
        for(LONG k=10;k<=70;k+=10) if(k!=30) check_item(cursor(&f,&key),k);
        EXPECT_EQ(cursor(&f,&key),NULL); EXPECT_EQ(count(&f),6); break;
    case 24: EXPECT_EQ(empty(&f),TRUE); EXPECT_EQ(count(&f),0); break;
    }
done:
    cleanup(&f);
}

#define TABLE_TESTS(prefix,avl) \
    TEST(prefix##_initialize_callbacks_context) { table_case(avl,0); } \
    TEST(prefix##_empty_lookup) { table_case(avl,1); } \
    TEST(prefix##_empty_delete) { table_case(avl,2); } \
    TEST(prefix##_empty_enumeration) { table_case(avl,3); } \
    TEST(prefix##_empty_index) { table_case(avl,4); } \
    TEST(prefix##_insert_one) { table_case(avl,5); } \
    TEST(prefix##_insert_copies_caller_data) { table_case(avl,6); } \
    TEST(prefix##_insert_optional_new_flag) { table_case(avl,7); } \
    TEST(prefix##_duplicate_preserves_data_no_allocate) { table_case(avl,8); } \
    TEST(prefix##_allocation_failure_empty_recovery) { table_case(avl,9); } \
    TEST(prefix##_lookup_existing_keys) { table_case(avl,10); } \
    TEST(prefix##_lookup_missing_keys) { table_case(avl,11); } \
    TEST(prefix##_element_pointer_lifetime) { table_case(avl,12); } \
    TEST(prefix##_enumerate_sorted) { table_case(avl,13); } \
    TEST(prefix##_enumerate_restart) { table_case(avl,14); } \
    TEST(prefix##_independent_cursors) { table_case(avl,15); } \
    TEST(prefix##_indexed_order_and_cache) { table_case(avl,16); } \
    TEST(prefix##_index_out_of_range) { table_case(avl,17); } \
    TEST(prefix##_delete_internal_key) { table_case(avl,18); } \
    TEST(prefix##_delete_missing_unchanged) { table_case(avl,19); } \
    TEST(prefix##_delete_reinsert_new_payload) { table_case(avl,20); } \
    TEST(prefix##_allocation_failure_preserves_tree) { table_case(avl,21); } \
    TEST(prefix##_delete_all_callback_cleanup) { table_case(avl,22); } \
    TEST(prefix##_enumerate_after_delete_fresh_cursor) { table_case(avl,23); } \
    TEST(prefix##_empty_predicate) { table_case(avl,24); }
TABLE_TESTS(rtl_tables_splay,0)
TABLE_TESTS(rtl_tables_avl,1)

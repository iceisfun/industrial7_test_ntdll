/* Builds a minimal, code-free PE32+ DLL whose only section is a hand-assembled resource tree, so the
 * loader resource APIs can be tested against a resource directory whose exact contents are known.
 *
 * Resource tree (type / name / language -> data):
 *   RT_RCDATA(10) / 1 / 0x409 -> "data-1-409"   (11 bytes incl. NUL)
 *   RT_RCDATA(10) / 1 / 0x407 -> "data-1-407"
 *   RT_RCDATA(10) / 2 / 0     -> "data-2-neutral"
 *   RT_HTML(23)   / 7 / 0x409 -> "<html/>"
 *   L"CUSTOM"     / L"MYRES" / 0x409 -> "named-res"
 *   L"MUI"        / 1 / 0 -> 0xA4-byte resource-config block (signature 0xFECDFECD, size, version 0x10000, main-file type
 *                       lists {10,23} / {CUSTOM,MUI} so every type stays in this file)
 * Directory order follows the PE rule: named entries first (case-insensitive), then ascending ids.
 */
#ifndef PEBUILD_H
#define PEBUILD_H
#include <stdlib.h>

#define PEB_RSRC_RVA   0x1000
#define PEB_RAW_OFF    0x200
#define PEB_FILE_SIZE  0xA00          /* headers 0x200 + one 0x800 raw section */
#define PEB_SECT_RAW   0x800
#define PEB_MUI_SIZE   0xA4

typedef struct { BYTE rs[PEB_SECT_RAW]; ULONG used; } peb_pool;

static ULONG peb_alloc(peb_pool *p, ULONG n)
{
    ULONG o = (p->used + 3) & ~3u;
    p->used = o + n;
    return o;
}
static ULONG peb_dir(peb_pool *p, USHORT nnamed, USHORT nid)
{
    ULONG o = peb_alloc(p, 16 + 8u * (nnamed + nid));
    *(USHORT *)(p->rs + o + 12) = nnamed;
    *(USHORT *)(p->rs + o + 14) = nid;
    return o;
}
static ULONG peb_name(peb_pool *p, const WCHAR *s)
{
    ULONG len = (ULONG)lstrlenW(s), o = peb_alloc(p, 2 + 2 * len);
    *(USHORT *)(p->rs + o) = (USHORT)len;
    memcpy(p->rs + o + 2, s, 2 * len);
    return o;
}
/* idx counts named entries first; name_off != 0 selects a named entry. */
static void peb_entry(peb_pool *p, ULONG dir, ULONG idx, ULONG id_or_name_off, int named, ULONG target, int is_dir)
{
    ULONG *e = (ULONG *)(p->rs + dir + 16 + 8 * idx);
    e[0] = named ? (id_or_name_off | 0x80000000u) : id_or_name_off;
    e[1] = is_dir ? (target | 0x80000000u) : target;
}
static ULONG peb_data(peb_pool *p, const void *d, ULONG n)
{
    ULONG de = peb_alloc(p, 16), o = peb_alloc(p, n);
    memcpy(p->rs + o, d, n);
    *(ULONG *)(p->rs + de) = PEB_RSRC_RVA + o;
    *(ULONG *)(p->rs + de + 4) = n;
    *(ULONG *)(p->rs + de + 8) = 1252;
    return de;
}
/* lang directory with ids sorted ascending */
static ULONG peb_langs(peb_pool *p, int n, const USHORT *lang, const char *const *txt)
{
    ULONG d = peb_dir(p, 0, (USHORT)n);
    for (int i = 0; i < n; i++)
        peb_entry(p, d, i, lang[i], 0, peb_data(p, txt[i], (ULONG)strlen(txt[i]) + 1), 0);
    return d;
}

static ULONG peb_checksum(const BYTE *f, ULONG n, ULONG cksum_off)
{
    ULONGLONG sum = 0;
    for (ULONG i = 0; i < n; i += 2) {
        if (i == cksum_off || i == cksum_off + 2) continue;
        USHORT w = (i + 1 < n) ? *(const USHORT *)(f + i) : f[i];
        sum += w;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    return (ULONG)(sum + n);
}

/* out must hold PEB_FILE_SIZE bytes; with_checksum stores a valid optional-header checksum. */
static void peb_build(BYTE *out, int with_checksum)
{
    static const USHORT l409[] = {0x409}, l407_409[] = {0x407, 0x409}, l0[] = {0};
    static const char *const t409[] = {"<html/>"}, *const tnamed[] = {"named-res"};
    static const char *const t1[] = {"data-1-407", "data-1-409"}, *const t2[] = {"data-2-neutral"};
    peb_pool *p = (peb_pool *)calloc(1, sizeof *p);
    p->used = 0;
    ULONG root = peb_dir(p, 2, 2);
    ULONG d_custom = peb_dir(p, 1, 0), d10 = peb_dir(p, 0, 2), d23 = peb_dir(p, 0, 1);
    ULONG n_custom = peb_name(p, L"CUSTOM"), n_myres = peb_name(p, L"MYRES");
    ULONG l1 = peb_langs(p, 2, l407_409, t1), l2 = peb_langs(p, 1, l0, t2);
    ULONG l7 = peb_langs(p, 1, l409, t409), lm = peb_langs(p, 1, l409, tnamed);
    ULONG d_mui = peb_dir(p, 0, 1), n_mui = peb_name(p, L"MUI");
    BYTE mui[PEB_MUI_SIZE] = {0};
    *(ULONG *)(mui + 0) = 0xFECDFECDu; *(ULONG *)(mui + 4) = PEB_MUI_SIZE; *(ULONG *)(mui + 0x10) = 0x12; *(ULONG *)(mui + 8) = 0x10000;
    /* main-file type lists: ids {10,23} at 0x84 (8 bytes) and names {CUSTOM, MUI} at 0x8C (24 bytes) */
    *(ULONG *)(mui + 0x5c) = 0x84; *(ULONG *)(mui + 0x60) = 8;
    *(ULONG *)(mui + 0x84) = 10; *(ULONG *)(mui + 0x88) = 23;
    *(ULONG *)(mui + 0x54) = 0x8C; *(ULONG *)(mui + 0x58) = 24;
    memcpy(mui + 0x8C, L"CUSTOM\0MUI\0\0", 24);
    ULONG lmui = peb_dir(p, 0, 1);
    peb_entry(p, lmui, 0, 0, 0, peb_data(p, mui, PEB_MUI_SIZE), 0);
    peb_entry(p, d_mui, 0, 1, 0, lmui, 1);
    peb_entry(p, root, 0, n_custom, 1, d_custom, 1);
    peb_entry(p, root, 1, n_mui, 1, d_mui, 1);
    peb_entry(p, root, 2, 10, 0, d10, 1);
    peb_entry(p, root, 3, 23, 0, d23, 1);
    peb_entry(p, d_custom, 0, n_myres, 1, lm, 1);
    peb_entry(p, d10, 0, 1, 0, l1, 1);
    peb_entry(p, d10, 1, 2, 0, l2, 1);
    peb_entry(p, d23, 0, 7, 0, l7, 1);
    memset(out, 0, PEB_FILE_SIZE);
    BYTE *h = out;
    h[0] = 'M'; h[1] = 'Z'; *(ULONG *)(h + 0x3c) = 0x40;
    BYTE *nt = h + 0x40;
    memcpy(nt, "PE\0\0", 4);
    BYTE *fh = nt + 4;
    *(USHORT *)(fh + 0) = 0x8664; *(USHORT *)(fh + 2) = 1;
    *(USHORT *)(fh + 16) = 0xF0; *(USHORT *)(fh + 18) = 0x2022;
    BYTE *oh = fh + 20;
    *(USHORT *)(oh + 0) = 0x20b;
    *(ULONG *)(oh + 4) = PEB_SECT_RAW;               /* SizeOfCode (unused) */
    *(ULONGLONG *)(oh + 24) = 0x180000000ull;        /* ImageBase */
    *(ULONG *)(oh + 32) = 0x1000; *(ULONG *)(oh + 36) = 0x200;
    *(USHORT *)(oh + 40) = 6; *(USHORT *)(oh + 48) = 6;
    *(ULONG *)(oh + 56) = 0x2000; *(ULONG *)(oh + 60) = 0x200;
    *(USHORT *)(oh + 68) = 2;                        /* GUI subsystem */
    *(ULONGLONG *)(oh + 72) = 0x100000; *(ULONGLONG *)(oh + 80) = 0x1000;
    *(ULONGLONG *)(oh + 88) = 0x100000; *(ULONGLONG *)(oh + 96) = 0x1000;
    *(ULONG *)(oh + 108) = 16;
    *(ULONG *)(oh + 112 + 8 * 2) = PEB_RSRC_RVA;     /* resource directory */
    *(ULONG *)(oh + 112 + 8 * 2 + 4) = p->used;
    BYTE *sh = oh + 0xF0;
    memcpy(sh, ".rsrc\0\0\0", 8);
    *(ULONG *)(sh + 8) = 0x1000; *(ULONG *)(sh + 12) = PEB_RSRC_RVA;
    *(ULONG *)(sh + 16) = PEB_SECT_RAW; *(ULONG *)(sh + 20) = PEB_RAW_OFF;
    *(ULONG *)(sh + 36) = 0x40000040;
    memcpy(out + PEB_RAW_OFF, p->rs, PEB_SECT_RAW);
    free(p);
    if (with_checksum)
        *(ULONG *)(oh + 64) = peb_checksum(out, PEB_FILE_SIZE, (ULONG)(oh + 64 - out));
}
static int peb_write(const char *path, int with_checksum, void (*mutate)(BYTE *))
{
    BYTE *b = (BYTE *)malloc(PEB_FILE_SIZE);
    peb_build(b, with_checksum);
    if (mutate) mutate(b);
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD w = 0; int ok = f != INVALID_HANDLE_VALUE && WriteFile(f, b, PEB_FILE_SIZE, &w, NULL) && w == PEB_FILE_SIZE;
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    free(b);
    return ok;
}
#endif

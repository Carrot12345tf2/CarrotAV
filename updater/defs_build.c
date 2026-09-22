/* defs_build.c - unpack ClamAV .cvd files and compile carrot.cdb (format v2).
 *
 * A .cvd is a 512-byte ASCII header followed by a gzipped tar. We gunzip with
 * zlib, walk the tar in memory, and pull out three kinds of exact-match
 * signature:
 *
 *   .hdb / .hdu        MD5:FileSize:Name            whole-file MD5
 *   .hsb / .hsu        Hash:FileSize:Name           whole-file MD5 or SHA-256
 *                                                   (SHA-1 lines are skipped)
 *   .mdb / .mdu        SectionSize:MD5:Name         PE section MD5
 *
 * Pattern (.ndb) signatures are deliberately left out: they are anchored to
 * offsets and file types in ClamAV, and matching them unanchored is what
 * produced the mass false positives in CarrotAV 1.0.
 *
 * Engine 1.x output of this file had two bugs that are fixed here:
 *   - every malware name was dropped (all records pointed at ""), so online
 *     updates produced detections with a blank threat name;
 *   - the EICAR pattern record was written from an unpacked struct (12 bytes)
 *     while the loader reads 10, shifting the pattern data and name blob.
 *
 * Plain portable C (no Windows headers) so it can be tested off-Windows.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#pragma pack(push,1)
typedef struct { unsigned char md5[16]; unsigned int size; unsigned int nameoff; } SIGHASH;
typedef struct { unsigned char sha[32]; unsigned int size; unsigned int nameoff; } SIGSHA;
typedef struct { unsigned short len; unsigned int dataoff; unsigned int nameoff; } SIGPAT;
typedef struct {
    char magic[4]; unsigned int version, nhash, npat, patblob, nameblob, built;
} SIGHDR;
typedef struct { unsigned int nsha, nsect, reserved[6]; } SIGHDR2;
#pragma pack(pop)

/* ---------- growable arrays ---------- */
typedef struct { unsigned char *p; size_t len, cap; } BUF;
static int buf_put(BUF *b, const void *d, size_t n)
{
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap + b->cap / 2 : 65536;
        unsigned char *np;
        while (b->len + n > nc) nc += nc / 2;
        np = (unsigned char*)realloc(b->p, nc);
        if (!np) return 0;
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
    return 1;
}

static BUF g_md5, g_sha, g_sect;
static int g_oom;

/* ---------- names ----------
 * Names go straight to a temp file as they're parsed, instead of being held in
 * RAM: a full ClamAV build has ~70 MB of them. ClamAV lists all the sections of
 * one sample together, so repeating the previous name is the common case and
 * is stored once. Offset 0 is always "". */
static FILE        *g_namef;
static unsigned int g_namelen;
static char         g_lastname[201];
static size_t       g_lastlen;
static unsigned int g_lastoff;

static unsigned int intern(const char *s, size_t n)
{
    unsigned int off;
    char zero = 0;
    if (n == 0) return 0;
    if (n > 200) n = 200;
    if (n == g_lastlen && memcmp(s, g_lastname, n) == 0) return g_lastoff;
    off = g_namelen;
    if (fwrite(s, 1, n, g_namef) != n || fwrite(&zero, 1, 1, g_namef) != 1) {
        g_oom = 1;
        return 0;
    }
    g_namelen += (unsigned int)n + 1;
    memcpy(g_lastname, s, n);
    g_lastlen = n;
    g_lastoff = off;
    return off;
}

/* ---------- line parsing ---------- */
static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int unhex(const char *s, size_t n, unsigned char *out)
{
    size_t i;
    for (i = 0; i < n / 2; i++) {
        int hi = hexval(s[i*2]), lo = hexval(s[i*2+1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/* Split a line into up to 4 ':' fields. Returns the field count. */
static int split(const char *p, const char *end, const char **f, size_t *fl)
{
    int n = 0;
    while (n < 4) {
        const char *c = memchr(p, ':', (size_t)(end - p));
        f[n] = p;
        fl[n] = (size_t)((c ? c : end) - p);
        n++;
        if (!c) break;
        p = c + 1;
    }
    return n;
}

static int parse_size(const char *s, size_t n, unsigned int *out)
{
    unsigned long v = 0;
    size_t i;
    if (n == 1 && s[0] == '*') { *out = 0; return 1; }      /* any size */
    if (n == 0 || n > 10) return 0;
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        v = v * 10 + (unsigned long)(s[i] - '0');
    }
    if (v > 0xFFFFFFFFul) return 0;
    *out = (unsigned int)v;
    return 1;
}

enum { DB_HASH, DB_SECT };
static unsigned long g_skipped_sha1, g_skipped_bad;

static void parse_line(const char *p, const char *le, int kind)
{
    const char *f[4];
    size_t fl[4];
    int nf;
    if (le > p && le[-1] == '\r') le--;
    if (le == p || *p == '#') return;
    nf = split(p, le, f, fl);
    if (nf < 3) return;
    if (kind == DB_HASH) {                          /* Hash:Size:Name */
        unsigned int size;
        if (!parse_size(f[1], fl[1], &size)) { g_skipped_bad++; return; }
        if (fl[0] == 32) {
            SIGHASH r;
            if (!unhex(f[0], 32, r.md5)) { g_skipped_bad++; return; }
            r.size = size; r.nameoff = intern(f[2], fl[2]);
            if (!buf_put(&g_md5, &r, sizeof r)) g_oom = 1;
        } else if (fl[0] == 64) {
            SIGSHA r;
            if (!unhex(f[0], 64, r.sha)) { g_skipped_bad++; return; }
            r.size = size; r.nameoff = intern(f[2], fl[2]);
            if (!buf_put(&g_sha, &r, sizeof r)) g_oom = 1;
        } else if (fl[0] == 40) g_skipped_sha1++;
        else g_skipped_bad++;
    } else {                                        /* Size:MD5:Name */
        unsigned int size;
        SIGHASH r;
        /* wildcard-size section signatures can't be used: the scanner only
         * hashes sections whose size is listed */
        if (fl[1] == 32 && parse_size(f[0], fl[0], &size) && size &&
            unhex(f[1], 32, r.md5)) {
            r.size = size; r.nameoff = intern(f[2], fl[2]);
            if (!buf_put(&g_sect, &r, sizeof r)) g_oom = 1;
        } else if (fl[1] == 40 || fl[1] == 64) g_skipped_sha1++;
        else g_skipped_bad++;
    }
}

/* ---------- streaming gunzip + tar ----------
 * The old version inflated the whole of main.cvd into memory (hundreds of MB)
 * before looking at it, which sent low-RAM XP machines into heavy swapping.
 * Now the tar is parsed as it comes out of zlib, 64 KB at a time. */

enum { T_HDR, T_DATA, T_PAD, T_END };
typedef struct {
    int state, kind;
    unsigned char hdr[512];
    unsigned int hlen, pad;
    unsigned long left;
    char line[1024];
    unsigned int llen;
    int overflow;
    unsigned long members;
} TARST;

static unsigned int tar_octal(const unsigned char *p, int n)
{
    unsigned int v = 0; int i;
    for (i = 0; i < n && p[i]; i++) {
        if (p[i] < '0' || p[i] > '7') break;
        v = v * 8 + (unsigned)(p[i] - '0');
    }
    return v;
}

static int ends_with(const char *s, const char *suf)
{
    size_t a = strlen(s), b = strlen(suf), i;
    if (a < b) return 0;
    for (i = 0; i < b; i++) {
        char x = s[a-b+i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (x != suf[i]) return 0;
    }
    return 1;
}

static void end_line(TARST *t)
{
    if (!t->overflow && t->llen) parse_line(t->line, t->line + t->llen, t->kind);
    t->llen = 0;
    t->overflow = 0;
}

static void tar_feed(TARST *t, const unsigned char *p, size_t n)
{
    while (n && t->state != T_END && !g_oom) {
        if (t->state == T_HDR) {
            size_t take = 512 - t->hlen;
            if (take > n) take = n;
            memcpy(t->hdr + t->hlen, p, take);
            t->hlen += (unsigned int)take; p += take; n -= take;
            if (t->hlen < 512) break;
            t->hlen = 0;
            if (t->hdr[0] == 0) { t->state = T_END; break; }   /* end of archive */
            {
                char name[101];
                memcpy(name, t->hdr, 100); name[100] = 0;
                t->left = tar_octal(t->hdr + 124, 12);
                t->pad  = (unsigned int)((512 - (t->left % 512)) % 512);
                if (ends_with(name, ".hdb") || ends_with(name, ".hdu") ||
                    ends_with(name, ".hsb") || ends_with(name, ".hsu"))
                    t->kind = DB_HASH;
                else if (ends_with(name, ".mdb") || ends_with(name, ".mdu"))
                    t->kind = DB_SECT;
                else
                    t->kind = -1;
                if (t->kind >= 0) t->members++;
            }
            t->llen = 0; t->overflow = 0;
            t->state = t->left ? T_DATA : (t->pad ? T_PAD : T_HDR);
        } else if (t->state == T_DATA) {
            size_t take = n < t->left ? n : t->left, i;
            if (t->kind >= 0) {
                for (i = 0; i < take; i++) {
                    char c = (char)p[i];
                    if (c == '\n') end_line(t);
                    else if (t->llen < sizeof(t->line)) t->line[t->llen++] = c;
                    else t->overflow = 1;                      /* absurd line: drop it */
                }
            }
            p += take; n -= take; t->left -= take;
            if (!t->left) {
                if (t->kind >= 0) end_line(t);                 /* last line, no newline */
                t->state = t->pad ? T_PAD : T_HDR;
            }
        } else {                                               /* T_PAD */
            size_t take = n < t->pad ? n : t->pad;
            p += take; n -= take; t->pad -= (unsigned int)take;
            if (!t->pad) t->state = T_HDR;
        }
    }
}

static void progress(const char *label, int pct)
{
    char bar[31];
    int i, fill = pct * 30 / 100;
    for (i = 0; i < 30; i++) bar[i] = i < fill ? '#' : '.';
    bar[30] = 0;
    printf("\r  %-10s [%s] %3d%%", label, bar, pct);
    fflush(stdout);
}

static const char *base_name(const char *path)
{
    const char *a = strrchr(path, '\\'), *b = strrchr(path, '/');
    if (b > a) a = b;
    return a ? a + 1 : path;
}

static int process_cvd(const char *path, unsigned long *members)
{
    FILE *f = fopen(path, "rb");
    unsigned char *in, *out;
    z_stream zs;
    TARST *t;
    long total, pos;
    int ret = Z_OK, last = -1, pct, ok = 1;
    size_t rd;

    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    total = ftell(f);
    fseek(f, 512, SEEK_SET);                        /* skip the CVD text header */

    in  = (unsigned char*)malloc(65536);
    out = (unsigned char*)malloc(65536);
    t   = (TARST*)calloc(1, sizeof(TARST));
    memset(&zs, 0, sizeof zs);
    if (!in || !out || !t || inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
        free(in); free(out); free(t); fclose(f); return 0;
    }

    while (ret != Z_STREAM_END && t->state != T_END && !g_oom) {
        rd = fread(in, 1, 65536, f);
        if (rd == 0) break;
        zs.next_in = in; zs.avail_in = (uInt)rd;
        do {
            zs.next_out = out; zs.avail_out = 65536;
            ret = inflate(&zs, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) { ok = 0; break; }
            tar_feed(t, out, 65536 - zs.avail_out);
        } while (zs.avail_out == 0 && ret != Z_STREAM_END);
        if (!ok) break;
        pos = ftell(f);
        pct = total > 512 ? (int)((double)(pos - 512) * 100.0 / (double)(total - 512)) : 100;
        if (pct > 100) pct = 100;
        if (pct != last) { progress(base_name(path), pct); last = pct; }
    }
    if (ok) progress(base_name(path), 100);
    printf("\n");
    *members += t->members;
    inflateEnd(&zs);
    free(in); free(out); free(t);
    fclose(f);
    return ok;
}

/* ---------- sort + dedup ---------- */
static int cmp_hash(const void *a, const void *b)
{
    const SIGHASH *x = a, *y = b;
    int c = memcmp(x->md5, y->md5, 16);
    if (c) return c;
    return (x->size > y->size) - (x->size < y->size);
}
static int cmp_sha(const void *a, const void *b)
{
    const SIGSHA *x = a, *y = b;
    int c = memcmp(x->sha, y->sha, 32);
    if (c) return c;
    return (x->size > y->size) - (x->size < y->size);
}

static size_t dedup(void *base, size_t n, size_t sz, size_t keylen)
{
    unsigned char *p = base;
    size_t w = 0, r;
    if (!n) return 0;
    qsort(base, n, sz, keylen == 16 ? cmp_hash : cmp_sha);
    for (r = 1, w = 1; r < n; r++) {
        unsigned char *prev = p + (w - 1) * sz, *cur = p + r * sz;
        /* same hash AND same size field = duplicate */
        if (memcmp(prev, cur, keylen + 4) != 0) {
            if (w != r) memcpy(p + w * sz, cur, sz);
            w++;
        }
    }
    return w;
}

/* ---------- entry point ---------- */
int cvd_compile(const char **cvd_files, const char *out_cdb)
{
    static const char eicar[] =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    size_t nmd5, nsha, nsect;
    unsigned long members = 0;
    unsigned int eicar_name, ram_mb;
    char tmpname[1024], zero = 0;
    unsigned char copybuf[65536];
    SIGHDR hdr;
    SIGHDR2 hdr2;
    SIGPAT pat;
    FILE *o;
    size_t n;
    int fi, rc = -1;

    memset(&g_md5, 0, sizeof g_md5);
    memset(&g_sha, 0, sizeof g_sha);
    memset(&g_sect, 0, sizeof g_sect);
    g_oom = 0; g_skipped_sha1 = g_skipped_bad = 0;
    g_namelen = 0; g_lastlen = 0; g_lastoff = 0;

    /* names are written to a temp file next to the output as they're parsed */
    if (strlen(out_cdb) > sizeof(tmpname) - 16) return -1;
    sprintf(tmpname, "%s.names.tmp", out_cdb);
    g_namef = fopen(tmpname, "w+b");
    if (!g_namef) { printf("  cannot create %s\n", tmpname); return -1; }
    fwrite(&zero, 1, 1, g_namef);                     /* offset 0 = "" */
    g_namelen = 1;
    eicar_name = intern("Eicar-Test-Signature", 20);

    for (fi = 0; cvd_files[fi]; fi++)
        if (!process_cvd(cvd_files[fi], &members))
            printf("  (could not unpack %s)\n", cvd_files[fi]);
    if (g_oom) { printf("  ran out of memory or disk space while compiling\n"); goto out; }

    printf("  sorting signatures...");
    fflush(stdout);
    nmd5  = dedup(g_md5.p,  g_md5.len  / sizeof(SIGHASH), sizeof(SIGHASH), 16);
    nsha  = dedup(g_sha.p,  g_sha.len  / sizeof(SIGSHA),  sizeof(SIGSHA),  32);
    nsect = dedup(g_sect.p, g_sect.len / sizeof(SIGHASH), sizeof(SIGHASH), 16);
    printf(" done\n");

    printf("  %lu file MD5, %lu file SHA-256, %lu PE section signatures\n",
           (unsigned long)nmd5, (unsigned long)nsha, (unsigned long)nsect);
    printf("  from %lu database member(s); %lu SHA-1 lines skipped\n",
           members, g_skipped_sha1);
    if (nmd5 + nsha + nsect == 0) { printf("  nothing to write\n"); goto out; }

    /* what the engine keeps resident: a 12-byte key per MD5/section hash,
     * SHA-256 records whole, plus a list of section sizes */
    ram_mb = (unsigned int)((nmd5 * 12 + nsect * 16 + nsha * 40) >> 20) + 1;
    printf("  about %u MB of RAM once CarrotAV loads it\n", ram_mb);

    memset(&hdr, 0, sizeof hdr);
    memcpy(hdr.magic, "CAVD", 4);
    hdr.version  = 2;
    hdr.nhash    = (unsigned int)nmd5;
    hdr.npat     = 1;
    hdr.patblob  = (unsigned int)(sizeof(eicar) - 1);
    hdr.nameblob = g_namelen;
    hdr.built    = (unsigned int)time(NULL);
    memset(&hdr2, 0, sizeof hdr2);
    hdr2.nsha  = (unsigned int)nsha;
    hdr2.nsect = (unsigned int)nsect;
    pat.len = (unsigned short)(sizeof(eicar) - 1);
    pat.dataoff = 0;
    pat.nameoff = eicar_name;

    printf("  writing carrot.cdb...");
    fflush(stdout);
    o = fopen(out_cdb, "wb");
    if (!o) { printf("\n  cannot create %s\n", out_cdb); goto out; }
    fwrite(&hdr, sizeof hdr, 1, o);
    fwrite(&hdr2, sizeof hdr2, 1, o);
    if (nmd5)  fwrite(g_md5.p,  sizeof(SIGHASH), nmd5,  o);
    if (nsha)  fwrite(g_sha.p,  sizeof(SIGSHA),  nsha,  o);
    if (nsect) fwrite(g_sect.p, sizeof(SIGHASH), nsect, o);
    fwrite(&pat, sizeof pat, 1, o);
    fwrite(eicar, 1, sizeof(eicar) - 1, o);
    fflush(g_namef);
    fseek(g_namef, 0, SEEK_SET);                      /* append the names */
    while ((n = fread(copybuf, 1, sizeof copybuf, g_namef)) > 0)
        if (fwrite(copybuf, 1, n, o) != n) { fclose(o); printf("\n  write failed\n"); goto out; }
    if (fclose(o) != 0) { printf("\n  write failed\n"); goto out; }
    printf(" done\n");
    rc = 0;

out:
    fclose(g_namef);
    g_namef = NULL;
    remove(tmpname);
    free(g_md5.p); free(g_sha.p); free(g_sect.p);
    memset(&g_md5, 0, sizeof g_md5);
    memset(&g_sha, 0, sizeof g_sha);
    memset(&g_sect, 0, sizeof g_sect);
    return rc;
}

/* defs_build.c - unpack ClamAV .cvd files and compile carrot.cdb.
 *
 * A .cvd is: 512-byte ASCII colon-delimited header, then a gzip stream that
 * decompresses to a POSIX tar. We gunzip with zlib (compiled in), walk the tar
 * in memory, and pull hashes out of the .hdb / .hsb members. Pattern (.ndb)
 * signatures are intentionally skipped: they are offset/target-anchored in
 * ClamAV and matching them unanchored produced the mass false positives we hit
 * earlier, so the XP engine ships hash signatures only.
 *
 * Output format is byte-identical to what get_defs.py / build_defs.py write,
 * so CarrotAV loads it with no changes.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#define MAGIC       "CAVD"
#define FMT_VER     1

#pragma pack(push,1)
typedef struct { unsigned char md5[16]; unsigned int size; unsigned int nameoff; } SIGHASH;
typedef struct {
    char magic[4]; unsigned int version, nhash, npat, patblob, nameblob, built;
} SIGHDR;
#pragma pack(pop)

/* growable byte buffer */
typedef struct { unsigned char *p; size_t len, cap; } BUF;
static void buf_init(BUF *b){ b->p=NULL; b->len=0; b->cap=0; }
static void buf_put(BUF *b, const void *d, size_t n){
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap*2 : 65536;
        while (b->len + n > nc) nc *= 2;
        b->p = (unsigned char*)realloc(b->p, nc); b->cap = nc;
    }
    memcpy(b->p + b->len, d, n); b->len += n;
}

/* ---- gunzip a whole file into memory ---- */
static unsigned char *gunzip_file(const char *path, size_t *outlen)
{
    FILE *f = fopen(path, "rb");
    unsigned char in[16384];
    BUF out; z_stream zs;
    int ret; size_t rd;

    if (!f) return NULL;
    /* skip the 512-byte CVD header before the gzip stream */
    fseek(f, 512, SEEK_SET);

    buf_init(&out);
    memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) { fclose(f); return NULL; }

    do {
        rd = fread(in, 1, sizeof(in), f);
        if (rd == 0) break;
        zs.next_in = in; zs.avail_in = (uInt)rd;
        do {
            unsigned char chunk[32768];
            zs.next_out = chunk; zs.avail_out = sizeof(chunk);
            ret = inflate(&zs, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
                inflateEnd(&zs); fclose(f); free(out.p); return NULL;
            }
            buf_put(&out, chunk, sizeof(chunk) - zs.avail_out);
        } while (zs.avail_out == 0);
    } while (ret != Z_STREAM_END);

    inflateEnd(&zs);
    fclose(f);
    *outlen = out.len;
    return out.p;
}

/* ---- tar walk ---- */
static unsigned int tar_octal(const char *p, int n){
    unsigned int v = 0; int i;
    for (i = 0; i < n && p[i]; i++) { if (p[i] < '0' || p[i] > '7') break; v = v*8 + (p[i]-'0'); }
    return v;
}

/* ---- hash collection ---- */
typedef struct { unsigned char md5[16]; unsigned int size; } HREC;
static HREC *g_h; static size_t g_hn, g_hcap;

static void add_hash(const unsigned char md5[16], unsigned int size){
    if (g_hn >= g_hcap) {
        g_hcap = g_hcap ? g_hcap*2 : 1<<16;
        g_h = (HREC*)realloc(g_h, g_hcap * sizeof(HREC));
    }
    memcpy(g_h[g_hn].md5, md5, 16); g_h[g_hn].size = size; g_hn++;
}

static int hexval(char c){
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

/* parse a .hdb/.hsb member: <md5hex>:<size>:<name> per line */
static void parse_hashdb(const char *data, size_t len)
{
    const char *p = data, *end = data + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', end - p);
        const char *line_end = nl ? nl : end;
        const char *c1 = memchr(p, ':', line_end - p);
        if (c1 && (c1 - p) == 32) {
            unsigned char md5[16];
            int i, ok = 1;
            for (i = 0; i < 16; i++) {
                int hi = hexval(p[i*2]), lo = hexval(p[i*2+1]);
                if (hi < 0 || lo < 0) { ok = 0; break; }
                md5[i] = (unsigned char)((hi<<4)|lo);
            }
            if (ok) {
                const char *c2 = memchr(c1+1, ':', line_end - (c1+1));
                unsigned int size = 0;
                if (c2) {
                    if (c1[1] == '*') size = 0;
                    else size = (unsigned int)atoi(c1+1);
                }
                add_hash(md5, size);
            }
        }
        p = nl ? nl + 1 : end;
    }
}

static int cmp_hrec(const void *a, const void *b){
    return memcmp(((const HREC*)a)->md5, ((const HREC*)b)->md5, 16);
}

int cvd_compile(const char **cvd_files, const char *out_cdb)
{
    int fi;
    size_t total_members = 0;

    g_h = NULL; g_hn = 0; g_hcap = 0;

    for (fi = 0; cvd_files[fi]; fi++) {
        size_t tlen = 0;
        unsigned char *tar = gunzip_file(cvd_files[fi], &tlen);
        size_t pos = 0;
        if (!tar) { printf("  (could not unpack %s)\n", cvd_files[fi]); continue; }

        while (pos + 512 <= tlen) {
            char *hdr = (char*)tar + pos;
            char name[101];
            unsigned int fsize;
            if (hdr[0] == 0) break;                 /* end of archive */
            memcpy(name, hdr, 100); name[100] = 0;
            fsize = tar_octal(hdr + 124, 12);
            pos += 512;
            if (pos + fsize > tlen) break;

            {
                size_t nl = strlen(name);
                if (nl > 4 &&
                    (!_stricmp(name + nl - 4, ".hdb") ||
                     !_stricmp(name + nl - 4, ".hsb") ||
                     !_stricmp(name + nl - 4, ".hdu"))) {
                    parse_hashdb((char*)tar + pos, fsize);
                    total_members++;
                }
            }
            pos += (fsize + 511) & ~((size_t)511);   /* tar 512-byte padding */
        }
        free(tar);
    }

    printf("  parsed %u hash signatures from %u database member(s)\n",
           (unsigned)g_hn, (unsigned)total_members);

    if (g_hn == 0) { printf("  nothing to write\n"); return -1; }

    /* de-dup + sort so CarrotAV can binary-search */
    qsort(g_h, g_hn, sizeof(HREC), cmp_hrec);
    {
        size_t w = 1, r;
        for (r = 1; r < g_hn; r++) {
            if (memcmp(g_h[r].md5, g_h[w-1].md5, 16) != 0 ||
                g_h[r].size != g_h[w-1].size)
                g_h[w++] = g_h[r];
        }
        g_hn = w;
    }

    /* append EICAR as a pattern so installs stay verifiable */
    {
        static const unsigned char eicar[] =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        unsigned int elen = (unsigned int)strlen((const char*)eicar);

        /* names blob: one shared "" for hashes + the EICAR name */
        const char *ename = "Eicar-Test-Signature";
        unsigned int enameoff = 1;               /* offset 0 is the empty string */
        BUF names; buf_init(&names);
        { char z = 0; buf_put(&names, &z, 1); }
        buf_put(&names, ename, (unsigned int)strlen(ename) + 1);

        FILE *o = fopen(out_cdb, "wb");
        SIGHDR hdr;
        size_t i;
        if (!o) { printf("  cannot create %s\n", out_cdb); return -1; }

        memcpy(hdr.magic, MAGIC, 4);
        hdr.version = FMT_VER;
        hdr.nhash = (unsigned int)g_hn;
        hdr.npat = 1;
        hdr.patblob = elen;
        hdr.nameblob = (unsigned int)names.len;
        hdr.built = (unsigned int)time(NULL);
        fwrite(&hdr, sizeof(hdr), 1, o);

        for (i = 0; i < g_hn; i++) {
            SIGHASH sh;
            memcpy(sh.md5, g_h[i].md5, 16);
            sh.size = g_h[i].size;
            sh.nameoff = 0;                      /* all hashes share "" */
            fwrite(&sh, sizeof(sh), 1, o);
        }
        /* one pattern record: EICAR */
        {
            struct { unsigned short len; unsigned int dataoff, nameoff; } pat;
            pat.len = (unsigned short)elen; pat.dataoff = 0; pat.nameoff = enameoff;
            fwrite(&pat, sizeof(pat), 1, o);
        }
        fwrite(eicar, 1, elen, o);
        fwrite(names.p, 1, names.len, o);
        fclose(o);
        free(names.p);
    }

    free(g_h);
    return 0;
}

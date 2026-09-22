/* sigdb.c - compact signature database: load, binary-search hashes,
 * bucketed multi-pattern byte matching.
 *
 * On-disk layouts (both loaded):
 *   v1  SIGHDR | SIGHASH[nhash] | SIGPAT[npat] | patdata | names
 *   v2  SIGHDR | SIGHDR2 | SIGHASH[nhash] | SIGSHA[nsha] | SIGHASH[nsect]
 *              | SIGPAT[npat] | patdata | names
 *
 * Memory model (engine 2.0). A full ClamAV build is ~3.2 million hashes plus
 * ~70 MB of malware names - about 158 MB if held in RAM, far too much for an
 * XP machine to keep resident in the tray. So RAM holds only a 12-byte key
 * per hash (8-byte hash prefix + size). When a key matches, the full record
 * is read from carrot.cdb to confirm every byte of the hash, and the name is
 * read from disk too. Matches are rare, so the disk reads cost nothing in
 * practice, and a prefix collision can never produce a false detection
 * because the full hash is always checked.
 *
 * This relies on the file being sorted, which every CarrotAV writer does.
 * The file is untrusted, so that's verified on load rather than assumed.
 */
#include "av.h"

#define CAP_RECORDS 40000000u
#define CAP_BLOB    268435456u
#define CHUNK_RECS  4096

static int cmp_sha(const void *a, const void *b)
{
    return memcmp(((const SIGSHA*)a)->sha, ((const SIGSHA*)b)->sha, 32);
}
static int cmp_uint(const void *a, const void *b)
{
    unsigned int x = *(const unsigned int*)a, y = *(const unsigned int*)b;
    return (x > y) - (x < y);
}

void sigdb_free(SIGDB *db)
{
    int i;
    if (!db) return;
    for (i = 0; i < 256; i++) { free(db->bucket[i]); db->bucket[i] = NULL; db->bucketn[i] = 0; }
    free(db->hkeys);     db->hkeys     = NULL;
    free(db->skeys);     db->skeys     = NULL;
    free(db->shas);      db->shas      = NULL;
    free(db->sectsizes); db->sectsizes = NULL;
    free(db->pats);      db->pats      = NULL;
    free(db->patdata);   db->patdata   = NULL;
    db->nsectsizes = 0;
    db->loaded = FALSE;
}

static BOOL read_exact(HANDLE h, void *buf, DWORD n)
{
    DWORD rd;
    return n == 0 || (ReadFile(h, buf, n, &rd, NULL) && rd == n);
}

static BOOL read_at(HANDLE h, DWORD off, void *buf, DWORD n)
{
    if (SetFilePointer(h, (LONG)off, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
        GetLastError() != NO_ERROR) return FALSE;
    return read_exact(h, buf, n);
}

/* Read `count` SIGHASH records, keeping only a 12-byte key per record.
 * Rejects the file if the records aren't sorted - the key index must line up
 * with the on-disk record for the later full-hash check. */
static BOOL load_keys(HANDLE h, SIGKEY **out, unsigned int count)
{
    SIGHASH *chunk;
    SIGKEY *k;
    unsigned int done = 0, i, n;

    *out = NULL;
    if (!count) return TRUE;
    k = (SIGKEY*)malloc((size_t)count * sizeof(SIGKEY));
    chunk = (SIGHASH*)malloc(CHUNK_RECS * sizeof(SIGHASH));
    if (!k || !chunk) { free(k); free(chunk); return FALSE; }

    while (done < count) {
        n = count - done;
        if (n > CHUNK_RECS) n = CHUNK_RECS;
        if (!read_exact(h, chunk, n * sizeof(SIGHASH))) goto bad;
        for (i = 0; i < n; i++) {
            memcpy(k[done + i].pre, chunk[i].md5, 8);
            k[done + i].size = chunk[i].size;
            if (done + i > 0 && memcmp(k[done + i - 1].pre, k[done + i].pre, 8) > 0)
                goto bad;                                   /* not sorted */
        }
        done += n;
    }
    free(chunk);
    *out = k;
    return TRUE;
bad:
    free(chunk);
    free(k);
    return FALSE;
}

BOOL sigdb_load(SIGDB *db, const wchar_t *path)
{
    HANDLE h;
    DWORD fsz, hi = 0;
    unsigned __int64 end;
    unsigned int i, b, nrec, base;
    unsigned int counts[256];

    memset(db, 0, sizeof(*db));
    lstrcpynW(db->path, path, MAX_PATH);

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    fsz = GetFileSize(h, &hi);
    if (hi || fsz == INVALID_FILE_SIZE) goto fail;

    if (!read_exact(h, &db->hdr, sizeof(SIGHDR))) goto fail;
    if (memcmp(db->hdr.magic, "CAVD", 4) != 0) goto fail;
    if (db->hdr.version != 1 && db->hdr.version != 2) goto fail;
    if (db->hdr.version == 2 && !read_exact(h, &db->hdr2, sizeof(SIGHDR2))) goto fail;

    if (db->hdr.nhash > CAP_RECORDS || db->hdr.npat > CAP_RECORDS / 10 ||
        db->hdr2.nsha > CAP_RECORDS || db->hdr2.nsect > CAP_RECORDS ||
        db->hdr.patblob > CAP_BLOB || db->hdr.nameblob > CAP_BLOB)
        goto fail;

    /* Work out where every table lives and make sure the file really is that
     * big. This one check validates all the counts against the file at once. */
    base = sizeof(SIGHDR) + (db->hdr.version == 2 ? sizeof(SIGHDR2) : 0);
    end  = base;
    db->off_md5 = (DWORD)end;  end += (unsigned __int64)db->hdr.nhash  * sizeof(SIGHASH);
    end += (unsigned __int64)db->hdr2.nsha  * sizeof(SIGSHA);
    db->off_sect= (DWORD)end;  end += (unsigned __int64)db->hdr2.nsect * sizeof(SIGHASH);
    end += (unsigned __int64)db->hdr.npat   * sizeof(SIGPAT);
    end += db->hdr.patblob;
    db->off_names = (DWORD)end;
    end += db->hdr.nameblob;
    if (end > fsz) goto fail;
    db->filesize = fsz;

    nrec = db->hdr.nhash + db->hdr2.nsha + db->hdr2.nsect + db->hdr.npat;
    if (nrec && !db->hdr.nameblob) goto fail;          /* names must exist somewhere */
    if (db->hdr.npat && !db->hdr.patblob) goto fail;

    /* file is read strictly in layout order */
    if (!load_keys(h, &db->hkeys, db->hdr.nhash)) goto fail;
    if (db->hdr2.nsha) {
        db->shas = (SIGSHA*)malloc((size_t)db->hdr2.nsha * sizeof(SIGSHA));
        if (!db->shas || !read_exact(h, db->shas, db->hdr2.nsha * sizeof(SIGSHA))) goto fail;
    }
    if (!load_keys(h, &db->skeys, db->hdr2.nsect)) goto fail;
    if (db->hdr.npat) {
        db->pats = (SIGPAT*)malloc((size_t)db->hdr.npat * sizeof(SIGPAT));
        db->patdata = (unsigned char*)malloc(db->hdr.patblob);
        if (!db->pats || !db->patdata) goto fail;
        if (!read_exact(h, db->pats, db->hdr.npat * sizeof(SIGPAT))) goto fail;
        if (!read_exact(h, db->patdata, db->hdr.patblob)) goto fail;
    }
    CloseHandle(h);
    h = INVALID_HANDLE_VALUE;

    /* patterns: bytes must lie wholly inside patdata, or the pattern is dropped */
    for (i = 0; i < db->hdr.npat; i++) {
        SIGPAT *p = &db->pats[i];
        if (p->len == 0 || p->len > MAX_PAT || p->dataoff >= db->hdr.patblob ||
            (unsigned __int64)p->dataoff + p->len > db->hdr.patblob)
            p->len = 0;
    }
    if (db->hdr2.nsha > 1) qsort(db->shas, db->hdr2.nsha, sizeof(SIGSHA), cmp_sha);

    /* Distinct section sizes, so the scanner can skip hashing any section
     * whose size no signature has. Shrunk to fit once deduplicated. */
    if (db->hdr2.nsect) {
        unsigned int *t;
        db->sectsizes = (unsigned int*)malloc((size_t)db->hdr2.nsect * sizeof(unsigned int));
        if (!db->sectsizes) goto fail;
        for (i = 0; i < db->hdr2.nsect; i++) db->sectsizes[i] = db->skeys[i].size;
        qsort(db->sectsizes, db->hdr2.nsect, sizeof(unsigned int), cmp_uint);
        for (i = 0; i < db->hdr2.nsect; i++)
            if (db->nsectsizes == 0 || db->sectsizes[db->nsectsizes - 1] != db->sectsizes[i])
                db->sectsizes[db->nsectsizes++] = db->sectsizes[i];
        t = (unsigned int*)realloc(db->sectsizes, db->nsectsizes * sizeof(unsigned int));
        if (t) db->sectsizes = t;
    }

    memset(counts, 0, sizeof(counts));
    for (i = 0; i < db->hdr.npat; i++)
        if (db->pats[i].len) counts[db->patdata[db->pats[i].dataoff]]++;
    for (b = 0; b < 256; b++)
        if (counts[b]) {
            db->bucket[b] = (unsigned int*)malloc(counts[b] * sizeof(unsigned int));
            if (!db->bucket[b]) goto fail;
        }
    for (i = 0; i < db->hdr.npat; i++) {
        if (!db->pats[i].len) continue;
        b = db->patdata[db->pats[i].dataoff];
        db->bucket[b][db->bucketn[b]++] = i;
    }

    db->loaded = TRUE;
    return TRUE;

fail:
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    sigdb_free(db);
    return FALSE;
}

unsigned int sigdb_count(SIGDB *db)
{
    if (!db || !db->loaded) return 0;
    return db->hdr.nhash + db->hdr2.nsha + db->hdr2.nsect + db->hdr.npat;
}

/* ---------------- on-demand disk reads ---------------- */

/* Open the database for a confirming read. Returns INVALID_HANDLE_VALUE if
 * the file has been replaced since load (an update in progress): the in-RAM
 * keys no longer describe it, so we report nothing rather than guess. */
static HANDLE open_db(SIGDB *db)
{
    DWORD hi = 0, sz;
    HANDLE h = CreateFileW(db->path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return h;
    sz = GetFileSize(h, &hi);
    if (hi || sz != db->filesize) { CloseHandle(h); return INVALID_HANDLE_VALUE; }
    return h;
}

/* A small ring of name buffers: callers copy the name straight away, and the
 * scanner and shield can both be reporting at once, so one static buffer
 * isn't enough. 64 slots is far more hits than can be in flight. */
#define NAME_SLOTS 64
static char  g_name[NAME_SLOTS][160];
static LONG  g_slot;

static const char *read_name(SIGDB *db, HANDLE h, unsigned int nameoff)
{
    char *out = g_name[(unsigned)InterlockedIncrement(&g_slot) & (NAME_SLOTS - 1)];
    DWORD want, i;
    out[0] = 0;
    if (nameoff >= db->hdr.nameblob) return out;          /* bad offset: blank name */
    want = db->hdr.nameblob - nameoff;
    if (want > 159) want = 159;
    if (!read_at(h, db->off_names + nameoff, out, want)) { out[0] = 0; return out; }
    out[want] = 0;
    for (i = 0; i < want; i++) if (!out[i]) break;         /* stop at the NUL */
    return out;
}

static const char *name_only(SIGDB *db, unsigned int nameoff)
{
    const char *n;
    HANDLE h = open_db(db);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    n = read_name(db, h, nameoff);
    CloseHandle(h);
    return n;
}

/* Find the first key with this 8-byte prefix, walk every key sharing it, and
 * confirm each size-compatible candidate against its full on-disk record. */
static const char *lookup(SIGDB *db, const SIGKEY *keys, unsigned int n, DWORD table_off,
                          const unsigned char md5[16], unsigned int size)
{
    long lo = 0, hi = (long)n - 1, mid, first = -1;
    HANDLE h = INVALID_HANDLE_VALUE;
    const char *hit = NULL;
    unsigned int i;

    if (!keys || !n) return NULL;
    while (lo <= hi) {                                     /* lower bound */
        mid = lo + (hi - lo) / 2;
        if (memcmp(keys[mid].pre, md5, 8) >= 0) { if (!memcmp(keys[mid].pre, md5, 8)) first = mid; hi = mid - 1; }
        else lo = mid + 1;
    }
    if (first < 0) return NULL;

    for (i = (unsigned int)first; i < n && !memcmp(keys[i].pre, md5, 8) && !hit; i++) {
        SIGHASH rec;
        if (keys[i].size != 0 && keys[i].size != size) continue;
        if (h == INVALID_HANDLE_VALUE) {
            h = open_db(db);
            if (h == INVALID_HANDLE_VALUE) return NULL;
        }
        if (!read_at(h, table_off + i * (DWORD)sizeof(SIGHASH), &rec, sizeof rec)) break;
        if (memcmp(rec.md5, md5, 16) == 0)                 /* every byte, not just 8 */
            hit = read_name(db, h, rec.nameoff);
    }
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    return hit;
}

const char *sigdb_match_hash(SIGDB *db, const unsigned char md5[16], unsigned int size)
{
    if (!db || !db->loaded) return NULL;
    return lookup(db, db->hkeys, db->hdr.nhash, db->off_md5, md5, size);
}

const char *sigdb_match_sect(SIGDB *db, const unsigned char md5[16], unsigned int size)
{
    if (!db || !db->loaded) return NULL;
    return lookup(db, db->skeys, db->hdr2.nsect, db->off_sect, md5, size);
}

const char *sigdb_match_sha(SIGDB *db, const unsigned char sha[32], unsigned int size)
{
    long lo, hi, mid;
    int c;
    if (!db || !db->loaded || !db->shas || !db->hdr2.nsha) return NULL;
    lo = 0; hi = (long)db->hdr2.nsha - 1;
    while (lo <= hi) {
        mid = lo + (hi - lo) / 2;
        c = memcmp(sha, db->shas[mid].sha, 32);
        if (c == 0) {
            while (mid > 0 && memcmp(db->shas[mid-1].sha, sha, 32) == 0) mid--;
            while ((unsigned long)mid < db->hdr2.nsha &&
                   memcmp(db->shas[mid].sha, sha, 32) == 0) {
                if (db->shas[mid].size == 0 || db->shas[mid].size == size)
                    return name_only(db, db->shas[mid].nameoff);
                mid++;
            }
            return NULL;
        }
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return NULL;
}

BOOL sigdb_has_sect_size(SIGDB *db, unsigned int size)
{
    long lo, hi, mid;
    if (!db || !db->loaded || !db->nsectsizes) return FALSE;
    lo = 0; hi = (long)db->nsectsizes - 1;
    while (lo <= hi) {
        mid = lo + (hi - lo) / 2;
        if (db->sectsizes[mid] == size) return TRUE;
        if (db->sectsizes[mid] < size) lo = mid + 1; else hi = mid - 1;
    }
    return FALSE;
}

const char *sigdb_match_buf(SIGDB *db, const unsigned char *buf, unsigned int len)
{
    unsigned int i, k;
    const SIGPAT *p;

    if (!db || !db->loaded || !db->hdr.npat || len < 2 || !db->patdata) return NULL;
    for (i = 0; i < len; i++) {
        unsigned char first = buf[i];
        if (!db->bucketn[first]) continue;
        for (k = 0; k < db->bucketn[first]; k++) {
            p = &db->pats[db->bucket[first][k]];
            if (i + p->len > len) continue;
            if (memcmp(buf + i, db->patdata + p->dataoff, p->len) == 0)
                return name_only(db, p->nameoff);
        }
    }
    return NULL;
}

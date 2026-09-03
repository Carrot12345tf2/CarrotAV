/* sigdb.c - compact signature database: load, binary-search hashes,
 * bucketed multi-pattern byte matching.
 */
#include "av.h"

static int cmp_md5(const void *a, const void *b)
{
    return memcmp(((const SIGHASH*)a)->md5, ((const SIGHASH*)b)->md5, 16);
}

void sigdb_free(SIGDB *db)
{
    int i;
    if (!db) return;
    for (i = 0; i < 256; i++) { free(db->bucket[i]); db->bucket[i] = NULL; db->bucketn[i] = 0; }
    free(db->hashes);  db->hashes  = NULL;
    free(db->pats);    db->pats    = NULL;
    free(db->patdata); db->patdata = NULL;
    free(db->names);   db->names   = NULL;
    db->loaded = FALSE;
}

BOOL sigdb_load(SIGDB *db, const wchar_t *path)
{
    HANDLE h;
    DWORD  rd;
    unsigned int i, b;
    unsigned int counts[256];

    memset(db, 0, sizeof(*db));

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    if (!ReadFile(h, &db->hdr, sizeof(SIGHDR), &rd, NULL) || rd != sizeof(SIGHDR))
        goto fail;
    if (memcmp(db->hdr.magic, "CAVD", 4) != 0 || db->hdr.version != 1)
        goto fail;
    /* sanity caps so a corrupt file can't ask for 3 GB */
    if (db->hdr.nhash > 40000000u || db->hdr.npat > 4000000u ||
        db->hdr.patblob > 268435456u || db->hdr.nameblob > 268435456u)
        goto fail;

    /* The allocation sizes below are computed in 32-bit if we aren't careful:
     * nhash * sizeof(SIGHASH) can wrap and under-allocate, after which the
     * ReadFile would write past the buffer. Do the multiply in 64-bit and
     * reject anything that doesn't fit in a DWORD. This database is data from
     * disk that we do not control, so every field gets checked. */
    if ((unsigned __int64)db->hdr.nhash * sizeof(SIGHASH) > 0xFFFFFFFFull ||
        (unsigned __int64)db->hdr.npat  * sizeof(SIGPAT)  > 0xFFFFFFFFull)
        goto fail;

    if (db->hdr.nhash) {
        db->hashes = (SIGHASH*)malloc((size_t)db->hdr.nhash * sizeof(SIGHASH));
        if (!db->hashes) goto fail;
        if (!ReadFile(h, db->hashes, db->hdr.nhash * sizeof(SIGHASH), &rd, NULL) ||
            rd != db->hdr.nhash * sizeof(SIGHASH)) goto fail;
    }
    if (db->hdr.npat) {
        db->pats = (SIGPAT*)malloc((size_t)db->hdr.npat * sizeof(SIGPAT));
        if (!db->pats) goto fail;
        if (!ReadFile(h, db->pats, db->hdr.npat * sizeof(SIGPAT), &rd, NULL) ||
            rd != db->hdr.npat * sizeof(SIGPAT)) goto fail;
    }
    if (db->hdr.patblob) {
        db->patdata = (unsigned char*)malloc(db->hdr.patblob);
        if (!db->patdata) goto fail;
        if (!ReadFile(h, db->patdata, db->hdr.patblob, &rd, NULL) ||
            rd != db->hdr.patblob) goto fail;
    }
    if (db->hdr.nameblob) {
        db->names = (char*)malloc(db->hdr.nameblob);
        if (!db->names) goto fail;
        if (!ReadFile(h, db->names, db->hdr.nameblob, &rd, NULL) ||
            rd != db->hdr.nameblob) goto fail;
        db->names[db->hdr.nameblob - 1] = 0;
    }
    CloseHandle(h);

    /* ---- validate every record before anything uses it ----
     *
     * A malformed or hostile carrot.cdb must not be able to make us read
     * outside our own buffers. The file gives us offsets into two blobs
     * (patdata and names) and we previously trusted most of them:
     *
     *   - pattern data was checked with `dataoff >= patblob` only, so a
     *     pattern with dataoff = patblob-1 and len = 200 read 199 bytes off
     *     the end during matching;
     *   - nameoff was never checked at all, yet `db->names + nameoff` is
     *     returned as a C string on every hit.
     *
     * Rather than re-checking at match time (easy to miss a path), we sanitize
     * here once: any record that doesn't fit is neutered - patterns get len 0
     * so the matcher skips them, and bad name offsets are pointed at the
     * blob's final NUL so they read as an empty string instead of running off
     * the end. After this loop, every remaining offset is in range. */
    if (db->names && db->hdr.nameblob)
        db->names[db->hdr.nameblob - 1] = 0;   /* guarantee a terminator */

    /* If records exist but the blob they point into does not, there is no safe
     * offset to fall back to - `names + anything` would be NULL-based. Reject
     * the database outright instead of hoping every caller NULL-checks. */
    if ((db->hdr.nhash || db->hdr.npat) && (!db->names || !db->hdr.nameblob))
        { sigdb_free(db); return FALSE; }
    if (db->hdr.npat && (!db->patdata || !db->hdr.patblob))
        { sigdb_free(db); return FALSE; }

    for (i = 0; i < db->hdr.nhash; i++) {
        if (db->hashes[i].nameoff >= db->hdr.nameblob)
            db->hashes[i].nameoff = db->hdr.nameblob - 1;
    }
    for (i = 0; i < db->hdr.npat; i++) {
        SIGPAT *p = &db->pats[i];
        /* pattern bytes must lie wholly inside patdata */
        if (p->len == 0 || p->len > MAX_PAT ||
            p->dataoff >= db->hdr.patblob ||
            (unsigned __int64)p->dataoff + p->len > db->hdr.patblob) {
            p->len = 0;                 /* matcher skips zero-length patterns */
            continue;
        }
        if (p->nameoff >= db->hdr.nameblob)
            p->nameoff = db->hdr.nameblob - 1;
    }

    /* the writer should already sort, but never trust the file */
    if (db->hdr.nhash > 1)
        qsort(db->hashes, db->hdr.nhash, sizeof(SIGHASH), cmp_md5);

    /* bucket patterns by first byte (all offsets validated above) */
    memset(counts, 0, sizeof(counts));
    for (i = 0; i < db->hdr.npat; i++) {
        if (db->pats[i].len == 0) continue;
        counts[db->patdata[db->pats[i].dataoff]]++;
    }
    for (b = 0; b < 256; b++) {
        if (counts[b]) {
            db->bucket[b] = (unsigned int*)malloc(counts[b] * sizeof(unsigned int));
            if (!db->bucket[b]) { sigdb_free(db); return FALSE; }
        }
    }
    for (i = 0; i < db->hdr.npat; i++) {
        if (db->pats[i].len == 0) continue;
        b = db->patdata[db->pats[i].dataoff];
        db->bucket[b][db->bucketn[b]++] = i;
    }

    db->loaded = TRUE;
    return TRUE;

fail:
    CloseHandle(h);
    sigdb_free(db);
    return FALSE;
}

unsigned int sigdb_count(SIGDB *db)
{
    if (!db || !db->loaded) return 0;
    return db->hdr.nhash + db->hdr.npat;
}

const char *sigdb_match_hash(SIGDB *db, const unsigned char md5[16], unsigned int size)
{
    long lo, hi, mid;
    int  c;

    if (!db || !db->loaded || !db->hdr.nhash || !db->names) return NULL;

    lo = 0; hi = (long)db->hdr.nhash - 1;
    while (lo <= hi) {
        mid = lo + (hi - lo) / 2;
        c = memcmp(md5, db->hashes[mid].md5, 16);
        if (c == 0) {
            /* walk back to the first record with this hash */
            while (mid > 0 && memcmp(db->hashes[mid-1].md5, md5, 16) == 0) mid--;
            while ((unsigned long)mid < db->hdr.nhash &&
                   memcmp(db->hashes[mid].md5, md5, 16) == 0) {
                if (db->hashes[mid].size == 0 || db->hashes[mid].size == size)
                    return db->names + db->hashes[mid].nameoff;
                mid++;
            }
            return NULL;
        }
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return NULL;
}

const char *sigdb_match_buf(SIGDB *db, const unsigned char *buf, unsigned int len)
{
    unsigned int i, k;
    unsigned char first;
    const SIGPAT *p;

    if (!db || !db->loaded || !db->hdr.npat || len < 2) return NULL;
    if (!db->patdata || !db->names) return NULL;

    for (i = 0; i < len; i++) {
        first = buf[i];
        if (!db->bucketn[first]) continue;
        for (k = 0; k < db->bucketn[first]; k++) {
            p = &db->pats[db->bucket[first][k]];
            if (i + p->len > len) continue;
            if (memcmp(buf + i, db->patdata + p->dataoff, p->len) == 0)
                return db->names + p->nameoff;
        }
    }
    return NULL;
}

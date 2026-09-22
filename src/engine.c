/* engine.c - CarrotAV Engine 2.0 signature matching.
 *
 * Engine 1.0 knew one trick: MD5 the whole file, look it up. Engine 2.0 adds:
 *
 *   - Whole-file SHA-256 (ClamAV .hsb). Newer ClamAV hash signatures are
 *     increasingly SHA-256 only, and engine 1.0 threw every one of them away.
 *   - PE section MD5 (ClamAV .mdb). Malware that's been recompiled, re-packed
 *     or had its resources swapped usually still carries the same code
 *     section, so a whole-file hash misses it but a section hash doesn't.
 *
 * Costs are kept flat for old machines: MD5 and SHA-256 are computed in the
 * same single read of the file, SHA-256 only when the loaded database has any
 * SHA-256 signatures, and a section is only hashed if its exact size appears
 * in the database - which rules out almost every section of almost every
 * file without reading a byte of it.
 */
#include "av.h"
#include "sha256.h"
#include "pe.h"

#define ENG_CHUNK    65536
#define PE_HEADSIZE  65536          /* enough for any sane PE header */
#define SECT_MAX     (64u << 20)    /* don't hash sections over 64 MB */

static HCRYPTPROV g_eprov;

static BOOL eprov(void)
{
    if (g_eprov) return TRUE;
    if (!CryptAcquireContextW(&g_eprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        g_eprov = 0;
        return FALSE;
    }
    return TRUE;
}

static unsigned int file_size32(HANDLE h)
{
    DWORD hi = 0, lo = GetFileSize(h, &hi);
    if (lo == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) return 0;
    if (hi) return 0xFFFFFFFFu;
    return lo;
}

/* One pass over the file: MD5 always, SHA-256 when want_sha. */
BOOL eng_hash_file(const wchar_t *path, unsigned char md5[16], unsigned char sha[32],
                   BOOL want_sha, unsigned int *size)
{
    HANDLE h;
    HCRYPTHASH hh = 0;
    SHA256_CTX sc;
    BYTE *buf;
    DWORD rd, len = 16;
    BOOL ok = FALSE;

    if (!eprov()) return FALSE;
    buf = (BYTE*)malloc(ENG_CHUNK);
    if (!buf) return FALSE;

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) { free(buf); return FALSE; }
    if (size) *size = file_size32(h);

    if (!CryptCreateHash(g_eprov, CALG_MD5, 0, 0, &hh)) goto done;
    if (want_sha) sha256_init(&sc);

    for (;;) {
        if (!ReadFile(h, buf, ENG_CHUNK, &rd, NULL)) goto done;
        if (rd == 0) break;
        if (!CryptHashData(hh, buf, rd, 0)) goto done;
        if (want_sha) sha256_update(&sc, buf, rd);
    }
    ok = CryptGetHashParam(hh, HP_HASHVAL, md5, &len, 0);
    if (ok && want_sha) sha256_final(&sc, sha);

done:
    if (hh) CryptDestroyHash(hh);
    CloseHandle(h);
    free(buf);
    return ok;
}

/* MD5 of len bytes at offset off. */
static BOOL md5_region(HANDLE h, unsigned int off, unsigned int len,
                       BYTE *buf, unsigned char out[16])
{
    HCRYPTHASH hh = 0;
    DWORD rd, want, hl = 16;
    BOOL ok = FALSE;

    if (SetFilePointer(h, (LONG)off, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
        GetLastError() != NO_ERROR) return FALSE;
    if (!CryptCreateHash(g_eprov, CALG_MD5, 0, 0, &hh)) return FALSE;
    while (len) {
        want = len > ENG_CHUNK ? ENG_CHUNK : len;
        if (!ReadFile(h, buf, want, &rd, NULL) || rd != want) goto done;
        if (!CryptHashData(hh, buf, rd, 0)) goto done;
        len -= rd;
    }
    ok = CryptGetHashParam(hh, HP_HASHVAL, out, &hl, 0);
done:
    CryptDestroyHash(hh);
    return ok;
}

/* PE section signatures. Returns the malware name or NULL. */
const char *eng_match_sections(SIGDB *db, const wchar_t *path)
{
    HANDLE h;
    BYTE *buf;
    DWORD rd;
    unsigned int fsize;
    PESECT s[96];
    int n, i;
    unsigned char md5[16];
    const char *hit = NULL;

    if (!db || !db->loaded || !db->hdr2.nsect || !eprov()) return NULL;

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    buf = (BYTE*)malloc(PE_HEADSIZE > ENG_CHUNK ? PE_HEADSIZE : ENG_CHUNK);
    if (!buf) { CloseHandle(h); return NULL; }

    fsize = file_size32(h);
    if (ReadFile(h, buf, PE_HEADSIZE, &rd, NULL) && rd >= 64) {
        n = pe_sections(buf, rd, fsize, s, 96);
        for (i = 0; i < n && !hit; i++) {
            if (s[i].rsz > SECT_MAX) continue;
            if (!sigdb_has_sect_size(db, s[i].rsz)) continue;   /* cheap reject */
            if (md5_region(h, s[i].raw, s[i].rsz, buf, md5))
                hit = sigdb_match_sect(db, md5, s[i].rsz);
        }
    }
    free(buf);
    CloseHandle(h);
    return hit;
}

/* Every signature type engine 2.0 knows, in cost order. md5/size are handed
 * back because the baseline and known-good checks need them too. *read_ok is
 * FALSE if the file couldn't be read at all. */
const char *eng_match_file(SIGDB *db, const wchar_t *path,
                           unsigned char md5[16], unsigned int *size, BOOL *read_ok)
{
    unsigned char sha[32];
    BOOL want_sha = db && db->loaded && db->hdr2.nsha;
    const char *hit;

    *read_ok = eng_hash_file(path, md5, sha, want_sha, size);
    if (!*read_ok) return NULL;
    if (!db || !db->loaded) return NULL;

    hit = sigdb_match_hash(db, md5, *size);
    if (!hit && want_sha) hit = sigdb_match_sha(db, sha, *size);
    if (!hit && db->hdr2.nsect) hit = eng_match_sections(db, path);
    return hit;
}

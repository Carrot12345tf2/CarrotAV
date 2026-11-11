/* zipscan.c - scan the files INSIDE a ZIP, with hard limits.
 *
 * The archive guard (archive.c) only reads a zip's directory to refuse bombs.
 * This goes one step further: it unpacks each member into memory and runs the
 * full signature engine on it, so a known-malicious .exe sitting in a .zip is
 * caught before anyone extracts it.
 *
 * Everything is bounded, because a zip is attacker-controlled input:
 *   - members over 32 MB unpacked are skipped
 *   - at most 64 MB is unpacked per archive in total
 *   - at most 1000 members are looked at
 *   - one level only: zips inside zips are not opened
 *   - encrypted, ZIP64 and non-deflate members are skipped
 *   - a member that inflates to more than its declared size is abandoned
 * The archive guard always runs first, so bombs never reach this code.
 */
#include "av.h"
#include "zlib.h"

#define ZS_MEMBER_MAX  (32u << 20)
#define ZS_TOTAL_MAX   (64u << 20)
#define ZS_ENTRIES_MAX 1000u
#define ZS_CD_MAX      (16u << 20)

static unsigned int rd16(const BYTE *p) { return p[0] | (p[1] << 8); }
static unsigned int rd32(const BYTE *p)
{ return p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned int)p[3] << 24); }

static BOOL read_at(HANDLE h, DWORD off, void *buf, DWORD n)
{
    DWORD rd;
    if (SetFilePointer(h, (LONG)off, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
        GetLastError() != NO_ERROR) return FALSE;
    return ReadFile(h, buf, n, &rd, NULL) && rd == n;
}

/* Find the End Of Central Directory record near the end of the file. */
static BOOL eocd(HANDLE h, DWORD fsize, DWORD *cdoff, DWORD *cdsize, unsigned *entries)
{
    DWORD tail = fsize < 66000 ? fsize : 66000;
    BYTE *b = (BYTE*)malloc(tail);
    long i;
    BOOL ok = FALSE;
    if (!b) return FALSE;
    if (read_at(h, fsize - tail, b, tail)) {
        for (i = (long)tail - 22; i >= 0; i--)
            if (rd32(b + i) == 0x06054b50) {
                *entries = rd16(b + i + 10);
                *cdsize  = rd32(b + i + 12);
                *cdoff   = rd32(b + i + 16);
                ok = TRUE;
                break;
            }
    }
    free(b);
    return ok;
}

/* Inflate raw deflate data into out[usize]. FALSE if it doesn't produce
 * exactly usize bytes (damaged, or lying about its size). */
static BOOL inflate_exact(const BYTE *in, DWORD csize, BYTE *out, DWORD usize)
{
    z_stream z;
    int r;
    memset(&z, 0, sizeof z);
    if (inflateInit2(&z, -MAX_WBITS) != Z_OK) return FALSE;
    z.next_in = (Bytef*)in;   z.avail_in = csize;
    z.next_out = out;         z.avail_out = usize;
    r = inflate(&z, Z_FINISH);
    inflateEnd(&z);
    return r == Z_STREAM_END && z.total_out == usize;
}

const char *zip_scan_members(SIGDB *db, const wchar_t *path, char *member, int cap)
{
    HANDLE h;
    DWORD fsize, cdoff, cdsize, pos = 0, total = 0;
    unsigned entries = 0, seen = 0;
    BYTE *cd = NULL;
    const char *hit = NULL;

    if (member && cap) member[0] = 0;
    if (!db || !db->loaded) return NULL;

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    fsize = GetFileSize(h, NULL);
    if (fsize == INVALID_FILE_SIZE || fsize < 22 ||
        !eocd(h, fsize, &cdoff, &cdsize, &entries) ||
        !cdsize || cdsize > ZS_CD_MAX || cdoff >= fsize || cdsize > fsize - cdoff)
        goto done;

    cd = (BYTE*)malloc(cdsize);
    if (!cd || !read_at(h, cdoff, cd, cdsize)) goto done;

    while (pos + 46 <= cdsize && seen < ZS_ENTRIES_MAX && !hit) {
        const BYTE *e = cd + pos;
        unsigned flags, method, nlen, xlen, clen;
        DWORD csize, usize, lho;
        BYTE lh[30], *comp = NULL, *data = NULL;

        if (rd32(e) != 0x02014b50) break;          /* not a directory entry */
        flags  = rd16(e + 8);
        method = rd16(e + 10);
        csize  = rd32(e + 20);
        usize  = rd32(e + 24);
        nlen   = rd16(e + 28);
        xlen   = rd16(e + 30);
        clen   = rd16(e + 32);
        lho    = rd32(e + 42);
        if (pos + 46 + nlen + xlen + clen > cdsize) break;
        pos += 46 + nlen + xlen + clen;
        seen++;

        if (flags & 1) continue;                            /* encrypted */
        if (method != 0 && method != 8) continue;           /* not stored/deflate */
        if (csize == 0xFFFFFFFF || usize == 0xFFFFFFFF) continue;   /* ZIP64 */
        if (usize == 0 || usize > ZS_MEMBER_MAX) continue;
        if (nlen && e[46 + nlen - 1] == '/') continue;      /* directory */
        if (total + usize > ZS_TOTAL_MAX) break;            /* archive budget spent */
        if (method == 0 && csize != usize) continue;

        /* local header gives where the data really starts */
        if (lho >= fsize || !read_at(h, lho, lh, 30) || rd32(lh) != 0x04034b50) continue;
        {
            DWORD doff = lho + 30 + rd16(lh + 26) + rd16(lh + 28);
            if (doff >= fsize || csize > fsize - doff) continue;
            comp = (BYTE*)malloc(csize ? csize : 1);
            if (!comp) continue;
            if (!read_at(h, doff, comp, csize)) { free(comp); continue; }
        }
        if (method == 0) {
            data = comp; comp = NULL;
        } else {
            data = (BYTE*)malloc(usize);
            if (!data || !inflate_exact(comp, csize, data, usize)) {
                free(comp); free(data); continue;
            }
            free(comp);
        }
        total += usize;

        hit = eng_match_buffer(db, data, usize);
        if (hit && member && cap) {
            int n = (int)nlen < cap - 1 ? (int)nlen : cap - 1, i;
            for (i = 0; i < n; i++) {
                char c = (char)e[46 + i];
                member[i] = (c >= 32 && c < 127) ? c : '?';
            }
            member[n] = 0;
        }
        free(data);
    }

done:
    free(cd);
    CloseHandle(h);
    return hit;
}

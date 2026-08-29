/* archive.c - archive bomb and zip-slip detection.
 *
 * The whole point: decide whether an archive is hostile WITHOUT decompressing
 * a single byte of it. A ZIP records, in its central directory, the compressed
 * and uncompressed size of every member. That is all you need to spot a bomb -
 * you read the manifest, do the arithmetic, and refuse. Decompressing first to
 * find out whether decompressing is safe is exactly the mistake that lets
 * 42.zip take a machine down.
 *
 * What gets caught:
 *   ratio bombs      a few KB claiming to expand to gigabytes
 *   recursive bombs  42.zip style - the same member repeated many times at
 *                    each nesting level, which shows up as one (CRC,size)
 *                    pair appearing over and over in the directory
 *   entry floods     hundreds of thousands of members to exhaust memory
 *   zip64 overflow   sizes marked 0xFFFFFFFF to hide the real expansion
 *   zip slip         member names containing ../ or absolute paths, which
 *                    escape the extraction folder and overwrite system files
 */
#include "av.h"

#define EOCD_SIG   0x06054b50u
#define CDIR_SIG   0x02014b50u
#define LOCAL_SIG  0x04034b50u

/* thresholds - deliberately generous so normal archives never trip them */
#define BOMB_RATIO        150        /* uncompressed:compressed             */
#define BOMB_RATIO_MINOUT (32u*1024u*1024u)  /* ...and at least this big    */
#define BOMB_TOTAL        (2048ull*1024ull*1024ull)  /* 2 GB expansion      */
#define BOMB_ENTRIES      20000
#define BOMB_DUPES        10         /* identical members + nesting = bomb  */
#define BOMB_DUPES_ALONE  100        /* identical members, no nesting       */
#define BOMB_DUPE_MINSZ   512u       /* 42.zip's members are only ~42 KB,
                                      * so this must stay small or the
                                      * classic recursive bomb walks past  */

typedef struct { unsigned int crc, size, count; } DUPE;

BOOL arc_is_archive(const wchar_t *path)
{
    static const wchar_t *ext[] = {
        L".zip",L".jar",L".apk",L".docx",L".xlsx",L".pptx",L".odt",L".ods",
        L".epub",L".xpi",L".crx",L".war",L".ear",L".cbz",NULL };
    const wchar_t *e = wcsrchr(path, L'.');
    int i;
    if (!e) return FALSE;
    for (i = 0; ext[i]; i++) if (!lstrcmpiW(e, ext[i])) return TRUE;
    return FALSE;
}

/* Locate the End Of Central Directory record by scanning backwards. */
static BOOL find_eocd(HANDLE h, DWORD fsize, DWORD *cdoff, DWORD *cdsize,
                      unsigned int *entries)
{
    DWORD tail = fsize < 66000 ? fsize : 66000;
    BYTE *buf;
    DWORD rd;
    long i;
    BOOL ok = FALSE;

    if (fsize < 22) return FALSE;
    buf = (BYTE*)malloc(tail);
    if (!buf) return FALSE;

    SetFilePointer(h, fsize - tail, NULL, FILE_BEGIN);
    if (!ReadFile(h, buf, tail, &rd, NULL) || rd < 22) { free(buf); return FALSE; }

    for (i = (long)rd - 22; i >= 0; i--) {
        if (*(DWORD*)(buf + i) == EOCD_SIG) {
            *entries = *(WORD*)(buf + i + 10);
            *cdsize  = *(DWORD*)(buf + i + 12);
            *cdoff   = *(DWORD*)(buf + i + 16);
            ok = TRUE;
            break;
        }
    }
    free(buf);
    return ok;
}

int arc_inspect(const wchar_t *path, ARCINFO *info)
{
    HANDLE h;
    DWORD fsize, cdoff, cdsize, rd;
    unsigned int entries = 0, i;
    BYTE *cd = NULL;
    DUPE *dupes = NULL;
    int ndupe = 0, maxdupe = 0;
    unsigned int pos = 0;
    int verdict = ARC_OK;

    memset(info, 0, sizeof(*info));

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return ARC_OK;

    fsize = GetFileSize(h, NULL);
    if (fsize == INVALID_FILE_SIZE || fsize < 22) { CloseHandle(h); return ARC_OK; }

    if (!find_eocd(h, fsize, &cdoff, &cdsize, &entries)) {
        CloseHandle(h);
        return ARC_OK;                       /* not a zip we understand */
    }

    info->entries = entries;

    /* An entry count that huge is itself the attack - never allocate for it */
    if (entries > BOMB_ENTRIES) {
        CloseHandle(h);
        lstrcpynA(info->name, "Bomb.ZipEntryFlood", sizeof(info->name));
        return ARC_BOMB;
    }
    if (!cdsize || cdsize > 64u*1024u*1024u || cdoff >= fsize) {
        CloseHandle(h);
        return ARC_OK;
    }

    cd = (BYTE*)malloc(cdsize);
    if (!cd) { CloseHandle(h); return ARC_OK; }

    SetFilePointer(h, cdoff, NULL, FILE_BEGIN);
    if (!ReadFile(h, cd, cdsize, &rd, NULL) || rd != cdsize) {
        free(cd); CloseHandle(h); return ARC_OK;
    }
    CloseHandle(h);

    dupes = (DUPE*)calloc(entries ? entries : 1, sizeof(DUPE));

    for (i = 0; i < entries; i++) {
        unsigned int crc, csize, usize, namelen, extralen, commentlen;
        const char *name;

        if (pos + 46 > cdsize) break;
        if (*(DWORD*)(cd + pos) != CDIR_SIG) break;

        crc        = *(DWORD*)(cd + pos + 16);
        csize      = *(DWORD*)(cd + pos + 20);
        usize      = *(DWORD*)(cd + pos + 24);
        namelen    = *(WORD*)(cd + pos + 28);
        extralen   = *(WORD*)(cd + pos + 30);
        commentlen = *(WORD*)(cd + pos + 32);
        name       = (const char*)(cd + pos + 46);

        if (pos + 46 + namelen > cdsize) break;

        /* zip64 marker: the real size is hidden in an extra field, which is
         * a favourite way to disguise the true expansion */
        if (usize == 0xFFFFFFFFu || csize == 0xFFFFFFFFu) {
            info->zip64 = TRUE;
        } else {
            info->total_out += usize;
            info->total_in  += csize;
        }

        /* zip slip: a member that escapes the extraction directory */
        if (namelen >= 2) {
            unsigned int k;
            for (k = 0; k + 1 < namelen; k++) {
                if (name[k] == '.' && name[k+1] == '.' &&
                    (k + 2 >= namelen || name[k+2] == '/' || name[k+2] == '\\')) {
                    info->slip = TRUE; break;
                }
            }
            if (name[0] == '/' || name[0] == '\\' ||
                (namelen > 2 && name[1] == ':')) info->slip = TRUE;
        }

        /* nested archives - the recursive bomb's building block */
        if (namelen > 4) {
            const char *dot = NULL;
            unsigned int k;
            for (k = 0; k < namelen; k++) if (name[k] == '.') dot = name + k;
            if (dot && (!_strnicmp(dot, ".zip", 4) || !_strnicmp(dot, ".gz", 3) ||
                        !_strnicmp(dot, ".rar", 4) || !_strnicmp(dot, ".7z", 3) ||
                        !_strnicmp(dot, ".bz2", 4) || !_strnicmp(dot, ".xz", 3)))
                info->nested++;
        }

        /* identical members repeated: 42.zip is 16 copies of the same file at
         * every level. One (CRC,size) pair recurring is the fingerprint. */
        if (dupes && usize >= BOMB_DUPE_MINSZ && usize != 0xFFFFFFFFu) {
            int d, found = 0;
            for (d = 0; d < ndupe; d++) {
                if (dupes[d].crc == crc && dupes[d].size == usize) {
                    dupes[d].count++;
                    if ((int)dupes[d].count > maxdupe) maxdupe = dupes[d].count;
                    found = 1; break;
                }
            }
            if (!found && ndupe < (int)entries) {
                dupes[ndupe].crc = crc; dupes[ndupe].size = usize;
                dupes[ndupe].count = 1; ndupe++;
                if (maxdupe < 1) maxdupe = 1;
            }
        }

        pos += 46 + namelen + extralen + commentlen;
    }

    free(cd);
    free(dupes);

    info->dupes = maxdupe;
    info->ratio = info->total_in ? (unsigned int)(info->total_out / info->total_in) : 0;

    /* ---- verdicts, most specific first ---- */
    if (info->slip) {
        lstrcpynA(info->name, "Exploit.ZipSlip", sizeof(info->name));
        verdict = ARC_BOMB;
    } else if (maxdupe >= BOMB_DUPES && info->nested > 0) {
        lstrcpynA(info->name, "Bomb.ZipRecursive", sizeof(info->name));
        verdict = ARC_BOMB;
    } else if (info->total_out > BOMB_TOTAL) {
        lstrcpynA(info->name, "Bomb.ZipExpansion", sizeof(info->name));
        verdict = ARC_BOMB;
    } else if (info->ratio >= BOMB_RATIO && info->total_out >= BOMB_RATIO_MINOUT) {
        lstrcpynA(info->name, "Bomb.ZipRatio", sizeof(info->name));
        verdict = ARC_BOMB;
    } else if (info->zip64 && info->nested > 0) {
        lstrcpynA(info->name, "Bomb.Zip64Hidden", sizeof(info->name));
        verdict = ARC_SUSPECT;
    } else if (maxdupe >= BOMB_DUPES_ALONE) {
        lstrcpynA(info->name, "Bomb.ZipDuplicates", sizeof(info->name));
        verdict = ARC_SUSPECT;
    }

    if (verdict != ARC_OK)
        log_line(L"ARCHIVE  %s -> %S (%u entries, ratio %u:1, %u dupes, %u nested)",
                 path, info->name, info->entries, info->ratio,
                 info->dupes, info->nested);

    return verdict;
}

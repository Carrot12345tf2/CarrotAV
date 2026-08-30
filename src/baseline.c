/* baseline.c - the XP system integrity database.
 *
 * Three jobs, all of which make the scanner behave properly on an actual
 * XP install rather than treating Windows itself as suspicious:
 *
 *  1. WHITELIST. Every hash in the baseline is known-good. The scanner
 *     checks this before it checks anything else, so a stock XP file (or
 *     any file you chose to baseline, like a game folder) can never be
 *     reported by a signature or a heuristic. This is what stops the
 *     "safe game flagged as a virus" problem at the root.
 *
 *  2. INTEGRITY. A file that is in the baseline by path but whose hash no
 *     longer matches has been modified since the snapshot. On XP that is
 *     exactly what a file infector looks like - Sality, Virut and Parite
 *     all work by appending to existing system binaries.
 *
 *  3. REPAIR. XP keeps pristine copies of protected files in
 *     %WINDIR%\system32\dllcache (the Windows File Protection cache), and
 *     the install media has compressed originals in \i386. We restore
 *     from those, then re-hash to confirm the repair took.
 */
#include "av.h"

#define BASE_MAGIC "CAVB"

static BASEDB g_base;

static int cmp_rec_md5(const void *a, const void *b)
{
    const BASEREC *x = *(const BASEREC**)a, *y = *(const BASEREC**)b;
    return memcmp(x->md5, y->md5, 16);
}

static BASEDB *g_sortctx;

static int cmp_rec_path(const void *a, const void *b)
{
    const BASEREC *x = *(const BASEREC**)a, *y = *(const BASEREC**)b;
    return lstrcmpiW(g_sortctx->blob + x->pathoff, g_sortctx->blob + y->pathoff);
}

void base_path(wchar_t *out, int cch)
{
    app_dir(out, cch);
    lstrcatW(out, L"\\defs\\system.cavb");
}

void base_free(void)
{
    free(g_base.recs);   g_base.recs = NULL;
    free(g_base.blob);   g_base.blob = NULL;
    free(g_base.byhash); g_base.byhash = NULL;
    free(g_base.bypath); g_base.bypath = NULL;
    g_base.count = 0;
    g_base.loaded = FALSE;
}

BOOL base_load(void)
{
    wchar_t p[MAX_PATH];
    HANDLE h;
    DWORD rd;
    unsigned int i;
    struct { char magic[4]; unsigned int ver, count, blobsz, built; } hdr;

    base_free();
    base_path(p, MAX_PATH);

    h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    if (!ReadFile(h, &hdr, sizeof(hdr), &rd, NULL) || rd != sizeof(hdr) ||
        memcmp(hdr.magic, BASE_MAGIC, 4) || hdr.ver != 1 ||
        hdr.count > 2000000u || hdr.blobsz > 134217728u) {
        CloseHandle(h); return FALSE;
    }

    g_base.recs = (BASEREC*)malloc((size_t)hdr.count * sizeof(BASEREC));
    g_base.blob = (wchar_t*)malloc(hdr.blobsz);
    if (!g_base.recs || !g_base.blob) { CloseHandle(h); base_free(); return FALSE; }

    if (!ReadFile(h, g_base.recs, hdr.count * sizeof(BASEREC), &rd, NULL) ||
        rd != hdr.count * sizeof(BASEREC)) { CloseHandle(h); base_free(); return FALSE; }
    if (!ReadFile(h, g_base.blob, hdr.blobsz, &rd, NULL) ||
        rd != hdr.blobsz) { CloseHandle(h); base_free(); return FALSE; }
    CloseHandle(h);

    g_base.count = hdr.count;
    g_base.built = hdr.built;

    /* index by hash for the whitelist lookup */
    g_base.byhash = (BASEREC**)malloc((size_t)hdr.count * sizeof(BASEREC*));
    if (!g_base.byhash) { base_free(); return FALSE; }
    for (i = 0; i < hdr.count; i++) g_base.byhash[i] = &g_base.recs[i];
    qsort(g_base.byhash, hdr.count, sizeof(BASEREC*), cmp_rec_md5);

    /* second index, by path, so integrity lookups are a binary search
     * instead of a linear walk of every record for every file scanned */
    g_base.bypath = (BASEREC**)malloc((size_t)hdr.count * sizeof(BASEREC*));
    if (!g_base.bypath) { base_free(); return FALSE; }
    for (i = 0; i < hdr.count; i++) g_base.bypath[i] = &g_base.recs[i];
    g_sortctx = &g_base;
    qsort(g_base.bypath, hdr.count, sizeof(BASEREC*), cmp_rec_path);

    g_base.loaded = TRUE;
    return TRUE;
}

unsigned int base_count(void) { return g_base.loaded ? g_base.count : 0; }
unsigned int base_built(void) { return g_base.loaded ? g_base.built : 0; }
BOOL base_ready(void)         { return g_base.loaded; }

/* --- whitelist: is this exact content a known-good system file? --- */
BOOL base_known_hash(const unsigned char md5[16])
{
    long lo, hi, mid;
    int c;
    if (!g_base.loaded) return FALSE;
    lo = 0; hi = (long)g_base.count - 1;
    while (lo <= hi) {
        mid = lo + (hi - lo) / 2;
        c = memcmp(md5, g_base.byhash[mid]->md5, 16);
        if (c == 0) return TRUE;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return FALSE;
}

/* Integrity, bound to the path. CLEAN means "this exact file is byte for
 * byte what we recorded at this exact location" - which is a far stronger
 * claim than "some file somewhere once had these bytes". */
int base_check_path(const wchar_t *path, const unsigned char md5[16])
{
    long lo, hi, mid;
    int c;

    if (!g_base.loaded || !g_base.bypath) return BASE_UNKNOWN;

    lo = 0; hi = (long)g_base.count - 1;
    while (lo <= hi) {
        mid = lo + (hi - lo) / 2;
        c = lstrcmpiW(path, g_base.blob + g_base.bypath[mid]->pathoff);
        if (c == 0)
            return memcmp(md5, g_base.bypath[mid]->md5, 16) == 0
                   ? BASE_CLEAN : BASE_MODIFIED;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return BASE_UNKNOWN;
}

const wchar_t *base_path_at(unsigned int i)
{
    if (!g_base.loaded || i >= g_base.count) return NULL;
    return g_base.blob + g_base.recs[i].pathoff;
}

const unsigned char *base_md5_at(unsigned int i)
{
    if (!g_base.loaded || i >= g_base.count) return NULL;
    return g_base.recs[i].md5;
}

/* Is this file byte-identical to Windows' own protected copy? */
BOOL wfp_trusted(const wchar_t *path, const unsigned char md5[16])
{
    wchar_t sys[MAX_PATH], twin[MAX_PATH];
    const wchar_t *name = PathFindFileNameW(path);
    unsigned char other[16];
    unsigned int sz = 0;

    if (!GetSystemDirectoryW(sys, MAX_PATH)) return FALSE;

    /* A file that lives inside dllcache IS Windows File Protection's own
     * pristine reference copy. There is nothing more authoritative to compare
     * it against, and it is what everything else gets repaired FROM, so trust
     * it directly. Without this, the cached original gets a plain "Detected"
     * verdict while its system32 twin shows "Verified" - the same file judged
     * two different ways depending on which folder you scanned. */
    if (StrStrIW(path, L"\\dllcache\\")) return TRUE;

    wsprintfW(twin, L"%s\\dllcache\\%s", sys, name);

    if (lstrcmpiW(twin, path) == 0) return FALSE;
    if (GetFileAttributesW(twin) == INVALID_FILE_ATTRIBUTES) return FALSE;
    if (!hash_file_md5(twin, other, &sz)) return FALSE;

    return memcmp(other, md5, 16) == 0;
}

/* ------------------------- building the baseline ------------------------- */

typedef struct {
    BASEREC *recs;
    unsigned int count, cap;
    wchar_t *blob;
    unsigned int blobused, blobcap;
    HWND notify;
    volatile LONG *cancel;
} BUILDER;

static BOOL want_baseline(const wchar_t *name)
{
    static const wchar_t *ext[] = {
        L".exe",L".dll",L".sys",L".ocx",L".cpl",L".drv",L".scr",L".com",
        L".ax",L".acm",L".nls",L".msc",L".tlb",L".pif",
        L".js",L".vbs",L".hta",L".wsf",L".bat",L".cmd",L".inf",NULL };
    const wchar_t *e = wcsrchr(name, L'.');
    int i;
    if (!e) return FALSE;
    for (i = 0; ext[i]; i++) if (!lstrcmpiW(e, ext[i])) return TRUE;
    return FALSE;
}

static void build_add(BUILDER *b, const wchar_t *path,
                      const unsigned char md5[16], unsigned int size)
{
    unsigned int need;

    if (b->count >= b->cap) {
        unsigned int nc = b->cap ? b->cap * 2 : 4096;
        BASEREC *nr = (BASEREC*)realloc(b->recs, (size_t)nc * sizeof(BASEREC));
        if (!nr) return;
        b->recs = nr; b->cap = nc;
    }
    need = (unsigned int)(lstrlenW(path) + 1);
    if (b->blobused + need > b->blobcap) {
        unsigned int nc = b->blobcap ? b->blobcap * 2 : 65536;
        wchar_t *nb;
        while (b->blobused + need > nc) nc *= 2;
        nb = (wchar_t*)realloc(b->blob, (size_t)nc * sizeof(wchar_t));
        if (!nb) return;
        b->blob = nb; b->blobcap = nc;
    }
    memcpy(b->blob + b->blobused, path, need * sizeof(wchar_t));
    b->recs[b->count].pathoff = b->blobused;
    memcpy(b->recs[b->count].md5, md5, 16);
    b->recs[b->count].size = size;
    b->blobused += need;
    b->count++;
}

static void build_walk(BUILDER *b, const wchar_t *dir, int depth)
{
    WIN32_FIND_DATAW fd;
    HANDLE h;
    wchar_t pat[MAX_PATH*2], sub[MAX_PATH*2];

    if (depth > 8 || (b->cancel && *b->cancel)) return;
    wsprintfW(pat, L"%s\\*", dir);
    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (b->cancel && *b->cancel) break;
        if (!lstrcmpW(fd.cFileName, L".") || !lstrcmpW(fd.cFileName, L"..")) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        wsprintfW(sub, L"%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            build_walk(b, sub, depth + 1);
        } else if (want_baseline(fd.cFileName)) {
            unsigned char md5[16];
            unsigned int sz = fd.nFileSizeLow;
            if (hash_file_md5(sub, md5, &sz)) {
                build_add(b, sub, md5, sz);
                if (b->notify && (b->count % 25) == 0) {
                    wchar_t *copy;
                    size_t n = (wcslen(sub) + 1) * sizeof(wchar_t);
                    copy = (wchar_t*)LocalAlloc(LPTR, n);
                    if (copy) {
                        memcpy(copy, sub, n);
                        if (!PostMessageW(b->notify, WM_SCAN_FILE, 0, (LPARAM)copy))
                            LocalFree(copy);
                    }
                }
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

/* Snapshot the system. Do this on a machine you believe is clean. */
int base_build(HWND notify, volatile LONG *cancel)
{
    BUILDER b;
    wchar_t dir[MAX_PATH], out[MAX_PATH];
    HANDLE h;
    DWORD wr;
    struct { char magic[4]; unsigned int ver, count, blobsz, built; } hdr;
    int n;

    memset(&b, 0, sizeof(b));
    b.notify = notify;
    b.cancel = cancel;

    if (GetSystemDirectoryW(dir, MAX_PATH)) build_walk(&b, dir, 0);
    if (GetWindowsDirectoryW(dir, MAX_PATH)) {
        wchar_t sub[MAX_PATH];
        build_walk(&b, dir, 7);                 /* top level only */
        wsprintfW(sub, L"%s\\system", dir);   build_walk(&b, sub, 6);
        wsprintfW(sub, L"%s\\AppPatch", dir); build_walk(&b, sub, 6);
    }

    if (!b.count) { free(b.recs); free(b.blob); return 0; }

    app_dir(out, MAX_PATH);
    lstrcatW(out, L"\\defs");
    CreateDirectoryW(out, NULL);
    base_path(out, MAX_PATH);

    h = CreateFileW(out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { free(b.recs); free(b.blob); return 0; }

    memcpy(hdr.magic, BASE_MAGIC, 4);
    hdr.ver = 1;
    hdr.count = b.count;
    hdr.blobsz = b.blobused * sizeof(wchar_t);
    hdr.built = (unsigned int)time(NULL);

    WriteFile(h, &hdr, sizeof(hdr), &wr, NULL);
    WriteFile(h, b.recs, b.count * sizeof(BASEREC), &wr, NULL);
    WriteFile(h, b.blob, hdr.blobsz, &wr, NULL);
    CloseHandle(h);

    n = (int)b.count;
    free(b.recs);
    free(b.blob);

    log_line(L"BASELINE  snapshot written: %d system files", n);
    base_load();
    return n;
}

/* ------------------------------- repair ------------------------------- */

static BOOL try_copy_verify(const wchar_t *src, const wchar_t *dest,
                            const unsigned char want[16])
{
    unsigned char md5[16];
    unsigned int sz = 0;

    if (GetFileAttributesW(src) == INVALID_FILE_ATTRIBUTES) return FALSE;

    SetFileAttributesW(dest, FILE_ATTRIBUTE_NORMAL);
    if (!CopyFileW(src, dest, FALSE)) {
        /* file in use: stage the replacement for the next boot */
        wchar_t tmp[MAX_PATH];
        wsprintfW(tmp, L"%s.cav_new", dest);
        if (CopyFileW(src, tmp, FALSE) &&
            MoveFileExW(tmp, dest, MOVEFILE_REPLACE_EXISTING |
                                   MOVEFILE_DELAY_UNTIL_REBOOT)) {
            log_line(L"REPAIR  %s staged for replacement at next boot", dest);
            return TRUE;
        }
        return FALSE;
    }
    if (want) {
        if (!hash_file_md5(dest, md5, &sz)) return FALSE;
        if (memcmp(md5, want, 16) != 0) {
            log_line(L"REPAIR  %s copied but hash still differs", dest);
            return FALSE;
        }
    }
    return TRUE;
}

/* Where did this machine install from? XP records it. */
static BOOL get_source_path(wchar_t *out, int cch)
{
    HKEY k;
    DWORD type, cb = cch * sizeof(wchar_t);
    BOOL ok = FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 0, KEY_READ, &k)
        == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, L"SourcePath", NULL, &type, (LPBYTE)out, &cb)
            == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ))
            ok = TRUE;
        RegCloseKey(k);
    }
    return ok;
}

int base_repair(const wchar_t *path)
{
    wchar_t sys[MAX_PATH], src[MAX_PATH], srcpath[MAX_PATH];
    const wchar_t *name = PathFindFileNameW(path);
    const unsigned char *want = NULL;
    unsigned int i;

    /* the hash we expect to end up with */
    for (i = 0; i < base_count(); i++) {
        const wchar_t *p = base_path_at(i);
        if (p && !lstrcmpiW(p, path)) { want = base_md5_at(i); break; }
    }

    /* 1. Windows File Protection cache - the fast, offline path */
    if (GetSystemDirectoryW(sys, MAX_PATH)) {
        wsprintfW(src, L"%s\\dllcache\\%s", sys, name);
        if (try_copy_verify(src, path, want)) {
            log_line(L"REPAIR  %s restored from dllcache", path);
            return REPAIR_DLLCACHE;
        }
    }

    /* 2. the original install media / source folder */
    if (get_source_path(srcpath, MAX_PATH)) {
        wchar_t comp[MAX_PATH];
        int len;

        wsprintfW(src, L"%s\\i386\\%s", srcpath, name);
        if (try_copy_verify(src, path, want)) {
            log_line(L"REPAIR  %s restored from %s", path, src);
            return REPAIR_SOURCE;
        }

        /* compressed original: kernel32.dll -> kernel32.dl_ */
        lstrcpynW(comp, src, MAX_PATH);
        len = lstrlenW(comp);
        if (len > 1) {
            comp[len-1] = L'_';
            if (GetFileAttributesW(comp) != INVALID_FILE_ATTRIBUTES) {
                wchar_t cmd[MAX_PATH*3];
                STARTUPINFOW si;
                PROCESS_INFORMATION pi;
                DWORD code = 1;

                wsprintfW(cmd, L"expand.exe \"%s\" \"%s\"", comp, path);
                memset(&si, 0, sizeof(si));
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;
                SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
                if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                                   NULL, NULL, &si, &pi)) {
                    WaitForSingleObject(pi.hProcess, 30000);
                    GetExitCodeProcess(pi.hProcess, &code);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    if (code == 0) {
                        log_line(L"REPAIR  %s expanded from %s", path, comp);
                        return REPAIR_SOURCE;
                    }
                }
            }
        }
    }

    log_line(L"REPAIR  no clean copy available for %s", path);
    return REPAIR_FAILED;
}

/* Hand the job to Windows itself. Needs the XP CD in the drive. */
BOOL base_run_sfc(void)
{
    SHELLEXECUTEINFOW ei;
    memset(&ei, 0, sizeof(ei));
    ei.cbSize = sizeof(ei);
    ei.lpVerb = L"open";
    ei.lpFile = L"sfc.exe";
    ei.lpParameters = L"/scannow";
    ei.nShow = SW_SHOWNORMAL;
    log_line(L"REPAIR  launching sfc /scannow");
    return ShellExecuteExW(&ei);
}

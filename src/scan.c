/* scan.c - scan engine. Runs on a worker thread and posts progress to the UI. */
#include "av.h"
#include <math.h>

BOOL g_arcguard = TRUE;

static HCRYPTPROV g_prov = 0;

static BOOL crypt_init(void)
{
    if (g_prov) return TRUE;
    if (!CryptAcquireContextW(&g_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        g_prov = 0;
        return FALSE;
    }
    return TRUE;
}

BOOL is_pe(const unsigned char *head, DWORD len)
{
    DWORD e;
    if (len < 0x40 || head[0] != 'M' || head[1] != 'Z') return FALSE;
    e = *(const DWORD*)(head + 0x3C);
    if (e + 4 > len) return FALSE;
    return head[e] == 'P' && head[e+1] == 'E' && head[e+2] == 0 && head[e+3] == 0;
}

double entropy_of(const unsigned char *buf, DWORD len)
{
    DWORD counts[256];
    DWORD i;
    double h = 0.0, p;
    if (!len) return 0.0;
    memset(counts, 0, sizeof(counts));
    for (i = 0; i < len; i++) counts[buf[i]]++;
    for (i = 0; i < 256; i++) {
        if (!counts[i]) continue;
        p = (double)counts[i] / (double)len;
        h -= p * (log(p) / log(2.0));
    }
    return h;
}

BOOL hash_file_md5(const wchar_t *path, unsigned char out[16], unsigned int *size)
{
    HANDLE h;
    HCRYPTHASH hh = 0;
    BYTE buf[SCAN_CHUNK];
    DWORD rd, len = 16;
    LARGE_INTEGER li;
    BOOL ok = FALSE;

    if (!crypt_init()) return FALSE;

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    if (GetFileSizeEx(h, &li) && size) {
        *size = (li.QuadPart > 0xFFFFFFFFLL) ? 0xFFFFFFFFu : (unsigned int)li.QuadPart;
    }
    if (!CryptCreateHash(g_prov, CALG_MD5, 0, 0, &hh)) goto done;

    for (;;) {
        if (!ReadFile(h, buf, sizeof(buf), &rd, NULL)) goto done;
        if (rd == 0) break;
        if (!CryptHashData(hh, buf, rd, 0)) goto done;
    }
    ok = CryptGetHashParam(hh, HP_HASHVAL, out, &len, 0);

done:
    if (hh) CryptDestroyHash(hh);
    CloseHandle(h);
    return ok;
}

/* --------- heuristics: cheap structural checks, no signature needed --------- */

static const wchar_t *ext_of(const wchar_t *p)
{
    const wchar_t *d = wcsrchr(p, L'.');
    return d ? d : L"";
}

static BOOL icontains(const wchar_t *hay, const wchar_t *needle)
{
    return StrStrIW(hay, needle) != NULL;
}

int heur_check(const wchar_t *path, const unsigned char *head, DWORD headlen,
               DWORD filesize, char *outname, int outsz)
{
    const wchar_t *ext = ext_of(path);
    const wchar_t *base = PathFindFileNameW(path);
    DWORD attr;
    double e;
    wchar_t windir[MAX_PATH];
    BOOL in_windows = FALSE;

    /* Case-insensitive prefix test. StrStrIW finds the folder anywhere; we
     * want it specifically at the start of the path. Comparing the returned
     * pointer to the start is the prefix check - but normalize by just asking
     * whether windir appears and the char after it is a separator, which is
     * robust to how the path was built (drive letter case, etc). */
    if (GetWindowsDirectoryW(windir, MAX_PATH)) {
        const wchar_t *m = StrStrIW(path, windir);
        if (m == path) in_windows = TRUE;
        /* also treat the well-known Microsoft content trees as Windows */
        if (StrStrIW(path, L"\\Help\\")   || StrStrIW(path, L"\\Tours\\") ||
            StrStrIW(path, L"\\Web\\Wallpaper") ||
            StrStrIW(path, L"\\Microsoft.NET\\"))
            in_windows = TRUE;
    }

    /* Installers legitimately run executables out of Temp, so skip the
     * scratch folders they all use rather than reporting every setup. */
    if (StrStrIW(path, L"\\~nsu") || StrStrIW(path, L"\\is-") ||
        StrStrIW(path, L"\\_ir_") || StrStrIW(path, L"\\_is") ||
        !lstrcmpiW(base, L"Un.exe") || !lstrcmpiW(base, L"uninst.exe"))
        return -1;

    /* double extension: invoice.pdf.exe, photo.jpg.scr */
    if (headlen && is_pe(head, headlen)) {
        wchar_t tmp[MAX_PATH];
        const wchar_t *d1;
        lstrcpynW(tmp, base, MAX_PATH);
        d1 = wcsrchr(tmp, L'.');
        if (d1) {
            *(wchar_t*)d1 = 0;
            if (wcsrchr(tmp, L'.')) {
                const wchar_t *inner = wcsrchr(tmp, L'.');
                if (!lstrcmpiW(inner, L".pdf") || !lstrcmpiW(inner, L".doc") ||
                    !lstrcmpiW(inner, L".jpg") || !lstrcmpiW(inner, L".txt") ||
                    !lstrcmpiW(inner, L".xls") || !lstrcmpiW(inner, L".zip")) {
                    lstrcpynA(outname, "Heur.DoubleExtension", outsz);
                    return DET_HEUR;
                }
            }
        }
    }

    /* executable dropped in a temp path */
    if (headlen && is_pe(head, headlen)) {
        if (icontains(path, L"\\Temp\\") || icontains(path, L"\\Temporary Internet Files\\") ||
            icontains(path, L"\\Local Settings\\Temp")) {
            /* NSIS installers (CarrotAV's own included) run from a temp
             * "ns<random>.tmp" directory containing nsExec.dll, System.dll,
             * etc. That is normal installer scaffolding, not a threat. Skip
             * the specific NSIS shape only; any other temp-dropped exe is
             * still flagged. */
            if (icontains(path, L".tmp\\ns") ||
                icontains(path, L"nsExec.dll") ||
                icontains(path, L".tmp\\System.dll"))
                ; /* NSIS scaffolding - fall through, do not flag */
            else {
                lstrcpynA(outname, "Heur.ExecInTempPath", outsz);
                return DET_PUA;
            }
        }
    }

    /* hidden + system executable outside of system32 */
    attr = GetFileAttributesW(path);
    if (attr != INVALID_FILE_ATTRIBUTES &&
        (attr & FILE_ATTRIBUTE_HIDDEN) && (attr & FILE_ATTRIBUTE_SYSTEM)) {
        if (!lstrcmpiW(ext, L".exe") || !lstrcmpiW(ext, L".scr") || !lstrcmpiW(ext, L".pif")) {
            if (!icontains(path, L"\\system32\\")) {
                lstrcpynA(outname, "Heur.HiddenSystemExec", outsz);
                return DET_HEUR;
            }
        }
    }

    /* autorun.inf on removable media is a classic worm vector */
    if (!lstrcmpiW(base, L"autorun.inf") && headlen > 8) {
        if (StrStrIA((const char*)head, "open=") || StrStrIA((const char*)head, "shellexecute=")) {
            lstrcpynA(outname, "Heur.AutorunInf", outsz);
            return DET_PUA;
        }
    }

    /* packed/encrypted PE: tiny file, very high entropy.
     * Not applied inside %WINDIR% - plenty of stock XP binaries are packed. */
    if (!in_windows && headlen >= 4096 && is_pe(head, headlen) && filesize < 512*1024) {
        e = entropy_of(head + 1024, headlen - 1024);
        if (e > 7.4) {
            lstrcpynA(outname, "Heur.PackedHighEntropy", outsz);
            return DET_HEUR;
        }
    }

    /* script with obfuscation markers. Windows ships plenty of dense
     * scripts (Help, Tours, IE) that trip this, so %WINDIR% is exempt. */
    if (!in_windows &&
        (!lstrcmpiW(ext, L".vbs") || !lstrcmpiW(ext, L".js") ||
         !lstrcmpiW(ext, L".hta") || !lstrcmpiW(ext, L".wsf")) && headlen > 32) {
        int hits = 0;
        if (StrStrIA((const char*)head, "eval(")) hits++;
        if (StrStrIA((const char*)head, "unescape(")) hits++;
        if (StrStrIA((const char*)head, "fromCharCode")) hits++;
        if (StrStrIA((const char*)head, "Shell.Application")) hits++;
        if (StrStrIA((const char*)head, "WScript.Shell")) hits++;
        if (StrStrIA((const char*)head, "ADODB.Stream")) hits++;
        if (hits >= 2) {
            lstrcpynA(outname, "Heur.ObfuscatedScript", outsz);
            return DET_HEUR;
        }
    }
    return -1;
}

/* ------------------------- file scanning ------------------------- */

static void post_file(SCANJOB *j, const wchar_t *path)
{
    wchar_t *copy;
    size_t n;
    if (!j->notify) return;
    n = (wcslen(path) + 1) * sizeof(wchar_t);
    copy = (wchar_t*)LocalAlloc(LPTR, n);
    if (!copy) return;
    memcpy(copy, path, n);
    if (!PostMessageW(j->notify, WM_SCAN_FILE, 0, (LPARAM)copy)) LocalFree(copy);
}

static void post_hit(SCANJOB *j, const wchar_t *path, const char *name, int kind)
{
    DETECTION *d;
    InterlockedIncrement(&j->found);
    log_line(L"DETECT  %s  [%S]", path, name);

    /* Scans NEVER auto-quarantine. They report what they found and the user
     * decides which files to act on from the results list. This is the whole
     * safety model: a manual scan is a review, so a false positive can never
     * remove a file on its own. (The live shield in realtime.c still acts
     * automatically - that's active defense on files as they arrive.) */

    if (!j->notify) return;
    d = (DETECTION*)LocalAlloc(LPTR, sizeof(DETECTION));
    if (!d) return;
    lstrcpynW(d->path, path, MAX_PATH*2);
    lstrcpynA(d->name, name, 128);
    d->kind = kind;
    if (!PostMessageW(j->notify, WM_SCAN_HIT, 0, (LPARAM)d)) LocalFree(d);
}

/* Known-good file hashes: transient installer scaffolding that ClamAV flags
 * because malware also abuses these components. We exempt ONLY the exact
 * bytes of the legitimate files (by MD5), so a malicious file merely NAMED
 * nsExec.dll - with different bytes - is still caught. These are NSIS's
 * x86-ansi plugin DLLs, which CarrotAV's own installer extracts to a temp
 * folder for a few seconds at install time.
 *
 * If you rebuild the installer against a different NSIS version and it starts
 * flagging its own temp files again, update these hashes: md5sum the files in
 * NSIS's Plugins/x86-ansi/ directory. */
BOOL known_good_hash(const unsigned char md5[16])
{
    static const unsigned char good[][16] = {
        /* nsExec.dll  716a8112b4958582b37aeb58652d0e89 */
        {0x71,0x6a,0x81,0x12,0xb4,0x95,0x85,0x82,0xb3,0x7a,0xeb,0x58,0x65,0x2d,0x0e,0x89},
        /* System.dll  902062be905e55afb760d2c64411a12c */
        {0x90,0x20,0x62,0xbe,0x90,0x5e,0x55,0xaf,0xb7,0x60,0xd2,0xc6,0x44,0x11,0xa1,0x2c},
    };
    int i;
    for (i = 0; i < (int)(sizeof(good)/sizeof(good[0])); i++)
        if (memcmp(md5, good[i], 16) == 0) return TRUE;
    return FALSE;
}

/* returns TRUE if a detection was reported */
static BOOL scan_one(SCANJOB *j, const wchar_t *path, DWORD filesize)
{
    unsigned char md5[16];
    unsigned char head[8192];
    const char *hit;
    char hname[128];
    unsigned int sz = filesize;
    BOOL verified;
    HANDLE h;
    DWORD rd = 0;
    int k;

    if (path_excluded(path)) return FALSE;

    InterlockedIncrement(&j->files);

    /* Archives get their manifest read first. Nothing is decompressed, so a
     * bomb is identified and refused before it can cost us anything. */
    if (g_arcguard && arc_is_archive(path)) {
        ARCINFO ai;
        int v = arc_inspect(path, &ai);
        if (v != ARC_OK) {
            post_hit(j, path, ai.name, v == ARC_BOMB ? DET_HEUR : DET_PUA);
            return TRUE;
        }
    }

    if (!hash_file_md5(path, md5, &sz)) {
        InterlockedIncrement(&j->skipped);
        return FALSE;
    }

    /* Legit installer scaffolding (exact bytes) - never a threat. */
    if (known_good_hash(md5)) return FALSE;

    /* Is this file byte-identical to what we recorded at this exact path,
     * or to Windows' own protected copy? Verified means unchanged - it does
     * NOT mean immune from scanning. */
    verified = (base_check_path(path, md5) == BASE_CLEAN) || wfp_trusted(path, md5);

    /* Signatures run against everything, verified or not. A baselined file
     * can still genuinely be malware - the snapshot may have been taken on
     * an already-infected machine. What verification buys us is knowing the
     * bytes are unchanged, so a hit here is far more likely to be a bad
     * signature than a real infection: report it, flag the disagreement,
     * and never quarantine it automatically. */
    hit = sigdb_match_hash(j->db, md5, sz);
    if (hit) {
        post_hit(j, path, hit, verified ? DET_DISPUTED : DET_SIG);
        return TRUE;
    }

    /* Content changed since the snapshot: on XP that is what a file
     * infector looks like. Repair, never delete. */
    if (base_check_path(path, md5) == BASE_MODIFIED) {
        post_hit(j, path, "System.FileModified", DET_MODIFIED);
        return TRUE;
    }

    /* Heuristics are guesswork, so verified files are exempt from them. */
    if (verified) return FALSE;

    /* read a head buffer for heuristics and for cheap pattern scanning */
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        ReadFile(h, head, sizeof(head) - 1, &rd, NULL);
        head[rd] = 0;
        CloseHandle(h);
    }

    if (j->heuristics && rd) {
        k = heur_check(path, head, rd, filesize, hname, sizeof(hname));
        if (k >= 0) { post_hit(j, path, hname, k); return TRUE; }
    }

    /* deep mode: full-file pattern sweep with overlap between chunks */
    if (j->mode == SCAN_DEEP && j->db->hdr.npat) {
        unsigned char *buf = (unsigned char*)malloc(SCAN_CHUNK + MAX_PAT);
        DWORD carry = 0, total, keep;
        if (!buf) return FALSE;
        h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (h == INVALID_HANDLE_VALUE) { free(buf); return FALSE; }
        for (;;) {
            if (!ReadFile(h, buf + carry, SCAN_CHUNK, &rd, NULL) || rd == 0) break;
            total = carry + rd;
            hit = sigdb_match_buf(j->db, buf, total);
            if (hit) {
                CloseHandle(h);
                free(buf);
                post_hit(j, path, hit, DET_SIG);
                return TRUE;
            }
            /* keep the tail so a signature straddling a chunk boundary still hits */
            keep = (total > MAX_PAT) ? MAX_PAT : total;
            memmove(buf, buf + total - keep, keep);
            carry = keep;
            if (j->cancel) break;
        }
        CloseHandle(h);
        free(buf);
    }
    return FALSE;
}

static BOOL want_file(SCANJOB *j, const wchar_t *name, DWORD size)
{
    const wchar_t *e = wcsrchr(name, L'.');
    static const wchar_t *hot[] = {
        L".exe",L".dll",L".sys",L".scr",L".com",L".pif",L".cpl",L".ocx",L".drv",
        L".vbs",L".js",L".jse",L".vbe",L".wsf",L".wsh",L".hta",L".bat",L".cmd",
        L".jar",L".class",L".doc",L".xls",L".ppt",L".rtf",L".pdf",L".lnk",
        L".zip",L".rar",L".cab",L".msi",L".inf",L".reg",NULL
    };
    int i;
    if (size > 200u*1024u*1024u) return FALSE;    /* skip giant blobs */
    if (j->mode == SCAN_DEEP || j->mode == SCAN_CUSTOM) return TRUE;
    if (!e) return FALSE;
    for (i = 0; hot[i]; i++) if (!lstrcmpiW(e, hot[i])) return TRUE;
    return FALSE;
}

static void walk(SCANJOB *j, const wchar_t *dir, int depth)
{
    WIN32_FIND_DATAW fd;
    HANDLE h;
    wchar_t pat[MAX_PATH*2], sub[MAX_PATH*2];

    if (j->cancel || depth > 32) return;

    wsprintfW(pat, L"%s\\*", dir);
    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    InterlockedIncrement(&j->dirs);

    do {
        if (j->cancel) break;
        if (!lstrcmpW(fd.cFileName, L".") || !lstrcmpW(fd.cFileName, L"..")) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        wsprintfW(sub, L"%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* never descend into our own install tree */
            if (path_excluded(sub)) continue;
            if (j->mode == SCAN_QUICK && depth >= 1) continue;
            walk(j, sub, depth + 1);
        } else {
            if (!want_file(j, fd.cFileName, fd.nFileSizeLow)) continue;
            post_file(j, sub);
            scan_one(j, sub, fd.nFileSizeLow);
        }
    } while (FindNextFileW(h, &fd));

    FindClose(h);
}

static void scan_memory(SCANJOB *j)
{
    HANDLE snap;
    MODULEENTRY32W me;
    PROCESSENTRY32W pe;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            HANDLE ms;
            if (j->cancel) break;
            ms = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID);
            if (ms == INVALID_HANDLE_VALUE) continue;
            me.dwSize = sizeof(me);
            if (Module32FirstW(ms, &me)) {
                post_file(j, me.szExePath);
                scan_one(j, me.szExePath, 0);
            }
            CloseHandle(ms);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

static void scan_run_key(SCANJOB *j, HKEY root, const wchar_t *sub)
{
    HKEY k;
    DWORD i = 0, type, cbName, cbData;
    wchar_t name[256], data[MAX_PATH*2], expanded[MAX_PATH*2], *p;

    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return;

    for (;;) {
        cbName = 256; cbData = sizeof(data);
        if (RegEnumValueW(k, i++, name, &cbName, NULL, &type,
                          (LPBYTE)data, &cbData) != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        ExpandEnvironmentStringsW(data, expanded, MAX_PATH*2);
        /* strip quotes and trailing args */
        p = expanded;
        if (*p == L'"') {
            wchar_t *q = wcschr(p + 1, L'"');
            if (q) { *q = 0; p++; }
        } else {
            wchar_t *q = StrStrIW(p, L".exe");
            if (q) *(q + 4) = 0;
        }
        if (GetFileAttributesW(p) == INVALID_FILE_ATTRIBUTES) continue;
        post_file(j, p);
        scan_one(j, p, 0);
        if (j->cancel) break;
    }
    RegCloseKey(k);
}

DWORD WINAPI scan_thread(LPVOID param)
{
    SCANJOB *j = (SCANJOB*)param;
    wchar_t buf[MAX_PATH], drives[512], *d;

    InterlockedExchange(&j->running, 1);
    j->started = GetTickCount();
    j->files = j->dirs = j->found = j->skipped = 0;

    log_line(L"--- scan start (mode %d) ---", j->mode);

    switch (j->mode) {
    case SCAN_QUICK:
        scan_memory(j);
        if (GetWindowsDirectoryW(buf, MAX_PATH)) walk(j, buf, 0);
        if (GetSystemDirectoryW(buf, MAX_PATH)) walk(j, buf, 0);
        if (GetTempPathW(MAX_PATH, buf)) { PathRemoveBackslashW(buf); walk(j, buf, 1); }
        if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, buf) == S_OK) walk(j, buf, 1);
        if (SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, buf) == S_OK) walk(j, buf, 1);
        if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, buf) == S_OK) walk(j, buf, 1);
        scan_run_key(j, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        scan_run_key(j, HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        break;

    case SCAN_MEMORY:
        scan_memory(j);
        break;

    case SCAN_BOOT:
        scan_run_key(j, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        scan_run_key(j, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        scan_run_key(j, HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        scan_run_key(j, HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, buf) == S_OK) walk(j, buf, 1);
        if (SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, buf) == S_OK) walk(j, buf, 1);
        break;

    case SCAN_BASELINE:
        base_build(j->notify, &j->cancel);
        break;

    case SCAN_VERIFY: {
        unsigned int i, n = base_count();
        for (i = 0; i < n && !j->cancel; i++) {
            const wchar_t *bp = base_path_at(i);
            unsigned char md5[16];
            unsigned int sz = 0;
            if (!bp) continue;
            post_file(j, bp);
            InterlockedIncrement(&j->files);
            if (GetFileAttributesW(bp) == INVALID_FILE_ATTRIBUTES) {
                post_hit(j, bp, "System.FileMissing", DET_MODIFIED);
                continue;
            }
            if (!hash_file_md5(bp, md5, &sz)) { InterlockedIncrement(&j->skipped); continue; }
            if (memcmp(md5, base_md5_at(i), 16) != 0)
                post_hit(j, bp, "System.FileModified", DET_MODIFIED);
        }
        break;
    }

    case SCAN_CUSTOM: {
        DWORD a = GetFileAttributesW(j->root);
        if (a == INVALID_FILE_ATTRIBUTES) {
            log_line(L"target not found: %s", j->root);
        } else if (a & FILE_ATTRIBUTE_DIRECTORY) {
            walk(j, j->root, 0);
        } else {
            /* right-clicked a single file: scan it directly, always deep */
            post_file(j, j->root);
            scan_one(j, j->root, 0);
        }
        break;
    }

    case SCAN_FULL:
    case SCAN_DEEP:
    default:
        scan_memory(j);
        if (GetLogicalDriveStringsW(512, drives)) {
            for (d = drives; *d; d += wcslen(d) + 1) {
                if (GetDriveTypeW(d) != DRIVE_FIXED) continue;
                lstrcpynW(buf, d, MAX_PATH);
                PathRemoveBackslashW(buf);
                walk(j, buf, 0);
                if (j->cancel) break;
            }
        }
        break;
    }

    log_line(L"--- scan done: %ld files, %ld detections ---", j->files, j->found);
    InterlockedExchange(&j->running, 0);
    if (j->notify) PostMessageW(j->notify, WM_SCAN_DONE, 0, 0);
    return 0;
}

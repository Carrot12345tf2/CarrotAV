/* protect.c - quarantine vault, web blocker (hosts), firewall control,
 * and the user-mode real-time watcher.
 */
#include "av.h"
#include <stdarg.h>

#define QMASK 0x5A     /* quarantined files are XOR-masked so they cannot run */

void app_dir(wchar_t *out, int cch)
{
    wchar_t *p;
    GetModuleFileNameW(NULL, out, cch);
    p = wcsrchr(out, L'\\');
    if (p) *p = 0;
}

void log_line(const wchar_t *fmt, ...)
{
    wchar_t path[MAX_PATH], line[2048], stamp[64];
    SYSTEMTIME st;
    va_list ap;
    HANDLE h;
    DWORD wr;
    char *utf8;
    int n;

    app_dir(path, MAX_PATH);
    lstrcatW(path, L"\\carrotav.log");

    GetLocalTime(&st);
    wsprintfW(stamp, L"%04d-%02d-%02d %02d:%02d:%02d  ",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    va_start(ap, fmt);
    wvsprintfW(line, fmt, ap);
    va_end(ap);

    lstrcatW(stamp, L"");
    h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    n = WideCharToMultiByte(CP_UTF8, 0, stamp, -1, NULL, 0, NULL, NULL);
    utf8 = (char*)malloc(n + 4096);
    if (utf8) {
        WideCharToMultiByte(CP_UTF8, 0, stamp, -1, utf8, n, NULL, NULL);
        SetFilePointer(h, 0, NULL, FILE_END);
        WriteFile(h, utf8, lstrlenA(utf8), &wr, NULL);
        n = WideCharToMultiByte(CP_UTF8, 0, line, -1, NULL, 0, NULL, NULL);
        free(utf8);
        utf8 = (char*)malloc(n + 4);
        if (utf8) {
            WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8, n, NULL, NULL);
            WriteFile(h, utf8, lstrlenA(utf8), &wr, NULL);
            WriteFile(h, "\r\n", 2, &wr, NULL);
            free(utf8);
        }
    }
    CloseHandle(h);
}

/* ------------------------------ quarantine ------------------------------ */

void quar_dir(wchar_t *out, int cch)
{
    app_dir(out, cch);
    lstrcatW(out, L"\\Quarantine");
    CreateDirectoryW(out, NULL);
}

static void quar_index(wchar_t *out, int cch)
{
    quar_dir(out, cch);
    lstrcatW(out, L"\\vault.idx");
}

/* Files that must never be quarantined, however convincing the detection.
 * Removing any of these bricks the machine, so a signature hit on one is
 * reported but the file is left strictly alone. */
/* ---- user exclusion list (defs\exclusions.txt, one path per line) ---- */

static void excl_file(wchar_t *out, int cch)
{
    app_dir(out, cch);
    lstrcatW(out, L"\\defs\\exclusions.txt");
}

BOOL excl_add(const wchar_t *path)
{
    wchar_t f[MAX_PATH];
    HANDLE h;
    DWORD wr;
    char utf8[MAX_PATH*3];
    int n;

    excl_file(f, MAX_PATH);
    h = CreateFileW(f, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    n = WideCharToMultiByte(CP_UTF8, 0, path, -1, utf8, sizeof(utf8)-3, NULL, NULL);
    if (n > 0) {
        SetFilePointer(h, 0, NULL, FILE_END);
        WriteFile(h, utf8, n - 1, &wr, NULL);
        WriteFile(h, "\r\n", 2, &wr, NULL);
    }
    CloseHandle(h);
    log_line(L"EXCLUDE  added %s", path);
    return TRUE;
}

int excl_list(wchar_t ***out)
{
    wchar_t f[MAX_PATH], **arr = NULL;
    HANDLE h;
    DWORD sz, rd;
    char *buf;
    int n = 0, cap = 0;
    char *line, *next;

    *out = NULL;
    excl_file(f, MAX_PATH);
    h = CreateFileW(f, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz > 1048576) { CloseHandle(h); return 0; }
    buf = (char*)malloc(sz + 1);
    if (!buf) { CloseHandle(h); return 0; }
    ReadFile(h, buf, sz, &rd, NULL);
    buf[rd] = 0;
    CloseHandle(h);

    for (line = buf; line && *line; line = next) {
        wchar_t w[MAX_PATH];
        char *cr;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        cr = strchr(line, '\r'); if (cr) *cr = 0;
        if (!*line || *line == '#') continue;
        MultiByteToWideChar(CP_UTF8, 0, line, -1, w, MAX_PATH);
        if (n >= cap) {
            int nc = cap ? cap * 2 : 32;
            wchar_t **na = (wchar_t**)realloc(arr, nc * sizeof(wchar_t*));
            if (!na) break;
            arr = na; cap = nc;
        }
        arr[n] = (wchar_t*)malloc((lstrlenW(w) + 1) * sizeof(wchar_t));
        if (!arr[n]) break;
        lstrcpyW(arr[n], w);
        n++;
    }
    free(buf);
    *out = arr;
    return n;
}

/* Does 'path' fall under the excluded directory (or equal an excluded file)?
 *
 * This used to be a raw substring test, which over-matched badly: an exclusion
 * for "C:\Temp" also excluded "C:\Temperature\", and an entry like "bin" would
 * exclude every path containing those letters anywhere. Now the exclusion must
 * match from the start of the path and end on a real boundary - either the
 * whole path, or followed by a backslash. */
static BOOL excl_covers(const wchar_t *path, const wchar_t *excl)
{
    int n = lstrlenW(excl);
    if (n <= 0) return FALSE;
    /* ignore a trailing backslash on the stored exclusion */
    while (n > 1 && excl[n-1] == L'\\') n--;
    if (StrCmpNIW(path, excl, n) != 0) return FALSE;
    return path[n] == 0 || path[n] == L'\\';
}

BOOL excl_match(const wchar_t *path)
{
    wchar_t **list;
    int n, i;
    BOOL hit = FALSE;
    n = excl_list(&list);
    for (i = 0; i < n; i++) {
        if (!hit && excl_covers(path, list[i])) hit = TRUE;
        free(list[i]);
    }
    free(list);
    return hit;
}

/* ---- restore grace list ----
 * When the user deliberately restores a file from quarantine, the live shield
 * must not instantly re-quarantine it - otherwise "Restore" is meaningless for
 * anything the shield would catch (a restored zip bomb just gets eaten again).
 * We remember recently-restored paths for a short window and tell the shield
 * to leave them alone. In-process, so a plain array is enough. */
#define GRACE_MAX     32
#define GRACE_SECS    60
static struct { wchar_t path[MAX_PATH*2]; DWORD until; } g_grace[GRACE_MAX];
static int g_grace_n = 0;

void grace_add(const wchar_t *path)
{
    int i;
    DWORD now = GetTickCount();
    /* reuse an expired slot or the oldest one */
    for (i = 0; i < g_grace_n; i++) {
        if (!lstrcmpiW(g_grace[i].path, path)) {
            g_grace[i].until = now + GRACE_SECS * 1000;
            return;
        }
    }
    if (g_grace_n < GRACE_MAX) i = g_grace_n++;
    else {
        int oldest = 0, j;
        for (j = 1; j < g_grace_n; j++)
            if (g_grace[j].until < g_grace[oldest].until) oldest = j;
        i = oldest;
    }
    lstrcpynW(g_grace[i].path, path, MAX_PATH*2);
    g_grace[i].until = now + GRACE_SECS * 1000;
}

BOOL grace_active(const wchar_t *path)
{
    int i;
    DWORD now = GetTickCount();
    for (i = 0; i < g_grace_n; i++) {
        if (!lstrcmpiW(g_grace[i].path, path))
            return (long)(g_grace[i].until - now) > 0;
    }
    return FALSE;
}

BOOL path_excluded(const wchar_t *path)
{
    static const wchar_t *critical[] = {
        L"\\ntldr", L"\\ntdetect.com", L"\\boot.ini", L"\\bootfont.bin",
        L"\\ntoskrnl.exe", L"\\hal.dll", L"\\ntdll.dll", L"\\kernel32.dll",
        L"\\winlogon.exe", L"\\csrss.exe", L"\\smss.exe", L"\\services.exe",
        L"\\lsass.exe", L"\\userinit.exe", L"\\explorer.exe",
        L"\\win.ini", L"\\system.ini", L"\\pagefile.sys", NULL
    };
    wchar_t self[MAX_PATH], selflong[MAX_PATH], pathlong[MAX_PATH];
    int i;

    /* Our own install tree. Compare canonicalised paths: GetModuleFileName
     * can hand back a short 8.3 form (C:\PROGRA~1\...) when launched from a
     * shortcut, which never substring-matches the long form the scanner
     * builds while walking the disk. That mismatch is why the database and
     * README were being scanned and flagged. */
    app_dir(self, MAX_PATH);
    if (self[0]) {
        if (StrStrIW(path, self)) return TRUE;
        if (GetLongPathNameW(self, selflong, MAX_PATH) &&
            GetLongPathNameW(path, pathlong, MAX_PATH)) {
            if (StrStrIW(pathlong, selflong)) return TRUE;
        }
        /* last resort: match on the install folder's own name */
        {
            const wchar_t *leaf = PathFindFileNameW(self);
            wchar_t frag[MAX_PATH];
            if (leaf && *leaf) {
                wsprintfW(frag, L"\\%s\\", leaf);
                if (StrStrIW(path, frag)) return TRUE;
            }
        }
    }

    for (i = 0; critical[i]; i++)
        if (StrStrIW(path, critical[i])) return TRUE;

    if (excl_match(path)) return TRUE;

    return FALSE;
}

BOOL quar_add(const wchar_t *path, const char *threat)
{
    wchar_t dir[MAX_PATH], dest[MAX_PATH], idx[MAX_PATH];
    HANDLE in, outh;
    BYTE buf[32768];
    DWORD rd, wr, i;
    SYSTEMTIME st;
    QITEM it;
    static LONG counter = 0;
    LONG id;
    DWORD srcsize = 0, written = 0;
    BOOL copy_ok = TRUE, deleted;

    if (path_excluded(path)) {
        log_line(L"PROTECTED  refused to quarantine %s [%S]", path, threat);
        return FALSE;
    }

    quar_dir(dir, MAX_PATH);
    GetLocalTime(&st);
    id = InterlockedIncrement(&counter);
    wsprintfW(dest, L"%s\\%04d%02d%02d_%02d%02d%02d_%03ld.qtn",
              dir, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, id);

    in = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                     OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (in == INVALID_HANDLE_VALUE) return FALSE;

    outh = CreateFileW(dest, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (outh == INVALID_HANDLE_VALUE) { CloseHandle(in); return FALSE; }

    memset(&it, 0, sizeof(it));
    srcsize = GetFileSize(in, NULL);
    it.size = srcsize;

    /* --- copy into the vault, checking every write --- */
    for (;;) {
        if (!ReadFile(in, buf, sizeof(buf), &rd, NULL)) { copy_ok = FALSE; break; }
        if (rd == 0) break;
        for (i = 0; i < rd; i++) buf[i] ^= QMASK;
        if (!WriteFile(outh, buf, rd, &wr, NULL) || wr != rd) {
            copy_ok = FALSE;            /* disk full, write error, etc. */
            break;
        }
        written += wr;
    }
    FlushFileBuffers(outh);             /* get it on disk before we delete */
    CloseHandle(in);
    CloseHandle(outh);

    /* --- verify the vault copy is complete BEFORE touching the original ---
     * Deleting first and discovering the copy was short would destroy the
     * file. If anything went wrong, throw away the partial vault file and
     * leave the original alone - a failed quarantine must not lose data. */
    if (!copy_ok || written != srcsize) {
        DeleteFileW(dest);
        log_line(L"QUARANTINE  FAILED to vault %s (%lu of %lu bytes) - original left in place",
                 path, written, srcsize);
        return FALSE;
    }

    /* --- now remove the original --- */
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    deleted = DeleteFileW(path);
    if (!deleted) {
        /* Locked (running executable, open handle). Schedule removal at next
         * boot - but only claim success if that scheduling actually worked. */
        if (MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            log_line(L"QUARANTINE  %s -> %s (original locked; removal pending reboot)",
                     path, dest);
        } else {
            /* We could neither delete nor schedule. The vault copy exists but
             * the threat is STILL THERE - say so rather than reporting success. */
            log_line(L"QUARANTINE  INCOMPLETE %s -> %s (could not remove original)",
                     path, dest);
        }
    }

    lstrcpynW(it.orig, path, MAX_PATH*2);
    lstrcpynW(it.stored, dest, MAX_PATH);
    lstrcpynA(it.threat, threat, 128);
    GetSystemTimeAsFileTime(&it.when);

    quar_index(idx, MAX_PATH);
    outh = CreateFileW(idx, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outh != INVALID_HANDLE_VALUE) {
        SetFilePointer(outh, 0, NULL, FILE_END);
        WriteFile(outh, &it, sizeof(it), &wr, NULL);
        CloseHandle(outh);
    }
    if (deleted)
        log_line(L"QUARANTINE  %s -> %s", path, dest);
    return TRUE;
}

int quar_list(QITEM **out)
{
    wchar_t idx[MAX_PATH];
    HANDLE h;
    DWORD size, rd;
    QITEM *items;
    int n;

    *out = NULL;
    quar_index(idx, MAX_PATH);
    h = CreateFileW(idx, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    size = GetFileSize(h, NULL);
    n = (int)(size / sizeof(QITEM));
    if (n <= 0) { CloseHandle(h); return 0; }

    items = (QITEM*)LocalAlloc(LPTR, n * sizeof(QITEM));
    if (!items) { CloseHandle(h); return 0; }
    ReadFile(h, items, n * sizeof(QITEM), &rd, NULL);
    CloseHandle(h);

    *out = items;
    return n;
}

static BOOL quar_rewrite_without(const QITEM *drop)
{
    wchar_t idx[MAX_PATH];
    QITEM *items;
    int n, i;
    HANDLE h;
    DWORD wr;

    n = quar_list(&items);
    if (!n) return FALSE;

    quar_index(idx, MAX_PATH);
    h = CreateFileW(idx, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { LocalFree(items); return FALSE; }
    for (i = 0; i < n; i++) {
        if (!lstrcmpiW(items[i].stored, drop->stored)) continue;
        WriteFile(h, &items[i], sizeof(QITEM), &wr, NULL);
    }
    CloseHandle(h);
    LocalFree(items);
    return TRUE;
}

BOOL quar_restore(const QITEM *it)
{
    HANDLE in, outh;
    BYTE buf[32768];
    DWORD rd, wr, i;

    in = CreateFileW(it->stored, GENERIC_READ, FILE_SHARE_READ, NULL,
                     OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (in == INVALID_HANDLE_VALUE) return FALSE;

    /* The original folder may be gone (user deleted it, or it was a temp
     * dir). CREATE_ALWAYS fails if the parent doesn't exist, which is the
     * silent failure that left files un-restored. Recreate the parent path
     * first. */
    {
        wchar_t dir[MAX_PATH*2];
        wchar_t *p;
        lstrcpynW(dir, it->orig, MAX_PATH*2);
        p = wcsrchr(dir, L'\\');
        if (p) {
            *p = 0;
            /* build the directory tree component by component */
            {
                wchar_t make[MAX_PATH*2];
                wchar_t *s = dir;
                int n = 0;
                make[0] = 0;
                while (*s) {
                    make[n++] = *s;
                    if (*s == L'\\') { make[n] = 0; CreateDirectoryW(make, NULL); }
                    s++;
                }
                make[n] = 0;
                CreateDirectoryW(make, NULL);
            }
        }
    }

    outh = CreateFileW(it->orig, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (outh == INVALID_HANDLE_VALUE) { CloseHandle(in); return FALSE; }

    {
        DWORD vaultsize = GetFileSize(in, NULL), written = 0;
        BOOL ok = TRUE;
        for (;;) {
            if (!ReadFile(in, buf, sizeof(buf), &rd, NULL)) { ok = FALSE; break; }
            if (rd == 0) break;
            for (i = 0; i < rd; i++) buf[i] ^= QMASK;
            if (!WriteFile(outh, buf, rd, &wr, NULL) || wr != rd) { ok = FALSE; break; }
            written += wr;
        }
        FlushFileBuffers(outh);
        CloseHandle(in);
        CloseHandle(outh);

        /* Only drop the vault copy once the restored file is known good. A
         * short or failed write would otherwise leave a truncated file on disk
         * AND destroy the only intact copy. */
        if (!ok || written != vaultsize) {
            DeleteFileW(it->orig);
            log_line(L"RESTORE  FAILED %s (%lu of %lu bytes) - kept in quarantine",
                     it->orig, written, vaultsize);
            return FALSE;
        }
    }

    DeleteFileW(it->stored);
    quar_rewrite_without(it);
    grace_add(it->orig);   /* shield: leave this alone for a bit - user chose it */
    log_line(L"RESTORE  %s", it->orig);
    return TRUE;
}

BOOL quar_delete(const QITEM *it)
{
    SetFileAttributesW(it->stored, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(it->stored);
    quar_rewrite_without(it);
    log_line(L"PURGE  %s", it->orig);
    return TRUE;
}

/* --------------------------- web / hosts blocker --------------------------- */

#define HOSTS_BEGIN "# >>> CarrotAV Web Shield >>>\r\n"
#define HOSTS_END   "# <<< CarrotAV Web Shield <<<\r\n"

static void hosts_path(wchar_t *out, int cch)
{
    GetSystemDirectoryW(out, cch);
    lstrcatW(out, L"\\drivers\\etc\\hosts");
}

static char *hosts_read(DWORD *len)
{
    wchar_t p[MAX_PATH];
    HANDLE h;
    char *buf;
    DWORD sz, rd;

    hosts_path(p, MAX_PATH);
    h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz > 32u*1024u*1024u) { CloseHandle(h); return NULL; }
    buf = (char*)malloc(sz + 1);
    if (!buf) { CloseHandle(h); return NULL; }
    ReadFile(h, buf, sz, &rd, NULL);
    buf[rd] = 0;
    CloseHandle(h);
    if (len) *len = rd;
    return buf;
}

static BOOL hosts_write(const char *data, DWORD len)
{
    wchar_t p[MAX_PATH];
    HANDLE h;
    DWORD wr;

    hosts_path(p, MAX_PATH);
    SetFileAttributesW(p, FILE_ATTRIBUTE_NORMAL);
    h = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(h, data, len, &wr, NULL);
    CloseHandle(h);
    return wr == len;
}

/* returns a copy of hosts with our managed block stripped out */
static char *hosts_strip(DWORD *outlen)
{
    char *buf, *b, *e, *res;
    DWORD len;

    buf = hosts_read(&len);
    if (!buf) return NULL;

    b = strstr(buf, HOSTS_BEGIN);
    if (!b) { if (outlen) *outlen = len; return buf; }
    e = strstr(b, HOSTS_END);
    if (!e) { *b = 0; if (outlen) *outlen = (DWORD)(b - buf); return buf; }
    e += strlen(HOSTS_END);

    res = (char*)malloc(len + 1);
    if (!res) { free(buf); return NULL; }
    memcpy(res, buf, b - buf);
    memcpy(res + (b - buf), e, len - (e - buf));
    len = (DWORD)((b - buf) + (len - (e - buf)));
    res[len] = 0;
    free(buf);
    if (outlen) *outlen = len;
    return res;
}

BOOL hosts_block_count(int *blocked)
{
    char *buf, *b, *e, *p;
    int n = 0;

    *blocked = 0;
    buf = hosts_read(NULL);
    if (!buf) return FALSE;
    b = strstr(buf, HOSTS_BEGIN);
    if (b) {
        e = strstr(b, HOSTS_END);
        if (!e) e = buf + strlen(buf);
        for (p = b; p < e; p++) if (*p == '\n') n++;
        n -= 1;                       /* discount the begin marker line */
        if (n < 0) n = 0;
    }
    free(buf);
    *blocked = n;
    return TRUE;
}

BOOL hosts_clear(void)
{
    char *stripped;
    DWORD len;
    BOOL ok;

    stripped = hosts_strip(&len);
    if (!stripped) return FALSE;
    ok = hosts_write(stripped, len);
    free(stripped);
    log_line(L"WEBSHIELD  blocklist cleared");
    return ok;
}

/* Import a hosts-format or plain-domain-per-line file into our managed block. */
BOOL hosts_import(const wchar_t *listfile, int *added)
{
    HANDLE h;
    DWORD sz, rd, outlen;
    char *src, *stripped, *out, *line, *next, *dom;
    size_t cap, used;
    int count = 0;

    *added = 0;

    h = CreateFileW(listfile, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz > 64u*1024u*1024u) { CloseHandle(h); return FALSE; }
    src = (char*)malloc(sz + 1);
    if (!src) { CloseHandle(h); return FALSE; }
    ReadFile(h, src, sz, &rd, NULL);
    src[rd] = 0;
    CloseHandle(h);

    stripped = hosts_strip(&outlen);
    if (!stripped) { free(src); return FALSE; }

    cap = outlen + rd * 2 + 4096;
    out = (char*)malloc(cap);
    if (!out) { free(src); free(stripped); return FALSE; }
    memcpy(out, stripped, outlen);
    used = outlen;
    free(stripped);

    if (used && out[used-1] != '\n') { out[used++] = '\r'; out[used++] = '\n'; }
    memcpy(out + used, HOSTS_BEGIN, strlen(HOSTS_BEGIN));
    used += strlen(HOSTS_BEGIN);

    for (line = src; line && *line; line = next) {
        char *sp;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        sp = strchr(line, '\r'); if (sp) *sp = 0;

        while (*line == ' ' || *line == '\t') line++;
        if (!*line || *line == '#') continue;

        /* accept "0.0.0.0 domain", "127.0.0.1 domain", or a bare domain */
        dom = line;
        if (!strncmp(line, "0.0.0.0", 7) || !strncmp(line, "127.0.0.1", 9)) {
            dom = line + (line[0] == '0' ? 7 : 9);
            while (*dom == ' ' || *dom == '\t') dom++;
        }
        sp = strpbrk(dom, " \t#");
        if (sp) *sp = 0;
        if (!*dom) continue;
        if (!strcmp(dom, "localhost") || !strcmp(dom, "localhost.localdomain")) continue;
        if (strlen(dom) > 250) continue;

        if (used + strlen(dom) + 16 > cap) break;
        used += (size_t)wsprintfA(out + used, "0.0.0.0 %s\r\n", dom);
        count++;
    }

    memcpy(out + used, HOSTS_END, strlen(HOSTS_END));
    used += strlen(HOSTS_END);

    hosts_write(out, (DWORD)used);
    free(out);
    free(src);

    *added = count;
    log_line(L"WEBSHIELD  imported %d domains", count);
    return TRUE;
}

BOOL hosts_add(const char *domain)
{
    char *buf, *ins, *out;
    DWORD len;
    size_t used;
    BOOL ok;

    buf = hosts_read(&len);
    if (!buf) return FALSE;

    out = (char*)malloc(len + 512);
    if (!out) { free(buf); return FALSE; }

    ins = strstr(buf, HOSTS_BEGIN);
    if (ins) {
        size_t pre = (size_t)(ins - buf) + strlen(HOSTS_BEGIN);
        memcpy(out, buf, pre);
        used = pre;
        used += (size_t)wsprintfA(out + used, "0.0.0.0 %s\r\n", domain);
        memcpy(out + used, buf + pre, len - pre);
        used += len - pre;
    } else {
        memcpy(out, buf, len);
        used = len;
        if (used && out[used-1] != '\n') { out[used++] = '\r'; out[used++] = '\n'; }
        memcpy(out + used, HOSTS_BEGIN, strlen(HOSTS_BEGIN)); used += strlen(HOSTS_BEGIN);
        used += (size_t)wsprintfA(out + used, "0.0.0.0 %s\r\n", domain);
        memcpy(out + used, HOSTS_END, strlen(HOSTS_END)); used += strlen(HOSTS_END);
    }
    ok = hosts_write(out, (DWORD)used);
    free(out);
    free(buf);
    return ok;
}

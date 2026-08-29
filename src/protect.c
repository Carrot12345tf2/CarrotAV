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

BOOL excl_match(const wchar_t *path)
{
    wchar_t **list;
    int n, i;
    BOOL hit = FALSE;
    n = excl_list(&list);
    for (i = 0; i < n; i++) {
        if (!hit && StrStrIW(path, list[i])) hit = TRUE;
        free(list[i]);
    }
    free(list);
    return hit;
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
    it.size = GetFileSize(in, NULL);

    for (;;) {
        if (!ReadFile(in, buf, sizeof(buf), &rd, NULL) || rd == 0) break;
        for (i = 0; i < rd; i++) buf[i] ^= QMASK;
        WriteFile(outh, buf, rd, &wr, NULL);
    }
    CloseHandle(in);
    CloseHandle(outh);

    /* original must go; clear read-only/hidden first */
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    if (!DeleteFileW(path)) {
        /* locked file: schedule removal at next boot */
        MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
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

    outh = CreateFileW(it->orig, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (outh == INVALID_HANDLE_VALUE) { CloseHandle(in); return FALSE; }

    for (;;) {
        if (!ReadFile(in, buf, sizeof(buf), &rd, NULL) || rd == 0) break;
        for (i = 0; i < rd; i++) buf[i] ^= QMASK;
        WriteFile(outh, buf, rd, &wr, NULL);
    }
    CloseHandle(in);
    CloseHandle(outh);
    DeleteFileW(it->stored);
    quar_rewrite_without(it);
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

/* report.c - Help -> Report a Problem.
 *
 * A small window where the user describes what went wrong (up to 200
 * characters). The CarrotAV version, Windows version, a random install ID and
 * the end of carrotav.log are attached automatically.
 *
 * Send: the report goes to Web3Forms over CarrotAV's own TLS (defupdate.exe
 * --report, run with no console window, since XP's own HTTPS can't reach
 * modern sites). Web3Forms emails it to the CarrotAV reports inbox. Its access
 * key is public by design: all it can do is deliver to that one inbox.
 *
 * Copy / Save as .txt: for offline machines, or if sending fails.
 *
 * Anti-spam (stops accidents and casual abuse): at most one report every
 * 10 minutes and 5 a day per install, and every email is tagged
 * "[CarrotAV report]" so the inbox can sort them.
 */
#include "av.h"
#include "resource.h"
#include <commdlg.h>
#include <stddef.h>
#include <stdio.h>

#define WEB3FORMS_KEY  "dfb6d775-21f3-4397-abb5-e011f215eec6"

#define RP_CLASS     L"CarrotAVReport"
#define RP_W         420
#define MAX_CHARS    200
#define COOLDOWN_S   (10 * 60)
#define MAX_PER_DAY  5
#define LOG_LINES    50

#define IDC_RP_EDIT    2201
#define IDC_RP_COUNT   2202
#define IDC_RP_LOG     2203
#define IDC_RP_STATUS  2204
#define IDC_RP_SEND    2205
#define IDC_RP_COPY    2206
#define IDC_RP_SAVE    2207
#define IDC_RP_CLOSE   2208
#define IDC_RP_LABEL   2209
#define WM_RP_RESULT   (WM_APP + 41)

static HWND  g_rp, g_rp_owner;
static HFONT g_rp_font;
static volatile LONG g_rp_sending;

/* ------------------------------------------------------------ helpers */

static DWORD now_unix(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    return (DWORD)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

static DWORD reg_get(const wchar_t *name, DWORD def)
{
    HKEY k;
    DWORD v = def, sz = sizeof v;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\CarrotAV", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, name, NULL, NULL, (BYTE*)&v, &sz) != ERROR_SUCCESS) v = def;
        RegCloseKey(k);
    }
    return v;
}

static void reg_set(const wchar_t *name, DWORD v)
{
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\CarrotAV", 0, NULL, 0,
                        KEY_WRITE, NULL, &k, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE*)&v, sizeof v);
        RegCloseKey(k);
    }
}

/* Random per-install ID so a flooding install can be filtered out. */
static void install_id(wchar_t *out, int cap)
{
    HKEY k;
    DWORD type, sz = (DWORD)(cap * sizeof(wchar_t));
    out[0] = 0;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\CarrotAV", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, L"InstallId", NULL, &type, (BYTE*)out, &sz) != ERROR_SUCCESS || type != REG_SZ)
            out[0] = 0;
        RegCloseKey(k);
    }
    if (!out[0]) {
        GUID g;
        if (CoCreateGuid(&g) == S_OK)
            wsprintfW(out, L"%08lX%04X", g.Data1, g.Data2);
        else
            wsprintfW(out, L"%08lX", GetTickCount() ^ GetCurrentProcessId());
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\CarrotAV", 0, NULL, 0,
                            KEY_WRITE, NULL, &k, NULL) == ERROR_SUCCESS) {
            RegSetValueExW(k, L"InstallId", 0, REG_SZ, (const BYTE*)out,
                           (DWORD)((lstrlenW(out) + 1) * sizeof(wchar_t)));
            RegCloseKey(k);
        }
    }
}

/* Last LOG_LINES lines of carrotav.log, as UTF-8 (malloc'd, may be ""). */
static char *log_tail(void)
{
    wchar_t path[MAX_PATH];
    HANDLE h;
    DWORD size, rd = 0, want;
    char *buf, *p;
    int lines = 0;

    app_dir(path, MAX_PATH);
    lstrcatW(path, L"\\carrotav.log");
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    buf = (char*)malloc(8192 + 1);
    if (!buf) { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); return NULL; }
    buf[0] = 0;
    if (h == INVALID_HANDLE_VALUE) return buf;
    size = GetFileSize(h, NULL);
    want = size < 8192 ? size : 8192;
    SetFilePointer(h, (LONG)(size - want), NULL, FILE_BEGIN);
    ReadFile(h, buf, want, &rd, NULL);
    CloseHandle(h);
    buf[rd] = 0;
    /* walk back LOG_LINES newlines */
    for (p = buf + rd; p > buf; p--)
        if (p[-1] == '\n' && ++lines > LOG_LINES) break;
    if (p != buf) memmove(buf, p, strlen(p) + 1);
    return buf;
}

/* Append s (UTF-8) to out as a JSON string body (no quotes). */
static void json_esc(char *out, size_t cap, const char *s)
{
    size_t n = strlen(out);
    for (; *s && n + 8 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { out[n++] = '\\'; out[n++] = (char)c; }
        else if (c == '\n') { out[n++] = '\\'; out[n++] = 'n'; }
        else if (c == '\r') { /* drop */ }
        else if (c == '\t') { out[n++] = '\\'; out[n++] = 't'; }
        else if (c < 0x20) { n += wsprintfA(out + n, "\\u%04x", c); }
        else out[n++] = (char)c;
    }
    out[n] = 0;
}

static char *to_utf8(const wchar_t *w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *s = (char*)malloc(n > 0 ? n : 1);
    if (!s) return NULL;
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL); else s[0] = 0;
    return s;
}

/* ------------------------------------------------------ build report */

typedef struct {
    char *message, *windows, *version, *id, *log;
} REPORT;

static BOOL collect(REPORT *r)
{
    wchar_t msg[MAX_CHARS + 1], idw[40];
    memset(r, 0, sizeof *r);
    GetDlgItemTextW(g_rp, IDC_RP_EDIT, msg, MAX_CHARS + 1);
    install_id(idw, 40);
    r->message = to_utf8(msg);
    r->windows = to_utf8(os_name());
    r->version = to_utf8(AV_VERSION);
    r->id      = to_utf8(idw);
    r->log     = IsDlgButtonChecked(g_rp, IDC_RP_LOG) == BST_CHECKED ? log_tail() : NULL;
    return r->message && r->windows && r->version && r->id;
}

static void report_free(REPORT *r)
{
    free(r->message); free(r->windows); free(r->version); free(r->id); free(r->log);
}

/* Plain text, for Copy and Save. CRLF so Notepad on XP shows lines. */
static char *as_text(const REPORT *r)
{
    size_t cap = 2048 + (r->log ? strlen(r->log) * 2 : 0);
    char *t = (char*)malloc(cap), *o;
    const char *s;
    if (!t) return NULL;
    /* strcat, not wsprintf: wsprintf output is capped at 1024 chars */
    strcpy(t, "CarrotAV problem report\r\n-----------------------\r\nWhat went wrong: ");
    strcat(t, r->message);
    strcat(t, "\r\n\r\nCarrotAV: ");   strcat(t, r->version);
    strcat(t, "\r\nWindows: ");          strcat(t, r->windows);
    strcat(t, "\r\nInstall ID: ");       strcat(t, r->id);
    strcat(t, "\r\n");
    if (r->log && r->log[0]) {
        strcat(t, "\r\nLast log lines:\r\n");
        o = t + strlen(t);
        for (s = r->log; *s && (size_t)(o - t) < cap - 3; s++) {
            if (*s == '\n' && (s == r->log || s[-1] != '\r')) *o++ = '\r';
            *o++ = *s;
        }
        *o = 0;
    }
    strcat(t, "\r\nPost it at: github.com/Carrot12345tf2/CarrotAV/issues\r\n");
    return t;
}

static char *as_json(const REPORT *r)
{
    size_t cap = 4096 + (r->log ? strlen(r->log) * 2 : 0);
    char *j = (char*)malloc(cap), subj[160];
    if (!j) return NULL;
    /* subject: tag + version + start of the message */
    {
        char head[48], *q;
        int k;
        lstrcpynA(head, r->message, 41);
        k = lstrlenA(head);
        /* don't cut a UTF-8 character in half: if the next byte continues a
         * character, back up to where that character starts */
        if (((unsigned char)r->message[k] & 0xC0) == 0x80) {
            while (k > 0 && ((unsigned char)head[k - 1] & 0xC0) == 0x80) k--;
            if (k > 0) k--;              /* the lead byte */
            head[k] = 0;
        }
        for (q = head; *q; q++) if (*q == '\r' || *q == '\n') *q = ' ';
        wsprintfA(subj, "[CarrotAV report] %s - %s%s", r->version, head,
                strlen(r->message) > 40 ? "..." : "");
    }
    strcpy(j, "{\"access_key\":\"" WEB3FORMS_KEY "\",\"subject\":\"");
    json_esc(j, cap, subj);
    strcat(j, "\",\"from_name\":\"CarrotAV ");     json_esc(j, cap, r->version);
    strcat(j, "\",\"message\":\"");                json_esc(j, cap, r->message);
    strcat(j, "\",\"carrotav_version\":\"");       json_esc(j, cap, r->version);
    strcat(j, "\",\"windows\":\"");                json_esc(j, cap, r->windows);
    strcat(j, "\",\"install_id\":\"");             json_esc(j, cap, r->id);
    strcat(j, "\",\"log\":\"");                    json_esc(j, cap, r->log && r->log[0] ? r->log : "(not attached)");
    strcat(j, "\"}");
    return j;
}

/* ------------------------------------------------------------ actions */

static void set_status(const wchar_t *s) { SetDlgItemTextW(g_rp, IDC_RP_STATUS, s); }

static void do_copy(void)
{
    REPORT r;
    char *t;
    wchar_t *w;
    int n;
    HGLOBAL g;
    if (!collect(&r)) { report_free(&r); return; }
    t = as_text(&r);
    report_free(&r);
    if (!t) return;
    n = MultiByteToWideChar(CP_UTF8, 0, t, -1, NULL, 0);
    g = GlobalAlloc(GMEM_MOVEABLE, n * sizeof(wchar_t));
    if (g && (w = (wchar_t*)GlobalLock(g)) != NULL) {
        MultiByteToWideChar(CP_UTF8, 0, t, -1, w, n);
        GlobalUnlock(g);
        if (OpenClipboard(g_rp)) {
            EmptyClipboard();
            if (SetClipboardData(CF_UNICODETEXT, g)) g = NULL;
            CloseClipboard();
        }
    }
    if (g) GlobalFree(g);
    free(t);
    set_status(L"Copied. Paste it into a new issue at github.com/Carrot12345tf2/CarrotAV/issues");
}

static void do_save(void)
{
    OPENFILENAMEW ofn;
    wchar_t file[MAX_PATH] = L"CarrotAV-report.txt";
    REPORT r;
    char *t;
    HANDLE h;
    DWORD wr;
    memset(&ofn, 0, sizeof ofn);
    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner = g_rp;
    ofn.lpstrFilter = L"Text files (*.txt)\0*.txt\0All files\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;
    if (!collect(&r)) { report_free(&r); return; }
    t = as_text(&r);
    report_free(&r);
    if (!t) return;
    h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        WriteFile(h, t, (DWORD)strlen(t), &wr, NULL);
        CloseHandle(h);
        set_status(L"Saved. Post it at github.com/Carrot12345tf2/CarrotAV/issues from any PC.");
    } else {
        set_status(L"Couldn't save the file there.");
    }
    free(t);
}

typedef struct { wchar_t body[MAX_PATH]; } SENDJOB;

/* Runs defupdate.exe --report=<file> with no window, waits for it. */
static DWORD WINAPI send_thread(LPVOID p)
{
    SENDJOB *j = (SENDJOB*)p;
    wchar_t dir[MAX_PATH], exe[MAX_PATH], cmd[MAX_PATH * 3], res[MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    char line[200] = "";
    LPARAM result = 0;        /* 0 fail, 1 ok, 2 busy, 3 no internet */
    FILE *f;

    app_dir(dir, MAX_PATH);
    wsprintfW(exe, L"%s\\tools\\defupdate.exe", dir);
    wsprintfW(res, L"%s\\tools\\report_result.txt", dir);
    wsprintfW(cmd, L"\"%s\" \"--report=%s\"", exe, j->body);
    DeleteFileW(res);

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (CreateProcessW(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        BOOL timed_out = FALSE;
        if (WaitForSingleObject(pi.hProcess, 120000) == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            timed_out = TRUE;
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        /* the file holds "stage ..." lines, then the answer: keep the last line */
        f = _wfopen(res, L"r");
        if (f) {
            char buf[200];
            while (fgets(buf, sizeof buf, f)) lstrcpynA(line, buf, sizeof line);
            fclose(f);
        }
        { char *q = line + strlen(line); while (q > line && (q[-1] == '\n' || q[-1] == '\r')) *--q = 0; }
        if (!strncmp(line, "ok", 2)) result = 1;
        else if (strstr(line, "busy")) result = 2;
        else if (strstr(line, "noconnect")) result = 3;
        else if (timed_out) result = 4;
        if (timed_out)
            log_line(L"REPORT  send timed out after 2 minutes (last step: %S)", line[0] ? line : "never started");
        else
            log_line(L"REPORT  send result: %S", line[0] ? line : "no answer");
    } else {
        log_line(L"REPORT  could not start defupdate.exe");
    }
    DeleteFileW(res);
    DeleteFileW(j->body);
    LocalFree(j);
    InterlockedExchange(&g_rp_sending, 0);
    if (g_rp) PostMessageW(g_rp, WM_RP_RESULT, 0, result);
    return 0;
}

static void do_send(void)
{
    REPORT r;
    char *json;
    DWORD now = now_unix(), last, day, count;
    SENDJOB *j;
    wchar_t tmp[MAX_PATH];
    HANDLE h, t;
    DWORD wr;

    if (g_rp_sending) return;

    /* anti-spam limits */
    last  = reg_get(L"ReportLast", 0);
    day   = reg_get(L"ReportDay", 0);
    count = reg_get(L"ReportCount", 0);
    if (day != now / 86400) count = 0;
    if (last && now - last < COOLDOWN_S) {
        wchar_t s[120];
        wsprintfW(s, L"Thanks! Please wait %lu more minute(s) before sending another report.",
                  (COOLDOWN_S - (now - last) + 59) / 60);
        set_status(s);
        return;
    }
    if (count >= MAX_PER_DAY) {
        set_status(L"That's the limit of 5 reports for today. Use Copy or Save instead.");
        return;
    }

    if (!collect(&r)) { report_free(&r); return; }
    json = as_json(&r);
    report_free(&r);
    if (!json) return;

    GetTempPathW(MAX_PATH, tmp);
    j = (SENDJOB*)LocalAlloc(LPTR, sizeof *j);
    if (!j) { free(json); return; }
    GetTempFileNameW(tmp, L"cav", 0, j->body);
    h = CreateFileW(j->body, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (h == INVALID_HANDLE_VALUE) { free(json); LocalFree(j); set_status(L"Couldn't prepare the report."); return; }
    WriteFile(h, json, (DWORD)strlen(json), &wr, NULL);
    CloseHandle(h);
    free(json);

    InterlockedExchange(&g_rp_sending, 1);
    EnableWindow(GetDlgItem(g_rp, IDC_RP_SEND), FALSE);
    set_status(L"Sending... this can take a minute on older PCs.");
    t = CreateThread(NULL, 0, send_thread, j, 0, NULL);
    if (!t) {
        DeleteFileW(j->body); LocalFree(j);
        InterlockedExchange(&g_rp_sending, 0);
        EnableWindow(GetDlgItem(g_rp, IDC_RP_SEND), TRUE);
        set_status(L"Couldn't start sending. Use Copy or Save instead.");
        return;
    }
    CloseHandle(t);
}

static void update_counter(void);

static void on_result(LPARAM result)
{
    if (result == 1) {
        DWORD now = now_unix(), day = reg_get(L"ReportDay", 0), count = reg_get(L"ReportCount", 0);
        if (day != now / 86400) { day = now / 86400; count = 0; }
        reg_set(L"ReportLast", now);
        reg_set(L"ReportDay", day);
        reg_set(L"ReportCount", count + 1);
        SetDlgItemTextW(g_rp, IDC_RP_EDIT, L"");
        update_counter();
        set_status(L"Sent! Thanks for helping make CarrotAV better.");
        log_line(L"REPORT  sent");
    } else {
        EnableWindow(GetDlgItem(g_rp, IDC_RP_SEND), GetWindowTextLengthW(GetDlgItem(g_rp, IDC_RP_EDIT)) > 0);
        if (result == 2)
            set_status(L"The report service is busy right now. Try again later, or use Copy / Save.");
        else if (result == 4)
            set_status(L"Sending took too long. Your text is still here - try again, or use Copy / Save.");
        else if (result == 3)
            set_status(L"Couldn't connect - is this PC online? You can use Copy or Save instead.");
        else
            set_status(L"Sending didn't work this time. Your text is still here - use Copy or Save instead.");
    }
}

static void update_counter(void)
{
    wchar_t s[32];
    int n = GetWindowTextLengthW(GetDlgItem(g_rp, IDC_RP_EDIT));
    wsprintfW(s, L"%d / %d", n, MAX_CHARS);
    SetDlgItemTextW(g_rp, IDC_RP_COUNT, s);
    if (!g_rp_sending) EnableWindow(GetDlgItem(g_rp, IDC_RP_SEND), n > 0);
}

/* ------------------------------------------------------------- window */

static HWND mk(const wchar_t *cls, const wchar_t *text, DWORD style, DWORD ex,
               int x, int y, int w, int h, int id)
{
    HWND c = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style,
                             x, y, w, h, g_rp, (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    SendMessageW(c, WM_SETFONT, (WPARAM)g_rp_font, TRUE);
    return c;
}

static LRESULT CALLBACK rp_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE: {
        HWND e;
        g_rp = h;
        mk(L"STATIC", L"What went wrong? (what you did, what happened)", SS_NOPREFIX, 0,
           12, 12, RP_W - 24, 16, IDC_RP_LABEL);
        e = mk(L"EDIT", L"", ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL | WS_TABSTOP,
               WS_EX_CLIENTEDGE, 12, 32, RP_W - 24, 110, IDC_RP_EDIT);
        SendMessageW(e, EM_LIMITTEXT, MAX_CHARS, 0);
        mk(L"STATIC", L"0 / 200", SS_RIGHT, 0, RP_W - 112, 146, 100, 16, IDC_RP_COUNT);
        mk(L"BUTTON", L"Attach the CarrotAV log (recommended)", BS_AUTOCHECKBOX | WS_TABSTOP, 0,
           12, 146, 260, 18, IDC_RP_LOG);
        CheckDlgButton(h, IDC_RP_LOG, BST_CHECKED);
        mk(L"STATIC", L"Your CarrotAV and Windows versions are included automatically.",
           SS_NOPREFIX, 0, 12, 172, RP_W - 24, 32, IDC_RP_STATUS);
        mk(L"BUTTON", L"Send", BS_DEFPUSHBUTTON | WS_TABSTOP, 0, 12, 214, 90, 26, IDC_RP_SEND);
        mk(L"BUTTON", L"Copy", WS_TABSTOP, 0, 108, 214, 90, 26, IDC_RP_COPY);
        mk(L"BUTTON", L"Save as .txt...", WS_TABSTOP, 0, 204, 214, 104, 26, IDC_RP_SAVE);
        mk(L"BUTTON", L"Close", WS_TABSTOP, 0, RP_W - 102, 214, 90, 26, IDC_RP_CLOSE);
        EnableWindow(GetDlgItem(h, IDC_RP_SEND), FALSE);
        SetFocus(e);
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_RP_EDIT:
            if (HIWORD(w) == EN_CHANGE) update_counter();
            return 0;
        case IDC_RP_SEND:  do_send();  return 0;
        case IDC_RP_COPY:  do_copy();  return 0;
        case IDC_RP_SAVE:  do_save();  return 0;
        case IDC_RP_CLOSE: DestroyWindow(h); return 0;
        }
        break;
    case WM_RP_RESULT:
        on_result(l);
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        g_rp = NULL;
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

void report_open(HWND owner)
{
    static BOOL registered;
    RECT r = { 0, 0, RP_W, 254 }, wa;
    HWND wnd;

    if (g_rp) { SetForegroundWindow(g_rp); return; }
    g_rp_owner = owner;
    if (!registered) {
        WNDCLASSW wc;
        NONCLIENTMETRICSW ncm;
        memset(&wc, 0, sizeof wc);
        wc.lpfnWndProc   = rp_proc;
        wc.hInstance     = GetModuleHandleW(NULL);
        wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.hIcon         = LoadIconW(wc.hInstance, MAKEINTRESOURCEW(IDI_APP));
        wc.lpszClassName = RP_CLASS;
        RegisterClassW(&wc);
        memset(&ncm, 0, sizeof ncm);
        ncm.cbSize = offsetof(NONCLIENTMETRICSW, lfMessageFont) + sizeof(LOGFONTW);
        if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, ncm.cbSize, &ncm, 0))
            g_rp_font = CreateFontIndirectW(&ncm.lfMessageFont);
        else
            g_rp_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        registered = TRUE;
    }
    AdjustWindowRectEx(&r, WS_POPUP | WS_CAPTION | WS_SYSMENU, FALSE, 0);
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    wnd = CreateWindowExW(0, RP_CLASS, L"Report a Problem - CarrotAV",
                          WS_POPUP | WS_CAPTION | WS_SYSMENU,
                          wa.left + ((wa.right - wa.left) - (r.right - r.left)) / 2,
                          wa.top + ((wa.bottom - wa.top) - (r.bottom - r.top)) / 2,
                          r.right - r.left, r.bottom - r.top, owner, NULL,
                          GetModuleHandleW(NULL), NULL);
    if (wnd) { ShowWindow(wnd, SW_SHOW); UpdateWindow(wnd); }
}

/* Lets Tab move between the report window's controls. */
BOOL report_dialog_message(MSG *msg)
{
    return g_rp && IsDialogMessageW(g_rp, msg);
}

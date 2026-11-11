/* devguard.c - Device Guard: scan USB drives, memory cards, CDs and DVDs the
 * moment they are inserted.
 *
 * Windows broadcasts WM_DEVICECHANGE / DBT_DEVICEARRIVAL to every top-level
 * window when a volume appears, so the (possibly hidden) main window just
 * forwards it here. Works the same on XP and 2000, no service needed.
 *
 * The window is deliberately small and in the middle of the screen:
 *
 *     +------------------------------------------+
 *     |  [carrot]  Scanning KINGSTON (E:)         |   <- blue band
 *     |  E:\games\setup.exe                       |
 *     |  [=================                ]      |
 *     |  412 of 1,380 files              [ Stop ] |
 *     +------------------------------------------+
 *
 * The band turns green when the drive is clean (and the window closes by
 * itself), red when something was found - then it lists the threats and asks:
 * Quarantine all / Ignore. Like manual scans, Device Guard never removes
 * anything on its own.
 *
 * Floppies are the exception to "automatic": floppy drives never tell Windows
 * a disk went in, and polling one makes it grind. So floppies (and any other
 * drive) can be scanned from File -> Scan a Disc or Drive..., which opens this
 * same window via dev_scan_now().
 */
#include "av.h"
#include <dbt.h>
#include <winioctl.h>
#include <stddef.h>
#include "resource.h"

#define UG_CLASS     L"CarrotAVDeviceGuard"
#define UG_W         460
#define UG_H_SMALL   172
#define UG_H_BIG     330
#define BAND_H       46
#define MAX_HITS     200

#define IDC_UG_STATUS  2101
#define IDC_UG_PROG    2102
#define IDC_UG_COUNT   2103
#define IDC_UG_BTN1    2104   /* Stop / Close / Quarantine all */
#define IDC_UG_BTN2    2105   /* Ignore */
#define IDC_UG_LIST    2106
#define IDC_UG_BTN3    2107   /* Open drive */
#define IDC_UG_NOTE    2108   /* "this drive wants to run ..." */

#define TMR_UPDATE   1
#define TMR_CLOSE    2

enum { ST_IDLE, ST_SCANNING, ST_CLEAN, ST_THREATS, ST_STOPPED, ST_REMOVED, ST_DONE_ACTED };

static HWND     g_owner, g_win;
static SIGDB   *g_db;
static BOOL     g_enabled = TRUE;
static HINSTANCE g_inst;
static HFONT    g_ftitle, g_fbody;

static SCANJOB  g_job;
static HANDLE   g_thread;
static int      g_state = ST_IDLE;
static wchar_t  g_letter;               /* drive being scanned */
static BOOL     g_readonly;             /* CD/DVD: nothing can be removed */
static wchar_t  g_arun[MAX_PATH*2];     /* autorun program on a clean drive */
static wchar_t  g_arun_args[MAX_PATH];
static wchar_t  g_title[160];           /* "KINGSTON (E:)" */
static wchar_t  g_lastfile[MAX_PATH*2];
static DETECTION *g_hits;            /* MAX_HITS entries, allocated once */
static int      g_nhits;
static wchar_t  g_queue[27];            /* drives waiting their turn */

/* ------------------------------------------------------------ settings */

static void save_enabled(void)
{
    HKEY k;
    DWORD v = g_enabled ? 1 : 0;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\CarrotAV", 0, NULL, 0,
                        KEY_WRITE, NULL, &k, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(k, L"DeviceGuard", 0, REG_DWORD, (const BYTE*)&v, sizeof v);
        RegCloseKey(k);
    }
}

static void load_enabled(void)
{
    HKEY k;
    DWORD v = 1, sz = sizeof v, type;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\CarrotAV", 0, KEY_READ, &k)
            == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, L"DeviceGuard", NULL, &type, (BYTE*)&v, &sz) != ERROR_SUCCESS)
            v = 1;
        RegCloseKey(k);
    }
    g_enabled = v != 0;
}

BOOL dev_enabled(void) { return g_enabled; }
void dev_set_enabled(BOOL on) { g_enabled = on; save_enabled(); }
BOOL dev_busy(void) { return g_job.running != 0; }

/* ------------------------------------------------------- which drives */

/* Is this a fixed disk hanging off USB (external hard drives report "fixed")?
 * Opening with no access rights is enough for this query and needs no admin.
 * If the IOCTL isn't supported (some Windows 2000 setups) we say no. */
static BOOL fixed_is_usb(wchar_t letter)
{
    wchar_t dev[8] = { L'\\', L'\\', L'.', L'\\', letter, L':', 0 };
    HANDLE h;
    BOOL usb = FALSE;
    h = CreateFileW(dev, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY q;
        BYTE out[512];
        DWORD got = 0;
        memset(&q, 0, sizeof q);
        q.PropertyId = StorageDeviceProperty;
        q.QueryType  = PropertyStandardQuery;
        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q,
                            out, sizeof out, &got, NULL) &&
            got >= offsetof(STORAGE_DEVICE_DESCRIPTOR, BusType) + sizeof(DWORD)) {
            STORAGE_DEVICE_DESCRIPTOR *d = (STORAGE_DEVICE_DESCRIPTOR*)out;
            usb = (d->BusType == BusTypeUsb);
        }
        CloseHandle(h);
    }
    return usb;
}

/* Device Guard covers: floppies and other removable drives (flash drives,
 * card readers, Zip disks), CD/DVD drives, and USB hard drives. Internal
 * hard disks and network drives are left to the normal scans. Only
 * GetDriveType is used here - it never touches the media, so a floppy drive
 * doesn't spin up just to build a menu. */
static BOOL drive_eligible(wchar_t letter)
{
    wchar_t root[4] = { letter, L':', L'\\', 0 };
    UINT t = GetDriveTypeW(root);
    if (t == DRIVE_REMOVABLE || t == DRIVE_CDROM) return TRUE;
    if (t == DRIVE_FIXED) return fixed_is_usb(letter);
    return FALSE;
}

/* "Floppy (A:)", "CD/DVD Drive (D:)" ... without touching the media. */
static void drive_kind(wchar_t letter, wchar_t *out)
{
    wchar_t root[4] = { letter, L':', L'\\', 0 };
    UINT t = GetDriveTypeW(root);
    const wchar_t *k =
        t == DRIVE_CDROM ? L"CD/DVD Drive" :
        t == DRIVE_REMOVABLE ? ((letter == L'A' || letter == L'B') ? L"Floppy Disk" : L"Removable Disk") :
        L"USB Drive";
    wsprintfW(out, L"%s (%c:)", k, letter);
}

/* Title with the real volume label when there is one: "KINGSTON (E:)". */
void dev_drive_title(wchar_t letter, wchar_t *out, int cap)
{
    wchar_t root[4] = { letter, L':', L'\\', 0 }, label[64] = L"";
    if (GetVolumeInformationW(root, label, 64, NULL, NULL, NULL, NULL, 0) && label[0])
        wsprintfW(out, L"%s (%c:)", label, letter);
    else
        drive_kind(letter, out);
    (void)cap;
}

/* Present Device Guard drives, for the File menu picker. Returns the count;
 * letters[] gets the drive letters. */
int dev_list_drives(wchar_t *letters, int cap)
{
    DWORD mask = GetLogicalDrives();
    int i, n = 0;
    for (i = 0; i < 26 && n < cap; i++)
        if ((mask & (1u << i)) && drive_eligible((wchar_t)(L'A' + i)))
            letters[n++] = (wchar_t)(L'A' + i);
    return n;
}

/* ------------------------------------------------------------- window */

static void center_window(HWND h, int w, int ht)
{
    RECT wa;
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    SetWindowPos(h, HWND_TOPMOST,
                 wa.left + ((wa.right - wa.left) - w) / 2,
                 wa.top  + ((wa.bottom - wa.top) - ht) / 2,
                 w, ht, SWP_SHOWWINDOW);
}

static void layout(int client_h)
{
    int bw = 104, bh = 25, y = client_h - bh - 12;
    MoveWindow(GetDlgItem(g_win, IDC_UG_STATUS), 14, BAND_H + 12, UG_W - 28, 16, TRUE);
    MoveWindow(GetDlgItem(g_win, IDC_UG_PROG),   14, BAND_H + 34, UG_W - 28, 18, TRUE);
    MoveWindow(GetDlgItem(g_win, IDC_UG_LIST),   14, BAND_H + 60, UG_W - 28,
               client_h - (BAND_H + 60) - bh - 22, TRUE);
    MoveWindow(GetDlgItem(g_win, IDC_UG_NOTE),   14, BAND_H + 34, UG_W - 28, 32, TRUE);
    MoveWindow(GetDlgItem(g_win, IDC_UG_COUNT),  14, y + 5, UG_W - 2*bw - 50, 16, TRUE);
    MoveWindow(GetDlgItem(g_win, IDC_UG_BTN3),   UG_W - 3*bw - 30, y, bw, bh, TRUE);
    MoveWindow(GetDlgItem(g_win, IDC_UG_BTN2),   UG_W - 2*bw - 22, y, bw, bh, TRUE);
    MoveWindow(GetDlgItem(g_win, IDC_UG_BTN1),   UG_W - bw - 14, y, bw, bh, TRUE);
}

static void resize_client(int client_h)
{
    RECT r = { 0, 0, UG_W, client_h };
    AdjustWindowRectEx(&r, WS_POPUP | WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_TOPMOST);
    center_window(g_win, r.right - r.left, r.bottom - r.top);
    layout(client_h);
}

static void set_buttons(const wchar_t *b1, const wchar_t *b2)
{
    SetDlgItemTextW(g_win, IDC_UG_BTN1, b1);
    if (b2) { SetDlgItemTextW(g_win, IDC_UG_BTN2, b2); ShowWindow(GetDlgItem(g_win, IDC_UG_BTN2), SW_SHOW); }
    else ShowWindow(GetDlgItem(g_win, IDC_UG_BTN2), SW_HIDE);
}

static void fmt_num(LONG n, wchar_t *out)
{
    wchar_t raw[16], *p;
    int len, i, j = 0;
    wsprintfW(raw, L"%ld", n);
    len = lstrlenW(raw);
    for (i = 0, p = raw; i < len; i++) {
        out[j++] = p[i];
        if ((len - i - 1) % 3 == 0 && i != len - 1) out[j++] = L',';
    }
    out[j] = 0;
}

static void update_progress(void)
{
    wchar_t a[16], b[16], line[80];
    HWND bar = GetDlgItem(g_win, IDC_UG_PROG);
    if (g_job.counting) {
        SetDlgItemTextW(g_win, IDC_UG_STATUS, L"Counting files...");
        fmt_num(g_job.total, a);
        wsprintfW(line, L"%s files found so far", a);
        SetDlgItemTextW(g_win, IDC_UG_COUNT, line);
        return;
    }
    if (g_lastfile[0]) SetDlgItemTextW(g_win, IDC_UG_STATUS, g_lastfile);
    if (g_job.total > 0) {
        LONG pos = (LONG)((double)g_job.files * 1000.0 / (double)g_job.total);
        if (pos > 1000) pos = 1000;
        SendMessageW(bar, PBM_SETPOS, pos, 0);
    }
    fmt_num(g_job.files, a);
    fmt_num(g_job.total, b);
    wsprintfW(line, L"%s of %s files", a, b);
    if (g_job.found) wsprintfW(line + lstrlenW(line), L"  -  %ld found", g_job.found);
    SetDlgItemTextW(g_win, IDC_UG_COUNT, line);
}

static void fill_list(void)
{
    HWND lb = GetDlgItem(g_win, IDC_UG_LIST);
    int i;
    SendMessageW(lb, LB_RESETCONTENT, 0, 0);
    for (i = 0; i < g_nhits; i++) {
        wchar_t row[MAX_PATH*2 + 160], wname[128];
        MultiByteToWideChar(CP_ACP, 0, g_hits[i].name, -1, wname, 128);
        wsprintfW(row, L"%s   -   %s", wname, g_hits[i].path);
        SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)row);
    }
}

static void start_next(void);

/* Read the drive's autorun.inf ourselves (Windows' INI reader is pointed at
 * nothing while AutoRun is blocked) and pull out what it wants to start:
 * shellexecute= or open=, split into program and arguments. Only offered if
 * that program really exists on the drive. */
static BOOL find_autorun(wchar_t letter)
{
    wchar_t inf[32];
    char buf[4096], *p, *line;
    HANDLE h;
    DWORD rd = 0;
    BOOL in_section = FALSE;
    char val[MAX_PATH] = "";

    g_arun[0] = g_arun_args[0] = 0;
    wsprintfW(inf, L"%c:\\autorun.inf", letter);
    h = CreateFileW(inf, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ReadFile(h, buf, sizeof buf - 1, &rd, NULL);
    CloseHandle(h);
    buf[rd] = 0;

    for (line = strtok(buf, "\r\n"); line; line = strtok(NULL, "\r\n")) {
        while (*line == ' ' || *line == '\t') line++;
        if (*line == '[') { in_section = (_strnicmp(line, "[autorun]", 9) == 0); continue; }
        if (!in_section) continue;
        if (!_strnicmp(line, "shellexecute", 12) || !_strnicmp(line, "open", 4)) {
            p = strchr(line, '=');
            if (!p) continue;
            p++;
            while (*p == ' ' || *p == '\t') p++;
            lstrcpynA(val, p, MAX_PATH);
            if (!_strnicmp(line, "shellexecute", 12)) break;   /* preferred */
        }
    }
    if (!val[0]) return FALSE;

    {   /* split "prog args" / "\"prog with spaces\" args" */
        char prog[MAX_PATH], *a;
        int n = 0;
        p = val;
        if (*p == '"') {
            p++;
            while (*p && *p != '"' && n < MAX_PATH - 1) prog[n++] = *p++;
            if (*p == '"') p++;
        } else {
            while (*p && *p != ' ' && *p != '\t' && n < MAX_PATH - 1) prog[n++] = *p++;
        }
        prog[n] = 0;
        a = p;
        while (*a == ' ' || *a == '\t') a++;
        if (!prog[0]) return FALSE;
        {
            wchar_t wp[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, prog, -1, wp, MAX_PATH);
            MultiByteToWideChar(CP_ACP, 0, a, -1, g_arun_args, MAX_PATH);
            if (wp[0] && wp[1] == L':') return FALSE;            /* must live on this drive */
            if (wp[0] == L'\\') wsprintfW(g_arun, L"%c:%s", letter, wp);
            else                 wsprintfW(g_arun, L"%c:\\%s", letter, wp);
            if (GetFileAttributesW(g_arun) == INVALID_FILE_ATTRIBUTES) { g_arun[0] = 0; return FALSE; }
        }
    }
    return TRUE;
}

static void run_autorun(void)
{
    wchar_t root[4] = { g_letter, L':', L'\\', 0 };
    HINSTANCE r = ShellExecuteW(g_win, L"open", g_arun, g_arun_args[0] ? g_arun_args : NULL,
                                root, SW_SHOWNORMAL);
    log_line(L"DEVGUARD  user ran AutoRun on %s: %s %s (%s)", g_title, g_arun, g_arun_args,
             (INT_PTR)r > 32 ? L"started" : L"failed");
    if ((INT_PTR)r <= 32)
        MessageBoxW(g_win, L"Windows couldn't start that program.", L"CarrotAV Device Guard", MB_ICONWARNING);
}

static void open_drive(void)
{
    wchar_t root[4] = { g_letter, L':', L'\\', 0 };
    ShellExecuteW(g_win, L"explore", root, NULL, NULL, SW_SHOWNORMAL);
}

static void finish(void)
{
    wchar_t a[16], line[160];
    KillTimer(g_win, TMR_UPDATE);
    if (g_thread) { CloseHandle(g_thread); g_thread = NULL; }
    g_lastfile[0] = 0;
    update_progress();                 /* final counts, not the last tick's */
    if (g_state != ST_REMOVED && !g_job.cancel)
        SendMessageW(GetDlgItem(g_win, IDC_UG_PROG), PBM_SETPOS, 1000, 0);
    fmt_num(g_job.files, a);

    if (g_state == ST_REMOVED) {
        SetDlgItemTextW(g_win, IDC_UG_STATUS, L"The drive was removed before the scan finished.");
        set_buttons(L"Close", NULL);
    } else if (g_job.cancel) {
        g_state = ST_STOPPED;
        wsprintfW(line, L"Scan stopped after %s files.", a);
        SetDlgItemTextW(g_win, IDC_UG_STATUS, line);
        set_buttons(L"Close", NULL);
    } else if (g_nhits) {
        g_state = ST_THREATS;
        if (g_readonly)
            lstrcpyW(line, L"This disc is read-only, so nothing can be removed. Don't open or run these files.");
        else
            wsprintfW(line, L"%s file%s checked. Nothing has been removed - you choose:", a, g_job.files == 1 ? L"" : L"s");
        SetDlgItemTextW(g_win, IDC_UG_STATUS, line);
        ShowWindow(GetDlgItem(g_win, IDC_UG_PROG), SW_HIDE);
        fill_list();
        ShowWindow(GetDlgItem(g_win, IDC_UG_LIST), SW_SHOW);
        resize_client(UG_H_BIG);
        MoveWindow(GetDlgItem(g_win, IDC_UG_LIST), 14, BAND_H + 36, UG_W - 28,
                   UG_H_BIG - (BAND_H + 36) - 25 - 22, TRUE);
        SetDlgItemTextW(g_win, IDC_UG_COUNT, L"");
        if (g_readonly) set_buttons(L"OK", NULL);
        else            set_buttons(L"Quarantine all", L"Ignore");
        MessageBeep(MB_ICONEXCLAMATION);
        FlashWindow(g_win, TRUE);
        log_line(L"DEVGUARD  %s: %d threat(s) found", g_title, g_nhits);
    } else {
        g_state = ST_CLEAN;
        wsprintfW(line, L"No threats found in %s file%s.", a, g_job.files == 1 ? L"" : L"s");
        SetDlgItemTextW(g_win, IDC_UG_STATUS, line);
        ShowWindow(GetDlgItem(g_win, IDC_UG_BTN3), SW_SHOW);
        if (find_autorun(g_letter)) {
            /* AutoRun is blocked in Windows, so offer it here - after the
             * scan, and only if the user clicks. No auto-close. */
            wchar_t note[MAX_PATH*2 + 80];
            wsprintfW(note, L"This %s wants to run %s.\nNothing runs unless you click Run AutoRun.",
                      g_readonly ? L"disc" : L"drive", PathFindFileNameW(g_arun));
            ShowWindow(GetDlgItem(g_win, IDC_UG_PROG), SW_HIDE);
            SetDlgItemTextW(g_win, IDC_UG_NOTE, note);
            ShowWindow(GetDlgItem(g_win, IDC_UG_NOTE), SW_SHOW);
            SetDlgItemTextW(g_win, IDC_UG_COUNT, L"");
            set_buttons(L"Close", L"Run AutoRun");
        } else {
            SetDlgItemTextW(g_win, IDC_UG_COUNT, L"");
            set_buttons(L"Close", NULL);
            SetTimer(g_win, TMR_CLOSE, 6000, NULL);
        }
        log_line(L"DEVGUARD  %s: clean (%ld files)", g_title, g_job.files);
    }
    InvalidateRect(g_win, NULL, TRUE);
}

static void close_window(void)
{
    if (g_job.running) {             /* let the thread wind down first */
        InterlockedExchange(&g_job.cancel, 1);
        return;
    }
    KillTimer(g_win, TMR_CLOSE);
    DestroyWindow(g_win);
    g_win = NULL;
    g_state = ST_IDLE;
    start_next();
}

static void quarantine_all(void)
{
    int i, ok = 0, fail = 0;
    wchar_t line[160];
    for (i = 0; i < g_nhits; i++) {
        if (quar_add(g_hits[i].path, g_hits[i].name)) ok++; else fail++;
    }
    log_line(L"DEVGUARD  quarantined %d, failed %d", ok, fail);
    g_state = ST_DONE_ACTED;
    if (fail)
        wsprintfW(line, L"Quarantined %d file(s). %d could not be moved (in use or read-only).", ok, fail);
    else
        wsprintfW(line, L"Quarantined %d file(s). You can restore them from the Quarantine tab.", ok);
    SetDlgItemTextW(g_win, IDC_UG_STATUS, line);
    set_buttons(L"Close", NULL);
    EnableWindow(GetDlgItem(g_win, IDC_UG_LIST), FALSE);
    InvalidateRect(g_win, NULL, TRUE);
}

static void paint_band(HDC dc)
{
    RECT r;
    COLORREF bg;
    HBRUSH br;
    HFONT old;
    HICON ico;
    wchar_t text[220];

    switch (g_state) {
    case ST_CLEAN:      bg = RGB(46, 160, 67);  break;
    case ST_THREATS:    bg = RGB(200, 32, 32);  break;
    case ST_DONE_ACTED: bg = RGB(46, 160, 67);  break;
    case ST_STOPPED:
    case ST_REMOVED:    bg = RGB(110, 110, 110); break;
    default:            bg = RGB(36, 94, 220);   break;   /* XP blue - the carrot shows up on it */
    }
    GetClientRect(g_win, &r);
    r.bottom = BAND_H;
    br = CreateSolidBrush(bg);
    FillRect(dc, &r, br);
    DeleteObject(br);

    ico = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, 32, 32, 0);
    if (ico) { DrawIconEx(dc, 10, (BAND_H - 32) / 2, ico, 32, 32, 0, NULL, DI_NORMAL); DestroyIcon(ico); }

    switch (g_state) {
    case ST_CLEAN:      wsprintfW(text, L"%s is clean", g_title); break;
    case ST_THREATS:    wsprintfW(text, L"%d threat%s found on %s", g_nhits,
                                  g_nhits == 1 ? L"" : L"s", g_title); break;
    case ST_DONE_ACTED: wsprintfW(text, L"%s is safe now", g_title); break;
    case ST_STOPPED:    wsprintfW(text, L"Scan stopped - %s", g_title); break;
    case ST_REMOVED:    wsprintfW(text, L"%s was removed", g_title); break;
    default:            wsprintfW(text, L"Scanning %s", g_title); break;
    }
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 255, 255));
    old = (HFONT)SelectObject(dc, g_ftitle);
    r.left = 52; r.right -= 10;
    DrawTextW(dc, text, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    SelectObject(dc, old);
}

static LRESULT CALLBACK ug_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE: {
        HWND c;
        c = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_PATHELLIPSIS | SS_NOPREFIX,
                            0, 0, 0, 0, h, (HMENU)IDC_UG_STATUS, g_inst, NULL);
        SendMessageW(c, WM_SETFONT, (WPARAM)g_fbody, TRUE);
        c = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                            0, 0, 0, 0, h, (HMENU)IDC_UG_PROG, g_inst, NULL);
        SendMessageW(c, PBM_SETRANGE, 0, MAKELPARAM(0, 1000));
        c = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                            WS_CHILD | WS_VSCROLL | WS_HSCROLL | LBS_NOINTEGRALHEIGHT | LBS_NOSEL,
                            0, 0, 0, 0, h, (HMENU)IDC_UG_LIST, g_inst, NULL);
        SendMessageW(c, WM_SETFONT, (WPARAM)g_fbody, TRUE);
        SendMessageW(c, LB_SETHORIZONTALEXTENT, 1600, 0);
        c = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
                            0, 0, 0, 0, h, (HMENU)IDC_UG_COUNT, g_inst, NULL);
        SendMessageW(c, WM_SETFONT, (WPARAM)g_fbody, TRUE);
        c = CreateWindowExW(0, L"BUTTON", L"Stop", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                            0, 0, 0, 0, h, (HMENU)IDC_UG_BTN1, g_inst, NULL);
        SendMessageW(c, WM_SETFONT, (WPARAM)g_fbody, TRUE);
        c = CreateWindowExW(0, L"BUTTON", L"Ignore", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
                            0, 0, 0, 0, h, (HMENU)IDC_UG_BTN2, g_inst, NULL);
        SendMessageW(c, WM_SETFONT, (WPARAM)g_fbody, TRUE);
        c = CreateWindowExW(0, L"BUTTON", L"Open drive", WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
                            0, 0, 0, 0, h, (HMENU)IDC_UG_BTN3, g_inst, NULL);
        SendMessageW(c, WM_SETFONT, (WPARAM)g_fbody, TRUE);
        c = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | SS_NOPREFIX,
                            0, 0, 0, 0, h, (HMENU)IDC_UG_NOTE, g_inst, NULL);
        SendMessageW(c, WM_SETFONT, (WPARAM)g_fbody, TRUE);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        paint_band(dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        /* the threat summary line reads in red */
        if ((HWND)l == GetDlgItem(h, IDC_UG_STATUS) &&
            (g_state == ST_THREATS)) {
            SetTextColor((HDC)w, RGB(180, 0, 0));
            SetBkMode((HDC)w, TRANSPARENT);
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
        }
        break;
    }
    case WM_TIMER:
        if (w == TMR_UPDATE) update_progress();
        else if (w == TMR_CLOSE && g_state == ST_CLEAN) close_window();
        return 0;
    case WM_SCAN_FILE:
        if (l) { lstrcpynW(g_lastfile, (wchar_t*)l, MAX_PATH*2); LocalFree((HLOCAL)l); }
        return 0;
    case WM_SCAN_HIT:
        if (l) {
            if (g_hits && g_nhits < MAX_HITS) g_hits[g_nhits++] = *(DETECTION*)l;
            LocalFree((HLOCAL)l);
        }
        return 0;
    case WM_SCAN_DONE:
        finish();
        if (!g_win) return 0;
        return 0;
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case IDC_UG_BTN1:
            if (g_state == ST_SCANNING) {
                InterlockedExchange(&g_job.cancel, 1);
                SetDlgItemTextW(h, IDC_UG_STATUS, L"Stopping...");
                EnableWindow(GetDlgItem(h, IDC_UG_BTN1), FALSE);
            } else if (g_state == ST_THREATS && !g_readonly) {
                quarantine_all();
            } else {
                close_window();
            }
            return 0;
        case IDC_UG_BTN3:            /* Open drive */
            KillTimer(h, TMR_CLOSE);
            open_drive();
            close_window();
            return 0;
        case IDC_UG_BTN2:            /* Ignore, or Run AutoRun on a clean drive */
            if (g_state == ST_CLEAN && g_arun[0]) {
                run_autorun();
                close_window();
                return 0;
            }
            log_line(L"DEVGUARD  user ignored %d threat(s) on %s", g_nhits, g_title);
            close_window();
            return 0;
        }
        break;
    case WM_CLOSE:
        if (g_state == ST_SCANNING) {
            InterlockedExchange(&g_job.cancel, 1);
            return 0;
        }
        close_window();
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

/* ------------------------------------------------------------ scanning */

static void begin_scan(wchar_t letter)
{
    DWORD tid;
    g_letter = letter;
    dev_drive_title(letter, g_title, 160);
    {
        wchar_t root[4] = { letter, L':', L'\\', 0 };
        g_readonly = GetDriveTypeW(root) == DRIVE_CDROM;
    }
    g_lastfile[0] = 0;
    g_nhits = 0;

    memset(&g_job, 0, sizeof g_job);
    g_job.mode = SCAN_DEVICE;
    wsprintfW(g_job.root, L"%c:", letter);
    g_job.db = g_db;
    g_job.heuristics = TRUE;
    g_job.archives = TRUE;
    g_job.autoquar = FALSE;

    g_win = CreateWindowExW(WS_EX_TOPMOST, UG_CLASS, L"CarrotAV Device Guard",
                            WS_POPUP | WS_CAPTION | WS_SYSMENU,
                            0, 0, UG_W, UG_H_SMALL, NULL, NULL, g_inst, NULL);
    if (!g_win) return;
    {   /* exact client size, then centre */
        RECT r = { 0, 0, UG_W, UG_H_SMALL };
        AdjustWindowRectEx(&r, WS_POPUP | WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_TOPMOST);
        center_window(g_win, r.right - r.left, r.bottom - r.top);
    }
    layout(UG_H_SMALL);
    set_buttons(L"Stop", NULL);
    g_job.notify = g_win;
    g_state = ST_SCANNING;
    InvalidateRect(g_win, NULL, TRUE);
    UpdateWindow(g_win);
    log_line(L"DEVGUARD  %s inserted - scanning", g_title);

    InterlockedExchange(&g_job.running, 1);   /* busy from the very start */
    g_thread = CreateThread(NULL, 0, scan_thread, &g_job, 0, &tid);
    if (!g_thread) {
        InterlockedExchange(&g_job.running, 0);
        InterlockedExchange(&g_job.cancel, 1);   /* report "stopped", never "clean" */
        finish();
        return;
    }
    SetTimer(g_win, TMR_UPDATE, 150, NULL);
}

static void start_next(void)
{
    while (g_queue[0] && !g_win) {
        wchar_t l = g_queue[0];
        memmove(g_queue, g_queue + 1, sizeof(g_queue) - sizeof(wchar_t));
        g_queue[26] = 0;
        if (GetDriveTypeW((wchar_t[]){ l, L':', L'\\', 0 }) == DRIVE_NO_ROOT_DIR) continue;
        begin_scan(l);
    }
}

static void enqueue(wchar_t letter)
{
    int n;
    if (g_win && g_letter == letter) {
        if (g_state == ST_SCANNING) return;       /* already on it */
        /* results for this drive are still up from last time - a fresh
         * insert replaces them with a fresh scan */
        close_window();
        if (g_win && g_letter == letter) return;  /* couldn't close yet */
    }
    n = lstrlenW(g_queue);
    if (wcschr(g_queue, letter)) return;
    if (n < 26) { g_queue[n] = letter; g_queue[n + 1] = 0; }
}

/* ---------------------------------------------------------- public API */

void dev_init(HWND owner, SIGDB *db)
{
    WNDCLASSW wc;
    NONCLIENTMETRICSW ncm;
    LOGFONTW lf;

    g_owner = owner;
    g_db = db;
    g_inst = GetModuleHandleW(NULL);
    load_enabled();
    /* An empty floppy or CD drive must never pop Windows' "There is no disk
     * in the drive" box from a background scan - fail quietly instead. */
    SetErrorMode(SetErrorMode(0) | SEM_FAILCRITICALERRORS);
    g_hits = (DETECTION*)LocalAlloc(LPTR, MAX_HITS * sizeof(DETECTION));

    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc   = ug_proc;
    wc.hInstance     = g_inst;
    wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hIcon         = LoadIconW(g_inst, MAKEINTRESOURCEW(IDI_APP));
    wc.lpszClassName = UG_CLASS;
    RegisterClassW(&wc);

    /* fonts: the system message font, plus a bold, larger one for the band */
    memset(&ncm, 0, sizeof ncm);
    ncm.cbSize = offsetof(NONCLIENTMETRICSW, lfMessageFont) + sizeof(LOGFONTW);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, ncm.cbSize, &ncm, 0)) {
        g_fbody = CreateFontIndirectW(&ncm.lfMessageFont);
        lf = ncm.lfMessageFont;
    } else {
        GetObjectW(GetStockObject(DEFAULT_GUI_FONT), sizeof lf, &lf);
        g_fbody = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    }
    lf.lfWeight = FW_BOLD;
    lf.lfHeight = -15;
    g_ftitle = CreateFontIndirectW(&lf);
}

/* Called from the main window for every WM_DEVICECHANGE. */
void dev_on_devicechange(WPARAM w, LPARAM l)
{
    DEV_BROADCAST_HDR *hdr = (DEV_BROADCAST_HDR*)l;
    DEV_BROADCAST_VOLUME *v;
    int i;

    if (!hdr || hdr->dbch_devicetype != DBT_DEVTYP_VOLUME) return;
    v = (DEV_BROADCAST_VOLUME*)hdr;
    if (v->dbcv_flags & DBTF_NET) return;

    for (i = 0; i < 26; i++) {
        wchar_t letter = (wchar_t)(L'A' + i);
        if (!(v->dbcv_unitmask & (1u << i))) continue;

        if (w == DBT_DEVICEARRIVAL) {
            if (!g_enabled || !g_db || !g_db->loaded) continue;
            if (!drive_eligible(letter)) continue;
            enqueue(letter);
        } else if (w == DBT_DEVICEREMOVECOMPLETE) {
            wchar_t *q = wcschr(g_queue, letter);
            if (q) memmove(q, q + 1, (lstrlenW(q)) * sizeof(wchar_t));
            if (g_win && g_letter == letter && g_state == ST_SCANNING) {
                g_state = ST_REMOVED;
                InterlockedExchange(&g_job.cancel, 1);
                log_line(L"DEVGUARD  %s removed during scan", g_title);
            } else if (g_win && g_letter == letter && g_state != ST_THREATS) {
                /* disc ejected / stick pulled while its results were showing:
                 * those results no longer apply, so put the window away.
                 * (A threat list stays up until the user has read it.) */
                close_window();
            }
        }
    }
    start_next();
}

/* File -> Scan a Disc or Drive...: scan one drive now, guard on or off. */
void dev_scan_now(wchar_t letter)
{
    wchar_t root[4] = { letter, L':', L'\\', 0 }, msg[160];
    if (!GetVolumeInformationW(root, NULL, 0, NULL, NULL, NULL, NULL, 0)) {
        wsprintfW(msg, L"There's no disk in drive %c:.\n\nInsert a disk or disc and try again.", letter);
        MessageBoxW(g_owner, msg, L"CarrotAV Device Guard", MB_ICONINFORMATION);
        return;
    }
    enqueue(letter);
    start_next();
}

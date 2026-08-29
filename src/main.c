/* main.c - CarrotAV user interface. Classic Win32, no frameworks. */
#include "av.h"
#include "resource.h"

#define TAB_SCAN   0
#define TAB_QUAR   1
#define TAB_MON    2
#define TAB_FW     3
#define TAB_WEB    4
#define TAB_SYS    5
#define TAB_UPDATE 6

static HINSTANCE g_inst;
static HWND  g_main, g_tab, g_list, g_prog, g_status;
static HWND  g_btn[5];
static HFONT g_font;
static int   g_colw[4]; static int g_ncol;
static SIGDB g_db;
static SCANJOB g_job;
static HANDLE g_thread;
static int   g_page = TAB_SCAN;
static QITEM *g_quar; static int g_quarn;
static BOOL  g_opt_heur = TRUE, g_opt_autoquar = FALSE;
static FWAPP *g_fwapps; static int g_fwappn;
static RTEVENT *g_events; static int g_eventn; static int g_eventcap;

static void tray_tip(const wchar_t *text);
static BOOL tray_balloon(const wchar_t *title, const wchar_t *text, DWORD flag);
static void tray_threat(const wchar_t *name, const wchar_t *path);

static void set_status(const wchar_t *fmt, ...)
{
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    wvsprintfW(buf, fmt, ap);
    va_end(ap);
    SendMessageW(g_status, SB_SETTEXTW, 0, (LPARAM)buf);
}

static void list_clear(void)
{
    ListView_DeleteAllItems(g_list);
}

/* Scale the stored column weights to whatever width the list actually has,
 * so the last column is never chopped off and no h-scrollbar appears. */
static void fit_columns(void)
{
    RECT rc;
    int i, total = 0, avail, used = 0, w;

    if (!g_ncol) return;
    GetClientRect(g_list, &rc);
    avail = rc.right - rc.left - GetSystemMetrics(SM_CXVSCROLL) - 4;
    if (avail < 200) return;

    for (i = 0; i < g_ncol; i++) total += g_colw[i];
    if (!total) return;

    for (i = 0; i < g_ncol; i++) {
        w = (i == g_ncol - 1) ? (avail - used)
                              : (int)((__int64)g_colw[i] * avail / total);
        if (w < 40) w = 40;
        used += w;
        ListView_SetColumnWidth(g_list, i, w);
    }
}

static void list_columns(const wchar_t *c0, int w0, const wchar_t *c1, int w1,
                         const wchar_t *c2, int w2, const wchar_t *c3, int w3)
{
    LVCOLUMNW col;
    int i;
    while (ListView_DeleteColumn(g_list, 0)) { }
    memset(&col, 0, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    g_ncol = 0;
    for (i = 0; i < 4; i++) {
        const wchar_t *t = i==0?c0 : i==1?c1 : i==2?c2 : c3;
        int w = i==0?w0 : i==1?w1 : i==2?w2 : w3;
        if (!t) break;
        col.iSubItem = i;
        col.pszText = (LPWSTR)t;
        col.cx = w;
        ListView_InsertColumn(g_list, i, &col);
        g_colw[g_ncol++] = w;
    }
    fit_columns();
}

static int list_add(const wchar_t *a, const wchar_t *b, const wchar_t *c, const wchar_t *d)
{
    LVITEMW it;
    int idx;
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = ListView_GetItemCount(g_list);
    it.pszText = (LPWSTR)a;
    idx = ListView_InsertItem(g_list, &it);
    if (b) ListView_SetItemText(g_list, idx, 1, (LPWSTR)b);
    if (c) ListView_SetItemText(g_list, idx, 2, (LPWSTR)c);
    if (d) ListView_SetItemText(g_list, idx, 3, (LPWSTR)d);
    return idx;
}

static void set_buttons(const wchar_t *b0, const wchar_t *b1, const wchar_t *b2,
                        const wchar_t *b3, const wchar_t *b4)
{
    const wchar_t *t[5];
    int i;
    t[0]=b0; t[1]=b1; t[2]=b2; t[3]=b3; t[4]=b4;
    for (i = 0; i < 5; i++) {
        if (t[i]) {
            SetWindowTextW(g_btn[i], t[i]);
            ShowWindow(g_btn[i], SW_SHOW);
        } else {
            ShowWindow(g_btn[i], SW_HIDE);
        }
    }
}

/* ------------------------------- pages ------------------------------- */

static void page_quar(void)
{
    int i;
    wchar_t name[160], sz[32];
    SYSTEMTIME st;
    wchar_t when[64];

    if (g_quar) { LocalFree(g_quar); g_quar = NULL; }
    g_quarn = quar_list(&g_quar);

    list_columns(L"Threat", 190, L"Original location", 340, L"Size", 80, L"Quarantined", 130);
    list_clear();

    for (i = 0; i < g_quarn; i++) {
        FILETIME lf;
        MultiByteToWideChar(CP_ACP, 0, g_quar[i].threat, -1, name, 160);
        wsprintfW(sz, L"%lu KB", (g_quar[i].size + 1023) / 1024);
        FileTimeToLocalFileTime(&g_quar[i].when, &lf);
        FileTimeToSystemTime(&lf, &st);
        wsprintfW(when, L"%04d-%02d-%02d %02d:%02d",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        list_add(name, g_quar[i].orig, sz, when);
    }
    set_buttons(L"&Restore", L"&Delete", L"Re&fresh", NULL, NULL);
    set_status(L"Quarantine: %d item(s)", g_quarn);
}

static void page_mon(void)
{
    RTSTATS st;
    wchar_t v[160], up[64];
    int i;

    rt_stats(&st);

    list_columns(L"Time", 80, L"Event", 230, L"Detail", 460, NULL, 0);
    list_clear();

    if (st.active) {
        wsprintfW(up, L"%lu:%02lu:%02lu", st.uptime/3600, (st.uptime/60)%60, st.uptime%60);
        wsprintfW(v, L"%d folder watchers, process guard, registry guard", st.watchers);
        list_add(L"--:--:--", L"Shield ACTIVE", v, NULL);
        wsprintfW(v, L"%ld files checked, %ld threats blocked, %ld new processes, %ld autostart changes",
                  st.checked, st.blocked, st.procs, st.autoruns);
        list_add(L"--:--:--", L"Statistics", v, NULL);
        list_add(L"--:--:--", L"Uptime", up, NULL);
    } else {
        list_add(L"--:--:--", L"Shield STOPPED", L"Nothing is being monitored right now", NULL);
    }

    /* newest events first */
    for (i = g_eventn - 1; i >= 0; i--) {
        wchar_t t[32];
        const wchar_t *tag;
        wsprintfW(t, L"%02d:%02d:%02d", g_events[i].when.wHour,
                  g_events[i].when.wMinute, g_events[i].when.wSecond);
        tag = g_events[i].sev == RT_THREAT ? L"[!] " :
              g_events[i].sev == RT_WARN   ? L"[*] " : L"";
        wsprintfW(v, L"%s%s", tag, g_events[i].what);
        list_add(t, v, g_events[i].detail, NULL);
    }

    set_buttons(st.active ? L"S&top shield" : L"S&tart shield",
                st.kill ? L"Kill procs: &ON" : L"Kill procs: O&FF",
                L"&Refresh", L"&Clear events", NULL);
    set_status(L"Live monitoring: %s | %ld checked, %ld blocked",
               st.active ? L"ACTIVE" : L"stopped", st.checked, st.blocked);
}

static void page_fw(void)
{
    FWSTATE st;
    FWPORT *ports = NULL;
    int nports, i;
    wchar_t v[256];

    if (g_fwapps) { LocalFree(g_fwapps); g_fwapps = NULL; }

    fw_get_state(&st);

    list_columns(L"Rule", 250, L"Status", 110, L"Program / detail", 410, NULL, 0);
    list_clear();

    list_add(L"Windows Firewall",
             st.enabled == 1 ? L"ON" : st.enabled == 0 ? L"OFF" : L"Unknown",
             st.com ? L"Controlled through the firewall COM API"
                    : L"COM unavailable - using registry/netsh fallback", NULL);
    list_add(L"Block all exceptions", st.block_all ? L"ON" : L"off",
             L"Ignores every allow rule below - use on untrusted networks", NULL);
    list_add(L"Notifications", st.notify_off ? L"off" : L"ON",
             L"Prompt when a program first tries to listen", NULL);

    g_fwappn = fw_list_apps(&g_fwapps);
    for (i = 0; i < g_fwappn; i++) {
        wsprintfW(v, L"%s%s", g_fwapps[i].path,
                  g_fwapps[i].scope == 1 ? L"  (local subnet only)" : L"");
        list_add(g_fwapps[i].name,
                 g_fwapps[i].enabled ? L"ALLOWED" : L"BLOCKED", v, NULL);
    }

    nports = fw_list_ports(&ports);
    for (i = 0; i < nports; i++) {
        wchar_t label[160];
        wsprintfW(label, L"Port %d/%s", ports[i].port, ports[i].tcp ? L"TCP" : L"UDP");
        list_add(label, ports[i].enabled ? L"OPEN" : L"closed", ports[i].name, NULL);
    }
    if (ports) LocalFree(ports);

    set_buttons(st.enabled == 1 ? L"Turn &off" : L"Turn &on",
                st.block_all ? L"Allow e&xceptions" : L"Block &all",
                L"&Block program...", L"&Remove rule", L"&Harden ports");
    set_status(L"Firewall: %s | %d program rule(s), %d open port(s)",
               st.enabled == 1 ? L"ON" : L"OFF", g_fwappn, nports);
}

static void page_web(void)
{
    int blocked = 0;
    wchar_t v[160];

    hosts_block_count(&blocked);

    list_columns(L"Item", 240, L"Status", 140, L"Detail", 440, NULL, 0);
    list_clear();

    wsprintfW(v, L"%d domain(s) currently blocked via HOSTS", blocked);
    list_add(L"Web shield", blocked > 0 ? L"Active" : L"Inactive", v, NULL);
    list_add(L"Method", L"HOSTS", L"Blocked names resolve to 0.0.0.0 before any request leaves", NULL);
    list_add(L"Safety", L"Marker block", L"Only entries between the CarrotAV markers are ever touched", NULL);
    list_add(L"Heuristics", g_opt_heur ? L"Enabled" : L"Disabled",
             L"Packer entropy, double extensions, temp execs, script obfuscation", NULL);
    list_add(L"Auto-quarantine", g_opt_autoquar ? L"Enabled" : L"Disabled",
             L"Move scan detections to the vault automatically", NULL);

    set_buttons(L"&Import blocklist...", L"&Add domain...", L"&Clear blocklist", NULL, NULL);
    set_status(L"Web shield: %d domain(s) blocked", blocked);
}

static void page_sys(void)
{
    wchar_t v[256];

    list_columns(L"Item", 240, L"Status", 150, L"Detail", 430, NULL, 0);
    list_clear();

    if (base_ready()) {
        time_t t = (time_t)base_built();
        struct tm *tmv = localtime(&t);
        wsprintfW(v, L"%u files hashed", base_count());
        list_add(L"System baseline", L"Present", v, NULL);
        if (tmv) {
            wsprintfW(v, L"%04d-%02d-%02d %02d:%02d",
                      tmv->tm_year+1900, tmv->tm_mon+1, tmv->tm_mday,
                      tmv->tm_hour, tmv->tm_min);
            list_add(L"Snapshot taken", v, L"Take a new one after Windows Update or a service pack", NULL);
        }
        list_add(L"Verification policy", L"Path-bound",
                 L"A file counts as verified only if its bytes match the snapshot AT THAT PATH", NULL);
        list_add(L"Signatures on verified files", L"Still checked",
                 L"A hit on a verified file is shown as Disputed and never auto-quarantined", NULL);
    } else {
        list_add(L"System baseline", L"NOT BUILT",
                 L"Build it now, ideally on a clean install - it is what stops false positives", NULL);
    }

    list_add(L"Protected files", L"Enforced",
             L"ntldr, boot.ini, hal.dll, winlogon, lsass and friends are never quarantined", NULL);
    {
        wchar_t **ex; int n = excl_list(&ex), i;
        wsprintfW(v, L"%d user exclusion(s)", n);
        list_add(L"Exclusions", n ? L"Active" : L"None", v, NULL);
        for (i = 0; i < n; i++) { list_add(L"  excluded", L"", ex[i], NULL); free(ex[i]); }
        if (ex) free(ex);
    }
    list_add(L"Archive bomb guard", g_arcguard ? L"Enabled" : L"Disabled",
             L"Reads the zip manifest only - ratio, recursion, entry floods and ../ escapes", NULL);
    list_add(L"Repair sources", L"dllcache + i386",
             L"Infected system files are restored from Windows' own clean copies", NULL);

    set_buttons(L"&Build baseline", L"&Verify system", L"&Repair selected",
                L"&Exclude folder...", L"Run &sfc /scannow");
    set_status(base_ready() ? L"Baseline: %u files" : L"No baseline built yet",
               base_count());
}

static void page_update(void)
{
    wchar_t v[256], dbpath[MAX_PATH];
    WIN32_FILE_ATTRIBUTE_DATA fad;

    list_columns(L"Item", 240, L"Value", 500, NULL, 0, NULL, 0);
    list_clear();

    app_dir(dbpath, MAX_PATH);
    lstrcatW(dbpath, L"\\defs\\carrot.cdb");

    list_add(L"Product", AV_NAME L" " AV_VERSION, NULL, NULL);
    list_add(L"Engine", L"CarrotAV Engine 1.0 (MD5 + pattern + heuristic)", NULL, NULL);
    list_add(L"Definition file", dbpath, NULL, NULL);

    if (g_db.loaded) {
        wsprintfW(v, L"%u hash + %u pattern = %u signatures",
                  g_db.hdr.nhash, g_db.hdr.npat, sigdb_count(&g_db));
        list_add(L"Signatures loaded", v, NULL, NULL);
    } else {
        list_add(L"Signatures loaded", L"NONE - definition file missing or corrupt", NULL, NULL);
    }

    if (GetFileAttributesExW(dbpath, GetFileExInfoStandard, &fad)) {
        SYSTEMTIME st; FILETIME lf;
        FileTimeToLocalFileTime(&fad.ftLastWriteTime, &lf);
        FileTimeToSystemTime(&lf, &st);
        wsprintfW(v, L"%04d-%02d-%02d %02d:%02d  (%lu KB)",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                  fad.nFileSizeLow / 1024);
        list_add(L"Definitions dated", v, NULL, NULL);
    }
    list_add(L"Source", L"ClamAV main/daily, compiled by tools\\build_defs.py", NULL, NULL);

    set_buttons(L"&Update online", L"&Load from file...", L"&Reload", L"View &log", NULL);
    set_status(L"Definitions: %u signatures", sigdb_count(&g_db));
}

static void page_scan(void)
{
    list_columns(L"Threat", 200, L"File", 460, L"Type", 110, L"Action", 110);
    set_buttons(L"&Quick scan", L"&Full scan", L"&Deep scan", L"&Custom...", L"S&top");
    EnableWindow(g_btn[4], FALSE);
    set_status(L"Ready. %u signatures loaded.", sigdb_count(&g_db));
}

static void show_page(int p)
{
    g_page = p;
    switch (p) {
    case TAB_SCAN:   list_clear(); page_scan();  break;
    case TAB_QUAR:   page_quar();   break;
    case TAB_MON:    page_mon();    break;
    case TAB_FW:     page_fw();     break;
    case TAB_WEB:    page_web();    break;
    case TAB_SYS:    page_sys();    break;
    case TAB_UPDATE: page_update(); break;
    }
}


/* Minimal one-field input box, built from an in-memory dialog template. */
static wchar_t *g_prompt_buf; static int g_prompt_cch;
static const wchar_t *g_prompt_label;

static INT_PTR CALLBACK prompt_proc(HWND dlg, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_INITDIALOG:
        SetWindowTextW(dlg, (LPCWSTR)l);
        SetDlgItemTextW(dlg, 200, g_prompt_label);
        SetFocus(GetDlgItem(dlg, 201));
        return FALSE;
    case WM_COMMAND:
        if (LOWORD(w) == IDOK) {
            GetDlgItemTextW(dlg, 201, g_prompt_buf, g_prompt_cch);
            EndDialog(dlg, 1); return TRUE;
        }
        if (LOWORD(w) == IDCANCEL) { EndDialog(dlg, 0); return TRUE; }
        break;
    }
    return FALSE;
}

static BOOL prompt_text(const wchar_t *title, const wchar_t *label,
                        wchar_t *buf, int cch)
{
    /* DLGTEMPLATE built by hand so we need no dialog resource */
    static WORD tmpl[512];
    WORD *p = tmpl;
    INT_PTR r;

    memset(tmpl, 0, sizeof(tmpl));
    *(DWORD*)p = WS_POPUP|WS_BORDER|WS_SYSMENU|WS_CAPTION|DS_MODALFRAME|DS_SETFONT; p += 2;
    *(DWORD*)p = 0; p += 2;
    *p++ = 3;                       /* control count */
    *p++ = 40; *p++ = 40; *p++ = 220; *p++ = 70;
    *p++ = 0; *p++ = 0;             /* no menu, default class */
    *p++ = 0;                       /* title set in WM_INITDIALOG */
    *p++ = 8; wcscpy((wchar_t*)p, L"MS Shell Dlg"); p += 13;

    #define ALIGN4(q) q = (WORD*)(((ULONG_PTR)(q) + 3) & ~(ULONG_PTR)3)
    ALIGN4(p);
    *(DWORD*)p = WS_CHILD|WS_VISIBLE; p += 2; *(DWORD*)p = 0; p += 2;
    *p++ = 8; *p++ = 8; *p++ = 204; *p++ = 16; *p++ = 200; *p++ = 0;
    *p++ = 0xFFFF; *p++ = 0x0082; *p++ = 0; *p++ = 0;

    ALIGN4(p);
    *(DWORD*)p = WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL; p += 2;
    *(DWORD*)p = 0; p += 2;
    *p++ = 8; *p++ = 26; *p++ = 204; *p++ = 14; *p++ = 201; *p++ = 0;
    *p++ = 0xFFFF; *p++ = 0x0081; *p++ = 0; *p++ = 0;

    ALIGN4(p);
    *(DWORD*)p = WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON; p += 2;
    *(DWORD*)p = 0; p += 2;
    *p++ = 116; *p++ = 48; *p++ = 44; *p++ = 14; *p++ = IDOK; *p++ = 0;
    *p++ = 0xFFFF; *p++ = 0x0080;
    wcscpy((wchar_t*)p, L"OK"); p += 3; *p++ = 0;

    g_prompt_buf = buf; g_prompt_cch = cch; g_prompt_label = label;
    buf[0] = 0;
    r = DialogBoxIndirectParamW(g_inst, (LPCDLGTEMPLATEW)tmpl, g_main,
                                prompt_proc, (LPARAM)title);
    return r == 1;
}

/* ------------------------------ scanning ------------------------------ */

static void start_scan_path(int mode, const wchar_t *target)
{
    DWORD tid;
    wchar_t root[MAX_PATH] = L"";

    if (target && *target) lstrcpynW(root, target, MAX_PATH);

    if (g_job.running) {
        MessageBoxW(g_main, L"A scan is already running.", AV_NAME, MB_ICONINFORMATION);
        return;
    }
    if (!g_db.loaded) {
        if (MessageBoxW(g_main,
            L"No definition database is loaded.\n\n"
            L"Only heuristic detection will be available.\n\nContinue anyway?",
            AV_NAME, MB_ICONWARNING | MB_YESNO) != IDYES) return;
    }

    if (mode == SCAN_CUSTOM && !root[0]) {
        BROWSEINFOW bi;
        LPITEMIDLIST pidl;
        memset(&bi, 0, sizeof(bi));
        bi.hwndOwner = g_main;
        bi.lpszTitle = L"Select a folder to scan:";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        pidl = SHBrowseForFolderW(&bi);
        if (!pidl) return;
        SHGetPathFromIDListW(pidl, root);
        CoTaskMemFree(pidl);
        if (!root[0]) return;
    }

    if (g_page != TAB_SCAN) {
        TabCtrl_SetCurSel(g_tab, TAB_SCAN);
        show_page(TAB_SCAN);
    }
    list_clear();

    memset(&g_job, 0, sizeof(g_job));
    g_job.notify     = g_main;
    g_job.mode       = mode;
    g_job.db         = &g_db;
    g_job.heuristics = g_opt_heur;
    g_job.autoquar   = g_opt_autoquar;
    lstrcpynW(g_job.root, root, MAX_PATH);

    SendMessageW(g_prog, PBM_SETMARQUEE, TRUE, 40);

    g_thread = CreateThread(NULL, 0, scan_thread, &g_job, 0, &tid);
    if (!g_thread) {
        MessageBoxW(g_main, L"Could not start the scan thread.", AV_NAME, MB_ICONERROR);
        return;
    }
    EnableWindow(g_btn[4], TRUE);
    set_status(L"Scanning...");
}

static void start_scan(int mode)
{
    start_scan_path(mode, NULL);
}

/* Turn a command line into a scan target. Explorer passes the right-clicked
 * path as a single quoted argument; the Background verb passes the folder. */
static BOOL scan_from_cmdline(const wchar_t *cmdline)
{
    wchar_t path[MAX_PATH];
    const wchar_t *p = cmdline;
    wchar_t *q;

    while (*p == L' ' || *p == L'\t') p++;
    if (!*p) return FALSE;
    if (*p == L'/' || *p == L'-') return FALSE;   /* a switch, not a path */

    if (*p == L'"') {
        lstrcpynW(path, p + 1, MAX_PATH);
        q = wcschr(path, L'"');
        if (q) *q = 0;
    } else {
        lstrcpynW(path, p, MAX_PATH);
        /* trim trailing whitespace */
        q = path + lstrlenW(path);
        while (q > path && (q[-1] == L' ' || q[-1] == L'\t')) *--q = 0;
    }
    if (!path[0]) return FALSE;
    PathRemoveBackslashW(path);
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return FALSE;

    start_scan_path(SCAN_CUSTOM, path);
    return TRUE;
}

static void stop_scan(void)
{
    if (!g_job.running) return;
    InterlockedExchange(&g_job.cancel, 1);
    set_status(L"Stopping...");
}

/* ------------------------------ commands ------------------------------ */

static void do_reload_defs(void);

static void do_load_defs(void)
{
    OPENFILENAMEW ofn;
    wchar_t file[MAX_PATH] = L"";

    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_main;
    ofn.lpstrFilter = L"CarrotAV definitions (*.cdb)\0*.cdb\0All files\0*.*\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = L"Load definition database";
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (!GetOpenFileNameW(&ofn)) return;

    sigdb_free(&g_db);
    if (sigdb_load(&g_db, file)) {
        wchar_t dest[MAX_PATH];
        app_dir(dest, MAX_PATH);
        lstrcatW(dest, L"\\defs");
        CreateDirectoryW(dest, NULL);
        lstrcatW(dest, L"\\carrot.cdb");
        if (lstrcmpiW(dest, file) != 0) CopyFileW(file, dest, FALSE);
        MessageBoxW(g_main, L"Definitions loaded.", AV_NAME, MB_ICONINFORMATION);
    } else {
        MessageBoxW(g_main, L"That file is not a valid CarrotAV database.",
                    AV_NAME, MB_ICONERROR);
    }
    show_page(TAB_UPDATE);
}

static void do_update_online(void)
{
    wchar_t exedir[MAX_PATH], updater[MAX_PATH], defsdir[MAX_PATH], ca[MAX_PATH];
    SHELLEXECUTEINFOW ei;

    app_dir(exedir, MAX_PATH);
    wsprintfW(updater, L"%s\\tools\\defupdate.exe", exedir);
    wsprintfW(ca,      L"%s\\tools\\cacerts.pem", exedir);
    wsprintfW(defsdir, L"%s\\defs", exedir);

    if (GetFileAttributesW(updater) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_main,
            L"defupdate.exe was not found in the tools folder.\n\n"
            L"It downloads and compiles fresh definitions directly on this "
            L"machine over a secure connection. Reinstall CarrotAV to restore it.",
            AV_NAME, MB_ICONWARNING);
        return;
    }
    if (GetFileAttributesW(ca) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_main,
            L"cacerts.pem is missing from the tools folder.\n\n"
            L"The updater needs it to verify the download server. Reinstall "
            L"CarrotAV to restore it.", AV_NAME, MB_ICONWARNING);
        return;
    }

    if (MessageBoxW(g_main,
        L"Download the latest virus definitions now?\n\n"
        L"CarrotAV will connect to the ClamAV database servers, download the "
        L"signature databases, and compile them here - no other computer "
        L"needed. This can take several minutes and a console window will "
        L"show the progress.\n\n"
        L"When it finishes, the definitions reload automatically.",
        L"Update definitions", MB_ICONINFORMATION | MB_YESNO) != IDYES) return;

    /* run the updater and wait, so we can auto-reload when it's done */
    memset(&ei, 0, sizeof(ei));
    ei.cbSize = sizeof(ei);
    ei.fMask  = SEE_MASK_NOCLOSEPROCESS;
    ei.lpVerb = L"open";
    ei.lpFile = updater;
    ei.lpParameters = defsdir;
    ei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&ei) || !ei.hProcess) {
        MessageBoxW(g_main, L"Could not start the updater.", AV_NAME, MB_ICONERROR);
        return;
    }

    /* pump messages while it runs so the UI stays alive */
    for (;;) {
        DWORD w = MsgWaitForMultipleObjects(1, &ei.hProcess, FALSE, INFINITE, QS_ALLINPUT);
        if (w == WAIT_OBJECT_0) break;
        {
            MSG msg;
            while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    CloseHandle(ei.hProcess);

    do_reload_defs();
    if (g_db.loaded) {
        wchar_t m[160];
        wsprintfW(m, L"Definitions reloaded: %u signatures now active.",
                  sigdb_count(&g_db));
        MessageBoxW(g_main, m, AV_NAME, MB_ICONINFORMATION);
    }
    if (g_page == TAB_UPDATE) page_update();
}

static void do_reload_defs(void)
{
    wchar_t p[MAX_PATH];
    app_dir(p, MAX_PATH);
    lstrcatW(p, L"\\defs\\carrot.cdb");
    sigdb_free(&g_db);
    sigdb_load(&g_db, p);
    if (g_page == TAB_UPDATE) page_update();
    set_status(L"%u signatures loaded.", sigdb_count(&g_db));
}

static void do_block_app(void)
{
    OPENFILENAMEW ofn;
    wchar_t file[MAX_PATH] = L"";

    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_main;
    ofn.lpstrFilter = L"Programs (*.exe)\0*.exe\0All files\0*.*\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = L"Block a program from the network";
    ofn.Flags       = OFN_FILEMUSTEXIST;

    if (!GetOpenFileNameW(&ofn)) return;

    if (fw_block_app(file))
        MessageBoxW(g_main, L"Program blocked in Windows Firewall.", AV_NAME, MB_ICONINFORMATION);
    else
        MessageBoxW(g_main, L"Could not add the firewall rule.\n"
                            L"Run CarrotAV as an administrator.", AV_NAME, MB_ICONERROR);
    page_fw();
}

static void do_import_blocklist(void)
{
    OPENFILENAMEW ofn;
    wchar_t file[MAX_PATH] = L"";
    int added = 0;

    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_main;
    ofn.lpstrFilter = L"Blocklists (*.txt;*.hosts)\0*.txt;*.hosts\0All files\0*.*\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = L"Import a domain blocklist (hosts format or one domain per line)";
    ofn.Flags       = OFN_FILEMUSTEXIST;

    if (!GetOpenFileNameW(&ofn)) return;

    if (hosts_import(file, &added)) {
        wchar_t m[256];
        wsprintfW(m, L"%d domains are now blocked.\n\n"
                     L"Existing entries in HOSTS were left untouched.", added);
        MessageBoxW(g_main, m, AV_NAME, MB_ICONINFORMATION);
    } else {
        MessageBoxW(g_main, L"Could not write to the HOSTS file.\n"
                            L"Run CarrotAV as an administrator.", AV_NAME, MB_ICONERROR);
    }
    page_web();
}

static void do_quar_action(BOOL restore)
{
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= g_quarn) {
        MessageBoxW(g_main, L"Select an item first.", AV_NAME, MB_ICONINFORMATION);
        return;
    }
    if (restore) {
        if (MessageBoxW(g_main, L"Restore this file to its original location?\n\n"
                                L"The file will be decoded and written back as-is.",
                        AV_NAME, MB_ICONWARNING | MB_YESNO) != IDYES) return;
        quar_restore(&g_quar[sel]);
    } else {
        if (MessageBoxW(g_main, L"Permanently delete this quarantined file?",
                        AV_NAME, MB_ICONWARNING | MB_YESNO) != IDYES) return;
        quar_delete(&g_quar[sel]);
    }
    page_quar();
}

static void do_view_log(void)
{
    wchar_t p[MAX_PATH];
    app_dir(p, MAX_PATH);
    lstrcatW(p, L"\\carrotav.log");
    ShellExecuteW(g_main, L"open", L"notepad.exe", p, NULL, SW_SHOWNORMAL);
}

static void do_add_domain(void)
{
    /* tiny modal input via a temp file is overkill; use a simple prompt box */
    wchar_t buf[256] = L"";
    if (!prompt_text(L"Block a domain", L"Domain to block (e.g. ads.example.com):",
                     buf, 256)) return;
    if (!buf[0]) return;
    {
        char a[256];
        WideCharToMultiByte(CP_ACP, 0, buf, -1, a, 256, NULL, NULL);
        if (hosts_add(a))
            MessageBoxW(g_main, L"Domain blocked.", AV_NAME, MB_ICONINFORMATION);
        else
            MessageBoxW(g_main, L"Could not write to HOSTS. Run as administrator.",
                        AV_NAME, MB_ICONERROR);
    }
    page_web();
}

static void do_fw_remove(void)
{
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    int idx = sel - 3;                 /* first three rows are state, not rules */
    if (idx < 0 || idx >= g_fwappn) {
        MessageBoxW(g_main, L"Select a program rule first.", AV_NAME, MB_ICONINFORMATION);
        return;
    }
    if (MessageBoxW(g_main, L"Remove this firewall rule?", AV_NAME,
                    MB_ICONWARNING | MB_YESNO) != IDYES) return;
    fw_app_remove(g_fwapps[idx].path);
    page_fw();
}

static void do_sys_repair(void)
{
    wchar_t path[MAX_PATH*2];
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    int r;

    if (sel < 0) {
        MessageBoxW(g_main, L"Run Verify system first, then select a modified "
                            L"file from the results.", AV_NAME, MB_ICONINFORMATION);
        return;
    }
    /* the verify results list keeps the path in column 1 */
    ListView_GetItemText(g_list, sel, 1, path, MAX_PATH*2);
    if (!path[0] || GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_main, L"Select a row whose second column is a file path.",
                    AV_NAME, MB_ICONINFORMATION);
        return;
    }
    if (MessageBoxW(g_main, L"Restore this file from Windows' own clean copy?\n\n"
                            L"CarrotAV will try the dllcache first, then the\n"
                            L"original install source, and verify the result\n"
                            L"against the baseline hash.",
                    AV_NAME, MB_ICONQUESTION | MB_YESNO) != IDYES) return;

    r = base_repair(path);
    MessageBoxW(g_main,
        r == REPAIR_DLLCACHE ? L"Repaired from the Windows File Protection cache." :
        r == REPAIR_SOURCE   ? L"Repaired from the original install source." :
        L"No clean copy was found.\n\nInsert the XP CD and try sfc /scannow, "
        L"or quarantine the file if you are sure it is malicious.",
        AV_NAME, r ? MB_ICONINFORMATION : MB_ICONWARNING);
}

static void do_exclude_folder(void)
{
    BROWSEINFOW bi;
    LPITEMIDLIST pidl;
    wchar_t path[MAX_PATH] = L"";

    memset(&bi, 0, sizeof(bi));
    bi.hwndOwner = g_main;
    bi.lpszTitle = L"Choose a folder to exclude from all scanning:";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return;
    SHGetPathFromIDListW(pidl, path);
    CoTaskMemFree(pidl);
    if (!path[0]) return;

    excl_add(path);
    MessageBoxW(g_main, L"Folder excluded. Nothing inside it will be scanned, "
                        L"flagged or quarantined.", AV_NAME, MB_ICONINFORMATION);
    page_sys();
}

static void do_button(int idx)
{
    switch (g_page) {
    case TAB_SCAN:
        if (idx == 0) start_scan(SCAN_QUICK);
        if (idx == 1) start_scan(SCAN_FULL);
        if (idx == 2) start_scan(SCAN_DEEP);
        if (idx == 3) start_scan(SCAN_CUSTOM);
        if (idx == 4) stop_scan();
        break;

    case TAB_QUAR:
        if (idx == 0) do_quar_action(TRUE);
        if (idx == 1) do_quar_action(FALSE);
        if (idx == 2) page_quar();
        break;

    case TAB_MON: {
        RTSTATS st;
        rt_stats(&st);
        if (idx == 0) {
            if (st.active) rt_stop(); else rt_start(g_main, &g_db);
            tray_tip(rt_active() ? AV_NAME L" - shield active"
                                 : AV_NAME L" - shield off");
        }
        if (idx == 1) rt_set_kill(!st.kill);
        if (idx == 3) { g_eventn = 0; }
        page_mon();
        break;
    }

    case TAB_FW: {
        FWSTATE st;
        fw_get_state(&st);
        if (idx == 0) {
            if (!fw_set(st.enabled != 1))
                MessageBoxW(g_main, L"Could not change the firewall state.\n"
                                    L"Run CarrotAV as an administrator.",
                            AV_NAME, MB_ICONERROR);
        }
        if (idx == 1) fw_set_block_all(!st.block_all);
        if (idx == 2) do_block_app();
        if (idx == 3) { do_fw_remove(); return; }
        if (idx == 4) {
            int n;
            if (MessageBoxW(g_main,
                    L"Close the legacy Windows ports that are most often attacked?\n\n"
                    L"135, 137-139, 445, 593, 1025 and 5000 (TCP and UDP).\n\n"
                    L"File and printer sharing will stop working on this machine.",
                    AV_NAME, MB_ICONWARNING | MB_YESNO) != IDYES) break;
            n = fw_harden();
            {
                wchar_t m[160];
                wsprintfW(m, L"Removed %d open-port rule(s).", n);
                MessageBoxW(g_main, m, AV_NAME, MB_ICONINFORMATION);
            }
        }
        page_fw();
        break;
    }

    case TAB_WEB:
        if (idx == 0) do_import_blocklist();
        if (idx == 1) do_add_domain();
        if (idx == 2) {
            if (MessageBoxW(g_main, L"Remove every domain CarrotAV added to HOSTS?",
                            AV_NAME, MB_ICONWARNING | MB_YESNO) == IDYES) {
                hosts_clear();
                page_web();
            }
        }
        break;

    case TAB_SYS:
        if (idx == 0) {
            if (MessageBoxW(g_main,
                    L"Snapshot every system binary on this machine?\n\n"
                    L"Do this while you believe Windows is clean. It takes a\n"
                    L"few minutes and is what teaches CarrotAV which files are\n"
                    L"legitimate, so it stops flagging them.",
                    AV_NAME, MB_ICONQUESTION | MB_YESNO) != IDYES) break;
            start_scan(SCAN_BASELINE);
        }
        if (idx == 1) {
            if (!base_ready()) {
                MessageBoxW(g_main, L"Build the baseline first.", AV_NAME, MB_ICONINFORMATION);
                break;
            }
            start_scan(SCAN_VERIFY);
        }
        if (idx == 2) do_sys_repair();
        if (idx == 3) do_exclude_folder();
        if (idx == 4) base_run_sfc();
        break;

    case TAB_UPDATE:
        if (idx == 0) do_update_online();
        if (idx == 1) do_load_defs();
        if (idx == 2) do_reload_defs();
        if (idx == 3) do_view_log();
        break;
    }
}


/* ------------------------------ tray icon ------------------------------
 * Rules, so this never becomes a nag:
 *   - balloons fire ONLY for threats actually blocked, or a finished scan
 *     that found something. Never for "you are protected", never on start,
 *     never on definition load, never for routine events.
 *   - nothing pops while the window is visible and in front. If you are
 *     already looking at the app, a balloon is noise.
 *   - one balloon per minute, maximum. Threats arriving inside that window
 *     are counted and folded into the next one.
 *   - no sound flag, no forced foreground, no modal anything.
 * ---------------------------------------------------------------------- */
#define WM_TRAYICON  (WM_APP + 6)
#define TRAY_ID      1
#define BALLOON_GAP  60000UL      /* ms between balloons */

static NOTIFYICONDATAW g_nid;
static BOOL  g_tray_on = FALSE;
static BOOL  g_opt_balloons = TRUE;
static BOOL  g_opt_mintotray = TRUE;
static BOOL  g_opt_closetray = TRUE;   /* X button hides instead of exits */
static BOOL  g_really_quit  = FALSE;
static BOOL  g_autostart_on(void);
static void  g_autostart_set(BOOL on);
static DWORD g_last_balloon = 0;
static BOOL  g_closetip_shown = FALSE;
static int   g_pending_threats = 0;
static wchar_t g_pending_name[160];

static void tray_tip(const wchar_t *text)
{
    if (!g_tray_on) return;
    g_nid.uFlags = NIF_TIP;
    lstrcpynW(g_nid.szTip, text, 128);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void tray_add(HWND hwnd)
{
    memset(&g_nid, 0, sizeof(g_nid));
    /* V2 size keeps this working on XP - the full struct is Vista-era */
    g_nid.cbSize = NOTIFYICONDATAW_V2_SIZE;
    g_nid.hWnd   = hwnd;
    g_nid.uID    = TRAY_ID;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon  = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP),
                        IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
                        GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
    lstrcpynW(g_nid.szTip, AV_NAME L" " AV_VERSION, 128);
    g_tray_on = Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void tray_remove(void)
{
    if (!g_tray_on) return;
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    if (g_nid.hIcon) DestroyIcon(g_nid.hIcon);
    g_tray_on = FALSE;
}

/* Returns TRUE if the balloon was actually shown. */
static BOOL tray_balloon(const wchar_t *title, const wchar_t *text, DWORD flag)
{
    DWORD now;

    if (!g_tray_on || !g_opt_balloons) return FALSE;

    /* you are already looking at it */
    if (IsWindowVisible(g_main) && !IsIconic(g_main) &&
        GetForegroundWindow() == g_main) return FALSE;

    now = GetTickCount();
    if (g_last_balloon && (now - g_last_balloon) < BALLOON_GAP) return FALSE;
    g_last_balloon = now;

    g_nid.uFlags = NIF_INFO;
    g_nid.uTimeout = 10000;
    g_nid.dwInfoFlags = flag;          /* no NIIF_NOSOUND needed - we never
                                        * ask for sound in the first place */
    lstrcpynW(g_nid.szInfoTitle, title, 64);
    lstrcpynW(g_nid.szInfo, text, 256);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    return TRUE;
}

/* A threat was blocked. Coalesce bursts instead of firing one per file. */
static void tray_threat(const wchar_t *name, const wchar_t *path)
{
    wchar_t msg[300];

    g_pending_threats++;
    lstrcpynW(g_pending_name, name, 160);

    if (g_pending_threats == 1) {
        wsprintfW(msg, L"%s\n%s", name, PathFindFileNameW(path));
        if (tray_balloon(L"Threat blocked", msg, NIIF_WARNING))
            g_pending_threats = 0;
    } else {
        wsprintfW(msg, L"%d threats blocked.\nMost recent: %s",
                  g_pending_threats, g_pending_name);
        if (tray_balloon(L"Threats blocked", msg, NIIF_WARNING))
            g_pending_threats = 0;
    }
}

static void tray_menu(HWND hwnd)
{
    HMENU m = CreatePopupMenu();
    POINT pt;
    int cmd;

    AppendMenuW(m, MF_STRING, 1, IsWindowVisible(hwnd) ? L"Hide window" : L"Open CarrotAV");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, 2, L"Quick scan");
    AppendMenuW(m, MF_STRING, 3, rt_active() ? L"Stop shield" : L"Start shield");
    AppendMenuW(m, MF_STRING | (g_opt_balloons ? MF_CHECKED : 0), 4, L"Balloon alerts");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, 5, L"Exit");

    GetCursorPos(&pt);
    SetForegroundWindow(hwnd);          /* so the menu dismisses correctly */
    cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON,
                         pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(m);

    switch (cmd) {
    case 1:
        if (IsWindowVisible(hwnd)) ShowWindow(hwnd, SW_HIDE);
        else { ShowWindow(hwnd, SW_SHOW); ShowWindow(hwnd, SW_RESTORE);
               SetForegroundWindow(hwnd); }
        break;
    case 2: ShowWindow(hwnd, SW_SHOW); SetForegroundWindow(hwnd);
            start_scan(SCAN_QUICK); break;
    case 3: if (rt_active()) rt_stop(); else rt_start(hwnd, &g_db);
            tray_tip(rt_active() ? AV_NAME L" - shield active"
                                 : AV_NAME L" - shield off");
            if (g_page == TAB_MON) page_mon();
            break;
    case 4: g_opt_balloons = !g_opt_balloons; break;
    case 5: g_really_quit = TRUE; PostMessageW(hwnd, WM_CLOSE, 0, 0); break;
    }
}

/* --- run the shield at logon: HKCU Run so it needs no admin at boot --- */
static BOOL g_autostart_on(void)
{
    HKEY k;
    BOOL on = FALSE;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_READ, &k) == ERROR_SUCCESS) {
        on = RegQueryValueExW(k, L"CarrotAV", NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
        RegCloseKey(k);
    }
    return on;
}

static void g_autostart_set(BOOL on)
{
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return;
    if (on) {
        wchar_t exe[MAX_PATH], cmd[MAX_PATH+16];
        GetModuleFileNameW(NULL, exe, MAX_PATH);
        wsprintfW(cmd, L"\"%s\" /background", exe);
        RegSetValueExW(k, L"CarrotAV", 0, REG_SZ,
                       (const BYTE*)cmd, (lstrlenW(cmd)+1)*sizeof(wchar_t));
    } else {
        RegDeleteValueW(k, L"CarrotAV");
    }
    RegCloseKey(k);
    log_line(L"AUTOSTART  %s", on ? L"enabled" : L"disabled");
}

/* ------------------------------ layout ------------------------------ */

static void layout(void)
{
    RECT rc, sb;
    int w, h, btnw = 128, btnh = 26, pad = 8, i, y;

    GetClientRect(g_main, &rc);
    SendMessageW(g_status, WM_SIZE, 0, 0);
    GetWindowRect(g_status, &sb);
    h = rc.bottom - (sb.bottom - sb.top);
    w = rc.right;

    MoveWindow(g_tab, 0, 0, w, h, TRUE);

    /* button column on the right of the tab body */
    for (i = 0; i < 5; i++) {
        y = 40 + i * (btnh + 6);
        MoveWindow(g_btn[i], w - btnw - pad - 4, y, btnw, btnh, TRUE);
    }
    MoveWindow(g_list, pad, 34, w - btnw - pad*3 - 8, h - 34 - 28 - pad, TRUE);
    MoveWindow(g_prog, pad, h - 26 - pad + 4, w - btnw - pad*3 - 8, 18, TRUE);
    fit_columns();
}

/* ------------------------------ wndproc ------------------------------ */

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_CREATE: {
        INITCOMMONCONTROLSEX ic;
        TCITEMW ti;
        int parts[3];
        int i;

        ic.dwSize = sizeof(ic);
        ic.dwICC  = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS |
                    ICC_TAB_CLASSES | ICC_BAR_CLASSES;
        InitCommonControlsEx(&ic);

        g_font = CreateFontW(-11, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                             DEFAULT_PITCH | FF_SWISS, L"MS Shell Dlg");

        g_tab = CreateWindowExW(0, WC_TABCONTROLW, NULL,
                    WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
                    0, 0, 0, 0, hwnd, (HMENU)IDC_TAB, g_inst, NULL);
        SendMessageW(g_tab, WM_SETFONT, (WPARAM)g_font, TRUE);

        memset(&ti, 0, sizeof(ti));
        ti.mask = TCIF_TEXT;
        ti.pszText = L"Scan";        TabCtrl_InsertItem(g_tab, 0, &ti);
        ti.pszText = L"Quarantine";  TabCtrl_InsertItem(g_tab, 1, &ti);
        ti.pszText = L"Monitor";     TabCtrl_InsertItem(g_tab, 2, &ti);
        ti.pszText = L"Firewall";    TabCtrl_InsertItem(g_tab, 3, &ti);
        ti.pszText = L"Web Shield";  TabCtrl_InsertItem(g_tab, 4, &ti);
        ti.pszText = L"System";      TabCtrl_InsertItem(g_tab, 5, &ti);
        ti.pszText = L"Definitions"; TabCtrl_InsertItem(g_tab, 6, &ti);

        g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
                    WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL |
                    LVS_SHOWSELALWAYS | WS_TABSTOP,
                    0, 0, 0, 0, hwnd, (HMENU)IDC_LIST, g_inst, NULL);
        ListView_SetExtendedListViewStyle(g_list,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        SendMessageW(g_list, WM_SETFONT, (WPARAM)g_font, TRUE);

        g_prog = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
                    WS_CHILD | WS_VISIBLE | PBS_MARQUEE,
                    0, 0, 0, 0, hwnd, (HMENU)IDC_PROGRESS, g_inst, NULL);

        for (i = 0; i < 5; i++) {
            g_btn[i] = CreateWindowExW(0, L"BUTTON", L"",
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                        0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)(IDC_BTN1 + i), g_inst, NULL);
            SendMessageW(g_btn[i], WM_SETFONT, (WPARAM)g_font, TRUE);
        }

        g_status = CreateWindowExW(0, STATUSCLASSNAMEW, NULL,
                    WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                    0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS, g_inst, NULL);
        parts[0] = 420; parts[1] = 620; parts[2] = -1;
        SendMessageW(g_status, SB_SETPARTS, 3, (LPARAM)parts);
        SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);

        SetTimer(hwnd, 1, 3000, NULL);
        /* Set both icon sizes explicitly. Relying on the class icon alone
         * leaves XP showing the default in the title bar and alt-tab. */
        {
            HICON big = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP),
                            IMAGE_ICON, GetSystemMetrics(SM_CXICON),
                            GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR);
            HICON small = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP),
                            IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
                            GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
            if (big)   SendMessageW(hwnd, WM_SETICON, ICON_BIG,   (LPARAM)big);
            if (small) SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)small);
        }

        tray_add(hwnd);
        show_page(TAB_SCAN);
        return 0;
    }

    case WM_SIZE:
        if (wp == SIZE_MINIMIZED && g_opt_mintotray && g_tray_on) {
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        }
        layout();
        return 0;

    case WM_APP + 99:            /* force-quit from an installer/upgrade */
        g_really_quit = TRUE;
        rt_stop();
        DestroyWindow(hwnd);
        return 0;

    case WM_TRAYICON:
        if (lp == WM_LBUTTONDBLCLK || lp == NIN_BALLOONUSERCLICK) {
            ShowWindow(hwnd, SW_SHOW);
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
            if (lp == NIN_BALLOONUSERCLICK) {
                TabCtrl_SetCurSel(g_tab, TAB_MON);
                show_page(TAB_MON);
            }
        } else if (lp == WM_RBUTTONUP || lp == WM_CONTEXTMENU) {
            tray_menu(hwnd);
        }
        return 0;

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO*)lp;
        mmi->ptMinTrackSize.x = 720;
        mmi->ptMinTrackSize.y = 420;
        return 0;
    }

    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == IDC_TAB && nh->code == TCN_SELCHANGE) {
            show_page(TabCtrl_GetCurSel(g_tab));
            return 0;
        }
        break;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id >= IDC_BTN1 && id <= IDC_BTN5) { do_button(id - IDC_BTN1); return 0; }
        switch (id) {
        case IDM_SCAN_QUICK:  start_scan(SCAN_QUICK);  return 0;
        case IDM_SCAN_FULL:   start_scan(SCAN_FULL);   return 0;
        case IDM_SCAN_DEEP:   start_scan(SCAN_DEEP);   return 0;
        case IDM_SCAN_CUSTOM: start_scan(SCAN_CUSTOM); return 0;
        case IDM_SCAN_MEMORY: start_scan(SCAN_MEMORY); return 0;
        case IDM_SCAN_BOOT:   start_scan(SCAN_BOOT);   return 0;
        case IDM_SCAN_STOP:   stop_scan(); return 0;
        case IDM_EXIT:        g_really_quit = TRUE; PostMessageW(hwnd, WM_CLOSE, 0, 0); return 0;
        case IDM_UPDATE_FILE: do_load_defs(); return 0;
        case IDM_UPDATE_ONLINE: do_update_online(); return 0;
        case IDM_UPDATE_INFO: TabCtrl_SetCurSel(g_tab, TAB_UPDATE); show_page(TAB_UPDATE); return 0;
        case IDM_SHIELD_TOGGLE:
            if (rt_active()) rt_stop(); else rt_start(hwnd, &g_db);
            if (g_page == TAB_MON) page_mon();
            return 0;
        case IDM_FW_ON:       fw_set(TRUE);  if (g_page==TAB_FW) page_fw(); return 0;
        case IDM_FW_HARDEN:   fw_harden(); if (g_page==TAB_FW) page_fw(); return 0;
        case IDM_FW_OFF:      fw_set(FALSE); if (g_page==TAB_FW) page_fw(); return 0;
        case IDM_FW_BLOCKAPP: do_block_app(); return 0;
        case IDM_WEB_IMPORT:  do_import_blocklist(); return 0;
        case IDM_WEB_CLEAR:
            if (MessageBoxW(hwnd, L"Remove every domain CarrotAV added to HOSTS?",
                            AV_NAME, MB_ICONWARNING|MB_YESNO) == IDYES) {
                hosts_clear();
                if (g_page == TAB_MON) page_mon();
            }
            return 0;
        case IDM_QUAR_RESTORE: do_quar_action(TRUE);  return 0;
        case IDM_QUAR_DELETE:  do_quar_action(FALSE); return 0;
        case IDM_QUAR_REFRESH: TabCtrl_SetCurSel(g_tab, TAB_QUAR); show_page(TAB_QUAR); return 0;
        case IDM_VIEW_LOG:     do_view_log(); return 0;
        case IDM_OPT_BALLOON: {
            g_opt_balloons = !g_opt_balloons;
            CheckMenuItem(GetMenu(hwnd), IDM_OPT_BALLOON,
                          g_opt_balloons ? MF_CHECKED : MF_UNCHECKED);
            return 0;
        }
        case IDM_OPT_TRAY: {
            g_opt_mintotray = !g_opt_mintotray;
            CheckMenuItem(GetMenu(hwnd), IDM_OPT_TRAY,
                          g_opt_mintotray ? MF_CHECKED : MF_UNCHECKED);
            return 0;
        }
        case IDM_OPT_CLOSETRAY: {
            g_opt_closetray = !g_opt_closetray;
            CheckMenuItem(GetMenu(hwnd), IDM_OPT_CLOSETRAY,
                          g_opt_closetray ? MF_CHECKED : MF_UNCHECKED);
            return 0;
        }
        case IDM_OPT_AUTORUN: {
            BOOL on = !g_autostart_on();
            g_autostart_set(on);
            CheckMenuItem(GetMenu(hwnd), IDM_OPT_AUTORUN,
                          on ? MF_CHECKED : MF_UNCHECKED);
            return 0;
        }
        case IDM_OPT_ARCGUARD: {
            g_arcguard = !g_arcguard;
            CheckMenuItem(GetMenu(hwnd), IDM_OPT_ARCGUARD,
                          g_arcguard ? MF_CHECKED : MF_UNCHECKED);
            if (g_page == TAB_SYS) page_sys();
            return 0;
        }
        case IDM_OPT_HEUR: {
            HMENU m = GetMenu(hwnd);
            g_opt_heur = !g_opt_heur;
            CheckMenuItem(m, IDM_OPT_HEUR, g_opt_heur ? MF_CHECKED : MF_UNCHECKED);
            if (g_page == TAB_MON) page_mon();
            return 0;
        }
        case IDM_OPT_AUTOQUAR: {
            HMENU m = GetMenu(hwnd);
            g_opt_autoquar = !g_opt_autoquar;
            CheckMenuItem(m, IDM_OPT_AUTOQUAR, g_opt_autoquar ? MF_CHECKED : MF_UNCHECKED);
            if (g_page == TAB_MON) page_mon();
            return 0;
        }
        case IDM_CHECK_UPDATE: {
            /* No network call. XP can't reach GitHub over modern TLS anyway,
             * so this checks something local and useful instead: how old the
             * virus definitions are. Fresh defs matter far more than app
             * version on a machine like this. */
            wchar_t m[600];
            if (!g_db.loaded) {
                MessageBoxW(hwnd,
                    L"No virus definitions are loaded.\n\n"
                    L"Run tools\\get_defs.py on a modern PC to build carrot.cdb, "
                    L"copy it into the defs folder, then use Definitions -> Reload.",
                    L"Definitions", MB_ICONWARNING);
                return 0;
            }
            {
                time_t built = (time_t)g_db.hdr.built;
                time_t now = time(NULL);
                long days = (long)((now - built) / 86400);
                struct tm *bt = localtime(&built);
                wchar_t datestr[64] = L"unknown";
                const wchar_t *verdict;
                UINT icon;

                if (bt)
                    wsprintfW(datestr, L"%04d-%02d-%02d",
                              bt->tm_year+1900, bt->tm_mon+1, bt->tm_mday);

                if (days < 0)   { verdict = L"The clock looks wrong - definition date is in the future."; icon = MB_ICONWARNING; }
                else if (days <= 7)   { verdict = L"These are current. Nothing to do."; icon = MB_ICONINFORMATION; }
                else if (days <= 30)  { verdict = L"Still reasonable, but a refresh wouldn't hurt."; icon = MB_ICONINFORMATION; }
                else if (days <= 90)  { verdict = L"Getting stale. Time to rebuild them."; icon = MB_ICONWARNING; }
                else                  { verdict = L"These are old. Rebuild them soon."; icon = MB_ICONWARNING; }

                wsprintfW(m,
                    L"Virus definitions\n\n"
                    L"    Built:       %s\n"
                    L"    Age:         %ld day(s)\n"
                    L"    Signatures:  %u\n\n%s\n\n"
                    L"To refresh: run tools\\get_defs.py on a PC with internet, "
                    L"copy the new carrot.cdb into this machine's defs folder, "
                    L"then Definitions -> Reload.\n\n"
                    L"App updates: check the GitHub releases page from any PC and "
                    L"run the installer here - it upgrades in place and keeps "
                    L"everything.",
                    datestr, days < 0 ? 0 : days, sigdb_count(&g_db), verdict);
                MessageBoxW(hwnd, m, L"Definition freshness", icon);
            }
            return 0;
        }
        case IDM_ABOUT:
            MessageBoxW(hwnd,
                AV_NAME L" " AV_VERSION L"\n"
                L"Lightweight on-demand scanner for Windows XP.\n\n"
                L"Engine: MD5 hash matching, byte-pattern matching, heuristics.\n"
                L"Definitions are compiled from the ClamAV database.\n\n"
                L"This is a hobby scanner. It is not a replacement for a\n"
                L"maintained commercial product on an internet-facing machine.\n\n"
                L"Help -> Check Definition Age shows how current your defs are.",
                L"About " AV_NAME, MB_ICONINFORMATION);
            return 0;
        }
        break;
    }

    case WM_SCAN_FILE: {
        wchar_t *p = (wchar_t*)lp;
        SendMessageW(g_status, SB_SETTEXTW, 1, (LPARAM)L"");
        {
            wchar_t sh[128];
            wsprintfW(sh, L"%ld files", g_job.files);
            SendMessageW(g_status, SB_SETTEXTW, 1, (LPARAM)sh);
        }
        SendMessageW(g_status, SB_SETTEXTW, 2, (LPARAM)p);
        LocalFree(p);
        return 0;
    }

    case WM_RT_EVENT: {
        RTEVENT *e = (RTEVENT*)lp;
        if (g_eventn >= g_eventcap) {
            int nc = g_eventcap ? g_eventcap * 2 : 128;
            RTEVENT *ne = (RTEVENT*)realloc(g_events, nc * sizeof(RTEVENT));
            if (ne) { g_events = ne; g_eventcap = nc; }
        }
        if (g_eventn < g_eventcap) g_events[g_eventn++] = *e;
        else memmove(g_events, g_events + 1, (g_eventn - 1) * sizeof(RTEVENT));
        LocalFree(e);
        if (g_page == TAB_MON) page_mon();
        return 0;
    }

    case WM_TIMER:
        if (wp == 1 && g_page == TAB_MON && rt_active()) page_mon();
        return 0;

    case WM_SCAN_HIT:
    case WM_RT_HIT: {
        DETECTION *d = (DETECTION*)lp;
        wchar_t name[160];
        MultiByteToWideChar(CP_ACP, 0, d->name, -1, name, 160);
        list_add(name, d->path,
                 d->kind == DET_SIG ? L"Signature" :
                 d->kind == DET_HEUR ? L"Heuristic" :
                 d->kind == DET_MODIFIED ? L"Integrity" :
                 d->kind == DET_DISPUTED ? L"Disputed" : L"PUA",
                 d->kind == DET_DISPUTED ? L"Verified - ignored" :
                 d->kind == DET_MODIFIED ? L"Repairable" :
                 (msg == WM_RT_HIT || g_opt_autoquar) ? L"Quarantined" : L"Detected");
        if (msg == WM_RT_HIT) {
            tray_threat(name, d->path);
            set_status(L"Real-time shield quarantined a threat.");
        }
        LocalFree(d);
        return 0;
    }

    case WM_SCAN_DONE: {
        DWORD secs = (GetTickCount() - g_job.started) / 1000;
        if (g_job.mode == SCAN_BASELINE) {
            base_load();
            SendMessageW(g_prog, PBM_SETMARQUEE, FALSE, 0);
            EnableWindow(g_btn[4], FALSE);
            if (g_thread) { CloseHandle(g_thread); g_thread = NULL; }
            SendMessageW(g_status, SB_SETTEXTW, 2, (LPARAM)L"");
            {
                wchar_t m[256];
                wsprintfW(m, L"Baseline built: %u system files hashed.\n\n"
                             L"These are now known-good and will never be "
                             L"reported as threats.", base_count());
                MessageBoxW(hwnd, m, AV_NAME, MB_ICONINFORMATION);
            }
            show_page(TAB_SYS);
            return 0;
        }
        SendMessageW(g_prog, PBM_SETMARQUEE, FALSE, 0);
        EnableWindow(g_btn[4], FALSE);
        if (g_thread) { CloseHandle(g_thread); g_thread = NULL; }
        SendMessageW(g_status, SB_SETTEXTW, 2, (LPARAM)L"");
        set_status(L"Done: %ld files in %lu s, %ld detection(s), %ld skipped.",
                   g_job.files, secs, g_job.found, g_job.skipped);
        if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) {
            if (g_job.found > 0) {
                wchar_t b[200];
                wsprintfW(b, L"%ld detection(s) in %ld files.", g_job.found, g_job.files);
                tray_balloon(L"Scan finished", b, NIIF_WARNING);
            }
            /* a clean scan the user cannot see is not worth interrupting for */
        } else if (g_job.found == 0 && !g_job.cancel) {
            MessageBoxW(hwnd, L"Scan complete. No threats were found.",
                        AV_NAME, MB_ICONINFORMATION);
        }
        return 0;
    }

    case WM_CLOSE:
        /* The X button must NOT stop protection. If the shield is running and
         * close-to-tray is on, we hide and keep guarding in the background.
         * This is the whole point - closing the window nearly cost a real XP
         * install because the shield went down with it. */
        if (!g_really_quit && g_opt_closetray && g_tray_on && rt_active()) {
            ShowWindow(hwnd, SW_HIDE);
            /* remind the user once that it is still on, quietly */
            if (!g_closetip_shown) {
                tray_balloon(L"CarrotAV is still running",
                    L"Protection stays on in the background. "
                    L"Right-click here and choose Exit to close it fully.",
                    NIIF_INFO);
                g_closetip_shown = TRUE;
            }
            return 0;
        }
        if (g_job.running) {
            if (MessageBoxW(hwnd, L"A scan is running. Stop it and exit?",
                            AV_NAME, MB_ICONQUESTION | MB_YESNO) != IDYES) return 0;
            InterlockedExchange(&g_job.cancel, 1);
            WaitForSingleObject(g_thread, 5000);
        }
        rt_stop();
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        tray_remove();
        KillTimer(hwnd, 1);
        if (g_events) free(g_events);
        if (g_fwapps) LocalFree(g_fwapps);
        base_free();
        sigdb_free(&g_db);
        if (g_quar) LocalFree(g_quar);
        if (g_font) DeleteObject(g_font);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, LPWSTR cmdline, int show)
{
    WNDCLASSEXW wc;
    MSG msg;
    HACCEL accel = NULL;
    wchar_t dbpath[MAX_PATH];

    (void)prev;
    g_inst = inst;
    CoInitialize(NULL);

    /* Silent helper used by the installer: apply a blocklist and exit.
     *   carrotav.exe /importhosts "C:\\path\\to\\blocklist.txt"      */
    /* installer calls this to unlock carrotav.exe before upgrading */
    if (cmdline && StrStrIW(cmdline, L"/exitnow")) {
        HWND prev = FindWindowW(L"CarrotAVMain", NULL);
        if (prev) SendMessageW(prev, WM_APP + 99, 0, 0);  /* force-quit signal */
        return 0;
    }

    if (cmdline && StrStrIW(cmdline, L"/importhosts")) {
        wchar_t file[MAX_PATH] = L"";
        const wchar_t *a = StrStrIW(cmdline, L"/importhosts") + 12;
        int added = 0;
        while (*a == L' ' || *a == L'"') a++;
        lstrcpynW(file, a, MAX_PATH);
        { wchar_t *q = wcschr(file, L'"'); if (q) *q = 0; }
        if (file[0]) hosts_import(file, &added);
        log_line(L"WEBSHIELD  installer import: %d domains", added);
        return added > 0 ? 0 : 1;
    }

    /* Silent helper used by the uninstaller: strip our HOSTS block and exit. */
    if (cmdline && StrStrIW(cmdline, L"/clearhosts")) {
        return hosts_clear() ? 0 : 1;
    }

    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = inst;
    wc.hIcon         = LoadIconW(inst, MAKEINTRESOURCEW(IDI_APP));
    wc.hIconSm       = wc.hIcon;
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"CarrotAVMain";
    wc.lpszMenuName  = MAKEINTRESOURCEW(IDR_MENU);
    RegisterClassExW(&wc);

    /* load definitions before the window comes up so the status line is honest */
    app_dir(dbpath, MAX_PATH);
    lstrcatW(dbpath, L"\\defs\\carrot.cdb");
    sigdb_load(&g_db, dbpath);
    base_load();

    g_main = CreateWindowExW(0, L"CarrotAVMain", AV_NAME L" " AV_VERSION,
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT, CW_USEDEFAULT, 860, 540,
                NULL, NULL, inst, NULL);
    if (!g_main) return 1;

    CheckMenuItem(GetMenu(g_main), IDM_OPT_HEUR, MF_CHECKED);
    CheckMenuItem(GetMenu(g_main), IDM_OPT_ARCGUARD, MF_CHECKED);
    CheckMenuItem(GetMenu(g_main), IDM_OPT_BALLOON, MF_CHECKED);
    CheckMenuItem(GetMenu(g_main), IDM_OPT_TRAY, MF_CHECKED);
    CheckMenuItem(GetMenu(g_main), IDM_OPT_CLOSETRAY, MF_CHECKED);
    if (g_autostart_on())
        CheckMenuItem(GetMenu(g_main), IDM_OPT_AUTORUN, MF_CHECKED);

    /* command line: /quick /full /deep /silent */
    if (cmdline && *cmdline) {
        if (StrStrIW(cmdline, L"/quick")) start_scan(SCAN_QUICK);
        else if (StrStrIW(cmdline, L"/full")) start_scan(SCAN_FULL);
        else if (StrStrIW(cmdline, L"/deep")) start_scan(SCAN_DEEP);
        else if (!StrStrIW(cmdline, L"/background")) scan_from_cmdline(cmdline);
    }

    /* Launched at logon: bring the shield up and stay in the tray, no window. */
    if (cmdline && StrStrIW(cmdline, L"/background")) {
        rt_start(g_main, &g_db);
        tray_tip(AV_NAME L" - shield active");
        ShowWindow(g_main, SW_HIDE);
    } else {
        ShowWindow(g_main, show);
        UpdateWindow(g_main);
    }

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (accel && TranslateAcceleratorW(g_main, accel, &msg)) continue;
        if (IsDialogMessageW(g_main, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    CoUninitialize();
    return (int)msg.wParam;
}

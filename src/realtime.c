/* realtime.c - live monitoring.
 *
 * Three independent guards, all user-mode (XP without a filter driver):
 *
 *   file guard      ReadDirectoryChangesW over several hot trees; anything
 *                   created or modified gets hashed and heuristically checked.
 *   process guard   polls the process list; every image that appears is
 *                   scanned before it has been running long, and can be
 *                   terminated on a signature hit.
 *   registry guard  RegNotifyChangeKeyValue on the Run keys; reports anything
 *                   that adds itself to autostart and scans the target.
 */
#include "av.h"

#define MAX_WATCH   6
#define MAX_PIDS    2048

typedef struct {
    HANDLE   thread;
    HANDLE   dirh;
    wchar_t  dir[MAX_PATH];
    volatile LONG active;
} WATCHER;

typedef struct {
    HWND     notify;
    SIGDB   *db;
    volatile LONG run;
    HANDLE   stopev;

    WATCHER  watch[MAX_WATCH];
    int      nwatch;

    HANDLE   proc_thread;
    HANDLE   reg_thread;

    /* counters shown on the Monitor tab */
    volatile LONG checked;
    volatile LONG blocked;
    volatile LONG procs;
    volatile LONG autoruns;
    DWORD    started;

    BOOL     kill_procs;    /* terminate a process on a signature hit */
} RTCTX;

static RTCTX g_rt;

/* ---------- event reporting ---------- */

static void rt_event(int sev, const wchar_t *what, const wchar_t *detail)
{
    RTEVENT *e;
    if (!g_rt.notify) return;
    e = (RTEVENT*)LocalAlloc(LPTR, sizeof(RTEVENT));
    if (!e) return;
    e->sev = sev;
    GetLocalTime(&e->when);
    lstrcpynW(e->what, what, 128);
    lstrcpynW(e->detail, detail, MAX_PATH);
    if (!PostMessageW(g_rt.notify, WM_RT_EVENT, 0, (LPARAM)e)) LocalFree(e);
}

static void rt_threat(const wchar_t *path, const char *name, const wchar_t *how)
{
    DETECTION *d;
    wchar_t wname[160], what[160];

    MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 160);
    wsprintfW(what, L"%s: %s", how, wname);
    InterlockedIncrement(&g_rt.blocked);

    quar_add(path, name);
    rt_event(RT_THREAT, what, path);

    if (!g_rt.notify) return;
    d = (DETECTION*)LocalAlloc(LPTR, sizeof(DETECTION));
    if (!d) return;
    lstrcpynW(d->path, path, MAX_PATH*2);
    lstrcpynA(d->name, name, 128);
    d->kind = DET_SIG;
    if (!PostMessageW(g_rt.notify, WM_RT_HIT, 0, (LPARAM)d)) LocalFree(d);
}

/* Scan one file the way the guards want it: hash first, heuristics second.
 * Returns the threat name or NULL. Caller supplies the name buffer. */
static const char *rt_check(const wchar_t *path, char *hbuf, int hsz)
{
    unsigned char md5[16], head[4096];
    unsigned int sz = 0;
    const char *hit = NULL;
    HANDLE fh;
    DWORD rd = 0;
    DWORD attr;

    attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
        return NULL;
    if (path_excluded(path)) return NULL;

    InterlockedIncrement(&g_rt.checked);

    if (g_arcguard && arc_is_archive(path)) {
        ARCINFO ai;
        if (arc_inspect(path, &ai) != ARC_OK) {
            lstrcpynA(hbuf, ai.name, hsz);
            return hbuf;
        }
    }

    if (hash_file_md5(path, md5, &sz)) {
        /* verified = unchanged at this path; skip it rather than fight a
         * bad signature over a file we know has not been touched */
        if (base_check_path(path, md5) == BASE_CLEAN) return NULL;
        if (wfp_trusted(path, md5)) return NULL;
        hit = sigdb_match_hash(g_rt.db, md5, sz);
    }
    if (hit) return hit;

    fh = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                     NULL, OPEN_EXISTING, 0, NULL);
    if (fh != INVALID_HANDLE_VALUE) {
        ReadFile(fh, head, sizeof(head) - 1, &rd, NULL);
        head[rd] = 0;
        CloseHandle(fh);
        if (rd && heur_check(path, head, rd, sz, hbuf, hsz) >= 0)
            return hbuf;
    }
    return NULL;
}

/* ---------- guard 1: file system ---------- */

static DWORD WINAPI watch_thread(LPVOID param)
{
    WATCHER *w = (WATCHER*)param;
    OVERLAPPED ov;
    BYTE *buf;
    HANDLE waits[2];
    DWORD ret, bytes;

    buf = (BYTE*)malloc(32768);
    if (!buf) return 0;

    w->dirh = CreateFileW(w->dir, FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (w->dirh == INVALID_HANDLE_VALUE) { free(buf); return 0; }

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    waits[0] = ov.hEvent;
    waits[1] = g_rt.stopev;

    InterlockedExchange(&w->active, 1);
    rt_event(RT_INFO, L"Watching folder", w->dir);

    while (g_rt.run) {
        ResetEvent(ov.hEvent);
        bytes = 0;
        if (!ReadDirectoryChangesW(w->dirh, buf, 32768, TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_ATTRIBUTES,
                NULL, &ov, NULL))
            break;

        ret = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (ret != WAIT_OBJECT_0 || !g_rt.run) break;
        if (!GetOverlappedResult(w->dirh, &ov, &bytes, FALSE) || !bytes) continue;

        {
            FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION*)buf;
            for (;;) {
                wchar_t rel[MAX_PATH], full[MAX_PATH*2];
                DWORD n = fni->FileNameLength / sizeof(wchar_t);
                if (n >= MAX_PATH) n = MAX_PATH - 1;
                memcpy(rel, fni->FileName, n * sizeof(wchar_t));
                rel[n] = 0;

                if (fni->Action == FILE_ACTION_ADDED ||
                    fni->Action == FILE_ACTION_MODIFIED ||
                    fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                    char hbuf[128];
                    const char *hit;

                    wsprintfW(full, L"%s\\%s", w->dir, rel);
                    Sleep(120);                 /* let the writer close it */
                    hit = rt_check(full, hbuf, sizeof(hbuf));
                    if (hit) rt_threat(full, hit, L"File blocked");
                }
                if (!fni->NextEntryOffset) break;
                fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
            }
        }
    }

    InterlockedExchange(&w->active, 0);
    CloseHandle(ov.hEvent);
    CloseHandle(w->dirh);
    w->dirh = NULL;
    free(buf);
    return 0;
}

/* ---------- guard 2: processes ---------- */

static DWORD WINAPI proc_thread(LPVOID param)
{
    DWORD known[MAX_PIDS];
    int nknown = 0;
    BOOL first = TRUE;
    (void)param;

    while (g_rt.run) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        DWORD current[MAX_PIDS];
        int ncur = 0;

        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    int i, seen = 0;
                    if (ncur < MAX_PIDS) current[ncur++] = pe.th32ProcessID;
                    for (i = 0; i < nknown; i++)
                        if (known[i] == pe.th32ProcessID) { seen = 1; break; }
                    if (seen || first) continue;

                    /* a process we have not seen before */
                    InterlockedIncrement(&g_rt.procs);
                    {
                        HANDLE ms = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
                                                             pe.th32ProcessID);
                        MODULEENTRY32W me;
                        me.dwSize = sizeof(me);
                        if (ms != INVALID_HANDLE_VALUE) {
                            if (Module32FirstW(ms, &me)) {
                                char hbuf[128];
                                const char *hit = rt_check(me.szExePath, hbuf, sizeof(hbuf));
                                if (hit) {
                                    if (g_rt.kill_procs) {
                                        HANDLE ph = OpenProcess(PROCESS_TERMINATE, FALSE,
                                                                pe.th32ProcessID);
                                        if (ph) {
                                            TerminateProcess(ph, 1);
                                            CloseHandle(ph);
                                            rt_event(RT_THREAT, L"Process terminated",
                                                     me.szExePath);
                                        }
                                    }
                                    rt_threat(me.szExePath, hit, L"Process blocked");
                                }
                            }
                            CloseHandle(ms);
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }

        memcpy(known, current, ncur * sizeof(DWORD));
        nknown = ncur;
        first = FALSE;

        if (WaitForSingleObject(g_rt.stopev, 2000) == WAIT_OBJECT_0) break;
    }
    return 0;
}

/* ---------- guard 3: autostart registry keys ---------- */

typedef struct { wchar_t name[256]; wchar_t data[MAX_PATH]; } RUNVAL;

static int read_run_key(HKEY root, const wchar_t *sub, RUNVAL *out, int max)
{
    HKEY k;
    DWORD i = 0, type, cbName, cbData;
    int n = 0;

    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return 0;
    for (;;) {
        if (n >= max) break;
        cbName = 256; cbData = sizeof(out[n].data);
        if (RegEnumValueW(k, i++, out[n].name, &cbName, NULL, &type,
                          (LPBYTE)out[n].data, &cbData) != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        n++;
    }
    RegCloseKey(k);
    return n;
}

static void scan_autorun_target(const wchar_t *cmdline)
{
    wchar_t expanded[MAX_PATH*2], *p, *q;
    char hbuf[128];
    const char *hit;

    ExpandEnvironmentStringsW(cmdline, expanded, MAX_PATH*2);
    p = expanded;
    if (*p == L'"') {
        p++;
        q = wcschr(p, L'"');
        if (q) *q = 0;
    } else {
        q = StrStrIW(p, L".exe");
        if (q) *(q + 4) = 0;
    }
    if (GetFileAttributesW(p) == INVALID_FILE_ATTRIBUTES) return;

    hit = rt_check(p, hbuf, sizeof(hbuf));
    if (hit) rt_threat(p, hit, L"Autostart blocked");
}

static DWORD WINAPI reg_thread(LPVOID param)
{
    static const struct { HKEY root; const wchar_t *sub; const wchar_t *label; } KEYS[] = {
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM\\...\\Run" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU\\...\\Run" },
    };
    RUNVAL prev[2][64];
    int nprev[2];
    HKEY hk[2] = {0,0};
    HANDLE ev[3];
    int i;
    (void)param;

    for (i = 0; i < 2; i++) {
        nprev[i] = read_run_key(KEYS[i].root, KEYS[i].sub, prev[i], 64);
        if (RegOpenKeyExW(KEYS[i].root, KEYS[i].sub, 0, KEY_NOTIFY | KEY_READ, &hk[i])
            != ERROR_SUCCESS) hk[i] = 0;
        ev[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
    }
    ev[2] = g_rt.stopev;

    while (g_rt.run) {
        DWORD w;
        for (i = 0; i < 2; i++) {
            if (!hk[i]) continue;
            ResetEvent(ev[i]);
            RegNotifyChangeKeyValue(hk[i], FALSE, REG_NOTIFY_CHANGE_LAST_SET,
                                    ev[i], TRUE);
        }
        w = WaitForMultipleObjects(3, ev, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0 + 2 || !g_rt.run) break;
        i = (int)(w - WAIT_OBJECT_0);
        if (i < 0 || i > 1) continue;

        Sleep(200);
        {
            RUNVAL now[64];
            int nnow = read_run_key(KEYS[i].root, KEYS[i].sub, now, 64);
            int a, b, found;
            for (a = 0; a < nnow; a++) {
                found = 0;
                for (b = 0; b < nprev[i]; b++) {
                    if (!lstrcmpiW(now[a].name, prev[i][b].name) &&
                        !lstrcmpW(now[a].data, prev[i][b].data)) { found = 1; break; }
                }
                if (!found) {
                    wchar_t what[160];
                    InterlockedIncrement(&g_rt.autoruns);
                    wsprintfW(what, L"New autostart entry (%s)", KEYS[i].label);
                    rt_event(RT_WARN, what, now[a].data);
                    scan_autorun_target(now[a].data);
                }
            }
            memcpy(prev[i], now, sizeof(RUNVAL) * nnow);
            nprev[i] = nnow;
        }
    }

    for (i = 0; i < 2; i++) {
        if (hk[i]) RegCloseKey(hk[i]);
        CloseHandle(ev[i]);
    }
    return 0;
}

/* ---------- lifecycle ---------- */

static void add_watch(const wchar_t *dir)
{
    DWORD tid;
    int i;
    if (g_rt.nwatch >= MAX_WATCH) return;
    if (GetFileAttributesW(dir) == INVALID_FILE_ATTRIBUTES) return;
    /* skip a directory already covered by an existing watcher */
    for (i = 0; i < g_rt.nwatch; i++)
        if (!lstrcmpiW(g_rt.watch[i].dir, dir)) return;

    lstrcpynW(g_rt.watch[g_rt.nwatch].dir, dir, MAX_PATH);
    g_rt.watch[g_rt.nwatch].thread =
        CreateThread(NULL, 0, watch_thread, &g_rt.watch[g_rt.nwatch], 0, &tid);
    if (g_rt.watch[g_rt.nwatch].thread) g_rt.nwatch++;
}

BOOL rt_start(HWND notify, SIGDB *db)
{
    wchar_t p[MAX_PATH];
    DWORD tid;

    if (g_rt.run) return TRUE;

    memset(&g_rt, 0, sizeof(g_rt));
    g_rt.notify     = notify;
    g_rt.db         = db;
    g_rt.run        = 1;
    g_rt.kill_procs = TRUE;
    g_rt.started    = GetTickCount();
    g_rt.stopev     = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* hot trees, in priority order */
    if (SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, p) == S_OK) {
        PathRemoveBackslashW(p); add_watch(p);
    }
    if (GetTempPathW(MAX_PATH, p)) { PathRemoveBackslashW(p); add_watch(p); }
    if (GetSystemDirectoryW(p, MAX_PATH))  add_watch(p);
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, p) == S_OK) add_watch(p);
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, p) == S_OK) add_watch(p);

    g_rt.proc_thread = CreateThread(NULL, 0, proc_thread, NULL, 0, &tid);
    g_rt.reg_thread  = CreateThread(NULL, 0, reg_thread,  NULL, 0, &tid);

    rt_event(RT_INFO, L"Real-time protection started", L"file, process and registry guards active");
    log_line(L"SHIELD  started with %d watchers", g_rt.nwatch);
    return TRUE;
}

void rt_stop(void)
{
    int i;
    if (!g_rt.run) return;

    g_rt.run = 0;
    SetEvent(g_rt.stopev);

    /* nudge each watcher out of ReadDirectoryChangesW */
    for (i = 0; i < g_rt.nwatch; i++)
        if (g_rt.watch[i].dirh) CancelIo(g_rt.watch[i].dirh);

    for (i = 0; i < g_rt.nwatch; i++) {
        if (!g_rt.watch[i].thread) continue;
        WaitForSingleObject(g_rt.watch[i].thread, 3000);
        CloseHandle(g_rt.watch[i].thread);
    }
    if (g_rt.proc_thread) {
        WaitForSingleObject(g_rt.proc_thread, 3000);
        CloseHandle(g_rt.proc_thread);
    }
    if (g_rt.reg_thread) {
        WaitForSingleObject(g_rt.reg_thread, 3000);
        CloseHandle(g_rt.reg_thread);
    }
    CloseHandle(g_rt.stopev);
    log_line(L"SHIELD  stopped");
    memset(&g_rt, 0, sizeof(g_rt));
}

BOOL rt_active(void) { return g_rt.run != 0; }

void rt_stats(RTSTATS *s)
{
    memset(s, 0, sizeof(*s));
    s->active   = g_rt.run != 0;
    s->watchers = g_rt.nwatch;
    s->checked  = g_rt.checked;
    s->blocked  = g_rt.blocked;
    s->procs    = g_rt.procs;
    s->autoruns = g_rt.autoruns;
    s->uptime   = g_rt.run ? (GetTickCount() - g_rt.started) / 1000 : 0;
    s->kill     = g_rt.kill_procs;
}

void rt_set_kill(BOOL on)
{
    g_rt.kill_procs = on;
}

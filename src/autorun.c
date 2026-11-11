/* autorun.c - stop Windows from running autorun.inf at all.
 *
 * AutoRun fires the instant a drive is inserted - before Device Guard (or any
 * scanner) can look at it - and it is the #1 way USB worms spread on XP. So
 * the only reliable defence is to switch it off in Windows itself, using the
 * two settings every security guide of the era recommended:
 *
 *  1. IniFileMapping\Autorun.inf = "@SYS:DoesNotExist"
 *     Windows reads autorun.inf through the INI-file APIs. Mapping that name
 *     to a registry key that doesn't exist makes every autorun.inf look
 *     empty - no auto-start, and no hijacked double-click "open" verb either.
 *     Works even on XP/2000 without the later Microsoft AutoRun patches.
 *
 *  2. Policies\Explorer\NoDriveTypeAutoRun = 0xFF
 *     Turns AutoRun/AutoPlay off for every drive type.
 *
 * Explorer also caches what it read from each drive's autorun.inf under
 * MountPoints2; that cache is cleared so a worm seen before can't come back
 * through it.
 *
 * The user's original values are backed up (HKLM\Software\CarrotAV\AutorunBackup)
 * before the first change, and put back exactly when the option is turned off
 * or CarrotAV is uninstalled (carrotav.exe /autorunrestore). Needs admin, which
 * CarrotAV already runs as.
 */
#include "av.h"

#define INIMAP_KEY  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\IniFileMapping\\Autorun.inf"
#define POLICY_KEY  L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
#define MOUNT_KEY   L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"
#define BACKUP_KEY  L"Software\\CarrotAV\\AutorunBackup"

static BOOL g_block = TRUE;

/* ------------------------------------------------------------ settings */

static void save_pref(void)
{
    HKEY k;
    DWORD v = g_block ? 1 : 0;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\CarrotAV", 0, NULL, 0,
                        KEY_WRITE, NULL, &k, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(k, L"BlockAutorun", 0, REG_DWORD, (const BYTE*)&v, sizeof v);
        RegCloseKey(k);
    }
}

static void load_pref(void)
{
    HKEY k;
    DWORD v = 1, sz = sizeof v, type;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\CarrotAV", 0, KEY_READ, &k)
            == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, L"BlockAutorun", NULL, &type, (BYTE*)&v, &sz) != ERROR_SUCCESS)
            v = 1;                         /* on by default */
        RegCloseKey(k);
    }
    g_block = v != 0;
}

/* ------------------------------------------------------------- backup */

/* Copy one value into the backup key under 'tag', keeping its type. If it
 * didn't exist, record that instead so restore deletes it again. */
static void backup_one(HKEY bk, HKEY root, const wchar_t *key, const wchar_t *name,
                       const wchar_t *tag)
{
    HKEY k;
    BYTE data[1024];
    DWORD type = 0, sz = sizeof data, one = 1;
    wchar_t absent[80];
    wsprintfW(absent, L"%s.absent", tag);
    if (RegOpenKeyExW(root, key, 0, KEY_READ, &k) == ERROR_SUCCESS) {
        LONG r = RegQueryValueExW(k, name, NULL, &type, data, &sz);
        RegCloseKey(k);
        if (r == ERROR_SUCCESS) {
            RegSetValueExW(bk, tag, 0, type, data, sz);
            RegDeleteValueW(bk, absent);
            return;
        }
    }
    RegSetValueExW(bk, absent, 0, REG_DWORD, (const BYTE*)&one, sizeof one);
}

static void restore_one(HKEY bk, HKEY root, const wchar_t *key, const wchar_t *name,
                        const wchar_t *tag)
{
    HKEY k;
    BYTE data[1024];
    DWORD type = 0, sz = sizeof data, a = 0, asz = sizeof a;
    wchar_t absent[80];
    wsprintfW(absent, L"%s.absent", tag);
    if (RegCreateKeyExW(root, key, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS)
        return;
    if (RegQueryValueExW(bk, absent, NULL, NULL, (BYTE*)&a, &asz) == ERROR_SUCCESS && a) {
        RegDeleteValueW(k, name);
    } else if (RegQueryValueExW(bk, tag, NULL, &type, data, &sz) == ERROR_SUCCESS) {
        RegSetValueExW(k, name, 0, type, data, sz);
    }
    RegCloseKey(k);
}

static BOOL set_dword(HKEY root, const wchar_t *key, const wchar_t *name, DWORD v)
{
    HKEY k;
    LONG r;
    if (RegCreateKeyExW(root, key, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS)
        return FALSE;
    r = RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE*)&v, sizeof v);
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

static BOOL set_sz(HKEY root, const wchar_t *key, const wchar_t *name, const wchar_t *v)
{
    HKEY k;
    LONG r;
    if (RegCreateKeyExW(root, key, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS)
        return FALSE;
    r = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)v, (DWORD)((lstrlenW(v) + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

/* ------------------------------------------------------------ public API */

/* Turn the block on (idempotent - safe to call at every start). */
BOOL autorun_block_apply(void)
{
    HKEY bk;
    DWORD done = 0, sz = sizeof done;
    BOOL ok;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, BACKUP_KEY, 0, NULL, 0,
                        KEY_READ | KEY_WRITE, NULL, &bk, NULL) != ERROR_SUCCESS) {
        log_line(L"AUTORUN  could not block AutoRun (needs administrator rights)");
        return FALSE;
    }
    if (RegQueryValueExW(bk, L"Saved", NULL, NULL, (BYTE*)&done, &sz) != ERROR_SUCCESS || !done) {
        DWORD one = 1, existed = 0;
        HKEY t;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, INIMAP_KEY, 0, KEY_READ, &t) == ERROR_SUCCESS) {
            existed = 1; RegCloseKey(t);
        }
        RegSetValueExW(bk, L"IniMapKeyExisted", 0, REG_DWORD, (const BYTE*)&existed, sizeof existed);
        backup_one(bk, HKEY_LOCAL_MACHINE, INIMAP_KEY, NULL,                L"IniMap");
        backup_one(bk, HKEY_LOCAL_MACHINE, POLICY_KEY, L"NoDriveTypeAutoRun", L"PolicyLM");
        backup_one(bk, HKEY_CURRENT_USER,  POLICY_KEY, L"NoDriveTypeAutoRun", L"PolicyCU");
        RegSetValueExW(bk, L"Saved", 0, REG_DWORD, (const BYTE*)&one, sizeof one);
    }
    RegCloseKey(bk);

    ok  = set_sz   (HKEY_LOCAL_MACHINE, INIMAP_KEY, NULL, L"@SYS:DoesNotExist");
    ok &= set_dword(HKEY_LOCAL_MACHINE, POLICY_KEY, L"NoDriveTypeAutoRun", 0xFF);
    ok &= set_dword(HKEY_CURRENT_USER,  POLICY_KEY, L"NoDriveTypeAutoRun", 0xFF);
    SHDeleteKeyW(HKEY_CURRENT_USER, MOUNT_KEY);     /* Explorer's autorun cache */
    log_line(L"AUTORUN  AutoRun blocked for all drives (%s)", ok ? L"ok" : L"partly failed");
    return ok;
}

/* Put the user's original settings back. FALSE if we never changed them. */
BOOL autorun_block_restore(void)
{
    HKEY bk;
    DWORD done = 0, sz = sizeof done;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, BACKUP_KEY, 0, KEY_READ, &bk) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(bk, L"Saved", NULL, NULL, (BYTE*)&done, &sz) != ERROR_SUCCESS || !done) {
        RegCloseKey(bk);
        return FALSE;
    }
    {
        /* the Autorun.inf mapping key normally doesn't exist at all - if so,
         * remove it entirely rather than leave an empty key behind */
        DWORD existed = 1, esz = sizeof existed;
        RegQueryValueExW(bk, L"IniMapKeyExisted", NULL, NULL, (BYTE*)&existed, &esz);
        if (existed) restore_one(bk, HKEY_LOCAL_MACHINE, INIMAP_KEY, NULL, L"IniMap");
        else         RegDeleteKeyW(HKEY_LOCAL_MACHINE, INIMAP_KEY);
    }
    restore_one(bk, HKEY_LOCAL_MACHINE, POLICY_KEY, L"NoDriveTypeAutoRun", L"PolicyLM");
    restore_one(bk, HKEY_CURRENT_USER,  POLICY_KEY, L"NoDriveTypeAutoRun", L"PolicyCU");
    RegCloseKey(bk);
    SHDeleteKeyW(HKEY_LOCAL_MACHINE, BACKUP_KEY);
    log_line(L"AUTORUN  original AutoRun settings restored");
    return TRUE;
}

void autorun_init(void)
{
    load_pref();
    if (g_block) autorun_block_apply();
}

BOOL autorun_blocked(void) { return g_block; }

void autorun_set_blocked(BOOL on)
{
    g_block = on;
    save_pref();
    if (on) autorun_block_apply();
    else    autorun_block_restore();
}

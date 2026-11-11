/* wsc.c - tell Windows XP's Security Center that CarrotAV is installed.
 *
 * XP SP2/SP3 decides whether "Virus Protection" is ON by reading instances of
 * the WMI class AntiVirusProduct in the root\SecurityCenter namespace. Every
 * antivirus of the era registered itself there; once CarrotAV does, the red
 * "Your computer might be at risk" shield stops nagging and Security Center
 * shows "CarrotAV" with its real state:
 *
 *   onAccessScanningEnabled  = the real-time shield is running
 *   productUptoDate          = definitions are less than 7 days old
 *
 * Both are kept honest: turn the shield off, or let the definitions go stale,
 * and Security Center says so under CarrotAV's name. The uninstaller removes
 * the entry (carrotav.exe /wscremove) so XP never thinks a removed antivirus
 * is still protecting it.
 *
 * Windows 2000 has no Security Center, and Vista+ uses a different, signed
 * mechanism, so this only runs on XP. Everything is best-effort: if WMI is
 * unavailable or the user isn't an administrator, CarrotAV works as before.
 */
#define COBJMACROS
#include "av.h"
#include <wbemidl.h>

/* Fixed identity - the instanceGuid is the key Security Center uses. */
#define WSC_GUID   L"{6A1C3E2B-7D4F-4B8A-9C5E-CA77E0A0F2D1}"
#define WSC_PATH   L"AntiVirusProduct.instanceGuid=\"" WSC_GUID L"\""
#define STALE_DAYS 7

static const CLSID k_CLSID_WbemLocator =
    { 0x4590f811, 0x1d3a, 0x11d0, { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
static const IID k_IID_IWbemLocator =
    { 0xdc12a687, 0x737f, 0x11cf, { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };

static int  g_last_on = -1, g_last_fresh = -1;
static volatile LONG g_busy;

typedef struct { BOOL on, fresh, remove; } WSCJOB;

static IWbemServices *connect_sc(void)
{
    IWbemLocator *loc = NULL;
    IWbemServices *svc = NULL;
    BSTR ns;
    if (FAILED(CoCreateInstance(&k_CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                                &k_IID_IWbemLocator, (void**)&loc)) || !loc)
        return NULL;
    ns = SysAllocString(L"root\\SecurityCenter");
    if (FAILED(IWbemLocator_ConnectServer(loc, ns, NULL, NULL, NULL, 0, NULL, NULL, &svc)))
        svc = NULL;
    SysFreeString(ns);
    IWbemLocator_Release(loc);
    if (svc)
        CoSetProxyBlanket((IUnknown*)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    return svc;
}

static void put_str(IWbemClassObject *o, const wchar_t *name, const wchar_t *val)
{
    VARIANT v;
    VariantInit(&v);
    v.vt = VT_BSTR;
    v.bstrVal = SysAllocString(val);
    IWbemClassObject_Put(o, name, 0, &v, 0);
    VariantClear(&v);
}

static void put_bool(IWbemClassObject *o, const wchar_t *name, BOOL b)
{
    VARIANT v;
    VariantInit(&v);
    v.vt = VT_BOOL;
    v.boolVal = b ? VARIANT_TRUE : VARIANT_FALSE;
    IWbemClassObject_Put(o, name, 0, &v, 0);
}

static BOOL do_register(BOOL on, BOOL fresh)
{
    IWbemServices *svc;
    IWbemClassObject *cls = NULL, *inst = NULL;
    BSTR cname;
    HRESULT hr = E_FAIL;
    wchar_t exe[MAX_PATH];

    svc = connect_sc();
    if (!svc) return FALSE;
    cname = SysAllocString(L"AntiVirusProduct");
    if (SUCCEEDED(IWbemServices_GetObject(svc, cname, 0, NULL, &cls, NULL)) && cls &&
        SUCCEEDED(IWbemClassObject_SpawnInstance(cls, 0, &inst)) && inst) {
        GetModuleFileNameW(NULL, exe, MAX_PATH);
        put_str (inst, L"instanceGuid",            WSC_GUID);
        put_str (inst, L"displayName",             AV_NAME);
        put_str (inst, L"companyName",             L"Carrot Software");
        put_str (inst, L"versionNumber",           AV_VERSION);
        put_str (inst, L"pathToSignedProductExe",  exe);
        put_bool(inst, L"onAccessScanningEnabled", on);
        put_bool(inst, L"productUptoDate",         fresh);
        /* create or update in one call */
        hr = IWbemServices_PutInstance(svc, inst, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    }
    if (inst) IWbemClassObject_Release(inst);
    if (cls) IWbemClassObject_Release(cls);
    SysFreeString(cname);
    IWbemServices_Release(svc);
    return SUCCEEDED(hr);
}

static BOOL do_remove(void)
{
    IWbemServices *svc = connect_sc();
    BSTR path;
    HRESULT hr;
    if (!svc) return FALSE;
    path = SysAllocString(WSC_PATH);
    hr = IWbemServices_DeleteInstance(svc, path, 0, NULL, NULL);
    SysFreeString(path);
    IWbemServices_Release(svc);
    return SUCCEEDED(hr);
}

/* WMI calls can take a moment (the service may be starting), so updates run
 * on a short-lived thread and never stall the window. */
static DWORD WINAPI wsc_thread(LPVOID p)
{
    WSCJOB j = *(WSCJOB*)p;
    BOOL ok;
    LocalFree(p);
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (j.remove) ok = do_remove();
    else          ok = do_register(j.on, j.fresh);
    CoUninitialize();
    if (j.remove)
        log_line(L"SECURITYCENTER  unregistered (%s)", ok ? L"ok" : L"failed");
    else
        log_line(L"SECURITYCENTER  shield %s, definitions %s (%s)",
                 j.on ? L"on" : L"off", j.fresh ? L"current" : L"out of date",
                 ok ? L"ok" : L"failed - needs admin rights and the WMI service");
    InterlockedExchange(&g_busy, 0);
    return 0;
}

static BOOL wsc_supported(void) { return os_kind() == OS_XP; }

static BOOL defs_fresh(const SIGDB *db)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    unsigned __int64 now;
    if (!db || !db->loaded || !db->hdr.built) return FALSE;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    now = (u.QuadPart - 116444736000000000ULL) / 10000000ULL;   /* -> unix time */
    if ((unsigned __int64)db->hdr.built > now) return TRUE;     /* clock skew */
    return (now - db->hdr.built) < (unsigned __int64)STALE_DAYS * 86400ULL;
}

/* Called every few seconds from the main window's timer. Only talks to WMI
 * when something actually changed. */
void wsc_tick(BOOL shield_on, const SIGDB *db)
{
    BOOL fresh;
    WSCJOB *j;
    HANDLE t;
    if (!wsc_supported()) return;
    fresh = defs_fresh(db);
    if ((int)shield_on == g_last_on && (int)fresh == g_last_fresh) return;
    if (InterlockedCompareExchange(&g_busy, 1, 0) != 0) return;   /* retry next tick */
    j = (WSCJOB*)LocalAlloc(LPTR, sizeof *j);
    if (!j) { InterlockedExchange(&g_busy, 0); return; }
    j->on = shield_on; j->fresh = fresh; j->remove = FALSE;
    t = CreateThread(NULL, 0, wsc_thread, j, 0, NULL);
    if (!t) { LocalFree(j); InterlockedExchange(&g_busy, 0); return; }
    CloseHandle(t);
    g_last_on = shield_on;
    g_last_fresh = fresh;
}

/* On exit: the shield is going away, so say so before we leave. Runs inline
 * (the process is ending) with a short wait for any update in flight. */
void wsc_exit(const SIGDB *db)
{
    int i;
    WSCJOB *j;
    HANDLE t;
    if (!wsc_supported()) return;
    for (i = 0; i < 20 && g_busy; i++) Sleep(100);
    /* On its own thread with a hard 2-second cap: a slow WMI service must
     * never hold up CarrotAV closing (the installer waits on that to upgrade). */
    j = (WSCJOB*)LocalAlloc(LPTR, sizeof *j);
    if (!j) return;
    j->on = FALSE; j->fresh = defs_fresh(db); j->remove = FALSE;
    InterlockedExchange(&g_busy, 1);
    t = CreateThread(NULL, 0, wsc_thread, j, 0, NULL);
    if (!t) { LocalFree(j); InterlockedExchange(&g_busy, 0); return; }
    WaitForSingleObject(t, 2000);
    CloseHandle(t);
}

/* Uninstaller: carrotav.exe /wscremove */
void wsc_remove(void)
{
    if (!wsc_supported()) return;
    if (do_remove()) log_line(L"SECURITYCENTER  unregistered by uninstaller");
}

/* fw.c - Windows Firewall control through the XP SP2 COM API (hnetcfg).
 *
 * This replaces the earlier netsh shelling. COM gives us the things netsh
 * cannot do cleanly: enumerate every authorized program and open port, read
 * their scope, and toggle individual rules without reparsing console text.
 * netsh remains as a fallback if the COM objects will not instantiate.
 */
#define COBJMACROS
#include "av.h"
#include <initguid.h>
#include <netfw.h>
#include <oleauto.h>

/* mingw ships the interface declarations but not the GUID symbols */
DEFINE_GUID(CLSID_NetFwMgr_,  0x304CE942,0x6E39,0x40D8,0x94,0x3A,0xB9,0x13,0xC4,0x0C,0x9C,0xD4);
DEFINE_GUID(IID_INetFwMgr_,   0xF7898AF5,0xCAC4,0x4632,0xA2,0xEC,0xDA,0x06,0xE5,0x11,0x1A,0xF2);
DEFINE_GUID(CLSID_NetFwAuthApp_,0xEC9846B3,0x2762,0x4A6B,0xA2,0x14,0x6A,0xCB,0x60,0x34,0x62,0xD2);
DEFINE_GUID(IID_INetFwAuthApp_, 0xB5E64FFA,0xC2C5,0x444E,0xA3,0x01,0xFB,0x5E,0x00,0x01,0x80,0x50);
DEFINE_GUID(CLSID_NetFwOpenPort_,0x0CA545C6,0x37AD,0x4A6C,0xBF,0x92,0x9F,0x76,0x10,0x06,0x7E,0xF5);
DEFINE_GUID(IID_INetFwOpenPort_, 0xE0483BA0,0x47FF,0x4D9C,0xA6,0xD6,0x77,0x41,0xD0,0xB1,0x95,0xF7);

/* ---- profile acquisition -------------------------------------------- */

static INetFwProfile *profile_get(void)
{
    INetFwMgr *mgr = NULL;
    INetFwPolicy *pol = NULL;
    INetFwProfile *prof = NULL;

    if (FAILED(CoCreateInstance(&CLSID_NetFwMgr_, NULL, CLSCTX_INPROC_SERVER,
                                &IID_INetFwMgr_, (void**)&mgr)))
        return NULL;
    if (SUCCEEDED(INetFwMgr_get_LocalPolicy(mgr, &pol))) {
        INetFwPolicy_get_CurrentProfile(pol, &prof);
        INetFwPolicy_Release(pol);
    }
    INetFwMgr_Release(mgr);
    return prof;
}

static void profile_put(INetFwProfile *p) { if (p) INetFwProfile_Release(p); }

BOOL fw_available(void)
{
    INetFwProfile *p = profile_get();
    if (!p) return FALSE;
    profile_put(p);
    return TRUE;
}

/* ---- overall state --------------------------------------------------- */

BOOL fw_get_state(FWSTATE *st)
{
    INetFwProfile *p;
    VARIANT_BOOL b;
    NET_FW_PROFILE_TYPE t;

    memset(st, 0, sizeof(*st));
    st->enabled = -1;

    p = profile_get();
    if (!p) {
        /* COM refused - fall back to the registry value */
        st->enabled = fw_status();
        st->com = FALSE;
        return st->enabled >= 0;
    }
    st->com = TRUE;

    if (SUCCEEDED(INetFwProfile_get_FirewallEnabled(p, &b)))
        st->enabled = (b != VARIANT_FALSE);
    if (SUCCEEDED(INetFwProfile_get_ExceptionsNotAllowed(p, &b)))
        st->block_all = (b != VARIANT_FALSE);
    if (SUCCEEDED(INetFwProfile_get_NotificationsDisabled(p, &b)))
        st->notify_off = (b != VARIANT_FALSE);
    if (SUCCEEDED(INetFwProfile_get_Type(p, &t)))
        st->profile = (int)t;

    profile_put(p);
    return TRUE;
}

BOOL fw_set(BOOL on)
{
    INetFwProfile *p = profile_get();
    HRESULT hr;

    if (!p) {
        /* fallback: the old netsh route */
        STARTUPINFOW si; PROCESS_INFORMATION pi; wchar_t cmd[256]; DWORD code = 1;
        wsprintfW(cmd, L"netsh firewall set opmode mode=%s", on ? L"ENABLE" : L"DISABLE");
        memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                            NULL, NULL, &si, &pi)) return FALSE;
        WaitForSingleObject(pi.hProcess, 20000);
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return code == 0;
    }
    hr = INetFwProfile_put_FirewallEnabled(p, on ? VARIANT_TRUE : VARIANT_FALSE);
    profile_put(p);
    log_line(L"FIREWALL  set %s (%s)", on ? L"ON" : L"OFF",
             SUCCEEDED(hr) ? L"ok" : L"failed");
    return SUCCEEDED(hr);
}

/* "Don't allow exceptions" - the panic switch for public networks */
BOOL fw_set_block_all(BOOL on)
{
    INetFwProfile *p = profile_get();
    HRESULT hr;
    if (!p) return FALSE;
    hr = INetFwProfile_put_ExceptionsNotAllowed(p, on ? VARIANT_TRUE : VARIANT_FALSE);
    profile_put(p);
    log_line(L"FIREWALL  block-all-exceptions %s", on ? L"ON" : L"OFF");
    return SUCCEEDED(hr);
}

BOOL fw_set_notifications(BOOL on)
{
    INetFwProfile *p = profile_get();
    HRESULT hr;
    if (!p) return FALSE;
    hr = INetFwProfile_put_NotificationsDisabled(p, on ? VARIANT_FALSE : VARIANT_TRUE);
    profile_put(p);
    return SUCCEEDED(hr);
}

/* ---- authorized programs -------------------------------------------- */

int fw_list_apps(FWAPP **out)
{
    INetFwProfile *prof;
    INetFwAuthorizedApplications *apps = NULL;
    IUnknown *unk = NULL;
    IEnumVARIANT *en = NULL;
    FWAPP *arr = NULL;
    long count = 0, n = 0;
    VARIANT v;
    ULONG fetched;

    *out = NULL;
    prof = profile_get();
    if (!prof) return 0;

    if (FAILED(INetFwProfile_get_AuthorizedApplications(prof, &apps))) {
        profile_put(prof); return 0;
    }
    INetFwAuthorizedApplications_get_Count(apps, &count);
    if (count <= 0) goto done;

    arr = (FWAPP*)LocalAlloc(LPTR, sizeof(FWAPP) * count);
    if (!arr) goto done;

    if (FAILED(INetFwAuthorizedApplications_get__NewEnum(apps, &unk))) goto done;
    if (FAILED(IUnknown_QueryInterface(unk, &IID_IEnumVARIANT, (void**)&en))) goto done;

    VariantInit(&v);
    while (n < count && IEnumVARIANT_Next(en, 1, &v, &fetched) == S_OK) {
        INetFwAuthorizedApplication *app = NULL;
        if (V_VT(&v) == VT_DISPATCH && V_DISPATCH(&v) &&
            SUCCEEDED(IDispatch_QueryInterface(V_DISPATCH(&v),
                        &IID_INetFwAuthApp_, (void**)&app))) {
            BSTR bs = NULL;
            VARIANT_BOOL b;
            NET_FW_SCOPE sc;

            if (SUCCEEDED(INetFwAuthorizedApplication_get_Name(app, &bs)) && bs) {
                lstrcpynW(arr[n].name, bs, 128); SysFreeString(bs); bs = NULL;
            }
            if (SUCCEEDED(INetFwAuthorizedApplication_get_ProcessImageFileName(app, &bs)) && bs) {
                lstrcpynW(arr[n].path, bs, MAX_PATH); SysFreeString(bs); bs = NULL;
            }
            if (SUCCEEDED(INetFwAuthorizedApplication_get_Enabled(app, &b)))
                arr[n].enabled = (b != VARIANT_FALSE);
            if (SUCCEEDED(INetFwAuthorizedApplication_get_Scope(app, &sc)))
                arr[n].scope = (int)sc;
            n++;
            INetFwAuthorizedApplication_Release(app);
        }
        VariantClear(&v);
    }

done:
    if (en)  IEnumVARIANT_Release(en);
    if (unk) IUnknown_Release(unk);
    if (apps) INetFwAuthorizedApplications_Release(apps);
    profile_put(prof);
    *out = arr;
    return (int)n;
}

/* Add or update a program rule. enabled=FALSE registers it as blocked. */
BOOL fw_app_set(const wchar_t *path, const wchar_t *name, BOOL enabled)
{
    INetFwProfile *prof;
    INetFwAuthorizedApplications *apps = NULL;
    INetFwAuthorizedApplication *app = NULL;
    HRESULT hr = E_FAIL;
    BSTR bpath = NULL, bname = NULL;

    prof = profile_get();
    if (!prof) return FALSE;

    if (FAILED(INetFwProfile_get_AuthorizedApplications(prof, &apps))) goto done;
    if (FAILED(CoCreateInstance(&CLSID_NetFwAuthApp_, NULL, CLSCTX_INPROC_SERVER,
                                &IID_INetFwAuthApp_, (void**)&app))) goto done;

    bpath = SysAllocString(path);
    bname = SysAllocString(name && *name ? name : PathFindFileNameW(path));
    if (!bpath || !bname) goto done;

    INetFwAuthorizedApplication_put_ProcessImageFileName(app, bpath);
    INetFwAuthorizedApplication_put_Name(app, bname);
    INetFwAuthorizedApplication_put_Scope(app, NET_FW_SCOPE_ALL);
    INetFwAuthorizedApplication_put_Enabled(app,
        enabled ? VARIANT_TRUE : VARIANT_FALSE);

    hr = INetFwAuthorizedApplications_Add(apps, app);

done:
    if (bpath) SysFreeString(bpath);
    if (bname) SysFreeString(bname);
    if (app)  INetFwAuthorizedApplication_Release(app);
    if (apps) INetFwAuthorizedApplications_Release(apps);
    profile_put(prof);
    log_line(L"FIREWALL  rule %s for %s (%s)",
             enabled ? L"ALLOW" : L"BLOCK", path, SUCCEEDED(hr) ? L"ok" : L"failed");
    return SUCCEEDED(hr);
}

BOOL fw_app_remove(const wchar_t *path)
{
    INetFwProfile *prof;
    INetFwAuthorizedApplications *apps = NULL;
    HRESULT hr = E_FAIL;
    BSTR bpath;

    prof = profile_get();
    if (!prof) return FALSE;
    if (FAILED(INetFwProfile_get_AuthorizedApplications(prof, &apps))) {
        profile_put(prof); return FALSE;
    }
    bpath = SysAllocString(path);
    if (bpath) {
        hr = INetFwAuthorizedApplications_Remove(apps, bpath);
        SysFreeString(bpath);
    }
    INetFwAuthorizedApplications_Release(apps);
    profile_put(prof);
    log_line(L"FIREWALL  removed rule for %s", path);
    return SUCCEEDED(hr);
}

/* convenience wrapper kept for the old call site */
BOOL fw_block_app(const wchar_t *exe)
{
    wchar_t nm[160];
    wsprintfW(nm, L"CarrotAV block %s", PathFindFileNameW(exe));
    return fw_app_set(exe, nm, FALSE);
}

/* ---- open ports ------------------------------------------------------ */

int fw_list_ports(FWPORT **out)
{
    INetFwProfile *prof;
    INetFwOpenPorts *ports = NULL;
    IUnknown *unk = NULL;
    IEnumVARIANT *en = NULL;
    FWPORT *arr = NULL;
    long count = 0, n = 0;
    VARIANT v;
    ULONG fetched;

    *out = NULL;
    prof = profile_get();
    if (!prof) return 0;

    if (FAILED(INetFwProfile_get_GloballyOpenPorts(prof, &ports))) {
        profile_put(prof); return 0;
    }
    INetFwOpenPorts_get_Count(ports, &count);
    if (count <= 0) goto done;

    arr = (FWPORT*)LocalAlloc(LPTR, sizeof(FWPORT) * count);
    if (!arr) goto done;

    if (FAILED(INetFwOpenPorts_get__NewEnum(ports, &unk))) goto done;
    if (FAILED(IUnknown_QueryInterface(unk, &IID_IEnumVARIANT, (void**)&en))) goto done;

    VariantInit(&v);
    while (n < count && IEnumVARIANT_Next(en, 1, &v, &fetched) == S_OK) {
        INetFwOpenPort *port = NULL;
        if (V_VT(&v) == VT_DISPATCH && V_DISPATCH(&v) &&
            SUCCEEDED(IDispatch_QueryInterface(V_DISPATCH(&v),
                        &IID_INetFwOpenPort_, (void**)&port))) {
            BSTR bs = NULL;
            VARIANT_BOOL b;
            LONG pn = 0;
            NET_FW_IP_PROTOCOL proto;

            if (SUCCEEDED(INetFwOpenPort_get_Name(port, &bs)) && bs) {
                lstrcpynW(arr[n].name, bs, 128); SysFreeString(bs);
            }
            if (SUCCEEDED(INetFwOpenPort_get_Port(port, &pn)))
                arr[n].port = (int)pn;
            if (SUCCEEDED(INetFwOpenPort_get_Protocol(port, &proto)))
                arr[n].tcp = (proto == NET_FW_IP_PROTOCOL_TCP);
            if (SUCCEEDED(INetFwOpenPort_get_Enabled(port, &b)))
                arr[n].enabled = (b != VARIANT_FALSE);
            n++;
            INetFwOpenPort_Release(port);
        }
        VariantClear(&v);
    }

done:
    if (en)  IEnumVARIANT_Release(en);
    if (unk) IUnknown_Release(unk);
    if (ports) INetFwOpenPorts_Release(ports);
    profile_put(prof);
    *out = arr;
    return (int)n;
}

BOOL fw_port_remove(int port, BOOL tcp)
{
    INetFwProfile *prof;
    INetFwOpenPorts *ports = NULL;
    HRESULT hr = E_FAIL;

    prof = profile_get();
    if (!prof) return FALSE;
    if (SUCCEEDED(INetFwProfile_get_GloballyOpenPorts(prof, &ports))) {
        hr = INetFwOpenPorts_Remove(ports, port,
                tcp ? NET_FW_IP_PROTOCOL_TCP : NET_FW_IP_PROTOCOL_UDP);
        INetFwOpenPorts_Release(ports);
    }
    profile_put(prof);
    log_line(L"FIREWALL  closed port %d/%s", port, tcp ? L"TCP" : L"UDP");
    return SUCCEEDED(hr);
}

/* Close the ports that XP historically got attacked through. Nothing here
 * is needed for normal internet use on a home machine. */
int fw_harden(void)
{
    static const int risky[] = { 135, 137, 138, 139, 445, 593, 1025, 5000, 0 };
    int i, closed = 0;
    for (i = 0; risky[i]; i++) {
        if (fw_port_remove(risky[i], TRUE))  closed++;
        if (fw_port_remove(risky[i], FALSE)) closed++;
    }
    log_line(L"FIREWALL  hardening removed %d open-port rules", closed);
    return closed;
}

int fw_status(void)
{
    HKEY k;
    DWORD val = 0, cb = sizeof(val), type;
    int r = -1;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, L"EnableFirewall", NULL, &type, (LPBYTE)&val, &cb) == ERROR_SUCCESS)
            r = val ? 1 : 0;
        RegCloseKey(k);
    }
    return r;
}

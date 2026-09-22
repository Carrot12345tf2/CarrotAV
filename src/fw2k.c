/* fw2k.c - firewall for systems with no Windows Firewall (Windows 2000).
 *
 * Two backends, chosen at runtime:
 *
 *  1. PACKET FILTER (iphlpapi Pf* API) - a true block-list: drop inbound
 *     traffic per port, live, no restart. Documented as a Windows 2000
 *     feature, but many 2000 installs don't actually export
 *     PfCreateInterface, so it can't be relied on.
 *
 *  2. TCP/IP FILTERING (registry) - the one every Windows 2000 has. It's the
 *     "TCP/IP filtering" option in Advanced TCP/IP Settings. This is an
 *     ALLOW-list: you name the inbound TCP ports that may be reached and
 *     everything else is refused. It needs a restart to take effect and it
 *     persists across reboots, so the uninstaller has to undo it.
 *
 *     Only TCP is filtered here. Windows applies a separate allow-list to UDP,
 *     and restricting that breaks DNS and DHCP replies on this era of Windows,
 *     so UDP and raw IP are deliberately left permitted. Outbound connections
 *     and the replies to them are unaffected by either backend.
 *
 * Neither backend can do per-program rules - a packet filter never sees which
 * process owns a packet - so that is reported honestly as not available.
 */
#include "av.h"
#include <iphlpapi.h>
#include <fltdefs.h>

#define FW2K_MAXIF    16
#define FW2K_MAXPORTS 64
#define FW2K_KEY      L"Software\\CarrotAV\\Firewall2000"
#define TCPIP_PARAMS  L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define TCPIP_IFACES  TCPIP_PARAMS L"\\Interfaces"

typedef DWORD (WINAPI *PFN_PfCreate)(DWORD, PFFORWARD_ACTION, PFFORWARD_ACTION,
                                     BOOL, BOOL, INTERFACE_HANDLE*);
typedef DWORD (WINAPI *PFN_PfDelete)(INTERFACE_HANDLE);
typedef DWORD (WINAPI *PFN_PfAdd)(INTERFACE_HANDLE, DWORD, PPF_FILTER_DESCRIPTOR,
                                  DWORD, PPF_FILTER_DESCRIPTOR, PFILTER_HANDLE);
typedef DWORD (WINAPI *PFN_PfBind)(INTERFACE_HANDLE, PFADDRESSTYPE, PBYTE);
typedef DWORD (WINAPI *PFN_PfUnbind)(INTERFACE_HANDLE);
typedef DWORD (WINAPI *PFN_GetIpAddrTable)(PMIB_IPADDRTABLE, PULONG, BOOL);
typedef DWORD (WINAPI *PFN_GetTcpTable)(PMIB_TCPTABLE, PDWORD, BOOL);
typedef DWORD (WINAPI *PFN_GetUdpTable)(PMIB_UDPTABLE, PDWORD, BOOL);

static PFN_PfCreate       pPfCreate;
static PFN_PfDelete       pPfDelete;
static PFN_PfAdd          pPfAdd;
static PFN_PfBind         pPfBind;
static PFN_PfUnbind       pPfUnbind;
static PFN_GetIpAddrTable pGetIpAddrTable;
static PFN_GetTcpTable    pGetTcpTable;
static PFN_GetUdpTable    pGetUdpTable;

static int      g_pf = -1;              /* is the Pf* API usable? */
static wchar_t  g_why[160];             /* why not, for the UI */
static int      g_method = FW2K_NONE;
static BOOL     g_reboot;

static INTERFACE_HANDLE g_if[FW2K_MAXIF];
static int      g_nif;
static BOOL     g_enabled;
static DWORD    g_err;
static DWORD    g_addrsig;
static int      g_tick;

static FW2KPORT g_ports[FW2K_MAXPORTS];
static int      g_nports;

/* Packet-filter defaults: the ports the 2000-era worms came in on. NOT 1025 or
 * 5000 - Windows 2000 uses 1025-5000 for your own outgoing connections, so
 * blocking inbound there would break browsing at random. */
static const FW2KPORT k_block[] = {
    { 135, TRUE  },   /* RPC endpoint mapper - Blaster, Welchia */
    { 139, TRUE  },   /* NetBIOS session */
    { 445, TRUE  },   /* SMB direct - Sasser, Conficker */
    { 593, TRUE  },   /* RPC over HTTP */
    { 135, FALSE },   /* RPC endpoint mapper (UDP) */
    { 1900, FALSE },  /* UPnP discovery */
};

/* ---------------- backend detection ---------------- */

static BOOL pf_load(void)
{
    HMODULE m;
    if (g_pf >= 0) return g_pf;
    g_pf = 0;
    m = LoadLibraryW(L"iphlpapi.dll");
    if (!m) {
        wsprintfW(g_why, L"iphlpapi.dll could not be loaded (error %lu)", GetLastError());
        return FALSE;
    }
    pPfCreate       = (PFN_PfCreate)(void*)GetProcAddress(m, "PfCreateInterface");
    pPfDelete       = (PFN_PfDelete)(void*)GetProcAddress(m, "PfDeleteInterface");
    pPfAdd          = (PFN_PfAdd)(void*)GetProcAddress(m, "PfAddFiltersToInterface");
    pPfBind         = (PFN_PfBind)(void*)GetProcAddress(m, "PfBindInterfaceToIPAddress");
    pPfUnbind       = (PFN_PfUnbind)(void*)GetProcAddress(m, "PfUnBindInterface");
    pGetIpAddrTable = (PFN_GetIpAddrTable)(void*)GetProcAddress(m, "GetIpAddrTable");
    pGetTcpTable    = (PFN_GetTcpTable)(void*)GetProcAddress(m, "GetTcpTable");
    pGetUdpTable    = (PFN_GetUdpTable)(void*)GetProcAddress(m, "GetUdpTable");

    if      (!pPfCreate)       lstrcpyW(g_why, L"iphlpapi.dll has no PfCreateInterface");
    else if (!pPfDelete)       lstrcpyW(g_why, L"iphlpapi.dll has no PfDeleteInterface");
    else if (!pPfAdd)          lstrcpyW(g_why, L"iphlpapi.dll has no PfAddFiltersToInterface");
    else if (!pPfBind)         lstrcpyW(g_why, L"iphlpapi.dll has no PfBindInterfaceToIPAddress");
    else if (!pPfUnbind)       lstrcpyW(g_why, L"iphlpapi.dll has no PfUnBindInterface");
    else if (!pGetIpAddrTable) lstrcpyW(g_why, L"iphlpapi.dll has no GetIpAddrTable");
    else g_pf = 1;
    return g_pf;
}

static BOOL tcpip_available(void)
{
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TCPIP_PARAMS, 0, KEY_READ, &k) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(k);
    return TRUE;
}

int fw2k_method(void)
{
    if (g_method != FW2K_NONE) return g_method;
    if (pf_load())            g_method = FW2K_PF;
    else if (tcpip_available()) g_method = FW2K_TCPIP;
    return g_method;
}

BOOL fw2k_available(void)     { return fw2k_method() != FW2K_NONE; }
BOOL fw2k_reboot_needed(void) { return g_reboot; }

const wchar_t *fw2k_why(void)
{
    pf_load();
    return g_why;
}

/* ---------------- config ---------------- */

static void save_config(void)
{
    HKEY k;
    wchar_t buf[FW2K_MAXPORTS * 8 + 8];
    int i, n = 0;
    DWORD en = g_enabled ? 1 : 0;

    buf[0] = 0;
    for (i = 0; i < g_nports; i++)
        n += wsprintfW(buf + n, L"%s%c%d", i ? L"," : L"",
                       g_ports[i].tcp ? L'T' : L'U', g_ports[i].port);

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, FW2K_KEY, 0, NULL, 0,
                        KEY_SET_VALUE, NULL, &k, NULL) != ERROR_SUCCESS)
        return;
    RegSetValueExW(k, L"Enabled", 0, REG_DWORD, (const BYTE*)&en, sizeof(en));
    RegSetValueExW(k, L"Ports", 0, REG_SZ, (const BYTE*)buf,
                   (lstrlenW(buf) + 1) * sizeof(wchar_t));
    RegCloseKey(k);
}

void fw2k_defaults(void)
{
    int i;
    g_nports = 0;
    /* The packet filter blocks what's listed. TCP/IP filtering allows what's
     * listed, so its sane default is an empty list: nothing inbound. */
    if (fw2k_method() == FW2K_PF)
        for (i = 0; i < (int)(sizeof(k_block) / sizeof(k_block[0])); i++)
            g_ports[g_nports++] = k_block[i];
}

static void load_config(void)
{
    HKEY k;
    /* The packet filter is live and reversible, so it defaults ON. TCP/IP
     * filtering needs a restart and persists, so it waits to be switched on. */
    DWORD en = (fw2k_method() == FW2K_PF) ? 1 : 0, sz, type;
    wchar_t buf[FW2K_MAXPORTS * 8 + 8];
    BOOL have_ports = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, FW2K_KEY, 0, KEY_READ, &k) == ERROR_SUCCESS) {
        sz = sizeof(DWORD);
        RegQueryValueExW(k, L"Enabled", NULL, &type, (BYTE*)&en, &sz);
        sz = sizeof(buf) - sizeof(wchar_t);
        if (RegQueryValueExW(k, L"Ports", NULL, &type, (BYTE*)buf, &sz) == ERROR_SUCCESS &&
            type == REG_SZ) {
            wchar_t *p = buf;
            buf[sz / sizeof(wchar_t)] = 0;
            have_ports = TRUE;
            g_nports = 0;
            while (*p && g_nports < FW2K_MAXPORTS) {
                BOOL tcp = (*p == L'T' || *p == L't');
                int port = 0;
                if (*p == L'T' || *p == L't' || *p == L'U' || *p == L'u') p++;
                while (*p >= L'0' && *p <= L'9') port = port * 10 + (*p++ - L'0');
                if (port > 0 && port < 65536) {
                    g_ports[g_nports].port = port;
                    g_ports[g_nports].tcp = tcp;
                    g_nports++;
                }
                while (*p && *p != L',') p++;
                if (*p == L',') p++;
            }
        }
        RegCloseKey(k);
    }
    if (!have_ports) fw2k_defaults();
    g_enabled = en ? TRUE : FALSE;
}

/* ---------------- backend 1: packet filter ---------------- */

static void pf_remove_all(void)
{
    int i;
    for (i = 0; i < g_nif; i++) { pPfUnbind(g_if[i]); pPfDelete(g_if[i]); }
    g_nif = 0;
}

static int get_addrs(DWORD *out, int max, DWORD *sig)
{
    MIB_IPADDRTABLE *t;
    ULONG sz = 0;
    DWORD i;
    int n = 0;

    *sig = 0;
    if (!pGetIpAddrTable) return 0;
    pGetIpAddrTable(NULL, &sz, FALSE);
    if (!sz) return 0;
    t = (MIB_IPADDRTABLE*)LocalAlloc(LPTR, sz);
    if (!t) return 0;
    if (pGetIpAddrTable(t, &sz, FALSE) == NO_ERROR) {
        for (i = 0; i < t->dwNumEntries && n < max; i++) {
            DWORD a = t->table[i].dwAddr;
            if (a == 0 || (a & 0xFF) == 127) continue;
            out[n++] = a;
            *sig = (*sig * 31) ^ a;
        }
    }
    LocalFree(t);
    *sig ^= (DWORD)n;
    return n;
}

static BOOL pf_apply(void)
{
    DWORD addrs[FW2K_MAXIF], sig;
    static BYTE any_addr[4] = {0,0,0,0}, any_mask[4] = {0,0,0,0};
    PF_FILTER_DESCRIPTOR f[FW2K_MAXPORTS];
    int na, i, ok = 0;

    pf_remove_all();
    g_err = 0;
    na = get_addrs(addrs, FW2K_MAXIF, &sig);
    g_addrsig = sig;
    if (!g_enabled || g_nports == 0) return TRUE;

    memset(f, 0, sizeof(f));
    for (i = 0; i < g_nports; i++) {
        f[i].pfatType          = PF_IPV4;
        f[i].SrcAddr           = any_addr;
        f[i].SrcMask           = any_mask;
        f[i].DstAddr           = any_addr;
        f[i].DstMask           = any_mask;
        f[i].dwProtocol        = g_ports[i].tcp ? FILTER_PROTO_TCP : FILTER_PROTO_UDP;
        f[i].wSrcPort          = FILTER_TCPUDP_PORT_ANY;
        f[i].wSrcPortHighRange = FILTER_TCPUDP_PORT_ANY;
        f[i].wDstPort          = (WORD)g_ports[i].port;
        f[i].wDstPortHighRange = (WORD)g_ports[i].port;
    }

    for (i = 0; i < na; i++) {
        INTERFACE_HANDLE h = NULL;
        DWORD r = pPfCreate(0, PF_ACTION_FORWARD, PF_ACTION_FORWARD, FALSE, TRUE, &h);
        if (r != NO_ERROR) { g_err = r; continue; }
        r = pPfAdd(h, (DWORD)g_nports, f, 0, NULL, NULL);
        if (r == NO_ERROR) r = pPfBind(h, PF_IPV4, (PBYTE)&addrs[i]);
        if (r != NO_ERROR) { g_err = r; pPfDelete(h); continue; }
        g_if[g_nif++] = h;
        ok++;
    }
    if (na > 0 && ok == 0) {
        log_line(L"FIREWALL  packet filter failed (error %lu)", g_err);
        return FALSE;
    }
    log_line(L"FIREWALL  %d port rule(s) active on %d address(es)", g_nports, ok);
    return TRUE;
}

/* ---------------- backend 2: TCP/IP filtering ---------------- */

/* Build a REG_MULTI_SZ of the allowed TCP ports. Returns the length in
 * characters including both terminators. */
static int build_allow_list(wchar_t *buf, int cch)
{
    int i, o = 0;
    for (i = 0; i < g_nports; i++) {
        if (!g_ports[i].tcp) continue;                 /* UDP stays permitted */
        if (o + 8 >= cch) break;
        o += wsprintfW(buf + o, L"%d", g_ports[i].port) + 1;
    }
    buf[o] = 0;
    return o + 1;
}

static BOOL tcpip_write(BOOL on)
{
    HKEY params, ifaces, one;
    DWORD i = 0, en = on ? 1 : 0;
    wchar_t sub[160], allowed[FW2K_MAXPORTS * 8 + 4];
    static const wchar_t permit_all[] = { L'0', 0, 0 };   /* "0" = permit all */
    int len;

    g_err = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TCPIP_PARAMS, 0, KEY_SET_VALUE, &params)
            != ERROR_SUCCESS) { g_err = ERROR_ACCESS_DENIED; return FALSE; }
    RegSetValueExW(params, L"EnableSecurityFilters", 0, REG_DWORD,
                   (const BYTE*)&en, sizeof(en));
    RegCloseKey(params);

    if (on) len = build_allow_list(allowed, FW2K_MAXPORTS * 8);
    else { lstrcpyW(allowed, L"0"); allowed[2] = 0; len = 3; }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TCPIP_IFACES, 0, KEY_READ, &ifaces)
            != ERROR_SUCCESS) { g_err = ERROR_ACCESS_DENIED; return FALSE; }
    while (RegEnumKeyW(ifaces, i++, sub, 160) == ERROR_SUCCESS) {
        if (RegOpenKeyExW(ifaces, sub, 0, KEY_SET_VALUE, &one) != ERROR_SUCCESS)
            continue;
        RegSetValueExW(one, L"TCPAllowedPorts", 0, REG_MULTI_SZ,
                       (const BYTE*)allowed, len * sizeof(wchar_t));
        /* Leave UDP and raw IP permitted - filtering UDP breaks DNS/DHCP. */
        RegSetValueExW(one, L"UDPAllowedPorts", 0, REG_MULTI_SZ,
                       (const BYTE*)permit_all, 3 * sizeof(wchar_t));
        RegSetValueExW(one, L"RawIPAllowedProtocols", 0, REG_MULTI_SZ,
                       (const BYTE*)permit_all, 3 * sizeof(wchar_t));
        RegCloseKey(one);
    }
    RegCloseKey(ifaces);
    g_reboot = TRUE;
    log_line(L"FIREWALL  TCP/IP filtering %s - restart required", on ? L"on" : L"off");
    return TRUE;
}

/* ---------------- shared front end ---------------- */

static BOOL apply(void)
{
    if (fw2k_method() == FW2K_PF)    return pf_apply();
    if (fw2k_method() == FW2K_TCPIP) return tcpip_write(g_enabled);
    return FALSE;
}

void fw2k_start(void)
{
    if (fw2k_method() == FW2K_NONE) return;
    load_config();
    /* TCP/IP filtering is already live from the registry across reboots; only
     * the packet filter has to be re-established each run. */
    if (fw2k_method() == FW2K_PF) apply();
}

void fw2k_stop(void)
{
    if (g_pf == 1) pf_remove_all();
}

/* Undo persistent changes - called by the uninstaller so CarrotAV never
 * leaves a machine filtered after it's gone. */
void fw2k_restore_permit_all(void)
{
    if (fw2k_method() == FW2K_TCPIP) tcpip_write(FALSE);
}

void fw2k_tick(void)
{
    DWORD addrs[FW2K_MAXIF], sig;
    if (fw2k_method() != FW2K_PF || !g_enabled) return;
    if (++g_tick < 10) return;
    g_tick = 0;
    get_addrs(addrs, FW2K_MAXIF, &sig);
    if (sig != g_addrsig) pf_apply();
}

BOOL  fw2k_enabled(void) { return g_enabled; }
int   fw2k_bound(void)   { return g_nif; }
DWORD fw2k_error(void)   { return g_err; }

BOOL fw2k_set_enabled(BOOL on)
{
    BOOL ok;
    if (fw2k_method() == FW2K_NONE) return FALSE;
    g_enabled = on;
    ok = apply();
    save_config();
    return ok;
}

int fw2k_ports(const FW2KPORT **out)
{
    *out = g_ports;
    return g_nports;
}

BOOL fw2k_add_port(int port, BOOL tcp)
{
    int i;
    if (port <= 0 || port > 65535) return FALSE;
    for (i = 0; i < g_nports; i++)
        if (g_ports[i].port == port && g_ports[i].tcp == tcp) return TRUE;
    if (g_nports >= FW2K_MAXPORTS) return FALSE;
    g_ports[g_nports].port = port;
    g_ports[g_nports].tcp  = tcp;
    g_nports++;
    save_config();
    return apply();
}

BOOL fw2k_remove_port(int port, BOOL tcp)
{
    int i;
    for (i = 0; i < g_nports; i++) {
        if (g_ports[i].port == port && g_ports[i].tcp == tcp) {
            memmove(&g_ports[i], &g_ports[i + 1],
                    (g_nports - i - 1) * sizeof(FW2KPORT));
            g_nports--;
            save_config();
            return apply();
        }
    }
    return FALSE;
}

void fw2k_restore_defaults(void)
{
    fw2k_defaults();
    save_config();
    apply();
}

BOOL fw2k_listening(int port, BOOL tcp)
{
    DWORD sz = 0, i;
    BOOL hit = FALSE;
    if (tcp) {
        MIB_TCPTABLE *t;
        if (!pGetTcpTable) return FALSE;
        pGetTcpTable(NULL, &sz, FALSE);
        if (!sz || !(t = (MIB_TCPTABLE*)LocalAlloc(LPTR, sz))) return FALSE;
        if (pGetTcpTable(t, &sz, FALSE) == NO_ERROR)
            for (i = 0; i < t->dwNumEntries && !hit; i++) {
                DWORD p = t->table[i].dwLocalPort;
                p = ((p & 0xFF) << 8) | ((p >> 8) & 0xFF);
                if (t->table[i].dwState == MIB_TCP_STATE_LISTEN && (int)p == port)
                    hit = TRUE;
            }
        LocalFree(t);
    } else {
        MIB_UDPTABLE *t;
        if (!pGetUdpTable) return FALSE;
        pGetUdpTable(NULL, &sz, FALSE);
        if (!sz || !(t = (MIB_UDPTABLE*)LocalAlloc(LPTR, sz))) return FALSE;
        if (pGetUdpTable(t, &sz, FALSE) == NO_ERROR)
            for (i = 0; i < t->dwNumEntries && !hit; i++) {
                DWORD p = t->table[i].dwLocalPort;
                p = ((p & 0xFF) << 8) | ((p >> 8) & 0xFF);
                if ((int)p == port) hit = TRUE;
            }
        LocalFree(t);
    }
    return hit;
}

const wchar_t *fw2k_port_name(int port, BOOL tcp)
{
    switch (port) {
    case 135:  return tcp ? L"RPC endpoint mapper (Blaster worm)" : L"RPC endpoint mapper";
    case 139:  return L"NetBIOS file/printer sharing";
    case 445:  return L"SMB file sharing (Sasser worm)";
    case 593:  return L"RPC over HTTP";
    case 1900: return L"UPnP discovery";
    case 21:   return L"FTP";
    case 23:   return L"Telnet";
    case 80:   return L"Web server";
    case 3389: return L"Terminal Services";
    case 5900: return L"VNC";
    default:   return L"Custom rule";
    }
}

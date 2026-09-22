/* compat.c - run one binary across the classic NT desktop family.
 *
 * CarrotAV targets Windows NT 4.0, 2000, XP and XP x64. Those share the Win32
 * API, but not all of it: a function that only exists on XP cannot be imported
 * statically, because Windows resolves every import at load time and an exe
 * with one missing import simply refuses to start - no error we can catch, no
 * fallback, no chance to tell the user anything.
 *
 * So anything not present on the oldest supported system is resolved here at
 * runtime, and callers get a working fallback or an honest "not available
 * currently" rather than a program that won't launch.
 */
#include "av.h"
#include <shlobj.h>

static int   g_os = -1;          /* cached OS_* value */

static void detect(void)
{
    OSVERSIONINFOW vi;
    if (g_os >= 0) return;

    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (!GetVersionExW(&vi)) { g_os = OS_UNKNOWN; return; }

    if (vi.dwPlatformId != VER_PLATFORM_WIN32_NT) {
        /* 9x/ME - not a supported target (ANSI-only, different kernel). */
        g_os = OS_UNKNOWN;
    } else if (vi.dwMajorVersion == 4) {
        g_os = OS_NT4;                       /* NT 4.0 */
    } else if (vi.dwMajorVersion == 5 && vi.dwMinorVersion == 0) {
        g_os = OS_2000;                      /* Windows 2000 */
    } else if (vi.dwMajorVersion == 5) {
        g_os = OS_XP;                        /* XP, XP x64, Server 2003 */
    } else {
        g_os = OS_NEWER;                     /* Vista and up */
    }
}

int os_kind(void)
{
    detect();
    return g_os;
}

const wchar_t *os_name(void)
{
    detect();
    switch (g_os) {
    case OS_NT4:   return L"Windows NT 4.0";
    case OS_2000:  return L"Windows 2000";
    case OS_XP:    return L"Windows XP / 2003";
    case OS_NEWER: return L"Windows (newer than XP)";
    default:       return L"Unknown / unsupported";
    }
}

/* Windows File Protection (and the dllcache it repairs from) arrived with
 * Windows 2000. NT 4.0 has no such cache. */
BOOL os_has_wfp(void)
{
    detect();
    return g_os == OS_2000 || g_os == OS_XP || g_os == OS_NEWER;
}

/* The firewall COM API (INetFwProfile) came with XP SP2. Earlier systems have
 * no built-in Windows firewall for us to drive. */
BOOL os_has_firewall(void)
{
    detect();
    return g_os == OS_XP || g_os == OS_NEWER;
}

/* ---- SHGetFolderPathW ----
 * On XP this is exported from shell32. On Windows 2000 and NT 4.0 it lives in
 * shfolder.dll and may be missing from shell32 entirely. Resolve it at runtime
 * from whichever module has it, and fall back to environment variables if
 * neither does, so startup folder scanning still works on a bare system.
 */
typedef HRESULT (WINAPI *PFN_SHGFP)(HWND, int, HANDLE, DWORD, LPWSTR);

HRESULT compat_folder_path(int csidl, wchar_t *out)
{
    static PFN_SHGFP fn = NULL;
    static int tried = 0;

    out[0] = 0;

    if (!tried) {
        HMODULE m;
        tried = 1;
        m = GetModuleHandleW(L"shell32.dll");
        if (m) fn = (PFN_SHGFP)(void*)GetProcAddress(m, "SHGetFolderPathW");
        if (!fn) {
            m = LoadLibraryW(L"shfolder.dll");     /* 2000 / NT4 */
            if (m) fn = (PFN_SHGFP)(void*)GetProcAddress(m, "SHGetFolderPathW");
        }
    }

    if (fn) return fn(NULL, csidl, NULL, 0, out);

    /* Last resort: derive the common ones from the environment. Better a
     * usable path than silently skipping the startup folders. */
    switch (csidl) {
    case CSIDL_PROFILE:
        if (ExpandEnvironmentStringsW(L"%USERPROFILE%", out, MAX_PATH)) return S_OK;
        break;
    case CSIDL_APPDATA:
        if (ExpandEnvironmentStringsW(L"%APPDATA%", out, MAX_PATH)) return S_OK;
        break;
    case CSIDL_STARTUP:
        if (ExpandEnvironmentStringsW(
                L"%USERPROFILE%\\Start Menu\\Programs\\Startup", out, MAX_PATH))
            return S_OK;
        break;
    case CSIDL_COMMON_STARTUP:
        if (ExpandEnvironmentStringsW(
                L"%ALLUSERSPROFILE%\\Start Menu\\Programs\\Startup", out, MAX_PATH))
            return S_OK;
        break;
    case CSIDL_COMMON_APPDATA:
        if (ExpandEnvironmentStringsW(L"%ALLUSERSPROFILE%\\Application Data",
                                      out, MAX_PATH))
            return S_OK;
        break;
    }
    return E_FAIL;
}

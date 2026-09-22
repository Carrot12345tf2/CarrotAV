/* trust.c - "is this file genuinely signed, and by whom?"
 *
 * Every false positive CarrotAV has hit so far (msinfo32, the Media Player
 * tour script, NSIS's own nsExec.dll) was a legitimately signed file. Instead
 * of adding one path exception per incident, engine 2.0 asks Windows itself.
 * WinVerifyTrust checks the file's Authenticode signature against the trusted
 * roots; for Windows' own files, which usually aren't signed individually, we
 * look the file up in the system's signed catalogs - the same database Windows
 * File Protection uses.
 *
 * The policy that uses this lives in the scanner and the shield:
 *   - a HEURISTIC hit on any validly signed file is dropped (a heuristic is a
 *     guess, a valid signature is evidence);
 *   - a SIGNATURE hit on a Microsoft-signed file becomes "Disputed" (shown,
 *     never auto-quarantined);
 *   - a signature hit on a file signed by anyone else is still a detection,
 *     because malware signed with a stolen certificate is a real thing.
 *
 * Called only when a file has already been flagged, never per file - signature
 * verification is far too slow to run on every file of a full scan.
 *
 * Every API is resolved at runtime so a missing export can't stop CarrotAV
 * loading on an older system; if anything is missing we simply return
 * TRUST_NONE and the detection stands.
 */
#include "av.h"
#include <stddef.h>
#include <wintrust.h>
#include <mscat.h>

/* WINTRUST_ACTION_GENERIC_VERIFY_V2, defined here so we don't need a uuid lib */
static GUID k_verify_v2 =
    { 0x00aac56b, 0xcd44, 0x11d0, { 0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee } };

typedef LONG (WINAPI *PFN_WVT)(HWND, GUID*, LPVOID);
typedef CRYPT_PROVIDER_DATA* (WINAPI *PFN_ProvData)(HANDLE);
typedef CRYPT_PROVIDER_SGNR* (WINAPI *PFN_GetSigner)(CRYPT_PROVIDER_DATA*, DWORD, BOOL, DWORD);
typedef BOOL (WINAPI *PFN_CatAcquire)(HCATADMIN*, const GUID*, DWORD);
typedef BOOL (WINAPI *PFN_CatHash)(HANDLE, DWORD*, BYTE*, DWORD);
typedef HCATINFO (WINAPI *PFN_CatEnum)(HCATADMIN, BYTE*, DWORD, DWORD, HCATINFO*);
typedef BOOL (WINAPI *PFN_CatInfo)(HCATINFO, CATALOG_INFO*, DWORD);
typedef BOOL (WINAPI *PFN_CatRelCat)(HCATADMIN, HCATINFO, DWORD);
typedef BOOL (WINAPI *PFN_CatRel)(HCATADMIN, DWORD);
typedef DWORD (WINAPI *PFN_CertName)(PCCERT_CONTEXT, DWORD, DWORD, void*, LPWSTR, DWORD);

static PFN_WVT       pWVT;
static PFN_ProvData  pProvData;
static PFN_GetSigner pGetSigner;
static PFN_CatAcquire pCatAcquire;
static PFN_CatHash   pCatHash;
static PFN_CatEnum   pCatEnum;
static PFN_CatInfo   pCatInfo;
static PFN_CatRelCat pCatRelCat;
static PFN_CatRel    pCatRel;
static PFN_CertName  pCertName;
static int g_ready = -1;

static BOOL load(void)
{
    HMODULE w, c;
    if (g_ready >= 0) return g_ready;
    g_ready = 0;
    w = LoadLibraryW(L"wintrust.dll");
    c = LoadLibraryW(L"crypt32.dll");
    if (!w) return FALSE;
    pWVT        = (PFN_WVT)(void*)GetProcAddress(w, "WinVerifyTrust");
    pProvData   = (PFN_ProvData)(void*)GetProcAddress(w, "WTHelperProvDataFromStateData");
    pGetSigner  = (PFN_GetSigner)(void*)GetProcAddress(w, "WTHelperGetProvSignerFromChain");
    pCatAcquire = (PFN_CatAcquire)(void*)GetProcAddress(w, "CryptCATAdminAcquireContext");
    pCatHash    = (PFN_CatHash)(void*)GetProcAddress(w, "CryptCATAdminCalcHashFromFileHandle");
    pCatEnum    = (PFN_CatEnum)(void*)GetProcAddress(w, "CryptCATAdminEnumCatalogFromHash");
    pCatInfo    = (PFN_CatInfo)(void*)GetProcAddress(w, "CryptCATCatalogInfoFromContext");
    pCatRelCat  = (PFN_CatRelCat)(void*)GetProcAddress(w, "CryptCATAdminReleaseCatalogContext");
    pCatRel     = (PFN_CatRel)(void*)GetProcAddress(w, "CryptCATAdminReleaseContext");
    if (c) pCertName = (PFN_CertName)(void*)GetProcAddress(c, "CertGetNameStringW");
    if (pWVT) g_ready = 1;
    return g_ready;
}

/* Run WinVerifyTrust and, if the signature is valid, read the signer's name. */
static LONG verify(WINTRUST_DATA *wd, wchar_t *who, int cch)
{
    LONG r;
    who[0] = 0;
    /* Size of the Windows 2000 layout (everything up to dwProvFlags). Newer
     * Windows accept it and treat the later fields as absent; 2000 may not
     * accept a struct that claims to be bigger than it knows. */
    wd->cbStruct      = (DWORD)offsetof(WINTRUST_DATA, dwUIContext);
    wd->dwUIChoice    = WTD_UI_NONE;
    wd->fdwRevocationChecks = WTD_REVOKE_NONE;     /* never go online for CRLs */
    wd->dwStateAction = WTD_STATEACTION_VERIFY;
    /* On XP, also forbid fetching missing intermediates from the internet: an
     * offline XP box would otherwise stall here. 2000 predates these flags. */
    wd->dwProvFlags   = (os_kind() == OS_XP || os_kind() == OS_NEWER)
                        ? (WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL) : 0;

    r = pWVT((HWND)INVALID_HANDLE_VALUE, &k_verify_v2, wd);

    if (r == ERROR_SUCCESS && pProvData && pGetSigner && pCertName) {
        CRYPT_PROVIDER_DATA *pd = pProvData(wd->hWVTStateData);
        CRYPT_PROVIDER_SGNR *sg = pd ? pGetSigner(pd, 0, FALSE, 0) : NULL;
        if (sg && sg->csCertChain && sg->pasCertChain && sg->pasCertChain[0].pCert)
            pCertName(sg->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                      0, NULL, who, (DWORD)cch);
    }
    wd->dwStateAction = WTD_STATEACTION_CLOSE;
    pWVT((HWND)INVALID_HANDLE_VALUE, &k_verify_v2, wd);
    return r;
}

/* Signed inside the file itself (most third-party software, installers). */
static BOOL embedded(const wchar_t *path, wchar_t *who, int cch)
{
    WINTRUST_FILE_INFO fi;
    WINTRUST_DATA wd;
    memset(&fi, 0, sizeof fi);
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = path;
    memset(&wd, 0, sizeof wd);
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    return verify(&wd, who, cch) == ERROR_SUCCESS;
}

/* Listed in a signed Windows catalog (Windows' own files, WHQL drivers). */
static BOOL catalog(const wchar_t *path, wchar_t *who, int cch)
{
    HCATADMIN adm = NULL;
    HCATINFO cat;
    HANDLE h;
    BYTE hash[64];
    DWORD cb = sizeof hash, i;
    wchar_t tag[129];
    BOOL ok = FALSE;

    if (!pCatAcquire || !pCatHash || !pCatEnum || !pCatInfo || !pCatRelCat || !pCatRel)
        return FALSE;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!pCatAcquire(&adm, NULL, 0)) { CloseHandle(h); return FALSE; }

    if (pCatHash(h, &cb, hash, 0) && cb && cb <= 64) {
        cat = pCatEnum(adm, hash, cb, 0, NULL);
        if (cat) {
            CATALOG_INFO ci;
            memset(&ci, 0, sizeof ci);
            ci.cbStruct = sizeof ci;
            if (pCatInfo(cat, &ci, 0)) {
                WINTRUST_CATALOG_INFO wc;
                WINTRUST_DATA wd;
                /* the catalog member tag is the file hash in uppercase hex */
                for (i = 0; i < cb; i++)
                    wsprintfW(tag + i * 2, L"%02X", hash[i]);
                memset(&wc, 0, sizeof wc);
                /* Windows 2000 layout: up to hMemberFile */
                wc.cbStruct = (DWORD)offsetof(WINTRUST_CATALOG_INFO, pbCalculatedFileHash);
                wc.pcwszCatalogFilePath = ci.wszCatalogFile;
                wc.pcwszMemberTag = tag;
                wc.pcwszMemberFilePath = path;
                wc.hMemberFile = h;
                memset(&wd, 0, sizeof wd);
                wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                wd.pCatalog = &wc;
                ok = verify(&wd, who, cch) == ERROR_SUCCESS;
            }
            pCatRelCat(adm, cat, 0);
        }
    }
    pCatRel(adm, 0);
    CloseHandle(h);
    return ok;
}

int trust_file(const wchar_t *path, wchar_t *signer, int cch)
{
    wchar_t who[256];
    BOOL ok;
    if (signer && cch) signer[0] = 0;
    if (!load()) return TRUST_NONE;

    ok = embedded(path, who, 256);
    if (!ok) ok = catalog(path, who, 256);
    if (!ok) return TRUST_NONE;

    if (signer && cch) lstrcpynW(signer, who, cch);
    /* Windows files, Microsoft software, and WHQL-signed drivers all carry a
     * Microsoft signer name ("Microsoft Windows", "Microsoft Corporation",
     * "Microsoft Windows Hardware Compatibility Publisher"). */
    if (StrStrIW(who, L"Microsoft")) return TRUST_MICROSOFT;
    return TRUST_SIGNED;
}

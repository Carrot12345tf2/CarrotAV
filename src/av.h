/* CarrotAV - lightweight antivirus for Windows XP (32-bit)
 * Shared declarations. Target: i686, Windows 5.1 API level.
 */
#ifndef AV_H
#define AV_H

#define WINVER       0x0501
#define _WIN32_WINNT 0x0501
#define _WIN32_IE    0x0600
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <commdlg.h>
#include <stdarg.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AV_NAME     L"CarrotAV"
#define AV_VERSION  L"2.0"
#define MAX_PAT     256      /* max signature pattern length in bytes  */
#define SCAN_CHUNK  (64*1024)

/* ---------------- signature database ---------------- */

#pragma pack(push,1)
typedef struct {
    unsigned char md5[16];
    unsigned int  size;      /* 0 = any size */
    unsigned int  nameoff;   /* offset into name blob */
} SIGHASH;

typedef struct {
    unsigned short len;
    unsigned int   dataoff;  /* offset into pattern blob */
    unsigned int   nameoff;
} SIGPAT;

typedef struct {
    char          magic[4];  /* "CAVD" */
    unsigned int  version;   /* 1 or 2 */
    unsigned int  nhash;
    unsigned int  npat;
    unsigned int  patblob;   /* bytes of pattern data */
    unsigned int  nameblob;  /* bytes of name data    */
    unsigned int  built;     /* unix time of build    */
} SIGHDR;

/* Version 2 appends this right after SIGHDR. Engine 2.0 adds whole-file
 * SHA-256 hashes and PE section MD5 hashes (ClamAV .hsb / .mdb). */
typedef struct {
    unsigned int  nsha;      /* SIGSHA records (whole-file SHA-256) */
    unsigned int  nsect;     /* SIGHASH records (PE section MD5, size = raw size) */
    unsigned int  reserved[6];
} SIGHDR2;

typedef struct {
    unsigned char sha[32];
    unsigned int  size;      /* 0 = any size */
    unsigned int  nameoff;
} SIGSHA;
#pragma pack(pop)

#pragma pack(push,1)
/* In-memory lookup key: the first 8 bytes of a hash plus the size field.
 * The full record (whole hash + name offset) stays on disk and is read only
 * when a key matches, to confirm the hit and fetch the name. */
typedef struct { unsigned char pre[8]; unsigned int size; } SIGKEY;
#pragma pack(pop)

typedef struct {
    SIGHDR         hdr;
    SIGHDR2        hdr2;     /* zero for version 1 files */
    SIGKEY        *hkeys;    /* whole-file MD5 keys, in file order (sorted) */
    SIGKEY        *skeys;    /* PE section MD5 keys, in file order (sorted) */
    SIGSHA        *shas;     /* whole-file SHA-256 - few, kept whole */
    unsigned int  *sectsizes;/* distinct section sizes, sorted - lets the scanner
                                skip hashing any section no signature could match */
    unsigned int   nsectsizes;
    SIGPAT        *pats;
    unsigned char *patdata;
    /* first-byte dispatch buckets for pattern matching */
    unsigned int  *bucket[256];
    unsigned int   bucketn[256];
    /* where the on-disk tables live, for confirming hits and reading names */
    wchar_t        path[MAX_PATH];
    DWORD          off_md5, off_sect, off_names, filesize;
    BOOL           loaded;
} SIGDB;

BOOL  sigdb_load(SIGDB *db, const wchar_t *path);
void  sigdb_free(SIGDB *db);
const char *sigdb_match_hash(SIGDB *db, const unsigned char md5[16], unsigned int size);
const char *sigdb_match_sha(SIGDB *db, const unsigned char sha[32], unsigned int size);
const char *sigdb_match_sect(SIGDB *db, const unsigned char md5[16], unsigned int size);
BOOL  sigdb_has_sect_size(SIGDB *db, unsigned int size);
const char *sigdb_match_buf(SIGDB *db, const unsigned char *buf, unsigned int len);
unsigned int sigdb_count(SIGDB *db);

/* ---------------- scanner ---------------- */

enum {
    SCAN_QUICK = 0,   /* system dirs, temp, startup, memory        */
    SCAN_FULL,        /* every fixed drive, hash only              */
    SCAN_DEEP,        /* every fixed drive, hash + patterns + heur */
    SCAN_CUSTOM,      /* user-selected folder                      */
    SCAN_MEMORY,      /* running process images                    */
    SCAN_BOOT,        /* autorun/registry startup entries          */
    SCAN_VERIFY,      /* compare system files against the baseline  */
    SCAN_BASELINE     /* build the baseline snapshot               */
};

enum { DET_SIG = 0, DET_HEUR, DET_PUA, DET_MODIFIED, DET_DISPUTED };

typedef struct {
    wchar_t path[MAX_PATH*2];
    char    name[128];
    int     kind;
} DETECTION;

typedef struct {
    HWND      notify;        /* window that receives progress messages */
    int       mode;
    wchar_t   root[MAX_PATH];
    SIGDB    *db;
    volatile LONG cancel;
    volatile LONG running;
    /* stats */
    volatile LONG files;
    volatile LONG dirs;
    volatile LONG found;
    volatile LONG skipped;
    volatile LONG total;     /* estimated files to scan, 0 = unknown */
    volatile LONG counting;  /* TRUE while the pre-count pass is running */
    DWORD     started;
    BOOL      heuristics;
    BOOL      archives;
    BOOL      autoquar;
} SCANJOB;

/* messages posted to notify window */
#define WM_SCAN_FILE   (WM_APP + 1)   /* lParam = wchar_t* (free with LocalFree) */
#define WM_SCAN_HIT    (WM_APP + 2)   /* lParam = DETECTION* (free with LocalFree) */
#define WM_SCAN_DONE   (WM_APP + 3)
#define WM_RT_HIT      (WM_APP + 4)   /* lParam = DETECTION* */
#define WM_RT_EVENT    (WM_APP + 5)   /* lParam = RTEVENT*   */

DWORD WINAPI scan_thread(LPVOID param);
BOOL  hash_file_md5(const wchar_t *path, unsigned char out[16], unsigned int *size);

/* ---- engine 2.0 (engine.c) ---- */
BOOL  eng_hash_file(const wchar_t *path, unsigned char md5[16], unsigned char sha[32],
                    BOOL want_sha, unsigned int *size);
const char *eng_match_sections(SIGDB *db, const wchar_t *path);
const char *eng_match_file(SIGDB *db, const wchar_t *path,
                           unsigned char md5[16], unsigned int *size, BOOL *read_ok);

/* ---- signature trust (trust.c) ---- */
enum { TRUST_NONE = 0, TRUST_SIGNED, TRUST_MICROSOFT };
int   trust_file(const wchar_t *path, wchar_t *signer, int cch);
BOOL  known_good_hash(const unsigned char md5[16]);
int   heur_check(const wchar_t *path, const unsigned char *head, DWORD headlen,
                 DWORD filesize, char *outname, int outsz);

/* ---------------- system baseline ---------------- */

enum { BASE_UNKNOWN = 0, BASE_CLEAN, BASE_MODIFIED };
enum { REPAIR_FAILED = 0, REPAIR_DLLCACHE, REPAIR_SOURCE };

#pragma pack(push,1)
typedef struct {
    unsigned int  pathoff;
    unsigned char md5[16];
    unsigned int  size;
} BASEREC;
#pragma pack(pop)

typedef struct {
    BASEREC  *recs;
    BASEREC **byhash;
    BASEREC **bypath;
    wchar_t  *blob;
    unsigned int count, built;
    BOOL loaded;
} BASEDB;

BOOL  base_load(void);
void  base_free(void);
void  base_path(wchar_t *out, int cch);
BOOL  base_ready(void);
unsigned int base_count(void);
unsigned int base_built(void);
BOOL  base_known_hash(const unsigned char md5[16]);
int   base_check_path(const wchar_t *path, const unsigned char md5[16]);
const wchar_t *base_path_at(unsigned int i);
const unsigned char *base_md5_at(unsigned int i);
int   base_build(HWND notify, volatile LONG *cancel);
int   base_repair(const wchar_t *path);
BOOL  base_run_sfc(void);
BOOL  wfp_trusted(const wchar_t *path, const unsigned char md5[16]);

/* user exclusions (games, tools you trust) */
BOOL  excl_add(const wchar_t *path);
BOOL  excl_match(const wchar_t *path);
int   excl_list(wchar_t ***out);

/* ---------------- archive bomb guard ---------------- */

enum { ARC_OK = 0, ARC_SUSPECT, ARC_BOMB };

typedef struct {
    unsigned int       entries;
    unsigned __int64   total_in;
    unsigned __int64   total_out;
    unsigned int       ratio;      /* out:in */
    int                dupes;      /* largest count of identical members */
    unsigned int       nested;     /* archives inside this archive */
    BOOL               zip64;
    BOOL               slip;       /* ../ or absolute member path */
    char               name[64];
} ARCINFO;

extern BOOL g_arcguard;
BOOL  arc_is_archive(const wchar_t *path);
int   arc_inspect(const wchar_t *path, ARCINFO *info);

/* ---------------- quarantine ---------------- */

typedef struct {
    wchar_t orig[MAX_PATH*2];
    wchar_t stored[MAX_PATH];
    char    threat[128];
    FILETIME when;
    DWORD   size;
} QITEM;

void  quar_dir(wchar_t *out, int cch);
BOOL  quar_add(const wchar_t *path, const char *threat);
BOOL  path_excluded(const wchar_t *path);
int   quar_list(QITEM **out);          /* returns count, free with LocalFree */
BOOL  quar_restore(const QITEM *it);
BOOL  quar_delete(const QITEM *it);
void  grace_add(const wchar_t *path);      /* restored files: brief shield exemption */
BOOL  grace_active(const wchar_t *path);

/* ---------------- protection modules ---------------- */

/* --- firewall (COM, with netsh fallback) --- */
typedef struct {
    int  enabled;      /* 1 on, 0 off, -1 unknown */
    BOOL block_all;    /* "don't allow exceptions" */
    BOOL notify_off;
    int  profile;      /* NET_FW_PROFILE_TYPE */
    BOOL com;          /* TRUE if the COM API answered */
} FWSTATE;

typedef struct {
    wchar_t name[128];
    wchar_t path[MAX_PATH];
    BOOL    enabled;
    int     scope;
} FWAPP;

typedef struct {
    wchar_t name[128];
    int     port;
    BOOL    tcp;
    BOOL    enabled;
} FWPORT;

BOOL  fw_available(void);
BOOL  fw_get_state(FWSTATE *st);
BOOL  fw_set(BOOL on);
BOOL  fw_set_block_all(BOOL on);
BOOL  fw_set_notifications(BOOL on);
int   fw_list_apps(FWAPP **out);       /* free with LocalFree */
BOOL  fw_app_set(const wchar_t *path, const wchar_t *name, BOOL enabled);
BOOL  fw_app_remove(const wchar_t *path);
BOOL  fw_block_app(const wchar_t *exe);
int   fw_list_ports(FWPORT **out);     /* free with LocalFree */
BOOL  fw_port_remove(int port, BOOL tcp);
int   fw_harden(void);
int   fw_status(void);

BOOL  hosts_block_count(int *blocked);
BOOL  hosts_import(const wchar_t *listfile, int *added);
BOOL  hosts_add(const char *domain);
BOOL  hosts_clear(void);

/* --- live monitoring --- */
enum { RT_INFO = 0, RT_WARN, RT_THREAT };

typedef struct {
    int        sev;
    SYSTEMTIME when;
    wchar_t    what[128];
    wchar_t    detail[MAX_PATH];
} RTEVENT;

typedef struct {
    BOOL  active;
    int   watchers;
    long  checked;
    long  blocked;
    long  procs;
    long  autoruns;
    DWORD uptime;      /* seconds */
    BOOL  kill;
} RTSTATS;

BOOL  rt_start(HWND notify, SIGDB *db);
void  rt_stop(void);
BOOL  rt_active(void);
void  rt_stats(RTSTATS *s);
void  rt_set_kill(BOOL on);

/* ---------------- OS compatibility ----------------
 * CarrotAV targets the whole classic NT desktop family (NT 4.0, 2000, XP,
 * XP x64) from ONE binary. Anything that isn't present on the oldest target
 * must be resolved at runtime with GetProcAddress instead of imported
 * statically - a missing static import makes the exe fail to load entirely,
 * with no chance to fall back or explain itself. */

enum {
    OS_UNKNOWN = 0,
    OS_NT4,
    OS_2000,
    OS_XP,          /* also XP x64 / 2003 */
    OS_NEWER
};

int   os_kind(void);                 /* one of the OS_* values */
const wchar_t *os_name(void);        /* human-readable, for the System tab */
BOOL  os_has_wfp(void);              /* Windows File Protection / dllcache */
BOOL  os_has_firewall(void);         /* XP SP2+ firewall COM API */

/* SHGetFolderPathW lives in shell32 on XP but in shfolder.dll on 2000/NT4,
 * so it is resolved at runtime. Same signature as the real thing. */
HRESULT compat_folder_path(int csidl, wchar_t *out);

/* ---------------- Windows 2000 firewall ----------------
 * 2000 has no Windows Firewall; this drives the built-in iphlpapi packet
 * filter instead. Inbound port blocking only - no per-program rules. */
typedef struct { int port; BOOL tcp; } FW2KPORT;

enum { FW2K_NONE = 0,
       FW2K_PF,        /* iphlpapi packet filter: list = ports to BLOCK */
       FW2K_TCPIP };   /* registry TCP/IP filtering: list = ports to ALLOW */

int   fw2k_method(void);
BOOL  fw2k_reboot_needed(void);
void  fw2k_defaults(void);
void  fw2k_restore_permit_all(void);

BOOL  fw2k_available(void);
const wchar_t *fw2k_why(void);      /* reason it is unavailable, "" if fine */
void  fw2k_start(void);
void  fw2k_stop(void);
void  fw2k_tick(void);
BOOL  fw2k_enabled(void);
BOOL  fw2k_set_enabled(BOOL on);
int   fw2k_bound(void);
DWORD fw2k_error(void);
int   fw2k_ports(const FW2KPORT **out);
BOOL  fw2k_add_port(int port, BOOL tcp);
BOOL  fw2k_remove_port(int port, BOOL tcp);
void  fw2k_restore_defaults(void);
BOOL  fw2k_listening(int port, BOOL tcp);
const wchar_t *fw2k_port_name(int port, BOOL tcp);

/* ---------------- misc helpers ---------------- */

void  app_dir(wchar_t *out, int cch);
void  log_line(const wchar_t *fmt, ...);
BOOL  is_pe(const unsigned char *head, DWORD len);
double entropy_of(const unsigned char *buf, DWORD len);

#endif /* AV_H */

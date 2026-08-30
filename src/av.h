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
#define AV_VERSION  L"1.8"
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
    unsigned int  version;   /* 1 */
    unsigned int  nhash;
    unsigned int  npat;
    unsigned int  patblob;   /* bytes of pattern data */
    unsigned int  nameblob;  /* bytes of name data    */
    unsigned int  built;     /* unix time of build    */
} SIGHDR;
#pragma pack(pop)

typedef struct {
    SIGHDR         hdr;
    SIGHASH       *hashes;   /* sorted by md5 */
    SIGPAT        *pats;
    unsigned char *patdata;
    char          *names;
    /* first-byte dispatch buckets for pattern matching */
    unsigned int  *bucket[256];
    unsigned int   bucketn[256];
    BOOL           loaded;
} SIGDB;

BOOL  sigdb_load(SIGDB *db, const wchar_t *path);
void  sigdb_free(SIGDB *db);
const char *sigdb_match_hash(SIGDB *db, const unsigned char md5[16], unsigned int size);
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

/* ---------------- misc helpers ---------------- */

void  app_dir(wchar_t *out, int cch);
void  log_line(const wchar_t *fmt, ...);
BOOL  is_pe(const unsigned char *head, DWORD len);
double entropy_of(const unsigned char *buf, DWORD len);

#endif /* AV_H */

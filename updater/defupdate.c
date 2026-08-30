/* defupdate.c - CarrotAV definition updater for Windows XP.
 *
 * Bundles its own TLS 1.2 (mbedTLS) so it can talk to modern HTTPS servers
 * that XP's own SCHANNEL.DLL cannot. Downloads ClamAV's main.cvd and daily.cvd
 * straight from the XP machine, unpacks them, and compiles carrot.cdb - the
 * same output get_defs.py produces, but with no Python and no second computer.
 *
 * Console app on purpose: the CarrotAV button launches it and you watch it
 * work. It writes carrot.cdb next to CarrotAV's defs folder and exits.
 *
 * Build: see build_defupdate.sh - links against the XP-targeted libmbedtls_xp.a.
 *
 * TLS note: this ships a CA bundle (cacerts.pem) and its own mbedTLS. Both may
 * need refreshing every year or two as servers rotate roots/ciphers. When the
 * download starts failing with a cert or handshake error, rebuild with a fresh
 * mbedTLS and CA bundle - see UPDATING_TLS.txt.
 */
#define WINVER       0x0501
#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <xpconfig.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

/* ---- ClamAV download endpoints (HTTPS, TLS 1.2) ---- */
/* Microsoft's public ClamAV mirror. ClamAV's own database.clamav.net sits
 * behind Cloudflare, which returns 403 to anything that isn't a current,
 * rate-limited FreshClam client - so a direct fetch from XP is blocked by
 * policy, not by the network. Microsoft mirrors the exact same .cvd files
 * (for their own Defender/tooling) on an open, unthrottled CDN with a normal
 * cert chain XP's bundled TLS validates. Same databases, no gatekeeping. */
#define DL_HOST   "packages.microsoft.com"
#define DL_PORT   "443"
static const char *CVDS[]  = { "main.cvd", "daily.cvd", NULL };
#define DL_PATHDIR "/clamav/"

#define MIN_PAT      32
#define MAX_PAT      256
#define BUF_SZ       16384

static mbedtls_x509_crt   g_cacert;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_entropy_context  g_entropy;

static void die(const char *msg)
{
    fprintf(stderr, "\n  ERROR: %s\n", msg);
    printf("\n  Press Enter to close...");
    getchar();
    exit(1);
}

/* ------------------------------------------------------------------ TLS GET
 * Streams an HTTPS response body to a file. Follows no redirects - the CVD
 * URLs are stable - and validates the server certificate against our bundle.
 */
static int https_download(const char *host, const char *port,
                          const char *path, const char *outfile)
{
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config  conf;
    int ret, in_body = 0;
    char req[512];
    unsigned char buf[BUF_SZ];
    FILE *out = NULL;
    long long total = 0, content_len = -1;
    char errbuf[128];

    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    printf("  connecting to %s ...\n", host);
    if ((ret = mbedtls_net_connect(&net, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        printf("  connect failed (-0x%04x)\n", -ret);
        return -1;
    }

    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf("  ssl config failed\n"); return -1;
    }
    /* Real certificate validation - refuse a bad or unknown chain. */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &g_cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_drbg);
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                        MBEDTLS_SSL_MINOR_VERSION_3); /* TLS 1.2 */

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) { printf("  ssl setup failed\n"); return -1; }
    if ((ret = mbedtls_ssl_set_hostname(&ssl, host)) != 0) { printf("  SNI failed\n"); return -1; }
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

    printf("  TLS handshake ...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            printf("  handshake failed: %s (-0x%04x)\n", errbuf, -ret);
            goto cleanup_fail;
        }
    }

    /* cert must verify */
    {
        uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
        if (flags != 0) {
            char vrfy[256];
            mbedtls_x509_crt_verify_info(vrfy, sizeof(vrfy), "  ! ", flags);
            printf("  certificate rejected:\n%s", vrfy);
            goto cleanup_fail;
        }
    }

    wsprintfA(req,
        "GET %s%s HTTP/1.1\r\nHost: %s\r\n"
        "User-Agent: CarrotAV-defupdate/1.0\r\n"
        "Connection: close\r\n\r\n", DL_PATHDIR, path, host);
    {
        size_t off = 0, n = strlen(req);
        while (off < n) {
            ret = mbedtls_ssl_write(&ssl, (unsigned char*)req + off, n - off);
            if (ret <= 0) { printf("  send failed\n"); goto cleanup_fail; }
            off += ret;
        }
    }

    out = fopen(outfile, "wb");
    if (!out) { printf("  cannot write %s\n", outfile); goto cleanup_fail; }

    printf("  downloading %s ", path);
    for (;;) {
        ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) break;
        if (ret < 0) { printf("\n  read error (-0x%04x)\n", -ret); goto cleanup_fail; }
        if (ret == 0) break;

        if (!in_body) {
            /* find the end of headers within this chunk */
            unsigned char *p = (unsigned char*)strstr((char*)buf, "\r\n\r\n");
            char *cl = strstr((char*)buf, "Content-Length:");
            if (cl) content_len = atoll(cl + 15);
            if (strstr((char*)buf, " 200") == NULL &&
                strstr((char*)buf, "200 OK") == NULL) {
                /* not a 200 - dump status line */
                char *eol = strstr((char*)buf, "\r\n");
                if (eol) *eol = 0;
                printf("\n  server said: %s\n", buf);
                goto cleanup_fail;
            }
            if (p) {
                int hlen = (int)(p - buf) + 4;
                int bodylen = ret - hlen;
                if (bodylen > 0) fwrite(p + 4, 1, bodylen, out);
                total += bodylen;
                in_body = 1;
            }
        } else {
            fwrite(buf, 1, ret, out);
            total += ret;
            if ((total % (1024*1024)) < BUF_SZ) { printf("."); fflush(stdout); }
        }
    }
    fclose(out); out = NULL;
    printf(" %.1f MB\n", total / 1048576.0);

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&net);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    return (total > 0) ? 0 : -1;

cleanup_fail:
    if (out) fclose(out);
    mbedtls_net_free(&net);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    return -1;
}

/* --------------------------------------------------- CVD unpack + compile
 * A .cvd is a 512-byte ASCII header, then a gzipped tar. We shell out to the
 * bundled gzip/tar? No - XP has neither. Instead we do the minimal gunzip via
 * zlib (compiled in) and read the tar directly. To keep this file focused, the
 * unpack + parse + compile is in defs_build.c.
 */
extern int cvd_compile(const char **cvd_files, const char *out_cdb);

/* --------------------------------------------------------------- init TLS */
static int tls_init(const char *cabundle)
{
    int ret;
    const char *pers = "carrotav-defupdate";

    mbedtls_x509_crt_init(&g_cacert);
    mbedtls_ctr_drbg_init(&g_drbg);
    mbedtls_entropy_init(&g_entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                    (const unsigned char*)pers, strlen(pers))) != 0) {
        printf("  RNG seed failed\n"); return -1;
    }
    {
        FILE *cf = fopen(cabundle, "rb");
        long n; unsigned char *pem;
        if (!cf) {
            printf("  could not open CA bundle '%s'\n", cabundle);
            printf("  cacerts.pem must sit next to defupdate.exe\n");
            return -1;
        }
        fseek(cf, 0, SEEK_END); n = ftell(cf); fseek(cf, 0, SEEK_SET);
        pem = (unsigned char*)malloc(n + 1);
        if (!pem || fread(pem, 1, n, cf) != (size_t)n) { fclose(cf); return -1; }
        pem[n] = 0;                       /* PEM parser needs NUL termination */
        fclose(cf);
        ret = mbedtls_x509_crt_parse(&g_cacert, pem, n + 1);
        free(pem);
        if (ret < 0) {
            char eb[128]; mbedtls_strerror(ret, eb, sizeof(eb));
            printf("  CA bundle parse failed: %s (-0x%04x)\n", eb, -ret);
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    char exedir[MAX_PATH], ca[MAX_PATH], defsdir[MAX_PATH];
    char cvdpaths[2][MAX_PATH];
    const char *cvd_files[3];
    char *p;
    int i, got = 0;

    printf("\n  CarrotAV definition updater (TLS 1.2, no Python needed)\n");
    printf("  ======================================================\n\n");

    GetModuleFileNameA(NULL, exedir, MAX_PATH);
    p = strrchr(exedir, '\\'); if (p) *p = 0;

    wsprintfA(ca, "%s\\cacerts.pem", exedir);

    /* defs folder: ..\defs relative to tools\, or a path arg */
    if (argc > 1) {
        lstrcpynA(defsdir, argv[1], MAX_PATH);
    } else {
        char parent[MAX_PATH];
        lstrcpynA(parent, exedir, MAX_PATH);
        p = strrchr(parent, '\\'); if (p) *p = 0;   /* drop \tools */
        wsprintfA(defsdir, "%s\\defs", parent);
    }
    CreateDirectoryA(defsdir, NULL);

    if (tls_init(ca) != 0) die("TLS init failed - see messages above.");

    printf("  Step 1/3  downloading ClamAV databases\n");
    for (i = 0; CVDS[i]; i++) {
        wsprintfA(cvdpaths[i], "%s\\%s", defsdir, CVDS[i]);
        if (https_download(DL_HOST, DL_PORT, CVDS[i], cvdpaths[i]) == 0) {
            cvd_files[got++] = cvdpaths[i];
        } else {
            printf("  %s failed.\n", CVDS[i]);
        }
    }
    cvd_files[got] = NULL;

    if (got == 0) {
        die("No databases downloaded. If this is a certificate or handshake\n"
            "  error, the bundled TLS may need refreshing (see UPDATING_TLS.txt),\n"
            "  or the network blocks port 443 to packages.microsoft.com.");
    }

    printf("\n  Step 2/3  compiling carrot.cdb (hash signatures only)\n");
    {
        char outcdb[MAX_PATH];
        wsprintfA(outcdb, "%s\\carrot.cdb", defsdir);
        if (cvd_compile(cvd_files, outcdb) != 0)
            die("Compile failed.");
        printf("\n  Step 3/3  done\n");
        printf("  Wrote %s\n", outcdb);
    }

    /* tidy the big .cvd downloads */
    for (i = 0; i < got; i++) DeleteFileA(cvd_files[i]);

    printf("\n  Definitions updated. In CarrotAV, choose Definitions -> Reload\n");
    printf("  (or just reopen it).\n\n");
    printf("  Press Enter to close...");
    getchar();
    return 0;
}

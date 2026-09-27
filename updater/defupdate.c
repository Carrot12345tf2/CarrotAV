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
#include "zlib.h"

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

/* --------------------------------------------------- app update check
 * Read the newest CarrotAV release tag from GitHub WITHOUT parsing JSON.
 * github.com/<repo>/releases/latest issues a 302 redirect to
 * .../releases/tag/<tag>. We do the request, don't follow the redirect, and
 * pull the tag out of the Location: header. XP can't reach GitHub with its
 * own TLS, but our bundled mbedTLS can - same engine that fetches the defs.
 */
#define GH_HOST  "github.com"
#define GH_PATH  "/Carrot12345tf2/CarrotAV/releases/latest"
#define GH_RELEASES_URL "https://github.com/Carrot12345tf2/CarrotAV/releases"

/* Fetch response headers only; copy the redirect tag into out. Returns 1 on
 * success (out holds the tag, e.g. "1.8"), 0 on any failure. */
static int github_latest_tag(char *out, int outcap)
{
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config  conf;
    int ret, ok = 0;
    char req[512], buf[4096];
    int total = 0, rd;

    out[0] = 0;
    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    if (mbedtls_net_connect(&net, GH_HOST, "443", MBEDTLS_NET_PROTO_TCP) != 0) goto done;
    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) goto done;
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &g_cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_drbg);
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                        MBEDTLS_SSL_MINOR_VERSION_3);
    if (mbedtls_ssl_setup(&ssl, &conf) != 0) goto done;
    if (mbedtls_ssl_set_hostname(&ssl, GH_HOST) != 0) goto done;
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) goto done;
    if (mbedtls_ssl_get_verify_result(&ssl) != 0) goto done;

    wsprintfA(req,
        "GET %s HTTP/1.1\r\nHost: %s\r\n"
        "User-Agent: CarrotAV-defupdate/1.0\r\n"
        "Accept: text/html\r\nConnection: close\r\n\r\n", GH_PATH, GH_HOST);
    {
        int off = 0, n = (int)strlen(req);
        while (off < n) {
            ret = mbedtls_ssl_write(&ssl, (unsigned char*)req + off, n - off);
            if (ret <= 0) goto done;
            off += ret;
        }
    }
    /* read just enough to capture the headers (Location is near the top) */
    while (total < (int)sizeof(buf) - 1) {
        ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf + total, sizeof(buf) - 1 - total);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret <= 0) break;
        total += ret;
        if (strstr(buf, "\r\n\r\n")) break;   /* end of headers */
    }
    buf[total] = 0;

    /* find "Location: https://github.com/.../releases/tag/<TAG>" */
    {
        char *loc = strstr(buf, "location:");
        if (!loc) loc = strstr(buf, "Location:");
        if (loc) {
            char *tag = strstr(loc, "/tag/");
            if (tag) {
                tag += 5;
                int i = 0;
                while (tag[i] && tag[i] != '\r' && tag[i] != '\n' &&
                       tag[i] != ' ' && i < outcap - 1) {
                    out[i] = tag[i]; i++;
                }
                out[i] = 0;
                if (i > 0) ok = 1;
            }
        }
    }
done:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&net);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    return ok;
}

/* dotted-version compare: returns <0, 0, >0 for a<b, a==b, a>b. Skips a
 * leading 'v' if present. 1.10 > 1.9. */
static int ver_cmp(const char *a, const char *b)
{
    if (*a == 'v' || *a == 'V') a++;
    if (*b == 'v' || *b == 'V') b++;
    while (*a || *b) {
        int na = 0, nb = 0;
        while (*a >= '0' && *a <= '9') na = na*10 + (*a++ - '0');
        while (*b >= '0' && *b <= '9') nb = nb*10 + (*b++ - '0');
        if (na != nb) return na < nb ? -1 : 1;
        if (*a == '.') a++;
        if (*b == '.') b++;
        if (!*a && !*b) break;
    }
    return 0;
}

/* --------------------------------------------------- app self-update
 * Downloads the release zip from GitHub over our own TLS (XP's IE can't
 * reach GitHub anymore), follows GitHub's redirect to its asset CDN, pulls
 * the Setup .exe out of the zip and leaves it in <app>\update\ for the GUI
 * to launch. Not %TEMP%: the shield flags executables dropped there. */

static int split_https_url(const char *url, char *host, int hcap,
                           char *port, int pcap, const char **path)
{
    const char *h, *e, *c;
    int n;
    if (_strnicmp(url, "https://", 8) != 0) return 0;
    h = url + 8;
    e = h; while (*e && *e != '/' && *e != '?') e++;
    c = h; while (c < e && *c != ':') c++;
    n = (int)(c - h);
    if (n <= 0 || n >= hcap) return 0;
    memcpy(host, h, n); host[n] = 0;
    if (c < e) {
        n = (int)(e - c - 1);
        if (n <= 0 || n >= pcap) return 0;
        memcpy(port, c + 1, n); port[n] = 0;
    } else lstrcpynA(port, "443", pcap);
    *path = *e ? e : "/";
    return 1;
}

/* GET url into outfile, following up to 5 redirects. Headers are read in
 * full before anything is interpreted, and Content-Length is enforced. */
static int https_get_file(const char *url_in, const char *outfile)
{
    char url[4096];
    int hop;
    lstrcpynA(url, url_in, sizeof(url));

    for (hop = 0; hop < 6; hop++) {
        mbedtls_net_context net;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config  conf;
        char host[256], port[8], *req = NULL, *hdr = NULL;
        const char *path;
        int ret, hlen = 0, status = 0, redirected = 0, ok = 0;
        long long clen = -1, total = 0;
        FILE *out = NULL;
        const int HCAP = 32768;

        if (!split_https_url(url, host, sizeof(host), port, sizeof(port), &path)) {
            printf("  bad URL\n"); return -1;
        }
        mbedtls_net_init(&net); mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&conf);

        if (mbedtls_net_connect(&net, host, port, MBEDTLS_NET_PROTO_TCP) != 0) {
            printf("  could not connect to %s\n", host); goto hop_done;
        }
        if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) goto hop_done;
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf, &g_cacert, NULL);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &g_drbg);
        mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                            MBEDTLS_SSL_MINOR_VERSION_3);
        if (mbedtls_ssl_setup(&ssl, &conf) != 0) goto hop_done;
        if (mbedtls_ssl_set_hostname(&ssl, host) != 0) goto hop_done;
        mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);
        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                char eb[128]; mbedtls_strerror(ret, eb, sizeof(eb));
                printf("  TLS handshake with %s failed: %s\n", host, eb);
                goto hop_done;
            }
        }
        if (mbedtls_ssl_get_verify_result(&ssl) != 0) {
            printf("  certificate for %s rejected\n", host); goto hop_done;
        }

        req = (char*)malloc(strlen(path) + strlen(host) + 256);
        if (!req) goto hop_done;
        sprintf(req, "GET %s HTTP/1.1\r\nHost: %s\r\n"
                     "User-Agent: CarrotAV-defupdate/1.0\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n", path, host);
        {
            size_t off = 0, n = strlen(req);
            while (off < n) {
                ret = mbedtls_ssl_write(&ssl, (unsigned char*)req + off, n - off);
                if (ret <= 0) goto hop_done;
                off += ret;
            }
        }

        /* read until the blank line that ends the headers */
        hdr = (char*)malloc(HCAP + 1);
        if (!hdr) goto hop_done;
        for (;;) {
            char *end;
            if (hlen >= HCAP) { printf("  headers too large\n"); goto hop_done; }
            ret = mbedtls_ssl_read(&ssl, (unsigned char*)hdr + hlen, HCAP - hlen);
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (ret <= 0) { printf("  connection closed early\n"); goto hop_done; }
            hlen += ret; hdr[hlen] = 0;
            end = strstr(hdr, "\r\n\r\n");
            if (end) {
                int body_off = (int)(end - hdr) + 4, i;
                char *line;
                end[2] = 0;                       /* headers only, CRLF-separated */
                if (strncmp(hdr, "HTTP/1.", 7) == 0) status = atoi(hdr + 9);
                for (line = hdr; line && *line; ) {
                    char *nl = strstr(line, "\r\n");
                    if (nl) *nl = 0;
                    if (!_strnicmp(line, "Content-Length:", 15)) clen = _atoi64(line + 15);
                    if (!_strnicmp(line, "Location:", 9) && status >= 300 && status < 400) {
                        char *v = line + 9;
                        while (*v == ' ') v++;
                        if (*v == '/') {                 /* relative: same host */
                            sprintf(url, "https://%s%s", host, v);
                        } else lstrcpynA(url, v, sizeof(url));
                        redirected = 1;
                    }
                    line = nl ? nl + 2 : NULL;
                }
                if (redirected) goto hop_done;
                if (status != 200) {
                    printf("  server said HTTP %d\n", status); goto hop_done;
                }
                out = fopen(outfile, "wb");
                if (!out) { printf("  cannot write %s\n", outfile); goto hop_done; }
                i = hlen - body_off;
                if (i > 0) { fwrite(hdr + body_off, 1, i, out); total += i; }
                break;
            }
        }

        /* body */
        {
            unsigned char buf[BUF_SZ];
            long long next_dot = 1024*1024;
            for (;;) {
                if (clen >= 0 && total >= clen) break;
                ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
                if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
                if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) break;
                if (ret < 0) { printf("\n  read error (-0x%04x)\n", -ret); goto hop_done; }
                if (fwrite(buf, 1, ret, out) != (size_t)ret) {
                    printf("\n  disk write failed\n"); goto hop_done;
                }
                total += ret;
                if (total >= next_dot) { printf("."); fflush(stdout); next_dot += 1024*1024; }
            }
        }
        printf(" %.1f MB\n", total / 1048576.0);
        if (total <= 0 || (clen >= 0 && total != clen)) {
            printf("  download incomplete\n"); goto hop_done;
        }
        ok = 1;

hop_done:
        if (out) { fclose(out); if (!ok) DeleteFileA(outfile); }
        free(req); free(hdr);
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_net_free(&net); mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf);
        if (ok) return 0;
        if (!redirected) return -1;
        printf("  -> redirect\n");
    }
    printf("  too many redirects\n");
    return -1;
}

static unsigned rd16(const unsigned char *p) { return p[0] | (p[1] << 8); }
static unsigned long rd32(const unsigned char *p)
{ return (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
         ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24); }

/* Pull the first *.exe out of a zip into outexe. Stored or deflated; CRC
 * checked. Returns 0 on success. */
static int zip_extract_exe(const char *zippath, const char *outexe)
{
    FILE *f = fopen(zippath, "rb"), *o = NULL;
    unsigned char *z = NULL, *outbuf = NULL;
    long n, i, eocd = -1;
    unsigned long cd_off, cd_cnt, k, pos;
    int rc = -1;

    if (!f) return -1;
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n < 22 || n > 200L*1024*1024) { fclose(f); return -1; }
    z = (unsigned char*)malloc(n);
    if (!z || fread(z, 1, n, f) != (size_t)n) { fclose(f); free(z); return -1; }
    fclose(f);

    for (i = n - 22; i >= 0 && i >= n - 22 - 65535; i--)
        if (rd32(z + i) == 0x06054b50) { eocd = i; break; }
    if (eocd < 0) goto out;
    cd_cnt = rd16(z + eocd + 10);
    cd_off = rd32(z + eocd + 16);
    pos = cd_off;

    for (k = 0; k < cd_cnt; k++) {
        unsigned method, nlen, xlen, clen_, lnlen, lxlen;
        unsigned long csize, usize, crc, loff, dataoff;
        const char *name;
        if (pos + 46 > (unsigned long)n || rd32(z + pos) != 0x02014b50) goto out;
        method = rd16(z + pos + 10);
        crc    = rd32(z + pos + 16);
        csize  = rd32(z + pos + 20);
        usize  = rd32(z + pos + 24);
        nlen   = rd16(z + pos + 28);
        xlen   = rd16(z + pos + 30);
        clen_  = rd16(z + pos + 32);
        loff   = rd32(z + pos + 42);
        name   = (const char*)z + pos + 46;
        if (pos + 46 + nlen > (unsigned long)n) goto out;
        pos += 46 + nlen + xlen + clen_;

        if (nlen < 5 || _strnicmp(name + nlen - 4, ".exe", 4) != 0) continue;
        if (loff + 30 > (unsigned long)n || rd32(z + loff) != 0x04034b50) goto out;
        lnlen = rd16(z + loff + 26);
        lxlen = rd16(z + loff + 28);
        dataoff = loff + 30 + lnlen + lxlen;
        if (dataoff + csize > (unsigned long)n || usize > 200UL*1024*1024) goto out;

        outbuf = (unsigned char*)malloc(usize ? usize : 1);
        if (!outbuf) goto out;
        if (method == 0) {
            if (csize != usize) goto out;
            memcpy(outbuf, z + dataoff, usize);
        } else if (method == 8) {
            z_stream s;
            memset(&s, 0, sizeof(s));
            if (inflateInit2(&s, -MAX_WBITS) != Z_OK) goto out;
            s.next_in = z + dataoff;  s.avail_in = csize;
            s.next_out = outbuf;      s.avail_out = usize;
            k = inflate(&s, Z_FINISH);
            inflateEnd(&s);
            if (k != Z_STREAM_END || s.total_out != usize) goto out;
        } else goto out;

        if (crc32(0L, outbuf, usize) != crc) { printf("  zip CRC mismatch\n"); goto out; }
        o = fopen(outexe, "wb");
        if (!o) goto out;
        if (fwrite(outbuf, 1, usize, o) != usize) { fclose(o); DeleteFileA(outexe); goto out; }
        fclose(o);
        rc = 0;
        goto out;
    }
out:
    free(z); free(outbuf);
    return rc;
}

/* Download CarrotAV-<tag>-Setup.zip and leave the Setup exe in updir.
 * Writes the exe path into exe_out. Returns 0 on success. */
static int fetch_app_update(const char *tag, const char *updir,
                            char *exe_out, int cap)
{
    char url[512], zip[MAX_PATH];
    wsprintfA(url, "https://github.com/Carrot12345tf2/CarrotAV/releases/download/"
                   "%s/CarrotAV-%s-Setup.zip", tag, tag);
    wsprintfA(zip, "%s\\CarrotAV-%s-Setup.zip", updir, tag);
    wsprintfA(exe_out, "%s\\CarrotAV-%s-Setup.exe", updir, tag);
    (void)cap;

    printf("  downloading CarrotAV-%s-Setup.zip ", tag);
    if (https_get_file(url, zip) != 0) return -1;
    printf("  unpacking installer ...\n");
    if (zip_extract_exe(zip, exe_out) != 0) {
        DeleteFileA(zip);
        printf("  could not unpack the installer\n");
        return -1;
    }
    DeleteFileA(zip);
    return 0;
}

/* wipe leftovers from a previous self-update */
static void clean_update_dir(const char *updir)
{
    char pat[MAX_PATH], f[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    wsprintfA(pat, "%s\\*.*", updir);
    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        wsprintfA(f, "%s\\%s", updir, fd.cFileName);
        DeleteFileA(f);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int main(int argc, char **argv)
{
    char exedir[MAX_PATH], ca[MAX_PATH], defsdir[MAX_PATH];
    char cvdpaths[2][MAX_PATH];
    const char *cvd_files[3];
    char *p;
    int i, got = 0;
    char newtag[32] = "";

    printf("\n  CarrotAV definition updater (TLS 1.2, no Python needed)\n");
    printf("  ======================================================\n\n");

    GetModuleFileNameA(NULL, exedir, MAX_PATH);
    p = strrchr(exedir, '\\'); if (p) *p = 0;

    wsprintfA(ca, "%s\\cacerts.pem", exedir);

    /* defs folder: ..\defs relative to tools\, or the first non-flag arg */
    {
        const char *defarg = NULL;
        int j;
        for (j = 1; j < argc; j++)
            if (argv[j][0] != '-') { defarg = argv[j]; break; }
        if (defarg) {
            lstrcpynA(defsdir, defarg, MAX_PATH);
        } else {
            char parent[MAX_PATH];
            lstrcpynA(parent, exedir, MAX_PATH);
            p = strrchr(parent, '\\'); if (p) *p = 0;   /* drop \tools */
            wsprintfA(defsdir, "%s\\defs", parent);
        }
    }
    CreateDirectoryA(defsdir, NULL);

    if (tls_init(ca) != 0) die("TLS init failed - see messages above.");

    /* App-update check. When the main app passes --ver=<current>, we compare
     * against GitHub's latest release tag and write the result to
     * <defsdir>\..\update_check.txt, which the GUI reads to decide whether to
     * offer an update. We also print human-readable status to the console. */
    {
        const char *myver = NULL;
        int j;
        for (j = 1; j < argc; j++)
            if (!strncmp(argv[j], "--ver=", 6)) myver = argv[j] + 6;

        if (myver) {
            char tag[32], respath[MAX_PATH];
            FILE *rf;
            wsprintfA(respath, "%s\\update_check.txt", exedir);
            printf("  Checking for a newer CarrotAV release ...\n");
            rf = fopen(respath, "w");
            if (github_latest_tag(tag, sizeof(tag))) {
                if (ver_cmp(myver, tag) < 0) {
                    printf("  A newer CarrotAV (%s) is available; you have %s.\n\n",
                           tag, myver);
                    if (rf) fprintf(rf, "update=%s\n", tag);
                    lstrcpynA(newtag, tag, sizeof(newtag));
                } else {
                    printf("  CarrotAV is up to date (%s).\n\n", myver);
                    if (rf) fprintf(rf, "current=%s\n", myver);
                }
            } else {
                printf("  (could not reach GitHub to check the app version)\n\n");
                if (rf) fprintf(rf, "error=unreachable\n");
            }
            if (rf) fclose(rf);
        }
    }


    for (i = 0; CVDS[i]; i++) {
        wsprintfA(cvdpaths[i], "%s\\%s", defsdir, CVDS[i]);
        if (https_download(DL_HOST, DL_PORT, CVDS[i], cvdpaths[i]) == 0) {
            cvd_files[got++] = cvdpaths[i];
        } else {
            printf("  %s failed.\n", CVDS[i]);
        }
    }
    cvd_files[got] = NULL;

    {
        int defs_ok = 0;
        if (got == 0) {
            printf("\n  No databases downloaded. If this is a certificate or handshake\n"
                   "  error, the bundled TLS may need refreshing (see UPDATING_TLS.txt),\n"
                   "  or the network blocks port 443 to packages.microsoft.com.\n");
        } else {
            char outcdb[MAX_PATH];
            printf("\n  Step 2/3  compiling carrot.cdb\n");
            wsprintfA(outcdb, "%s\\carrot.cdb", defsdir);
            if (cvd_compile(cvd_files, outcdb) != 0) {
                printf("\n  Compile failed.\n");
            } else {
                printf("\n  Step 3/3  done\n");
                printf("  Wrote %s\n", outcdb);
                defs_ok = 1;
            }
            /* tidy the big .cvd downloads */
            for (i = 0; i < got; i++) DeleteFileA(cvd_files[i]);
        }

        /* App update: now that the defs are done, fetch the new installer
         * here in the console. The GUI offers to run it when we exit. */
        if (newtag[0]) {
            char appdir[MAX_PATH], updir[MAX_PATH], setup[MAX_PATH], respath[MAX_PATH];
            lstrcpynA(appdir, exedir, MAX_PATH);
            p = strrchr(appdir, '\\'); if (p) *p = 0;      /* drop \tools */
            wsprintfA(updir, "%s\\update", appdir);
            CreateDirectoryA(updir, NULL);
            clean_update_dir(updir);
            printf("\n  App update  CarrotAV %s\n", newtag);
            if (fetch_app_update(newtag, updir, setup, MAX_PATH) == 0) {
                FILE *rf;
                wsprintfA(respath, "%s\\update_check.txt", exedir);
                rf = fopen(respath, "a");
                if (rf) { fprintf(rf, "installer=%s\n", setup); fclose(rf); }
                printf("  Ready: %s\n", setup);
                printf("  CarrotAV will install it when you close this window.\n");
            } else {
                printf("  App update download failed - your current version keeps working.\n");
            }
        }

        if (defs_ok)
            printf("\n  Definitions updated.\n\n");
        else
            printf("\n  Definitions were NOT updated this time.\n\n");
        printf("  Press Enter to close...");
        getchar();
        return defs_ok ? 0 : 1;
    }
}

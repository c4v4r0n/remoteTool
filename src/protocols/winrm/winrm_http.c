/*
 * libcurl wrapper for the WinRM back-end.
 *
 * Two operating modes share one curl easy handle (per session,
 * worker-thread owned):
 *
 *   1) "Plain" auth: Basic, or NTLM-over-HTTPS. libcurl drives the
 *      WWW-Authenticate dance via CURLAUTH_BASIC / CURLAUTH_NTLM and
 *      our payload travels as a normal SOAP envelope.
 *
 *   2) "Manual NTLM with WS-Man sealing": NTLM-over-HTTP. libcurl's
 *      built-in NTLM authenticates fine, but Windows demands SPNEGO
 *      message-level encryption when AllowUnencrypted=false (the
 *      default). libcurl can't seal payloads because it doesn't
 *      expose the negotiated session key. We therefore drive the
 *      Type1/Type2/Type3 handshake ourselves under CURLAUTH_NONE,
 *      then on every subsequent request wrap the SOAP body in the
 *      multipart/encrypted format described in [MS-WSMV] 2.2.9.1.
 *
 * Connection management for mode 2:
 *   - All requests on a session use the same curl handle, so libcurl
 *     reuses the underlying TCP connection from its pool.
 *   - NTLM authentication is connection-scoped on the server side.
 *     If the connection drops we'd need to re-authenticate; for now
 *     a connection drop surfaces as an HTTP 401 / curl error and the
 *     UI shows the corresponding state.
 *
 * Aborting: close() flips an atomic stop flag in the WinRM context;
 * the curl progress callback observes it and aborts the in-flight
 * POST. Same mechanism for both modes.
 */

#include "protocols/winrm/winrm_http.h"
#include "protocols/winrm/winrm_ntlm.h"
#include "protocols/winrm/winrm_crypto.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero, strncasecmp */

#include <curl/curl.h>

#define RT_WINRM_USER_AGENT      "remoteTool-WinRM/1.0"
#define RT_WINRM_TIMEOUT_SEC     60L
#define RT_WINRM_CONNECT_TIMEOUT 15L

struct rt_winrm_http {
    char                 *endpoint;     /* heap, owned */
    char                 *user_only;    /* heap, owned (no domain prefix) */
    char                 *domain;       /* heap, owned, may be empty/NULL */
    char                 *password;     /* heap, owned, wiped on free */
    char                 *userpwd;      /* heap, "DOMAIN\\user:password"  */
    rt_winrm_auth_t       auth;
    int                   ignore_cert;
    atomic_int           *abort_flag;   /* not owned */

    int                   manual_ntlm;  /* mode 2 in the file header */
    winrm_ntlm_t          ntlm;

    CURL                 *curl;
    struct curl_slist    *headers_plain;       /* SOAP envelope */
    struct curl_slist    *headers_encrypted;   /* multipart/encrypted */
    char                  curl_err[CURL_ERROR_SIZE];
};

/* ------------------------------------------------------------------ */
/* curl_global_init under once()                                      */
/* ------------------------------------------------------------------ */

static pthread_once_t g_curl_once = PTHREAD_ONCE_INIT;
static int            g_curl_init_rc = -1;

static void curl_init_once(void)
{
    g_curl_init_rc = curl_global_init(CURL_GLOBAL_DEFAULT);
}

/* ------------------------------------------------------------------ */
/* Response capture                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    char   *buf;
    size_t  len;
    size_t  cap;
} resp_buf_t;

static size_t resp_write_cb(char *data, size_t size, size_t nmemb, void *user)
{
    resp_buf_t *r = user;
    size_t add = size * nmemb;
    const size_t MAX = 16U * 1024U * 1024U;
    if (r->len + add + 1 > MAX) return 0;

    if (r->len + add + 1 > r->cap) {
        size_t new_cap = (r->cap == 0) ? 4096 : r->cap * 2;
        while (new_cap < r->len + add + 1) new_cap *= 2;
        char *nb = realloc(r->buf, new_cap);
        if (nb == NULL) return 0;
        r->buf = nb;
        r->cap = new_cap;
    }
    memcpy(r->buf + r->len, data, add);
    r->len += add;
    r->buf[r->len] = '\0';
    return add;
}

/* Header capture: pulls the WWW-Authenticate: Negotiate <b64> value
 * out of the response so the manual-NTLM path can decode Type 2. */
typedef struct {
    char *negotiate_b64;   /* heap, NUL-terminated */
} header_capture_t;

static char *trim_ws(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' ||
                     e[-1] == '\r' || e[-1] == '\n')) {
        *--e = '\0';
    }
    return s;
}

static size_t header_cb(char *buffer, size_t size, size_t nitems, void *user)
{
    header_capture_t *hc = user;
    size_t total = size * nitems;

    /* Header lines can recur (multiple WWW-Authenticate). Make a
     * NUL-terminated copy on the stack-ish for inspection. */
    static const char KEY[] = "WWW-Authenticate:";
    if (total > sizeof(KEY) - 1 &&
        strncasecmp(buffer, KEY, sizeof(KEY) - 1) == 0) {
        char *line = malloc(total + 1);
        if (line != NULL) {
            memcpy(line, buffer, total);
            line[total] = '\0';
            char *val = trim_ws(line + sizeof(KEY) - 1);
            /* Either "Negotiate <b64>" or "NTLM <b64>". Accept both. */
            if (strncasecmp(val, "Negotiate", 9) == 0 && val[9] == ' ') {
                free(hc->negotiate_b64);
                hc->negotiate_b64 = strdup(trim_ws(val + 9));
            } else if (strncasecmp(val, "NTLM", 4) == 0 && val[4] == ' ') {
                free(hc->negotiate_b64);
                hc->negotiate_b64 = strdup(trim_ws(val + 4));
            }
            free(line);
        }
    }
    return total;
}

/* Progress callback: returns non-zero to abort the transfer. */
static int xfer_cb(void *user,
                   curl_off_t dltotal, curl_off_t dlnow,
                   curl_off_t ultotal, curl_off_t ulnow)
{
    (void)dltotal; (void)dlnow; (void)ultotal; (void)ulnow;
    rt_winrm_http_t *h = user;
    if (h->abort_flag != NULL && atomic_load(h->abort_flag) != 0) {
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Construction / teardown                                            */
/* ------------------------------------------------------------------ */

static char *build_userpwd(const char *username,
                           const char *domain,
                           const char *password)
{
    if (username == NULL) username = "";
    if (password == NULL) password = "";

    char *out = NULL;
    int   n;
    if (domain != NULL && domain[0] != '\0') {
        n = asprintf(&out, "%s\\%s:%s", domain, username, password);
    } else {
        n = asprintf(&out, "%s:%s", username, password);
    }
    return (n < 0) ? NULL : out;
}

/* True if the given URL is HTTPS (we sniff the scheme for the
 * "should we do manual NTLM sealing?" decision). */
static int url_is_https(const char *url)
{
    return (url != NULL && strncasecmp(url, "https://", 8) == 0);
}

rt_winrm_http_t *rt_winrm_http_new(const char               *endpoint_url,
                                   const char               *username,
                                   const char               *domain,
                                   const char               *password,
                                   rt_winrm_auth_t           auth,
                                   int                       ignore_cert,
                                   atomic_int               *abort_flag)
{
    if (endpoint_url == NULL) return NULL;
    pthread_once(&g_curl_once, curl_init_once);
    if (g_curl_init_rc != 0) return NULL;

    rt_winrm_http_t *h = calloc(1, sizeof(*h));
    if (h == NULL) return NULL;
    h->auth        = auth;
    h->ignore_cert = ignore_cert;
    h->abort_flag  = abort_flag;
    h->endpoint    = strdup(endpoint_url);
    h->user_only   = strdup(username ? username : "");
    h->domain      = strdup(domain   ? domain   : "");
    h->password    = strdup(password ? password : "");
    h->userpwd     = build_userpwd(username, domain, password);
    if (h->endpoint == NULL || h->user_only == NULL ||
        h->domain   == NULL || h->password  == NULL ||
        h->userpwd  == NULL) {
        rt_winrm_http_free(h);
        return NULL;
    }

    h->curl = curl_easy_init();
    if (h->curl == NULL) {
        rt_winrm_http_free(h);
        return NULL;
    }

    h->headers_plain = curl_slist_append(NULL,
        "Content-Type: application/soap+xml;charset=UTF-8");
    h->headers_plain = curl_slist_append(h->headers_plain, "Expect:");
    h->headers_plain = curl_slist_append(h->headers_plain,
        "User-Agent: " RT_WINRM_USER_AGENT);

    h->headers_encrypted = curl_slist_append(NULL,
        "Content-Type: multipart/encrypted;"
        "protocol=\"application/HTTP-SPNEGO-session-encrypted\";"
        "boundary=\"Encrypted Boundary\"");
    h->headers_encrypted = curl_slist_append(h->headers_encrypted, "Expect:");
    h->headers_encrypted = curl_slist_append(h->headers_encrypted,
        "User-Agent: " RT_WINRM_USER_AGENT);

    /* Decide whether to use manual NTLM. Only kicks in for
     * NTLM auth over plain HTTP - the only combination that needs
     * WS-Man message encryption. */
    if (auth == RT_WINRM_AUTH_NTLM && !url_is_https(endpoint_url)) {
        h->manual_ntlm = 1;
        winrm_ntlm_init(&h->ntlm);
    }

    return h;
}

void rt_winrm_http_free(rt_winrm_http_t *h)
{
    if (h == NULL) return;
    if (h->curl != NULL) curl_easy_cleanup(h->curl);
    if (h->headers_plain     != NULL) curl_slist_free_all(h->headers_plain);
    if (h->headers_encrypted != NULL) curl_slist_free_all(h->headers_encrypted);
    if (h->userpwd != NULL) {
        explicit_bzero(h->userpwd, strlen(h->userpwd));
        free(h->userpwd);
    }
    if (h->password != NULL) {
        explicit_bzero(h->password, strlen(h->password));
        free(h->password);
    }
    free(h->user_only);
    free(h->domain);
    free(h->endpoint);
    if (h->manual_ntlm) {
        free(h->ntlm.workstation);
        free(h->ntlm.type1_bytes);
        explicit_bzero(&h->ntlm, sizeof(h->ntlm));
    }
    free(h);
}

/* ------------------------------------------------------------------ */
/* Common curl preflight                                              */
/* ------------------------------------------------------------------ */

/* Apply the options that every request uses. Per-request things
 * (POSTFIELDS, HTTPHEADER, HTTPAUTH, USERPWD, headerfunction) are
 * still set by the specific code paths below. */
static void apply_common_opts(rt_winrm_http_t *h, resp_buf_t *r)
{
    curl_easy_reset(h->curl);
    curl_easy_setopt(h->curl, CURLOPT_URL,             h->endpoint);
    curl_easy_setopt(h->curl, CURLOPT_POST,            1L);
    curl_easy_setopt(h->curl, CURLOPT_USERAGENT,       RT_WINRM_USER_AGENT);
    curl_easy_setopt(h->curl, CURLOPT_TIMEOUT,         RT_WINRM_TIMEOUT_SEC);
    curl_easy_setopt(h->curl, CURLOPT_CONNECTTIMEOUT,  RT_WINRM_CONNECT_TIMEOUT);
    curl_easy_setopt(h->curl, CURLOPT_NOSIGNAL,        1L);
    curl_easy_setopt(h->curl, CURLOPT_WRITEFUNCTION,   resp_write_cb);
    curl_easy_setopt(h->curl, CURLOPT_WRITEDATA,       r);
    curl_easy_setopt(h->curl, CURLOPT_ERRORBUFFER,     h->curl_err);
    curl_easy_setopt(h->curl, CURLOPT_NOPROGRESS,      0L);
    curl_easy_setopt(h->curl, CURLOPT_XFERINFOFUNCTION,xfer_cb);
    curl_easy_setopt(h->curl, CURLOPT_XFERINFODATA,    h);

    if (h->ignore_cert) {
        curl_easy_setopt(h->curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(h->curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
}

/* ------------------------------------------------------------------ */
/* Mode 1: plain libcurl-driven path                                  */
/* ------------------------------------------------------------------ */

static int post_plain(rt_winrm_http_t *h,
                      const char       *body,
                      size_t            body_len,
                      char            **out_resp,
                      size_t           *out_resp_len,
                      long             *out_status,
                      char             *err_buf,
                      size_t            err_buf_len)
{
    resp_buf_t r = {0};
    apply_common_opts(h, &r);
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDS,    body);
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
    curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER,    h->headers_plain);

    long auth_mask;
    switch (h->auth) {
    case RT_WINRM_AUTH_NTLM:  auth_mask = CURLAUTH_NTLM;  break;
    case RT_WINRM_AUTH_BASIC: /* fallthrough */
    default:                   auth_mask = CURLAUTH_BASIC; break;
    }
    curl_easy_setopt(h->curl, CURLOPT_HTTPAUTH, auth_mask);
    curl_easy_setopt(h->curl, CURLOPT_USERPWD,  h->userpwd);

    h->curl_err[0] = '\0';
    CURLcode rc = curl_easy_perform(h->curl);

    long status = 0;
    curl_easy_getinfo(h->curl, CURLINFO_RESPONSE_CODE, &status);
    if (out_status != NULL) *out_status = status;

    if (rc != CURLE_OK) {
        if (err_buf != NULL && err_buf_len > 0) {
            if (rc == CURLE_ABORTED_BY_CALLBACK) {
                snprintf(err_buf, err_buf_len, "aborted");
            } else {
                snprintf(err_buf, err_buf_len, "%s",
                         h->curl_err[0] ? h->curl_err
                                        : curl_easy_strerror(rc));
            }
        }
        free(r.buf);
        return -1;
    }
    if (status < 200 || status >= 300) {
        if (err_buf != NULL && err_buf_len > 0) {
            snprintf(err_buf, err_buf_len, "HTTP %ld", status);
        }
        if (out_resp != NULL)     { *out_resp = r.buf; r.buf = NULL; }
        if (out_resp_len != NULL) { *out_resp_len = r.len; }
        free(r.buf);
        return -1;
    }
    if (out_resp != NULL)     { *out_resp = r.buf; r.buf = NULL; }
    if (out_resp_len != NULL) { *out_resp_len = r.len; }
    free(r.buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Mode 2: manual NTLM dance + sealing                                */
/* ------------------------------------------------------------------ */

/* One bare POST that lets us inject our own Authorization header and
 * capture WWW-Authenticate from the response. Used only by the NTLM
 * handshake. body_len of 0 sends an empty entity-body. */
static int post_with_auth_header(rt_winrm_http_t *h,
                                 const char       *body,
                                 size_t            body_len,
                                 const char       *auth_header_value,
                                 struct curl_slist *base_headers,
                                 header_capture_t *hc,
                                 char            **out_resp,
                                 size_t           *out_resp_len,
                                 long             *out_status,
                                 char             *err_buf,
                                 size_t            err_buf_len)
{
    resp_buf_t r = {0};
    apply_common_opts(h, &r);

    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDS,    body ? body : "");
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
    curl_easy_setopt(h->curl, CURLOPT_HTTPAUTH,      (long)CURLAUTH_NONE);

    /* Build a one-shot header list = base + our Authorization. */
    struct curl_slist *hdrs = NULL;
    for (struct curl_slist *p = base_headers; p != NULL; p = p->next) {
        hdrs = curl_slist_append(hdrs, p->data);
    }
    char *auth_line = NULL;
    if (auth_header_value != NULL) {
        if (asprintf(&auth_line, "Authorization: %s", auth_header_value) < 0) {
            curl_slist_free_all(hdrs);
            free(r.buf);
            return -1;
        }
        hdrs = curl_slist_append(hdrs, auth_line);
    }
    curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, hdrs);

    if (hc != NULL) {
        curl_easy_setopt(h->curl, CURLOPT_HEADERFUNCTION, header_cb);
        curl_easy_setopt(h->curl, CURLOPT_HEADERDATA,     hc);
    }

    h->curl_err[0] = '\0';
    CURLcode rc = curl_easy_perform(h->curl);

    long status = 0;
    curl_easy_getinfo(h->curl, CURLINFO_RESPONSE_CODE, &status);
    if (out_status != NULL) *out_status = status;

    curl_slist_free_all(hdrs);
    free(auth_line);

    if (rc != CURLE_OK) {
        if (err_buf != NULL && err_buf_len > 0) {
            if (rc == CURLE_ABORTED_BY_CALLBACK) {
                snprintf(err_buf, err_buf_len, "aborted");
            } else {
                snprintf(err_buf, err_buf_len, "%s",
                         h->curl_err[0] ? h->curl_err
                                        : curl_easy_strerror(rc));
            }
        }
        if (out_resp != NULL) { *out_resp = r.buf; r.buf = NULL; }
        if (out_resp_len != NULL) *out_resp_len = r.len;
        free(r.buf);
        return -1;
    }

    if (out_resp != NULL)     { *out_resp = r.buf; r.buf = NULL; }
    if (out_resp_len != NULL) { *out_resp_len = r.len; }
    free(r.buf);
    return 0;
}

/* Drive the full NTLMSSP handshake on the current connection:
 *   POST empty body, Authorization: Negotiate <Type1>     -> 401 + Type2
 *   POST empty body, Authorization: Negotiate <Type3>     -> 200
 * After both round-trips finish, the connection is authenticated
 * server-side and our session keys are loaded into h->ntlm. From
 * then on, post_sealed sends sealed bodies with NO Authorization
 * header (libcurl reuses the same TCP connection from its pool, so
 * server-side NTLM state stays attached).
 *
 * Splitting the dance from the actual SOAP send (rather than
 * piggy-backing Type 3 onto the sealed POST) matches the working
 * pywinrm/requests-ntlm pattern: some Windows builds process the
 * Authorization header AFTER decrypting the body, which fails when
 * the body was sealed with keys derived from a Type 3 the server
 * hasn't yet accepted.
 */
static int ntlm_handshake(rt_winrm_http_t *h,
                          char            *err_buf,
                          size_t           err_buf_len)
{
    /* ---------- Type 1 (empty body) ---------- */
    uint8_t *type1     = NULL;
    size_t   type1_len = 0;
    if (winrm_ntlm_build_type1(&h->ntlm, &type1, &type1_len) != 0) {
        if (err_buf) snprintf(err_buf, err_buf_len, "ntlm: build Type1 failed");
        return -1;
    }
    char *t1_b64 = winrm_b64_encode(type1, type1_len);
    free(type1);
    if (t1_b64 == NULL) {
        if (err_buf) snprintf(err_buf, err_buf_len, "ntlm: b64 Type1 failed");
        return -1;
    }
    char *t1_neg = NULL;
    if (asprintf(&t1_neg, "Negotiate %s", t1_b64) < 0) {
        free(t1_b64);
        if (err_buf) snprintf(err_buf, err_buf_len, "ntlm: oom");
        return -1;
    }
    free(t1_b64);

    header_capture_t hc1 = {0};
    long   st1     = 0;
    char  *resp1   = NULL;
    size_t r1_len  = 0;
    int rc = post_with_auth_header(h, "", 0, t1_neg,
                                   h->headers_plain, &hc1,
                                   &resp1, &r1_len, &st1,
                                   err_buf, err_buf_len);
    free(t1_neg);
    free(resp1);
    if (rc != 0 && st1 != 401) {
        free(hc1.negotiate_b64);
        return -1;
    }
    if (st1 != 401 || hc1.negotiate_b64 == NULL) {
        free(hc1.negotiate_b64);
        if (err_buf) {
            snprintf(err_buf, err_buf_len,
                     "ntlm: server did not send Type2 (status %ld)", st1);
        }
        return -1;
    }

    /* ---------- Decode Type 2, build Type 3 ---------- */
    size_t t2_len = 0;
    uint8_t *type2 = winrm_b64_decode(hc1.negotiate_b64, &t2_len);
    free(hc1.negotiate_b64);
    if (type2 == NULL || t2_len == 0) {
        free(type2);
        if (err_buf) snprintf(err_buf, err_buf_len,
                              "ntlm: failed to decode Type2");
        return -1;
    }

    uint8_t *type3     = NULL;
    size_t   type3_len = 0;
    int t3rc = winrm_ntlm_build_type3(&h->ntlm,
                                      type2, t2_len,
                                      h->user_only,
                                      h->domain,
                                      h->password,
                                      &type3, &type3_len);
    free(type2);
    if (t3rc != 0) {
        if (err_buf) snprintf(err_buf, err_buf_len,
                              "ntlm: failed to build Type3");
        return -1;
    }

    /* ---------- Type 3 (empty body) ---------- */
    char *t3_b64 = winrm_b64_encode(type3, type3_len);
    explicit_bzero(type3, type3_len);
    free(type3);
    if (t3_b64 == NULL) {
        if (err_buf) snprintf(err_buf, err_buf_len, "ntlm: oom Type3");
        return -1;
    }
    char *t3_neg = NULL;
    if (asprintf(&t3_neg, "Negotiate %s", t3_b64) < 0) {
        free(t3_b64);
        if (err_buf) snprintf(err_buf, err_buf_len, "ntlm: oom");
        return -1;
    }
    free(t3_b64);

    long   st3    = 0;
    char  *resp3  = NULL;
    size_t r3_len = 0;
    rc = post_with_auth_header(h, "", 0, t3_neg,
                               h->headers_plain, NULL,
                               &resp3, &r3_len, &st3,
                               err_buf, err_buf_len);
    free(t3_neg);
    free(resp3);
    if (rc != 0) {
        return -1;
    }
    if (st3 == 401) {
        if (err_buf) snprintf(err_buf, err_buf_len,
                              "ntlm: Type3 rejected (bad credentials)");
        return -1;
    }
    if (st3 < 200 || st3 >= 300) {
        if (err_buf) snprintf(err_buf, err_buf_len,
                              "ntlm: Type3 returned HTTP %ld", st3);
        return -1;
    }

    return 0;
}

/* Send a sealed SOAP envelope. Lazily runs the handshake on the
 * first call. After that, every call is a single round-trip with
 * the encrypted body and no Authorization header. */
static int post_sealed(rt_winrm_http_t *h,
                       const char       *plaintext,
                       size_t            plaintext_len,
                       char            **out_resp,
                       size_t           *out_resp_len,
                       long             *out_status,
                       char             *err_buf,
                       size_t            err_buf_len)
{
    if (!h->ntlm.authenticated) {
        if (ntlm_handshake(h, err_buf, err_buf_len) != 0) {
            return -1;
        }
    }

    /* Seal the SOAP body. */
    char  *sealed_body     = NULL;
    size_t sealed_body_len = 0;
    if (winrm_ntlm_seal(&h->ntlm, plaintext, plaintext_len,
                        &sealed_body, &sealed_body_len, NULL) != 0) {
        if (err_buf) snprintf(err_buf, err_buf_len, "ntlm: seal failed");
        return -1;
    }

    char  *resp     = NULL;
    size_t resp_len = 0;
    int rc = post_with_auth_header(h, sealed_body, sealed_body_len,
                                   /*auth header=*/NULL,
                                   h->headers_encrypted, NULL,
                                   &resp, &resp_len, out_status,
                                   err_buf, err_buf_len);
    free(sealed_body);
    if (rc != 0) {
        free(resp);
        return -1;
    }

    /* Always try to unseal: WinRM seals SOAP faults inside the same
     * multipart/encrypted envelope, so a 500 still arrives encrypted. */
    char  *plain     = NULL;
    size_t plain_len = 0;
    int    unsealed  = 0;
    if (resp != NULL && resp_len > 0) {
        if (winrm_ntlm_unseal(&h->ntlm, resp, resp_len,
                              &plain, &plain_len) == 0) {
            unsealed = 1;
        }
    }

    /* Optional plaintext dump for debugging. */
    if (unsealed) {
        const char *dbg = getenv("RT_WINRM_DEBUG");
        if (dbg != NULL && dbg[0] != '\0' && dbg[0] != '0') {
            int dump = (int)(plain_len > 4096 ? 4096 : plain_len);
            fprintf(stderr,
                    "[winrm] decrypted response (%zu bytes):\n%.*s\n",
                    plain_len, dump, plain != NULL ? plain : "");
        }
    }

    long st = (out_status != NULL) ? *out_status : 0;

    if (st < 200 || st >= 300) {
        if (err_buf) snprintf(err_buf, err_buf_len, "HTTP %ld", st);
        /* Hand back whichever body we extracted - sealed faults
         * decrypt cleanly, plain 401/500 with no body falls through
         * as raw. soap_post will try to surface a Fault reason. */
        if (unsealed) {
            if (out_resp     != NULL) { *out_resp     = plain; plain = NULL; }
            if (out_resp_len != NULL) { *out_resp_len = plain_len; }
        } else {
            if (out_resp     != NULL) { *out_resp     = resp; resp = NULL; }
            if (out_resp_len != NULL) { *out_resp_len = resp_len; }
        }
        free(plain);
        free(resp);
        return -1;
    }

    /* 2xx with no body (e.g. an idle keepalive 200). */
    if (resp == NULL || resp_len == 0) {
        if (out_resp     != NULL) *out_resp     = NULL;
        if (out_resp_len != NULL) *out_resp_len = 0;
        free(resp);
        return 0;
    }
    /* 2xx but unseal failed: keys lost sync or server stopped sealing. */
    if (!unsealed) {
        if (err_buf) snprintf(err_buf, err_buf_len,
                              "ntlm: failed to decrypt response");
        free(resp);
        return -1;
    }
    free(resp);

    if (out_resp     != NULL) *out_resp     = plain;
    else                       free(plain);
    if (out_resp_len != NULL) *out_resp_len = plain_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

int rt_winrm_http_post(rt_winrm_http_t *h,
                       const char       *body,
                       size_t            body_len,
                       char            **out_resp,
                       size_t           *out_resp_len,
                       long             *out_status,
                       char             *err_buf,
                       size_t            err_buf_len)
{
    if (out_resp     != NULL) *out_resp     = NULL;
    if (out_resp_len != NULL) *out_resp_len = 0;
    if (out_status   != NULL) *out_status   = 0;
    if (err_buf != NULL && err_buf_len > 0) err_buf[0] = '\0';

    if (h == NULL || body == NULL) {
        if (err_buf) snprintf(err_buf, err_buf_len, "invalid arguments");
        return -1;
    }
    if (h->abort_flag != NULL && atomic_load(h->abort_flag) != 0) {
        if (err_buf) snprintf(err_buf, err_buf_len, "aborted");
        return -1;
    }

    if (h->manual_ntlm) {
        return post_sealed(h, body, body_len,
                           out_resp, out_resp_len, out_status,
                           err_buf, err_buf_len);
    }
    return post_plain(h, body, body_len,
                      out_resp, out_resp_len, out_status,
                      err_buf, err_buf_len);
}

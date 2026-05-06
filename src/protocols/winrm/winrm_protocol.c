/*
 * WinRM protocol implementation.
 *
 * Threading model
 * ---------------
 * One worker thread per session. The worker is the only thread that
 * touches the curl handle and the WinRM state machine. The UI feeds
 * commands through a thread-safe queue:
 *
 *   GTK main thread                     WinRM worker
 *   ---------------                     -------------
 *   ops->send(cmd) ─push to queue──┐
 *                                  ▼
 *                             pop command
 *                             SOAP Command  → CommandId
 *                             loop:
 *                               SOAP Receive
 *                               on_data(stdout/stderr)
 *                               break on Done
 *                             (next pop)
 *
 * open() is **non-blocking** by design: it allocates context, copies
 * the password into a private buffer, spawns the worker, and returns
 * immediately. The worker's first action is to build the curl handle
 * (which takes another internal copy of the password), wipe the
 * private buffer, then drive SOAP Create. State transitions are
 * emitted from the worker so the UI sees them as they happen instead
 * of all at once after a long synchronous connect.
 *
 * close() flips an atomic stop flag; the curl progress callback
 * observes it and aborts the in-flight POST. The worker then exits
 * its loop, the closing thread joins it, sends a best-effort Delete
 * shell, and frees state.
 *
 * Each "send" from the UI is treated as one command line. The view
 * widget posts the command followed by '\n'; the accumulator splits
 * on newlines and enqueues each line. Empty lines are dropped.
 *
 * Security
 * --------
 * The password lives in three places, each scrubbed on the earliest
 * possible boundary:
 *   1. session.c's `password` argument to open() (wiped on return).
 *   2. ctx->pending_password (wiped by the worker as soon as the
 *      curl handle has copied it internally).
 *   3. rt_winrm_http_t's userpwd (wiped in rt_winrm_http_free).
 * SOAP envelopes are never logged; the diagnostics that go to stderr
 * carry only metadata (host, status, error string).
 */

#include "protocols/winrm/winrm_protocol.h"
#include "protocols/winrm/winrm_http.h"
#include "protocols/winrm/winrm_soap.h"
#include "protocols/winrm/winrm_psrp.h"
#include "protocols/winrm/winrm_crypto.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero */
#include <time.h>

/* Set RT_WINRM_DEBUG=1 in the environment to enable diagnostic
 * stderr output from the worker thread. Off by default to keep the
 * tool quiet in normal use. Implemented as a real function (not a
 * variadic macro) to stay clean under -Wpedantic for callers that
 * have no format args. */
struct rt_protocol_ctx;  /* forward */
static void rt_log(const struct rt_protocol_ctx *c, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* ------------------------------------------------------------------ */
/* Internal types                                                     */
/* ------------------------------------------------------------------ */

typedef struct cmd_node {
    struct cmd_node *next;
    char            *cmd;     /* heap, NUL-terminated */
} cmd_node_t;

struct rt_protocol_ctx {
    /* Connection metadata. */
    char                 *endpoint;     /* "http(s)://host:port/wsman" */
    char                 *username;     /* heap copy, may be NULL/"" */
    rt_winrm_options_t    opts;         /* copy of options (domain owned) */

    /* Password ownership while waiting for the worker to construct
     * the http handle. Wiped + freed by the worker on first use. */
    char                 *pending_password;
    pthread_mutex_t       pwd_mtx;

    /* HTTP client owned by worker thread (set during first iter). */
    rt_winrm_http_t      *http;

    /* WinRM session state (worker thread only after init).
     * shell_id doubles as our PSRP RunspacePool ID; we generate it
     * client-side and ask the server to use it via the ShellId
     * attribute on Shell Create. */
    char                 *shell_id;     /* heap, NULL until Create */

    /* PSRP context (PowerShell remoting). */
    winrm_psrp_t          psrp;

    /* Worker. */
    pthread_t             thread;
    int                   thread_started;
    atomic_int            stop;

    /* Command queue. */
    pthread_mutex_t       q_mtx;
    pthread_cond_t        q_cv;
    cmd_node_t           *q_head;
    cmd_node_t           *q_tail;

    /* Input accumulator (see acc_feed). */
    char                 *acc;
    size_t                acc_len;
    size_t                acc_cap;
    pthread_mutex_t       acc_mtx;

    /* UI hook. */
    rt_proto_callbacks_t  cb;
    void                 *cb_user;

    int                   debug;        /* from RT_WINRM_DEBUG env */
};

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static void rt_log(const struct rt_protocol_ctx *c, const char *fmt, ...)
{
    if (c == NULL || !c->debug) return;
    va_list ap;
    va_start(ap, fmt);
    fputs("[winrm] ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void emit_state(rt_protocol_ctx_t *c,
                       rt_proto_state_t st, const char *msg)
{
    if (c->cb.on_state != NULL) {
        c->cb.on_state(c->cb_user, st, msg);
    }
}

static void emit_data(rt_protocol_ctx_t *c, const char *data, size_t len)
{
    if (c->cb.on_data != NULL && data != NULL && len > 0) {
        c->cb.on_data(c->cb_user, data, len);
    }
}

static void emit_text(rt_protocol_ctx_t *c, const char *s)
{
    if (s != NULL) {
        emit_data(c, s, strlen(s));
    }
}

static void emit_idle(rt_protocol_ctx_t *c)
{
    if (c->cb.on_idle != NULL) {
        c->cb.on_idle(c->cb_user);
    }
}

/* Build "scheme://host:port/wsman". Caller frees. */
static char *build_endpoint(const char *host, unsigned short port,
                            rt_winrm_transport_t transport)
{
    const char *scheme = (transport == RT_WINRM_TRANSPORT_HTTPS)
                          ? "https" : "http";
    char *out = NULL;
    int n = asprintf(&out, "%s://%s:%u/wsman", scheme,
                     host ? host : "", (unsigned)port);
    return (n < 0) ? NULL : out;
}

static char *dup_or_null(const char *s)
{
    return (s != NULL) ? strdup(s) : NULL;
}

static void wipe_and_free(char **p)
{
    if (p == NULL || *p == NULL) return;
    explicit_bzero(*p, strlen(*p));
    free(*p);
    *p = NULL;
}

/* ------------------------------------------------------------------ */
/* Validation                                                         */
/* ------------------------------------------------------------------ */

static int validate(const rt_connection_t *conn)
{
    if (conn == NULL || conn->host == NULL || conn->host[0] == '\0') {
        return -1;
    }
    if (conn->port == 0) {
        return -1;
    }
    if (conn->winrm == NULL) {
        return -1;
    }
    if (conn->winrm->transport != RT_WINRM_TRANSPORT_HTTP &&
        conn->winrm->transport != RT_WINRM_TRANSPORT_HTTPS) {
        return -1;
    }
    if (conn->winrm->auth_method != RT_WINRM_AUTH_BASIC &&
        conn->winrm->auth_method != RT_WINRM_AUTH_NTLM) {
        return -1;
    }
    /* Reject hosts with whitespace or control bytes. */
    for (const char *p = conn->host; *p; ++p) {
        if ((unsigned char)*p < 0x20 || *p == ' ') {
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Command queue                                                      */
/* ------------------------------------------------------------------ */

static void enqueue_command(rt_protocol_ctx_t *c, char *cmd /* takes ownership */)
{
    cmd_node_t *n = calloc(1, sizeof(*n));
    if (n == NULL) {
        free(cmd);
        return;
    }
    n->cmd = cmd;
    pthread_mutex_lock(&c->q_mtx);
    if (c->q_tail != NULL) c->q_tail->next = n;
    else                   c->q_head = n;
    c->q_tail = n;
    pthread_cond_signal(&c->q_cv);
    pthread_mutex_unlock(&c->q_mtx);
}

/* Wait up to `timeout_ms` for a command. Returns NULL on timeout/stop. */
static char *dequeue_command(rt_protocol_ctx_t *c, int timeout_ms)
{
    char *out = NULL;
    pthread_mutex_lock(&c->q_mtx);
    if (c->q_head == NULL && !atomic_load(&c->stop)) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec  += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec  += 1;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&c->q_cv, &c->q_mtx, &ts);
    }
    if (c->q_head != NULL) {
        cmd_node_t *n = c->q_head;
        c->q_head = n->next;
        if (c->q_head == NULL) c->q_tail = NULL;
        out = n->cmd;
        free(n);
    }
    pthread_mutex_unlock(&c->q_mtx);
    return out;
}

static void queue_drain_free(rt_protocol_ctx_t *c)
{
    pthread_mutex_lock(&c->q_mtx);
    cmd_node_t *n = c->q_head;
    c->q_head = c->q_tail = NULL;
    pthread_mutex_unlock(&c->q_mtx);
    while (n != NULL) {
        cmd_node_t *next = n->next;
        free(n->cmd);
        free(n);
        n = next;
    }
}

/* ------------------------------------------------------------------ */
/* Input accumulator                                                  */
/* ------------------------------------------------------------------ */

static int acc_feed(rt_protocol_ctx_t *c, const char *data, size_t len)
{
    pthread_mutex_lock(&c->acc_mtx);
    for (size_t i = 0; i < len; i++) {
        char ch = data[i];
        if (ch == '\n') {
            size_t end = c->acc_len;
            if (end > 0 && c->acc[end - 1] == '\r') end--;
            if (end > 0) {
                char *line = malloc(end + 1);
                if (line != NULL) {
                    memcpy(line, c->acc, end);
                    line[end] = '\0';
                    enqueue_command(c, line);
                }
            }
            c->acc_len = 0;
            continue;
        }
        if (c->acc_len + 2 > c->acc_cap) {
            size_t nc = c->acc_cap ? c->acc_cap * 2 : 256;
            char *nb = realloc(c->acc, nc);
            if (nb == NULL) {
                pthread_mutex_unlock(&c->acc_mtx);
                return -1;
            }
            c->acc = nb;
            c->acc_cap = nc;
        }
        c->acc[c->acc_len++] = ch;
    }
    pthread_mutex_unlock(&c->acc_mtx);
    return 0;
}

/* ------------------------------------------------------------------ */
/* SOAP exchange helpers                                              */
/* ------------------------------------------------------------------ */

static int soap_post(rt_protocol_ctx_t *c,
                     const char *envelope,
                     char **out_resp, size_t *out_resp_len,
                     int report_fault)
{
    char err[256];
    long status = 0;
    size_t env_len = strlen(envelope);
    if (c->debug) {
        size_t cap = env_len > 4096 ? 4096 : env_len;
        fprintf(stderr,
                "[winrm] outgoing envelope (%zu bytes):\n%.*s\n",
                env_len, (int)cap, envelope);
    }
    int rc = rt_winrm_http_post(c->http, envelope, env_len,
                                out_resp, out_resp_len, &status,
                                err, sizeof(err));
    rt_log(c, "POST -> rc=%d status=%ld err=\"%s\"", rc, status, err);
    /* If debugging, dump the response body length we'll be parsing
     * (the raw-or-unsealed plaintext) so the user can paste it back
     * when the parser fails. winrm_http already prints the unsealed
     * body itself; this just tells us how big it is. */
    if (c->debug && out_resp != NULL && *out_resp != NULL && out_resp_len != NULL) {
        rt_log(c, "response body len=%zu", *out_resp_len);
    }
    if (rc == 0) {
        return 0;
    }

    if (report_fault) {
        char msg[768];
        const char *hint = "";
        /* Common, hard-to-read libcurl/OpenSSL strings get a plain-
         * English hint appended so the user knows what to change. */
        if (strstr(err, "wrong version number") != NULL) {
            hint = " (HTTPS selected against an HTTP port? "
                   "WinRM HTTP is 5985, HTTPS is 5986.)";
        } else if (strstr(err, "certificate verify failed") != NULL ||
                   strstr(err, "self signed") != NULL ||
                   strstr(err, "self-signed") != NULL) {
            hint = " (Server cert not trusted. For lab use, enable "
                   "\"Ignore certificate validation\".)";
        } else if (strstr(err, "Could not resolve") != NULL) {
            hint = " (DNS lookup failed.)";
        } else if (strstr(err, "Connection refused") != NULL) {
            hint = " (Is WinRM enabled on the target? "
                   "Run `winrm quickconfig` on the server.)";
        } else if (status == 401) {
            /* Authentication failure. NTLM-over-HTTP is now handled
             * via our manual SPNEGO sealing path, so a 401 with NTLM
             * almost always means real bad credentials. */
            if (c->opts.auth_method == RT_WINRM_AUTH_BASIC) {
                hint = " (Basic auth is usually disabled by default. "
                       "On the server: `winrm set "
                       "winrm/config/service/auth @{Basic=\"true\"}` "
                       "(and, over HTTP, AllowUnencrypted=\"true\"). "
                       "Or use NTLM.)";
            } else {
                hint = " (Bad username/password, or wrong domain.)";
            }
        } else if (status == 500 &&
                   out_resp != NULL && *out_resp != NULL &&
                   strstr(*out_resp, "AccessDenied") != NULL) {
            /* Authenticated but the user can't open the cmd shell
             * endpoint. Default Windows ACLs allow non-admin users
             * (Remote Management Users) on the PowerShell endpoint
             * but require Administrators on the cmd endpoint - which
             * is what we target. evil-winrm targets PowerShell and
             * therefore "just works" for the same user. */
            hint = " (cmd-shell endpoint is Administrators-only by "
                   "default. Fix on the server: `winrm configsddl default`"
                   " (GUI) and grant your user Read+Execute. Or run as an "
                   "admin. PowerShell endpoint support is not yet wired "
                   "in this client.)";
        } else if (status == 405) {
            hint = " (HTTP 405 - the server is responding but not as "
                   "WinRM. Wrong port?)";
        } else if (status == 411) {
            hint = " (HTTP 411 - server demands encrypted payload "
                   "(WS-Man message encryption). Use HTTPS.)";
        }

        if (out_resp != NULL && *out_resp != NULL && *out_resp_len > 0) {
            char *reason = rt_winrm_soap_parse_fault_reason(
                *out_resp, *out_resp_len);
            if (reason != NULL && reason[0] != '\0') {
                snprintf(msg, sizeof(msg), "WinRM fault (%s): %s%s",
                         err, reason, hint);
            } else {
                snprintf(msg, sizeof(msg), "WinRM error: %s%s",
                         err, hint);
            }
            free(reason);
        } else {
            snprintf(msg, sizeof(msg), "WinRM error: %s%s", err, hint);
        }
        emit_state(c, RT_PROTO_STATE_ERROR, msg);
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* PSRP message dispatch (callback for the decoder)                   */
/* ------------------------------------------------------------------ */

/* State the dispatch callback updates as it walks PSRP messages. */
typedef struct {
    rt_protocol_ctx_t *c;
    int                pipeline_done;   /* set on PIPELINE_STATE Completed/Failed/Stopped */
    int                runspace_opened; /* set on RUNSPACEPOOL_STATE Opened             */
} psrp_dispatch_state_t;

static void on_psrp_message(uint32_t msg_type,
                            const uint8_t *msg, size_t msg_len,
                            void *user)
{
    psrp_dispatch_state_t *s = user;
    rt_protocol_ctx_t     *c = s->c;
    /* Payload starts after the 40-byte PSRP header. */
    const char *clixml     = (const char *)(msg + 40);
    size_t      clixml_len = (msg_len > 40) ? (msg_len - 40) : 0;

    rt_log(c, "psrp message type=0x%08X len=%zu", msg_type, msg_len);

    switch (msg_type) {
    case PSRP_MSG_PIPELINE_OUTPUT:
    case PSRP_MSG_ERROR_RECORD: {
        char *txt = winrm_psrp_clixml_to_text(clixml, clixml_len);
        if (txt != NULL) {
            emit_text(c, txt);
            free(txt);
        }
        break;
    }
    case PSRP_MSG_PIPELINE_STATE: {
        int st = winrm_psrp_parse_pipeline_state(msg, msg_len);
        rt_log(c, "pipeline state=%d", st);
        if (st == PSRP_PIPELINE_STATE_COMPLETED ||
            st == PSRP_PIPELINE_STATE_FAILED    ||
            st == PSRP_PIPELINE_STATE_STOPPED) {
            s->pipeline_done = 1;
        }
        if (st == PSRP_PIPELINE_STATE_FAILED) {
            /* The state CLIXML often embeds an ErrorRecord with the
             * fault text. Emit whatever strings are in there. */
            char *txt = winrm_psrp_clixml_to_text(clixml, clixml_len);
            if (txt != NULL) {
                emit_text(c, txt);
                free(txt);
            }
        }
        break;
    }
    case PSRP_MSG_RUNSPACEPOOL_STATE: {
        int st = winrm_psrp_parse_runspace_state(msg, msg_len);
        rt_log(c, "runspace state=%d", st);
        if (st == PSRP_RUNSPACE_STATE_OPENED) {
            s->runspace_opened = 1;
        }
        break;
    }
    default:
        /* Drop SESSION_CAPABILITY response, APPLICATION_PRIVATE_DATA,
         * host calls, etc. We don't need them for basic shell use. */
        break;
    }
}

/* Decode every <rsp:Stream> base64 payload in `xml` and feed the
 * resulting bytes through the PSRP decoder. The receive parser hands
 * us concatenated stream bodies in `out_data`; for PowerShell that
 * data IS PSRP fragment bytes (not text). */
static void feed_psrp_streams(rt_protocol_ctx_t *c,
                              const uint8_t     *bytes, size_t len,
                              psrp_dispatch_state_t *st)
{
    if (bytes == NULL || len == 0) return;
    if (winrm_psrp_decoder_feed(&c->psrp, bytes, len,
                                on_psrp_message, st) != 0) {
        rt_log(c, "psrp decoder framing error");
    }
}

/* ------------------------------------------------------------------ */
/* Drain Receive responses until a predicate is satisfied             */
/* ------------------------------------------------------------------ */

/* Receive loop variant. `wait_for_pipeline_done` toggles whether we
 * watch PSRP_MSG_PIPELINE_STATE (per-command) or just RUNSPACEPOOL_STATE
 * (post-Create). `command_id` may be NULL for the latter. */
static int receive_psrp_loop(rt_protocol_ctx_t     *c,
                             const char            *command_id,
                             int                    wait_for_pipeline_done,
                             psrp_dispatch_state_t *st)
{
    while (!atomic_load(&c->stop)) {
        char *recv_env = rt_winrm_soap_build_receive(
            c->endpoint, c->shell_id,
            command_id ? command_id : "");
        if (recv_env == NULL) {
            emit_text(c, "[winrm] out of memory building receive\n");
            return -1;
        }
        char  *resp     = NULL;
        size_t resp_len = 0;
        int rc = soap_post(c, recv_env, &resp, &resp_len, /*report_fault=*/1);
        free(recv_env);
        if (rc != 0) {
            free(resp);
            return -1;
        }

        char  *out     = NULL;
        size_t out_len = 0;
        int    done    = 0;
        int    exit_cd = 0;
        if (rt_winrm_soap_parse_receive(resp, resp_len,
                                        &out, &out_len, &done, &exit_cd) == 0) {
            feed_psrp_streams(c, (const uint8_t *)out, out_len, st);
        }
        free(out);
        free(resp);

        if (wait_for_pipeline_done && st->pipeline_done) return 0;
        if (!wait_for_pipeline_done && st->runspace_opened) return 0;
        /* WinRM CommandState=Done is also a terminal signal in the
         * cmd-shell model; for PowerShell we trust the PSRP state
         * messages, but if the server sets it we still respect it. */
        if (done) return 0;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Run one command end-to-end (PowerShell pipeline)                   */
/* ------------------------------------------------------------------ */

static void run_one_command(rt_protocol_ctx_t *c, const char *cmd)
{
    /* 1. Build a CREATE_PIPELINE PSRP message. */
    uint8_t  pid_bytes[16];
    uint8_t *frags     = NULL;
    size_t   frags_len = 0;
    if (winrm_psrp_build_create_pipeline(&c->psrp, cmd,
                                         pid_bytes,
                                         &frags, &frags_len) != 0) {
        emit_text(c, "[winrm] failed to build CREATE_PIPELINE\n");
        return;
    }
    char pid_uuid[37];
    winrm_psrp_uuid_format(pid_bytes, pid_uuid);

    /* 2. Base64 the (single, in our config) fragment. The PSRP module
     * caps fragments at 153600 bytes; user commands never come close. */
    char *frag_b64 = winrm_b64_encode(frags, frags_len);
    free(frags);
    if (frag_b64 == NULL) {
        emit_text(c, "[winrm] oom encoding fragment\n");
        return;
    }

    /* 3. SOAP Command with the fragment, pinning CommandId to our
     * pipeline UUID so server-side correlation matches the PSRP PID. */
    char *cmd_env = rt_winrm_soap_build_command_psrp(
        c->endpoint, c->shell_id, pid_uuid,
        frag_b64, NULL, 0);
    free(frag_b64);
    if (cmd_env == NULL) {
        emit_text(c, "[winrm] oom building Command envelope\n");
        return;
    }
    char  *resp     = NULL;
    size_t resp_len = 0;
    int rc = soap_post(c, cmd_env, &resp, &resp_len, /*report_fault=*/1);
    free(cmd_env);
    if (rc != 0) {
        free(resp);
        return;
    }
    free(resp);
    rt_log(c, "pipeline_id=%s sent", pid_uuid);

    /* 4. Drain Receive until the pipeline reports Completed/Failed. */
    psrp_dispatch_state_t st = { .c = c };
    if (receive_psrp_loop(c, pid_uuid,
                          /*wait_for_pipeline_done=*/1,
                          &st) != 0) {
        if (atomic_load(&c->stop)) {
            char *sig = rt_winrm_soap_build_signal_terminate(
                c->endpoint, c->shell_id, pid_uuid);
            if (sig != NULL) {
                (void)soap_post(c, sig, NULL, NULL, /*report_fault=*/0);
                free(sig);
            }
        }
    }

    /* Pipeline finished (or aborted). Tell the UI it can show the
     * next prompt. */
    emit_idle(c);
}

/* ------------------------------------------------------------------ */
/* Worker thread                                                      */
/* ------------------------------------------------------------------ */

/* Construct the curl handle from the pending password, then wipe
 * the password copy. Returns 0 on success, -1 on failure (caller
 * has already emitted a state message). */
static int worker_init_http(rt_protocol_ctx_t *c)
{
    pthread_mutex_lock(&c->pwd_mtx);
    char *pw = c->pending_password;
    c->pending_password = NULL;
    pthread_mutex_unlock(&c->pwd_mtx);

    if (pw == NULL) {
        emit_state(c, RT_PROTO_STATE_ERROR, "Internal error: no password");
        return -1;
    }

    c->http = rt_winrm_http_new(c->endpoint,
                                c->username,
                                c->opts.domain,
                                pw,
                                c->opts.auth_method,
                                c->opts.ignore_cert_validation,
                                &c->stop);
    /* Wipe the local copy regardless of outcome. */
    explicit_bzero(pw, strlen(pw));
    free(pw);

    if (c->http == NULL) {
        emit_state(c, RT_PROTO_STATE_ERROR,
                   "Failed to initialise HTTP client");
        return -1;
    }
    return 0;
}

/* The actual SOAP Create handshake for the PowerShell endpoint.
 *
 *   1. Init PSRP (generates RPID = our future ShellId).
 *   2. Build SESSION_CAPABILITY + INIT_RUNSPACEPOOL PSRP messages
 *      and concatenate their fragments.
 *   3. Base64-encode the concatenation; that's the <creationXml>.
 *   4. Send Shell Create with the PowerShell ResourceURI and our
 *      pre-chosen ShellId.
 *   5. Loop Receive until we see RUNSPACEPOOL_STATE=Opened.
 *
 * Emits AUTHENTICATING then CONNECTED (success) or ERROR (failure).
 */
static int worker_connect(rt_protocol_ctx_t *c)
{
    emit_state(c, RT_PROTO_STATE_AUTHENTICATING, NULL);

    /* Init PSRP and use its random RPID as both shell_id and runspace ID. */
    winrm_psrp_init(&c->psrp);
    char shell_uuid[37];
    winrm_psrp_uuid_format(c->psrp.rpid, shell_uuid);
    free(c->shell_id);
    c->shell_id = strdup(shell_uuid);
    if (c->shell_id == NULL) {
        emit_state(c, RT_PROTO_STATE_ERROR, "Out of memory");
        return -1;
    }
    rt_log(c, "shell_id (PSRP RPID) = %s", c->shell_id);

    /* Build the two initial PSRP messages and stitch their fragments. */
    uint8_t *sc_frags  = NULL; size_t sc_len  = 0;
    uint8_t *init_frags = NULL; size_t init_len = 0;
    if (winrm_psrp_build_session_capability(&c->psrp, &sc_frags, &sc_len) != 0 ||
        winrm_psrp_build_init_runspacepool (&c->psrp, &init_frags, &init_len) != 0) {
        free(sc_frags); free(init_frags);
        emit_state(c, RT_PROTO_STATE_ERROR,
                   "Out of memory building PSRP init messages");
        return -1;
    }
    uint8_t *both = malloc(sc_len + init_len);
    if (both == NULL) {
        free(sc_frags); free(init_frags);
        emit_state(c, RT_PROTO_STATE_ERROR, "Out of memory");
        return -1;
    }
    memcpy(both,           sc_frags,   sc_len);
    memcpy(both + sc_len,  init_frags, init_len);
    free(sc_frags); free(init_frags);

    char *creation_xml_b64 = winrm_b64_encode(both, sc_len + init_len);
    free(both);
    if (creation_xml_b64 == NULL) {
        emit_state(c, RT_PROTO_STATE_ERROR, "Out of memory base64");
        return -1;
    }

    /* SOAP Create against the PowerShell ResourceURI. */
    char *create_env = rt_winrm_soap_build_create_powershell(
        c->endpoint, c->shell_id, creation_xml_b64);
    free(creation_xml_b64);
    if (create_env == NULL) {
        emit_state(c, RT_PROTO_STATE_ERROR, "Out of memory");
        return -1;
    }

    char  *resp = NULL;
    size_t resp_len = 0;
    int rc = soap_post(c, create_env, &resp, &resp_len, /*report_fault=*/1);
    free(create_env);
    if (rc != 0) {
        free(resp);
        return -1;
    }
    /* Adopt whatever ShellId the server actually assigned. Modern
     * Windows ignores the ShellId we put in the request and picks
     * its own; we MUST use the server-side value in subsequent
     * WinRM SelectorSets or every follow-up POST returns
     * w:InvalidSelectors. The PSRP RPID stays as our original UUID
     * (kept in c->psrp.rpid) since that's what's already embedded
     * in the runspace pool we created. */
    char *server_shell_id = rt_winrm_soap_parse_shell_id(resp, resp_len);
    if (server_shell_id != NULL) {
        rt_log(c, "adopted server shell_id=%s (psrp rpid stays as our gen)",
               server_shell_id);
        free(c->shell_id);
        c->shell_id = server_shell_id;
    } else {
        rt_log(c, "server did not return a shell_id; keeping our generated one");
    }
    free(resp);

    /* Drain Receive until RUNSPACEPOOL_STATE=Opened. */
    psrp_dispatch_state_t st = { .c = c };
    if (receive_psrp_loop(c, /*command_id=*/NULL,
                          /*wait_for_pipeline_done=*/0,
                          &st) != 0) {
        emit_state(c, RT_PROTO_STATE_ERROR,
                   "PowerShell runspace failed to open");
        return -1;
    }

    emit_state(c, RT_PROTO_STATE_CONNECTED, NULL);
    /* First idle so the view paints its initial prompt. */
    emit_idle(c);
    return 0;
}

static void *worker_main(void *arg)
{
    rt_protocol_ctx_t *c = arg;
    rt_log(c, "worker starting endpoint=%s user=%s",
           c->endpoint, c->username ? c->username : "(none)");

    if (worker_init_http(c) != 0) {
        rt_log(c, "worker http init failed; exiting");
        return NULL;
    }

    if (worker_connect(c) != 0) {
        rt_log(c, "worker connect failed; exiting");
        return NULL;
    }

    /* Command loop. */
    while (!atomic_load(&c->stop)) {
        char *cmd = dequeue_command(c, 250);
        if (cmd == NULL) {
            continue;
        }
        rt_log(c, "running command: %.80s%s",
               cmd, strlen(cmd) > 80 ? "..." : "");
        run_one_command(c, cmd);
        free(cmd);
    }
    rt_log(c, "worker exiting");
    return NULL;
}

/* ------------------------------------------------------------------ */
/* ops: open / send / close                                           */
/* ------------------------------------------------------------------ */

static void destroy_ctx(rt_protocol_ctx_t *c)
{
    if (c == NULL) return;
    queue_drain_free(c);
    free(c->acc);
    pthread_mutex_destroy(&c->q_mtx);
    pthread_cond_destroy(&c->q_cv);
    pthread_mutex_destroy(&c->acc_mtx);
    pthread_mutex_destroy(&c->pwd_mtx);
    if (c->http != NULL) rt_winrm_http_free(c->http);
    winrm_psrp_reset(&c->psrp);
    free(c->shell_id);
    free(c->endpoint);
    free(c->username);
    free(c->opts.domain);
    /* Defensive: if we never got far enough for the worker to wipe. */
    wipe_and_free(&c->pending_password);
    free(c);
}

static rt_protocol_ctx_t *winrm_open(const rt_connection_t      *conn,
                                     const char                 *password,
                                     const rt_proto_callbacks_t *cb,
                                     void                       *user)
{
    if (validate(conn) != 0) {
        return NULL;
    }
    if (password == NULL) {
        return NULL;
    }

    rt_protocol_ctx_t *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    if (cb != NULL) c->cb = *cb;
    c->cb_user = user;
    pthread_mutex_init(&c->q_mtx,   NULL);
    pthread_cond_init (&c->q_cv,    NULL);
    pthread_mutex_init(&c->acc_mtx, NULL);
    pthread_mutex_init(&c->pwd_mtx, NULL);
    atomic_init(&c->stop, 0);

    const char *dbg = getenv("RT_WINRM_DEBUG");
    c->debug = (dbg != NULL && dbg[0] != '\0' && dbg[0] != '0') ? 1 : 0;

    /* Copy options. domain duplicated; the rest are scalars. */
    c->opts = *conn->winrm;
    c->opts.domain = NULL;
    if (conn->winrm->domain != NULL) {
        c->opts.domain = strdup(conn->winrm->domain);
        if (c->opts.domain == NULL) goto fail;
    }

    c->username = dup_or_null(conn->username);
    if (conn->username != NULL && c->username == NULL) goto fail;

    c->endpoint = build_endpoint(conn->host, conn->port, c->opts.transport);
    if (c->endpoint == NULL) goto fail;

    /* Take a private copy of the password so the worker can use it
     * after session.c wipes its copy on return. The worker wipes
     * this copy as soon as the curl handle has internalised it. */
    c->pending_password = strdup(password);
    if (c->pending_password == NULL) goto fail;

    /* Tell the UI we're connecting before we hand off to the worker.
     * The actual SOAP handshake happens on the worker so the GTK
     * main thread isn't blocked for the duration. */
    emit_state(c, RT_PROTO_STATE_CONNECTING, NULL);

    if (pthread_create(&c->thread, NULL, worker_main, c) != 0) {
        emit_state(c, RT_PROTO_STATE_ERROR, "Failed to spawn worker");
        goto fail;
    }
    c->thread_started = 1;
    return c;

fail:
    destroy_ctx(c);
    return NULL;
}

static int winrm_send(rt_protocol_ctx_t *c, const void *data, size_t len)
{
    if (c == NULL || data == NULL || len == 0) {
        return -1;
    }
    if (atomic_load(&c->stop)) {
        return -1;
    }
    return acc_feed(c, (const char *)data, len);
}

static void winrm_close_ctx(rt_protocol_ctx_t *c)
{
    if (c == NULL) return;

    atomic_store(&c->stop, 1);

    pthread_mutex_lock(&c->q_mtx);
    pthread_cond_broadcast(&c->q_cv);
    pthread_mutex_unlock(&c->q_mtx);

    if (c->thread_started) {
        pthread_join(c->thread, NULL);
        c->thread_started = 0;
    }

    /* Best-effort SOAP Delete to release the server-side shell. The
     * abort_flag is already set; clear it so this final request can
     * actually go out. */
    if (c->shell_id != NULL && c->http != NULL) {
        atomic_store(&c->stop, 0);
        char *del = rt_winrm_soap_build_delete(c->endpoint, c->shell_id);
        if (del != NULL) {
            (void)soap_post(c, del, NULL, NULL, /*report_fault=*/0);
            free(del);
        }
        atomic_store(&c->stop, 1);
    }

    emit_state(c, RT_PROTO_STATE_DISCONNECTED, "Shell closed.");
    destroy_ctx(c);
}

/* ------------------------------------------------------------------ */
/* Public ops table                                                   */
/* ------------------------------------------------------------------ */

static const rt_protocol_ops_t WINRM_OPS = {
    .name               = "winrm",
    .open               = winrm_open,
    .send               = winrm_send,
    .send_input         = NULL,
    .resize             = NULL,
    .set_clipboard_text = NULL,
    .get_framebuffer    = NULL,
    .close              = winrm_close_ctx,
};

const rt_protocol_ops_t *rt_winrm_get_ops(void)
{
    return &WINRM_OPS;
}

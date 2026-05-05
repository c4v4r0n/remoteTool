/*
 * SSH protocol implementation, libssh back-end.
 *
 * Threading: each session owns one POSIX thread. That thread is
 * the *only* thread that touches the libssh ssh_session / ssh_channel
 * (libssh's per-session API is not safe to call concurrently from
 * multiple threads). UI input is funnelled in via a thread-safe
 * send queue which the same thread drains between read poll cycles.
 *
 * Cleanup is synchronous: ssh_close() flips an atomic stop flag,
 * waits for the thread to exit (it polls in short slices so this is
 * bounded), then tears down the libssh objects on the main thread.
 *
 * Host-key policy: TOFU against ~/.config/remoteTool/known_hosts.
 * UNKNOWN/NOT_FOUND -> trust + persist. CHANGED/OTHER -> hard fail
 * with the offending fingerprint reported to the UI.
 */

#include "protocols/ssh/ssh_protocol.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero on glibc */
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libssh/libssh.h>

/* Tunables */
#define RT_SSH_CONNECT_TIMEOUT_SEC 10
#define RT_SSH_READ_TIMEOUT_MS     30   /* poll slice; bounds shutdown latency */
#define RT_SSH_READ_BUFSZ          4096

/* ------------------------------------------------------------------ */
/* Internal types                                                     */
/* ------------------------------------------------------------------ */

typedef struct send_node {
    struct send_node *next;
    size_t            len;
    unsigned char     data[]; /* flexible */
} send_node_t;

struct rt_protocol_ctx {
    /* libssh handles - touched only by the worker thread after the
     * worker has been launched. */
    ssh_session  sess;
    ssh_channel  chan;

    /* Worker */
    pthread_t            thread;
    int                  thread_started;
    atomic_int           stop;          /* set by close(), read by worker */

    /* Send queue */
    pthread_mutex_t      send_mtx;
    send_node_t         *send_head;
    send_node_t         *send_tail;

    /* Pending PTY resize. Coalesced: only the latest size matters,
     * so we just store cols/rows under the mutex and the worker
     * applies it on its next loop iteration. */
    pthread_mutex_t      resize_mtx;
    unsigned             pending_cols;
    unsigned             pending_rows;
    int                  resize_pending;

    /* UI hook */
    rt_proto_callbacks_t cb;
    void                *cb_user;
};

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static void emit_state(rt_protocol_ctx_t *c, rt_proto_state_t st, const char *msg)
{
    if (c->cb.on_state != NULL) {
        c->cb.on_state(c->cb_user, st, msg);
    }
}

static void emit_data(rt_protocol_ctx_t *c, const char *data, size_t len)
{
    if (c->cb.on_data != NULL) {
        c->cb.on_data(c->cb_user, data, len);
    }
}

/* mkdir -p $HOME/.config/remoteTool. Returns malloc'd path on
 * success (caller frees), NULL on failure. */
static char *known_hosts_path(void)
{
    const char *home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        return NULL;
    }

    char *cfg = NULL;
    if (asprintf(&cfg, "%s/.config/remoteTool", home) < 0) {
        return NULL;
    }
    /* Best-effort mkdir; ignore EEXIST. */
    if (mkdir(cfg, 0700) != 0 && errno != EEXIST) {
        free(cfg);
        return NULL;
    }

    char *out = NULL;
    int n = asprintf(&out, "%s/known_hosts", cfg);
    free(cfg);
    return (n < 0) ? NULL : out;
}

/* Format the server's host key fingerprint as a heap string. */
static char *server_fingerprint(ssh_session sess)
{
    ssh_key        key  = NULL;
    unsigned char *hash = NULL;
    size_t         hlen = 0;
    char          *out  = NULL;

    if (ssh_get_server_publickey(sess, &key) != SSH_OK) {
        return NULL;
    }
    if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256,
                               &hash, &hlen) != 0) {
        goto done;
    }
    char *fp = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
    if (fp != NULL) {
        out = strdup(fp);
        ssh_string_free_char(fp);
    }

done:
    if (hash != NULL) {
        ssh_clean_pubkey_hash(&hash);
    }
    if (key != NULL) {
        ssh_key_free(key);
    }
    return out;
}

/* ------------------------------------------------------------------ */
/* Host-key verification (TOFU)                                       */
/* ------------------------------------------------------------------ */

/* Returns 0 to proceed, -1 to abort. Reports its own state on error. */
static int verify_host(rt_protocol_ctx_t *c)
{
    enum ssh_known_hosts_e r = ssh_session_is_known_server(c->sess);
    char *fp = server_fingerprint(c->sess);
    char  buf[512];

    switch (r) {
    case SSH_KNOWN_HOSTS_OK:
        free(fp);
        return 0;

    case SSH_KNOWN_HOSTS_UNKNOWN:
    case SSH_KNOWN_HOSTS_NOT_FOUND: {
        /* TOFU: trust on first use. Persist + report. */
        if (ssh_session_update_known_hosts(c->sess) != SSH_OK) {
            snprintf(buf, sizeof(buf),
                     "Failed to record host key: %s",
                     ssh_get_error(c->sess));
            emit_state(c, RT_PROTO_STATE_ERROR, buf);
            free(fp);
            return -1;
        }
        snprintf(buf, sizeof(buf),
                 "First-time host: trusted and saved (%s).",
                 fp ? fp : "fingerprint unavailable");
        emit_state(c, RT_PROTO_STATE_AUTHENTICATING, buf);
        free(fp);
        return 0;
    }

    case SSH_KNOWN_HOSTS_CHANGED:
        snprintf(buf, sizeof(buf),
                 "HOST KEY CHANGED for this host. Refusing to connect. "
                 "Current key: %s",
                 fp ? fp : "unknown");
        emit_state(c, RT_PROTO_STATE_ERROR, buf);
        free(fp);
        return -1;

    case SSH_KNOWN_HOSTS_OTHER:
        emit_state(c, RT_PROTO_STATE_ERROR,
                   "Host key type mismatch with stored key. Refusing.");
        free(fp);
        return -1;

    case SSH_KNOWN_HOSTS_ERROR:
    default:
        snprintf(buf, sizeof(buf), "Host key check failed: %s",
                 ssh_get_error(c->sess));
        emit_state(c, RT_PROTO_STATE_ERROR, buf);
        free(fp);
        return -1;
    }
}

/* ------------------------------------------------------------------ */
/* Worker thread                                                      */
/* ------------------------------------------------------------------ */

/* Drain pending sends. Called from worker thread. */
static int drain_sends(rt_protocol_ctx_t *c)
{
    for (;;) {
        pthread_mutex_lock(&c->send_mtx);
        send_node_t *n = c->send_head;
        if (n != NULL) {
            c->send_head = n->next;
            if (c->send_head == NULL) {
                c->send_tail = NULL;
            }
        }
        pthread_mutex_unlock(&c->send_mtx);

        if (n == NULL) {
            return 0;
        }
        int w = ssh_channel_write(c->chan, n->data, (uint32_t)n->len);
        free(n);
        if (w == SSH_ERROR) {
            return -1;
        }
    }
}

/* Apply a coalesced PTY resize, if one is pending. Worker thread. */
static void apply_pending_resize(rt_protocol_ctx_t *c)
{
    pthread_mutex_lock(&c->resize_mtx);
    int      pending = c->resize_pending;
    unsigned cols    = c->pending_cols;
    unsigned rows    = c->pending_rows;
    c->resize_pending = 0;
    pthread_mutex_unlock(&c->resize_mtx);

    if (pending) {
        ssh_channel_change_pty_size(c->chan, (int)cols, (int)rows);
    }
}

static void *worker_main(void *arg)
{
    rt_protocol_ctx_t *c = arg;
    char buf[RT_SSH_READ_BUFSZ];

    while (!atomic_load(&c->stop)) {
        if (drain_sends(c) != 0) {
            emit_state(c, RT_PROTO_STATE_ERROR, "Channel write failed");
            break;
        }
        apply_pending_resize(c);

        int n = ssh_channel_read_timeout(c->chan, buf, sizeof(buf),
                                         /*is_stderr=*/0,
                                         RT_SSH_READ_TIMEOUT_MS);
        if (n > 0) {
            emit_data(c, buf, (size_t)n);
            continue;
        }
        if (n == SSH_ERROR) {
            emit_state(c, RT_PROTO_STATE_ERROR,
                       ssh_get_error(c->sess));
            break;
        }
        if (n == 0) {
            if (ssh_channel_is_eof(c->chan)) {
                emit_state(c, RT_PROTO_STATE_DISCONNECTED,
                           "Remote closed the channel.");
                break;
            }
            /* timeout - loop */
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* ops: open / send / close                                           */
/* ------------------------------------------------------------------ */

static void destroy_ctx(rt_protocol_ctx_t *c)
{
    if (c == NULL) {
        return;
    }
    if (c->chan != NULL) {
        ssh_channel_close(c->chan);
        ssh_channel_free(c->chan);
    }
    if (c->sess != NULL) {
        if (ssh_is_connected(c->sess)) {
            ssh_disconnect(c->sess);
        }
        ssh_free(c->sess);
    }
    /* Drain any leftover queued sends. */
    send_node_t *n = c->send_head;
    while (n != NULL) {
        send_node_t *next = n->next;
        free(n);
        n = next;
    }
    pthread_mutex_destroy(&c->send_mtx);
    pthread_mutex_destroy(&c->resize_mtx);
    free(c);
}

static int validate_conn(const rt_connection_t *conn)
{
    if (conn == NULL || conn->host == NULL || conn->host[0] == '\0') {
        return -1;
    }
    if (conn->port == 0) {
        return -1;
    }
    /* Reject obviously bogus hosts (NUL byte already excluded by C
     * string semantics; reject control chars). */
    for (const char *p = conn->host; *p; ++p) {
        if ((unsigned char)*p < 0x20 || *p == ' ') {
            return -1;
        }
    }
    return 0;
}

static rt_protocol_ctx_t *ssh_open(const rt_connection_t      *conn,
                                   const char                 *password,
                                   const rt_proto_callbacks_t *cb,
                                   void                       *user)
{
    if (validate_conn(conn) != 0) {
        return NULL;
    }
    if (password == NULL) {
        /* Phase 2: only password auth is supported. */
        return NULL;
    }

    rt_protocol_ctx_t *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    if (cb != NULL) {
        c->cb = *cb;
    }
    c->cb_user = user;
    pthread_mutex_init(&c->send_mtx, NULL);
    pthread_mutex_init(&c->resize_mtx, NULL);
    atomic_init(&c->stop, 0);

    emit_state(c, RT_PROTO_STATE_CONNECTING, NULL);

    c->sess = ssh_new();
    if (c->sess == NULL) {
        emit_state(c, RT_PROTO_STATE_ERROR, "ssh_new failed");
        destroy_ctx(c);
        return NULL;
    }

    /* Options. All set-by-value; libssh copies. */
    long timeout = RT_SSH_CONNECT_TIMEOUT_SEC;
    unsigned int port = conn->port;
    ssh_options_set(c->sess, SSH_OPTIONS_HOST,    conn->host);
    ssh_options_set(c->sess, SSH_OPTIONS_PORT,    &port);
    ssh_options_set(c->sess, SSH_OPTIONS_TIMEOUT, &timeout);
    if (conn->username != NULL && conn->username[0] != '\0') {
        ssh_options_set(c->sess, SSH_OPTIONS_USER, conn->username);
    }
    char *kh = known_hosts_path();
    if (kh != NULL) {
        ssh_options_set(c->sess, SSH_OPTIONS_KNOWNHOSTS, kh);
        free(kh);
    }

    if (ssh_connect(c->sess) != SSH_OK) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Connect failed: %s",
                 ssh_get_error(c->sess));
        emit_state(c, RT_PROTO_STATE_ERROR, buf);
        destroy_ctx(c);
        return NULL;
    }

    if (verify_host(c) != 0) {
        destroy_ctx(c);
        return NULL;
    }

    emit_state(c, RT_PROTO_STATE_AUTHENTICATING, NULL);
    if (ssh_userauth_password(c->sess, NULL, password) != SSH_AUTH_SUCCESS) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Authentication failed: %s",
                 ssh_get_error(c->sess));
        emit_state(c, RT_PROTO_STATE_ERROR, buf);
        destroy_ctx(c);
        return NULL;
    }

    /* Open an interactive shell channel with a PTY. Request
     * xterm-256color so the remote shell emits the escape sequences
     * VTE knows how to render. The 80x24 default is overwritten by
     * the first resize once the terminal widget is laid out. */
    c->chan = ssh_channel_new(c->sess);
    if (c->chan == NULL ||
        ssh_channel_open_session(c->chan) != SSH_OK ||
        ssh_channel_request_pty_size(c->chan, "xterm-256color", 80, 24) != SSH_OK ||
        ssh_channel_request_shell(c->chan) != SSH_OK) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Shell channel failed: %s",
                 ssh_get_error(c->sess));
        emit_state(c, RT_PROTO_STATE_ERROR, buf);
        destroy_ctx(c);
        return NULL;
    }

    /* Spawn the I/O worker. From this point, only the worker may
     * touch c->sess and c->chan. */
    if (pthread_create(&c->thread, NULL, worker_main, c) != 0) {
        emit_state(c, RT_PROTO_STATE_ERROR, "Failed to start worker thread");
        destroy_ctx(c);
        return NULL;
    }
    c->thread_started = 1;

    emit_state(c, RT_PROTO_STATE_CONNECTED, NULL);
    return c;
}

static int ssh_send_bytes(rt_protocol_ctx_t *c, const void *data, size_t len)
{
    if (c == NULL || data == NULL || len == 0) {
        return -1;
    }
    if (atomic_load(&c->stop)) {
        return -1;
    }

    send_node_t *n = malloc(sizeof(*n) + len);
    if (n == NULL) {
        return -1;
    }
    n->next = NULL;
    n->len  = len;
    memcpy(n->data, data, len);

    pthread_mutex_lock(&c->send_mtx);
    if (c->send_tail != NULL) {
        c->send_tail->next = n;
    } else {
        c->send_head = n;
    }
    c->send_tail = n;
    pthread_mutex_unlock(&c->send_mtx);
    return 0;
}

static void ssh_resize(rt_protocol_ctx_t *c, unsigned cols, unsigned rows)
{
    if (c == NULL || cols == 0 || rows == 0) {
        return;
    }
    pthread_mutex_lock(&c->resize_mtx);
    c->pending_cols    = cols;
    c->pending_rows    = rows;
    c->resize_pending  = 1;
    pthread_mutex_unlock(&c->resize_mtx);
}

static void ssh_close_ctx(rt_protocol_ctx_t *c)
{
    if (c == NULL) {
        return;
    }
    atomic_store(&c->stop, 1);
    if (c->thread_started) {
        pthread_join(c->thread, NULL);
        c->thread_started = 0;
    }
    destroy_ctx(c);
}

/* ------------------------------------------------------------------ */
/* Public ops table                                                   */
/* ------------------------------------------------------------------ */

static const rt_protocol_ops_t SSH_OPS = {
    .name               = "ssh",
    .open               = ssh_open,
    .send               = ssh_send_bytes,
    .send_input         = NULL,   /* SSH is byte-stream */
    .resize             = ssh_resize,
    .set_clipboard_text = NULL,
    .get_framebuffer    = NULL,
    .close              = ssh_close_ctx,
};

const rt_protocol_ops_t *rt_ssh_get_ops(void)
{
    return &SSH_OPS;
}

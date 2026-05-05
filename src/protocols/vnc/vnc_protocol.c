/*
 * VNC protocol implementation, libvncclient back-end.
 *
 * Threading
 * =========
 * One POSIX worker thread per session. The worker is the ONLY thread
 * that touches the rfbClient handle. UI input/clipboard reaches the
 * worker via mutex-guarded queues drained at the top of each event
 * loop iteration. The worker calls WaitForMessage(cl, 30 ms) which
 * caps input latency at 30 ms in the worst case (typical: a single
 * digit ms when there's network traffic to wake select).
 *
 * Framebuffer
 * ===========
 * We negotiate 32 bpp BGRA byte order on little-endian, which is
 * byte-compatible with CAIRO_FORMAT_ARGB32. libvncclient calls our
 * MallocFrameBuffer hook on connect AND on every server-initiated
 * resize (canHandleNewFBSize = TRUE). The buffer is owned by
 * libvncclient and freed by rfbClientCleanup; we just take fb_mtx
 * around the realloc so the UI doesn't read stale dims.
 *
 * View-only
 * =========
 * Enforced inside vnc_send_input() (returns immediately if the flag
 * is set). The widget separately suppresses input forwarding via
 * input_enabled, but defense-in-depth ensures a buggy widget can't
 * leak keystrokes to the remote.
 *
 * Clipboard
 * =========
 * Text only. RFB cut-text is Latin-1 by spec; we pass bytes through
 * unchanged in both directions. Pure ASCII works perfectly; non-ASCII
 * may render imperfectly until we add encoding conversion.
 * NEVER logs clipboard contents.
 */

#include "protocols/vnc/vnc_protocol.h"
#include "protocols/framebuffer_internal.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero */

#include <rfb/rfbclient.h>

/* ------------------------------------------------------------------ */
/* Tunables                                                           */
/* ------------------------------------------------------------------ */

#define RT_VNC_WAIT_TIMEOUT_US 30000        /* 30 ms */
#define RT_VNC_INPUT_CAP_HINT  256

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

typedef struct rt_vnc_framebuffer {
    struct rt_remote_framebuffer base;     /* must be first */
    struct rt_protocol_ctx      *owner;
} rt_vnc_framebuffer_t;

struct rt_protocol_ctx {
    /* libvncclient */
    rfbClient                  *cl;        /* worker-thread only */

    /* Framebuffer accessor */
    rt_vnc_framebuffer_t        fb_handle;
    pthread_mutex_t             fb_mtx;
    int                         fb_w, fb_h, fb_stride;

    /* Input mouse-button accumulator (RFB sends absolute button mask) */
    int                         button_mask;
    int                         mouse_x, mouse_y;

    /* Worker */
    pthread_t                   thread;
    int                         thread_started;
    atomic_int                  stop;

    /* Input queue (UI -> worker) */
    pthread_mutex_t             input_mtx;
    rt_input_event_t           *input_buf;
    size_t                      input_len;
    size_t                      input_cap;

    /* Clipboard out (UI -> remote) */
    pthread_mutex_t             clip_mtx;
    char                       *pending_clip;       /* heap, owned */
    size_t                      pending_clip_len;
    int                         clip_dirty;

    /* Connection params (owned copies). Password is wiped after the
     * RFB handshake completes. */
    char                       *host;
    char                       *username;            /* may be NULL */
    char                       *password;            /* may be NULL */
    int                         port;
    int                         view_only;
    int                         clipboard_enabled;

    /* UI hook */
    rt_proto_callbacks_t        cb;
    void                       *cb_user;
};

typedef struct rt_protocol_ctx rt_vnc_ctx_t;

/* libvncclient client-data key. The address is the key; it never
 * needs to be a real object, just a stable pointer. */
static int RT_VNC_CTX_KEY = 0;

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static void emit_state(rt_vnc_ctx_t *c, rt_proto_state_t st, const char *msg)
{
    if (c->cb.on_state != NULL) {
        c->cb.on_state(c->cb_user, st, msg);
    }
}

static void emit_frame(rt_vnc_ctx_t *c, const rt_remote_frame_t *f)
{
    if (c->cb.on_frame != NULL) {
        c->cb.on_frame(c->cb_user, f);
    }
}

static char *dup_str(const char *s)
{
    if (s == NULL) return NULL;
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    if (out != NULL) memcpy(out, s, n);
    return out;
}

/* ------------------------------------------------------------------ */
/* Framebuffer accessor                                               */
/* ------------------------------------------------------------------ */

static void vnc_fb_lock(struct rt_remote_framebuffer *self,
                        const uint8_t **out_pixels,
                        int *out_w, int *out_h, int *out_stride,
                        rt_frame_format_t *out_fmt)
{
    rt_vnc_framebuffer_t *fb = (rt_vnc_framebuffer_t *)self;
    rt_vnc_ctx_t        *c  = fb->owner;

    pthread_mutex_lock(&c->fb_mtx);
    if (out_pixels != NULL) {
        *out_pixels = (c->cl != NULL) ? (const uint8_t *)c->cl->frameBuffer : NULL;
    }
    if (out_w != NULL)      *out_w      = c->fb_w;
    if (out_h != NULL)      *out_h      = c->fb_h;
    if (out_stride != NULL) *out_stride = c->fb_stride;
    if (out_fmt != NULL)    *out_fmt    = RT_FRAME_FORMAT_BGRA32;
}

static void vnc_fb_release(struct rt_remote_framebuffer *self)
{
    rt_vnc_framebuffer_t *fb = (rt_vnc_framebuffer_t *)self;
    pthread_mutex_unlock(&fb->owner->fb_mtx);
}

static const rt_remote_framebuffer_vtbl_t VNC_FB_VTBL = {
    .lock    = vnc_fb_lock,
    .release = vnc_fb_release,
};

/* ------------------------------------------------------------------ */
/* libvncclient callbacks                                             */
/* ------------------------------------------------------------------ */

static rfbBool vnc_malloc_framebuffer(rfbClient *cl)
{
    rt_vnc_ctx_t *c = rfbClientGetClientData(cl, &RT_VNC_CTX_KEY);
    int new_w      = cl->width;
    int new_h      = cl->height;
    int new_stride = new_w * 4;

    pthread_mutex_lock(&c->fb_mtx);
    free(cl->frameBuffer);
    cl->frameBuffer = (uint8_t *)calloc(1, (size_t)new_h * (size_t)new_stride);
    if (cl->frameBuffer == NULL) {
        c->fb_w = c->fb_h = c->fb_stride = 0;
        pthread_mutex_unlock(&c->fb_mtx);
        return FALSE;
    }
    c->fb_w      = new_w;
    c->fb_h      = new_h;
    c->fb_stride = new_stride;
    pthread_mutex_unlock(&c->fb_mtx);

    /* Whole-frame invalidation so the widget repaints at the new size. */
    rt_remote_frame_t f = {
        .width   = new_w,
        .height  = new_h,
        .dirty_x = 0, .dirty_y = 0,
        .dirty_w = new_w, .dirty_h = new_h,
    };
    emit_frame(c, &f);
    return TRUE;
}

static void vnc_got_framebuffer_update(rfbClient *cl, int x, int y, int w, int h)
{
    rt_vnc_ctx_t *c = rfbClientGetClientData(cl, &RT_VNC_CTX_KEY);
    rt_remote_frame_t f = {
        .width   = c->fb_w,
        .height  = c->fb_h,
        .dirty_x = x, .dirty_y = y,
        .dirty_w = w, .dirty_h = h,
    };
    emit_frame(c, &f);
}

/* libvncclient owns the returned char* and frees it after use. */
static char *vnc_get_password(rfbClient *cl)
{
    rt_vnc_ctx_t *c = rfbClientGetClientData(cl, &RT_VNC_CTX_KEY);
    /* If we don't have one, return an empty string - the server will
     * reject and rfbInitClient will fail cleanly. */
    return strdup(c->password ? c->password : "");
}

/* For TLS-VNC / Apple-VNC and similar auth schemes that take a
 * username + password. Plain RFB never calls this. */
static rfbCredential *vnc_get_credential(rfbClient *cl, int credentialType)
{
    rt_vnc_ctx_t  *c = rfbClientGetClientData(cl, &RT_VNC_CTX_KEY);
    if (credentialType != rfbCredentialTypeUser) {
        return NULL;
    }
    rfbCredential *cred = calloc(1, sizeof(*cred));
    if (cred == NULL) return NULL;
    cred->userCredential.username = strdup(c->username ? c->username : "");
    cred->userCredential.password = strdup(c->password ? c->password : "");
    return cred;
}

/* Server -> local clipboard. RFB cut-text is Latin-1 per spec; we
 * pass bytes through. NEVER log contents. */
static void vnc_got_cut_text(rfbClient *cl, const char *text, int textlen)
{
    rt_vnc_ctx_t *c = rfbClientGetClientData(cl, &RT_VNC_CTX_KEY);
    if (!c->clipboard_enabled || c->cb.on_clipboard_text == NULL ||
        text == NULL || textlen <= 0) {
        return;
    }
    c->cb.on_clipboard_text(c->cb_user, text, (size_t)textlen);
}

/* ------------------------------------------------------------------ */
/* Input dispatch (worker thread)                                     */
/* ------------------------------------------------------------------ */

static void dispatch_one_input(rt_vnc_ctx_t *c, const rt_input_event_t *e)
{
    /* Hard view-only enforcement. */
    if (c->view_only || c->cl == NULL) {
        return;
    }

    switch (e->kind) {
    case RT_INPUT_MOUSE_MOVE:
        c->mouse_x = e->x;
        c->mouse_y = e->y;
        SendPointerEvent(c->cl, e->x, e->y, c->button_mask);
        break;

    case RT_INPUT_MOUSE_BUTTON: {
        int bit = 0;
        switch (e->button) {
        case 1: bit = rfbButton1Mask; break;
        case 2: bit = rfbButton2Mask; break; /* GTK middle = RFB middle */
        case 3: bit = rfbButton3Mask; break; /* GTK right  = RFB right  */
        default: return;
        }
        if (e->pressed) c->button_mask |= bit;
        else            c->button_mask &= ~bit;
        SendPointerEvent(c->cl, e->x, e->y, c->button_mask);
        break;
    }

    case RT_INPUT_MOUSE_WHEEL: {
        if (e->wheel_delta == 0) return;
        int wheel_btn = (e->wheel_delta > 0) ? rfbButton4Mask : rfbButton5Mask;
        /* RFB wheel = press+release of buttons 4/5 at the cursor. */
        SendPointerEvent(c->cl, e->x, e->y, c->button_mask | wheel_btn);
        SendPointerEvent(c->cl, e->x, e->y, c->button_mask);
        break;
    }

    case RT_INPUT_KEY:
        if (e->keysym != 0) {
            SendKeyEvent(c->cl, e->keysym, e->pressed ? TRUE : FALSE);
        }
        break;

    case RT_INPUT_UNICODE:
        SendKeyEvent(c->cl, e->unicode_cp, e->pressed ? TRUE : FALSE);
        break;
    }
}

static void drain_input(rt_vnc_ctx_t *c)
{
    pthread_mutex_lock(&c->input_mtx);
    rt_input_event_t *buf = c->input_buf;
    size_t            n   = c->input_len;
    c->input_buf = NULL;
    c->input_len = 0;
    c->input_cap = 0;
    pthread_mutex_unlock(&c->input_mtx);

    for (size_t i = 0; i < n; i++) {
        dispatch_one_input(c, &buf[i]);
    }
    free(buf);
}

static void drain_clipboard_out(rt_vnc_ctx_t *c)
{
    pthread_mutex_lock(&c->clip_mtx);
    int dirty = c->clip_dirty;
    char *text = NULL;
    size_t len = 0;
    if (dirty && c->pending_clip != NULL) {
        text = c->pending_clip;        /* hand off ownership */
        len  = c->pending_clip_len;
        c->pending_clip     = NULL;
        c->pending_clip_len = 0;
    }
    c->clip_dirty = 0;
    pthread_mutex_unlock(&c->clip_mtx);

    if (text != NULL && c->cl != NULL && c->clipboard_enabled) {
        SendClientCutText(c->cl, text, (int)len);
    }
    if (text != NULL) {
        explicit_bzero(text, len);
        free(text);
    }
}

/* ------------------------------------------------------------------ */
/* Worker                                                             */
/* ------------------------------------------------------------------ */

static void *worker_main(void *arg)
{
    rt_vnc_ctx_t *c = arg;

    emit_state(c, RT_PROTO_STATE_CONNECTING, NULL);

    /* (8 bitsPerSample, 3 samplesPerPixel, 4 bytesPerPixel) -> 32bpp,
     * 24-bit colour. We override format below to lock byte order. */
    rfbClient *cl = rfbGetClient(8, 3, 4);
    if (cl == NULL) {
        emit_state(c, RT_PROTO_STATE_ERROR, "rfbGetClient failed");
        goto wipe_pw;
    }

    cl->serverHost          = strdup(c->host);
    cl->serverPort          = c->port;
    cl->canHandleNewFBSize  = TRUE;

    /* BGRA byte order on little-endian, which matches CAIRO_FORMAT_
     * ARGB32. No per-frame conversion needed downstream. */
    cl->format.bitsPerPixel = 32;
    cl->format.depth        = 24;
    cl->format.bigEndian    = FALSE;
    cl->format.trueColour   = TRUE;
    cl->format.redMax       = 255;
    cl->format.greenMax     = 255;
    cl->format.blueMax      = 255;
    cl->format.redShift     = 16;
    cl->format.greenShift   = 8;
    cl->format.blueShift    = 0;

    cl->MallocFrameBuffer    = vnc_malloc_framebuffer;
    cl->GotFrameBufferUpdate = vnc_got_framebuffer_update;
    cl->GetPassword          = vnc_get_password;
    cl->GetCredential        = vnc_get_credential;
    if (c->clipboard_enabled) {
        cl->GotXCutText = vnc_got_cut_text;
    }

    rfbClientSetClientData(cl, &RT_VNC_CTX_KEY, c);

    /* Publish the handle BEFORE rfbInitClient because MallocFrameBuffer
     * fires from inside it and needs to find the ctx. */
    c->cl = cl;

    emit_state(c, RT_PROTO_STATE_AUTHENTICATING, NULL);

    int argc = 0;
    if (!rfbInitClient(cl, &argc, NULL)) {
        /* rfbInitClient already freed cl on failure - do NOT touch it. */
        c->cl = NULL;
        emit_state(c, RT_PROTO_STATE_ERROR, "VNC connect failed");
        goto wipe_pw;
    }

    /* Auth done - drop the password copy. */
    if (c->password != NULL) {
        explicit_bzero(c->password, strlen(c->password));
        free(c->password);
        c->password = NULL;
    }

    emit_state(c, RT_PROTO_STATE_CONNECTED, NULL);

    while (!atomic_load(&c->stop)) {
        drain_input(c);
        drain_clipboard_out(c);

        int n = WaitForMessage(cl, RT_VNC_WAIT_TIMEOUT_US);
        if (n < 0) {
            emit_state(c, RT_PROTO_STATE_ERROR, "WaitForMessage failed");
            break;
        }
        if (n > 0) {
            if (!HandleRFBServerMessage(cl)) {
                emit_state(c, RT_PROTO_STATE_DISCONNECTED, NULL);
                break;
            }
        }
    }

    rfbClientCleanup(cl);
    c->cl = NULL;
    return NULL;

wipe_pw:
    if (c->password != NULL) {
        explicit_bzero(c->password, strlen(c->password));
        free(c->password);
        c->password = NULL;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Lifecycle / ops                                                    */
/* ------------------------------------------------------------------ */

static int validate_conn(const rt_connection_t *conn)
{
    if (conn == NULL || conn->host == NULL || conn->host[0] == '\0') {
        return -1;
    }
    if (conn->port == 0) {
        return -1;
    }
    return 0;
}

static rt_vnc_ctx_t *ctx_new(const rt_connection_t      *conn,
                             const char                 *password,
                             const rt_proto_callbacks_t *cb,
                             void                       *user)
{
    rt_vnc_ctx_t *c = calloc(1, sizeof(*c));
    if (c == NULL) return NULL;
    if (cb != NULL) c->cb = *cb;
    c->cb_user = user;

    pthread_mutex_init(&c->fb_mtx,    NULL);
    pthread_mutex_init(&c->input_mtx, NULL);
    pthread_mutex_init(&c->clip_mtx,  NULL);
    atomic_init(&c->stop, 0);

    c->fb_handle.base.vtbl = &VNC_FB_VTBL;
    c->fb_handle.owner     = c;

    c->host     = dup_str(conn->host);
    c->username = dup_str(conn->username);
    c->password = dup_str(password);
    if (c->host == NULL ||
        (conn->username != NULL && c->username == NULL) ||
        (password       != NULL && c->password == NULL)) {
        goto fail;
    }
    c->port = conn->port;

    /* VNC options: defaults if the connection didn't carry an opts
     * struct (e.g. quick connect). */
    if (conn->vnc != NULL) {
        c->view_only         = conn->vnc->view_only         ? 1 : 0;
        c->clipboard_enabled = conn->vnc->clipboard_enabled ? 1 : 0;
    } else {
        c->view_only         = 0;
        c->clipboard_enabled = 1;
    }
    return c;

fail:
    pthread_mutex_destroy(&c->fb_mtx);
    pthread_mutex_destroy(&c->input_mtx);
    pthread_mutex_destroy(&c->clip_mtx);
    if (c->password != NULL) {
        explicit_bzero(c->password, strlen(c->password));
    }
    free(c->host); free(c->username); free(c->password);
    free(c);
    return NULL;
}

static void ctx_free(rt_vnc_ctx_t *c)
{
    if (c == NULL) return;
    free(c->input_buf);
    free(c->host);
    free(c->username);
    if (c->password != NULL) {
        explicit_bzero(c->password, strlen(c->password));
        free(c->password);
    }
    if (c->pending_clip != NULL) {
        explicit_bzero(c->pending_clip, c->pending_clip_len);
        free(c->pending_clip);
    }
    pthread_mutex_destroy(&c->fb_mtx);
    pthread_mutex_destroy(&c->input_mtx);
    pthread_mutex_destroy(&c->clip_mtx);
    free(c);
}

static rt_protocol_ctx_t *vnc_open(const rt_connection_t      *conn,
                                   const char                 *password,
                                   const rt_proto_callbacks_t *cb,
                                   void                       *user)
{
    if (validate_conn(conn) != 0) {
        return NULL;
    }
    rt_vnc_ctx_t *c = ctx_new(conn, password, cb, user);
    if (c == NULL) return NULL;

    if (pthread_create(&c->thread, NULL, worker_main, c) != 0) {
        emit_state(c, RT_PROTO_STATE_ERROR, "Failed to start worker thread");
        ctx_free(c);
        return NULL;
    }
    c->thread_started = 1;
    return c;
}

static int vnc_send_input(rt_protocol_ctx_t *c, const rt_input_event_t *evt)
{
    if (c == NULL || evt == NULL) return -1;
    if (atomic_load(&c->stop)) return -1;
    /* Cheap rejection of input on view-only sessions; saves the queue
     * cost. The worker re-checks before dispatch. */
    if (c->view_only) return 0;

    pthread_mutex_lock(&c->input_mtx);
    if (c->input_len + 1 > c->input_cap) {
        size_t new_cap = c->input_cap ? c->input_cap * 2 : RT_VNC_INPUT_CAP_HINT;
        rt_input_event_t *nb = realloc(c->input_buf,
                                       new_cap * sizeof(rt_input_event_t));
        if (nb == NULL) {
            pthread_mutex_unlock(&c->input_mtx);
            return -1;
        }
        c->input_buf = nb;
        c->input_cap = new_cap;
    }
    c->input_buf[c->input_len++] = *evt;
    pthread_mutex_unlock(&c->input_mtx);
    return 0;
}

static int vnc_set_clipboard_text(rt_protocol_ctx_t *c,
                                  const char *utf8, size_t len)
{
    if (c == NULL || utf8 == NULL) return -1;
    if (!c->clipboard_enabled) return -1;

    char *copy = malloc(len + 1);
    if (copy == NULL) return -1;
    memcpy(copy, utf8, len);
    copy[len] = '\0';

    pthread_mutex_lock(&c->clip_mtx);
    if (c->pending_clip != NULL) {
        explicit_bzero(c->pending_clip, c->pending_clip_len);
        free(c->pending_clip);
    }
    c->pending_clip     = copy;
    c->pending_clip_len = len;
    c->clip_dirty       = 1;
    pthread_mutex_unlock(&c->clip_mtx);
    return 0;
}

static rt_remote_framebuffer_t *vnc_get_framebuffer(rt_protocol_ctx_t *c)
{
    if (c == NULL) return NULL;
    return &c->fb_handle.base;
}

static void vnc_close(rt_protocol_ctx_t *c)
{
    if (c == NULL) return;
    atomic_store(&c->stop, 1);
    if (c->thread_started) {
        /* Worker exits within RT_VNC_WAIT_TIMEOUT_US (~30 ms). */
        pthread_join(c->thread, NULL);
        c->thread_started = 0;
    }
    ctx_free(c);
}

/* VNC has no DispDyn equivalent and no PTY; resize is a no-op. The
 * widget keeps doing client-side scaling. */
static void vnc_resize(rt_protocol_ctx_t *c, unsigned cols, unsigned rows)
{
    (void)c; (void)cols; (void)rows;
}

/* ------------------------------------------------------------------ */
/* Ops table                                                          */
/* ------------------------------------------------------------------ */

static const rt_protocol_ops_t VNC_OPS = {
    .name               = "vnc",
    .open               = vnc_open,
    .send               = NULL,                /* not byte-stream */
    .send_input         = vnc_send_input,
    .resize             = vnc_resize,
    .set_clipboard_text = vnc_set_clipboard_text,
    .get_framebuffer    = vnc_get_framebuffer,
    .close              = vnc_close,
};

const rt_protocol_ops_t *rt_vnc_get_ops(void)
{
    return &VNC_OPS;
}

/*
 * RDP protocol implementation, FreeRDP 3 back-end.
 *
 * Threading
 * =========
 * Each session owns one POSIX worker thread. That thread is the
 * ONLY thread that touches the FreeRDP `freerdp*` instance. The UI
 * thread interacts with the back-end exclusively via thread-safe
 * queues guarded by mutexes:
 *
 *    UI -> worker  : input events, resize requests, clipboard out
 *    worker -> UI  : on_state, on_frame, on_clipboard_text
 *
 * Cross-thread wakeup uses a winpr auto-reset event ("wake") added
 * to FreeRDP's wait set, so input from the UI is processed within
 * one event loop iteration instead of waiting for the network poll
 * timeout.
 *
 * Framebuffer
 * ===========
 * GDI is initialized as PIXEL_FORMAT_BGRA32, which is byte-compatible
 * with cairo's CAIRO_FORMAT_ARGB32 on little-endian. The pixel
 * buffer (`gdi->primary_buffer`) is owned by FreeRDP for the
 * lifetime of the context. We expose it through an
 * rt_remote_framebuffer_t whose lock/release pair holds `fb_mtx`
 * just long enough for the UI to blit. Writes to the buffer happen
 * exclusively on the worker thread (inside check_event_handles -> ...
 * -> EndPaint), so the UI lock prevents races with frame updates.
 *
 * Clipboard
 * =========
 * CLIPRDR text only (CF_UNICODETEXT). When `clipboard_enabled` is
 * false in the connection, the channel is never registered and all
 * the clipboard plumbing stays dormant. NEVER logs clipboard
 * contents, ever.
 *
 * Security
 * ========
 * Cert verification: by default unknown/changed certs are rejected.
 * If the connection's `insecure_cert_bypass` is set (lab-only flag,
 * surfaced as a checkbox marked INSECURE in the form), the verify
 * callbacks accept anything. Legacy SSL is NOT enabled here; the
 * default settings keep TLS on with NLA preferred.
 */

#include "protocols/rdp/rdp_protocol.h"
#include "protocols/framebuffer_internal.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero */
#include <sys/stat.h>     /* mkdir */
#include <sys/types.h>
#include <unistd.h>

/* FreeRDP headers can use 64-bit enum values that trip -Wpedantic. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

#include <freerdp/freerdp.h>
#include <freerdp/client.h>
#include <freerdp/settings.h>
#include <freerdp/event.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/input.h>
#include <freerdp/scancode.h>
#include <freerdp/locale/keyboard.h>
#include <freerdp/client/cliprdr.h>
#include <freerdp/channels/cliprdr.h>
#include <freerdp/client/disp.h>
#include <freerdp/channels/disp.h>
#include <freerdp/client/channels.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/addin.h>

#include <winpr/synch.h>
#include <winpr/string.h>
#include <winpr/clipboard.h>

#pragma GCC diagnostic pop

/* ------------------------------------------------------------------ */
/* Tunables                                                           */
/* ------------------------------------------------------------------ */

#define RT_RDP_WAIT_TIMEOUT_MS 100   /* network poll slice */
#define RT_RDP_INPUT_CAP_HINT  256   /* initial input queue capacity */

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

typedef struct rt_rdp_framebuffer {
    /* Header MUST be first - the public opaque type is this header.
     * See protocols/framebuffer_internal.h. */
    struct rt_remote_framebuffer base;
    struct rt_protocol_ctx      *owner;   /* back-pointer */
} rt_rdp_framebuffer_t;

typedef struct rt_rdp_freerdp_context {
    rdpContext                  common;   /* must be first */
    struct rt_protocol_ctx     *self;     /* back-pointer */
} rt_rdp_freerdp_context_t;

struct rt_protocol_ctx {
    /* FreeRDP */
    freerdp                    *instance;
    rdpGdi                     *gdi;            /* set in PostConnect */

    /* Framebuffer accessor exposed to UI. */
    rt_rdp_framebuffer_t        fb_handle;
    pthread_mutex_t             fb_mtx;
    int                         fb_w, fb_h, fb_stride;

    /* Worker */
    pthread_t                   thread;
    int                         thread_started;
    atomic_int                  stop;
    HANDLE                      wake;           /* winpr auto-reset event */

    /* Input queue (UI -> worker) */
    pthread_mutex_t             input_mtx;
    rt_input_event_t           *input_buf;
    size_t                      input_len;
    size_t                      input_cap;

    /* Pending resize (UI -> worker). v1 stores the request but does
     * NOT trigger a remote resolution change - we just drive the UI
     * draw scaling. The struct field is wired so phase 3.5 DispDyn
     * support can plug in without API churn. */
    pthread_mutex_t             resize_mtx;
    int                         pending_resize_w;
    int                         pending_resize_h;
    int                         resize_pending;

    /* Clipboard out (UI -> remote). */
    pthread_mutex_t             clip_mtx;
    char                       *pending_clip_utf8;  /* heap, owned */
    size_t                      pending_clip_len;
    int                         clip_dirty;          /* something to send */

    /* CLIPRDR */
    CliprdrClientContext       *cliprdr;             /* set on channel connect */
    int                         cliprdr_ready;       /* MonitorReady seen */

    /* DispDyn (Display Control) */
    DispClientContext          *disp;                /* set on channel connect */
    int                         disp_caps_received;
    UINT32                      disp_max_num_monitors;
    UINT32                      disp_max_factor_a;   /* max width */
    UINT32                      disp_max_factor_b;   /* max height */

    /* Cert TOFU. Single-threaded access (worker only); no mutex. */
    char                       *cert_error;          /* heap, owned */

    /* Connection params (owned copies). Password is wiped + freed
     * immediately after open(). */
    char                       *host;
    char                       *username;
    char                       *password;
    char                       *domain;
    int                         port;
    int                         width, height, color_depth;
    int                         insecure_cert;
    int                         clipboard_enabled;

    /* UI hook */
    rt_proto_callbacks_t        cb;
    void                       *cb_user;
};

typedef struct rt_protocol_ctx rt_rdp_ctx_t;

/* ------------------------------------------------------------------ */
/* Forward decls                                                      */
/* ------------------------------------------------------------------ */

static void *worker_main(void *arg);
static BOOL  pre_connect (freerdp *instance);
static BOOL  post_connect(freerdp *instance);
static void  post_disconnect(freerdp *instance);
static BOOL  authenticate(freerdp *instance,
                          char **username, char **password, char **domain);
static DWORD verify_certificate_ex(freerdp *instance,
                                   const char *host, UINT16 port,
                                   const char *common_name, const char *subject,
                                   const char *issuer, const char *fingerprint,
                                   DWORD flags);
static DWORD verify_changed_certificate_ex(freerdp *instance,
                                           const char *host, UINT16 port,
                                           const char *common_name, const char *subject,
                                           const char *issuer, const char *fingerprint,
                                           const char *old_subject, const char *old_issuer,
                                           const char *old_fingerprint, DWORD flags);

static BOOL  rdp_end_paint(rdpContext *context);

static void  channel_connected   (void *context, const ChannelConnectedEventArgs *e);
static void  channel_disconnected(void *context, const ChannelDisconnectedEventArgs *e);

static UINT  on_clip_monitor_ready(CliprdrClientContext *clipboard,
                                   const CLIPRDR_MONITOR_READY *ready);
static UINT  on_clip_server_capabilities(CliprdrClientContext *clipboard,
                                         const CLIPRDR_CAPABILITIES *caps);
static UINT  on_clip_server_format_list(CliprdrClientContext *clipboard,
                                        const CLIPRDR_FORMAT_LIST *list);
static UINT  on_clip_server_format_list_response(CliprdrClientContext *clipboard,
                                                 const CLIPRDR_FORMAT_LIST_RESPONSE *r);
static UINT  on_clip_server_format_data_request(CliprdrClientContext *clipboard,
                                                const CLIPRDR_FORMAT_DATA_REQUEST *req);
static UINT  on_clip_server_format_data_response(CliprdrClientContext *clipboard,
                                                 const CLIPRDR_FORMAT_DATA_RESPONSE *resp);

static UINT  on_disp_caps(DispClientContext *disp,
                          UINT32 max_num_monitors,
                          UINT32 max_factor_a,
                          UINT32 max_factor_b);

static BOOL  rdp_desktop_resize(rdpContext *context);

/* Cert TOFU helpers. */
static char *known_hosts_path(void);
typedef enum {
    KH_OK = 0,
    KH_NOT_FOUND,
    KH_CHANGED,
    KH_ERROR
} kh_result_t;
static kh_result_t known_hosts_lookup(const char *host, int port,
                                      const char *fingerprint);
static int   known_hosts_record(const char *host, int port,
                                const char *fingerprint);

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static void emit_state(rt_rdp_ctx_t *c, rt_proto_state_t st, const char *msg)
{
    if (c->cb.on_state != NULL) {
        c->cb.on_state(c->cb_user, st, msg);
    }
}

static void emit_frame(rt_rdp_ctx_t *c, const rt_remote_frame_t *f)
{
    if (c->cb.on_frame != NULL) {
        c->cb.on_frame(c->cb_user, f);
    }
}

static char *dup_str(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    if (out != NULL) {
        memcpy(out, s, n);
    }
    return out;
}

/* ------------------------------------------------------------------ */
/* Framebuffer vtbl                                                   */
/* ------------------------------------------------------------------ */

static void rdp_fb_lock(struct rt_remote_framebuffer *self,
                        const uint8_t **out_pixels,
                        int *out_w, int *out_h, int *out_stride,
                        rt_frame_format_t *out_fmt)
{
    rt_rdp_framebuffer_t *fb = (rt_rdp_framebuffer_t *)self;
    rt_rdp_ctx_t        *c  = fb->owner;

    pthread_mutex_lock(&c->fb_mtx);
    if (out_pixels != NULL) {
        *out_pixels = (c->gdi != NULL) ? c->gdi->primary_buffer : NULL;
    }
    if (out_w != NULL)      *out_w      = c->fb_w;
    if (out_h != NULL)      *out_h      = c->fb_h;
    if (out_stride != NULL) *out_stride = c->fb_stride;
    if (out_fmt != NULL)    *out_fmt    = RT_FRAME_FORMAT_BGRA32;
}

static void rdp_fb_release(struct rt_remote_framebuffer *self)
{
    rt_rdp_framebuffer_t *fb = (rt_rdp_framebuffer_t *)self;
    pthread_mutex_unlock(&fb->owner->fb_mtx);
}

static const rt_remote_framebuffer_vtbl_t RDP_FB_VTBL = {
    .lock    = rdp_fb_lock,
    .release = rdp_fb_release,
};

/* ------------------------------------------------------------------ */
/* Auth + cert callbacks                                              */
/* ------------------------------------------------------------------ */

static BOOL authenticate(freerdp *instance,
                         char **username, char **password, char **domain)
{
    rt_rdp_freerdp_context_t *fctx = (rt_rdp_freerdp_context_t *)instance->context;
    rt_rdp_ctx_t             *c    = fctx->self;

    /* All credentials are already in settings - nothing to prompt
     * for. Returning the existing pointers signals success. */
    (void)username; (void)password; (void)domain;
    emit_state(c, RT_PROTO_STATE_AUTHENTICATING, NULL);
    return TRUE;
}

/* Return value: 1 = accept once, 2 = accept and store, 0 = reject.
 *
 * Policy: insecure-bypass tickbox short-circuits to accept. Otherwise
 * TOFU - look the host up in our own known_hosts file and accept iff
 * the fingerprint matches what we recorded last time. First-time
 * hosts are trusted and persisted (mirrors the SSH back-end's
 * behaviour); changed hosts are hard-rejected. */
static DWORD verify_certificate_ex(freerdp *instance,
                                   const char *host, UINT16 port,
                                   const char *common_name, const char *subject,
                                   const char *issuer, const char *fingerprint,
                                   DWORD flags)
{
    rt_rdp_freerdp_context_t *fctx = (rt_rdp_freerdp_context_t *)instance->context;
    rt_rdp_ctx_t             *c    = fctx->self;
    char                      buf[512];

    (void)common_name; (void)subject; (void)issuer; (void)flags;

    if (c->insecure_cert) {
        return 1;  /* lab-only path */
    }
    if (host == NULL || fingerprint == NULL) {
        return 0;
    }

    switch (known_hosts_lookup(host, port, fingerprint)) {
    case KH_OK:
        return 1;

    case KH_NOT_FOUND:
        /* TOFU: trust + persist. */
        if (known_hosts_record(host, port, fingerprint) != 0) {
            free(c->cert_error);
            snprintf(buf, sizeof(buf),
                     "Failed to record host fingerprint for %s:%u",
                     host, (unsigned)port);
            c->cert_error = strdup(buf);
            return 0;
        }
        snprintf(buf, sizeof(buf),
                 "First-time host: trusted and saved (%s).", fingerprint);
        emit_state(c, RT_PROTO_STATE_AUTHENTICATING, buf);
        return 1;

    case KH_CHANGED:
        free(c->cert_error);
        snprintf(buf, sizeof(buf),
                 "HOST KEY CHANGED for %s:%u. Refusing. Current fingerprint: %s",
                 host, (unsigned)port, fingerprint);
        c->cert_error = strdup(buf);
        return 0;

    case KH_ERROR:
    default:
        free(c->cert_error);
        c->cert_error = strdup("Failed to read RDP known_hosts file.");
        return 0;
    }
}

static DWORD verify_changed_certificate_ex(freerdp *instance,
                                           const char *host, UINT16 port,
                                           const char *common_name, const char *subject,
                                           const char *issuer, const char *fingerprint,
                                           const char *old_subject, const char *old_issuer,
                                           const char *old_fingerprint, DWORD flags)
{
    rt_rdp_freerdp_context_t *fctx = (rt_rdp_freerdp_context_t *)instance->context;
    rt_rdp_ctx_t             *c    = fctx->self;
    char                      buf[512];

    (void)common_name; (void)subject; (void)issuer;
    (void)old_subject; (void)old_issuer; (void)old_fingerprint; (void)flags;

    if (c->insecure_cert) {
        return 1;
    }
    free(c->cert_error);
    snprintf(buf, sizeof(buf),
             "RDP server certificate CHANGED for %s:%u (now %s). "
             "Refusing - delete the entry from rdp_known_hosts to re-trust.",
             host ? host : "?", (unsigned)port,
             fingerprint ? fingerprint : "unknown");
    c->cert_error = strdup(buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* PreConnect / PostConnect                                           */
/* ------------------------------------------------------------------ */

static BOOL pre_connect(freerdp *instance)
{
    rt_rdp_freerdp_context_t *fctx = (rt_rdp_freerdp_context_t *)instance->context;
    rt_rdp_ctx_t             *c    = fctx->self;
    rdpSettings              *s    = instance->context->settings;

    /* Server identity + creds. */
    if (!freerdp_settings_set_string(s, FreeRDP_ServerHostname, c->host) ||
        !freerdp_settings_set_uint32(s, FreeRDP_ServerPort,    (UINT32)c->port)) {
        return FALSE;
    }
    if (c->username != NULL &&
        !freerdp_settings_set_string(s, FreeRDP_Username, c->username)) {
        return FALSE;
    }
    if (c->password != NULL &&
        !freerdp_settings_set_string(s, FreeRDP_Password, c->password)) {
        return FALSE;
    }
    if (c->domain != NULL &&
        !freerdp_settings_set_string(s, FreeRDP_Domain,   c->domain)) {
        return FALSE;
    }

    /* Display + perf knobs. */
    if (!freerdp_settings_set_uint32(s, FreeRDP_DesktopWidth,  (UINT32)c->width)  ||
        !freerdp_settings_set_uint32(s, FreeRDP_DesktopHeight, (UINT32)c->height) ||
        !freerdp_settings_set_uint32(s, FreeRDP_ColorDepth,    (UINT32)c->color_depth)) {
        return FALSE;
    }

    /* Security: TLS + NLA preferred (defaults). Cert verification
     * stays ON unless the user explicitly bypassed it (handled in
     * the verify callbacks, not here). Legacy SSL stays disabled. */
    if (c->insecure_cert) {
        /* Lab-only path: skip CA / hostname checks too. */
        if (!freerdp_settings_set_bool(s, FreeRDP_IgnoreCertificate, TRUE)) {
            return FALSE;
        }
    }

    /* Clipboard channel registration. Skipped entirely when
     * clipboard support is disabled at the connection level. */
    if (c->clipboard_enabled) {
        if (!freerdp_settings_set_bool(s, FreeRDP_RedirectClipboard, TRUE)) {
            return FALSE;
        }
    }

    /* Explicitly turn OFF device redirection. Some of these default
     * to TRUE in fresh rdpSettings, which causes load_addins to
     * dlopen librdpdr-client.so even though we never asked for it -
     * and that .so isn't shipped on stock Ubuntu/Mint outside of
     * the full xfreerdp client package. We don't do drives/printers/
     * smartcards/serial/parallel anyway. */
    freerdp_settings_set_bool(s, FreeRDP_DeviceRedirection,    FALSE);
    freerdp_settings_set_bool(s, FreeRDP_RedirectDrives,       FALSE);
    freerdp_settings_set_bool(s, FreeRDP_RedirectHomeDrive,    FALSE);
    freerdp_settings_set_bool(s, FreeRDP_RedirectPrinters,     FALSE);
    freerdp_settings_set_bool(s, FreeRDP_RedirectSmartCards,   FALSE);
    freerdp_settings_set_bool(s, FreeRDP_RedirectSerialPorts,  FALSE);
    freerdp_settings_set_bool(s, FreeRDP_RedirectParallelPorts,FALSE);

    /* DispDyn: enable Display Control (server-driven dynamic
     * resolution). Requires the dynamic-channel carrier (drdynvc)
     * plus the disp dynamic channel. If either fails to load, we
     * silently fall back to client-side scaling. */
    freerdp_settings_set_bool(s, FreeRDP_SupportDisplayControl,   TRUE);
    freerdp_settings_set_bool(s, FreeRDP_SupportDynamicChannels,  TRUE);
    freerdp_settings_set_bool(s, FreeRDP_DynamicResolutionUpdate, TRUE);

    {
        ADDIN_ARGV *args = freerdp_addin_argv_new(0, NULL);
        if (args != NULL) {
            if (!freerdp_addin_argv_add_argument(args, "disp") ||
                !freerdp_dynamic_channel_collection_add(s, args)) {
                freerdp_addin_argv_free(args);
                /* Non-fatal: connection proceeds without DispDyn. */
            }
        }
    }

    /* Load static / dynamic addins announced via settings (cliprdr,
     * etc.). Without this, RedirectClipboard is a no-op.
     *
     * A FALSE return here usually means SOME addin .so failed to
     * dlopen - typically rdpdr / device-redirection plugins missing
     * from the system. We don't want to abort the whole connect for
     * an optional channel; the worst case is "no clipboard". */
    /* Load static / dynamic addins announced via settings (cliprdr,
     * disp, etc.). A FALSE return usually means an optional addin
     * .so failed to dlopen - non-fatal, just disable clipboard so we
     * don't try to use a half-loaded channel later. */
    if (!freerdp_client_load_addins(instance->context->channels, s)) {
        if (c->clipboard_enabled) {
            freerdp_settings_set_bool(s, FreeRDP_RedirectClipboard, FALSE);
            c->clipboard_enabled = 0;
        }
    }

    /* Channel events fire on the worker thread (us). */
    PubSub_SubscribeChannelConnected   (instance->context->pubSub,
                                        channel_connected);
    PubSub_SubscribeChannelDisconnected(instance->context->pubSub,
                                        channel_disconnected);

    return TRUE;
}

static BOOL post_connect(freerdp *instance)
{
    rt_rdp_freerdp_context_t *fctx = (rt_rdp_freerdp_context_t *)instance->context;
    rt_rdp_ctx_t             *c    = fctx->self;

    if (!gdi_init(instance, PIXEL_FORMAT_BGRA32)) {
        return FALSE;
    }

    rdpGdi *gdi = instance->context->gdi;
    if (gdi == NULL || gdi->primary_buffer == NULL) {
        return FALSE;
    }

    pthread_mutex_lock(&c->fb_mtx);
    c->gdi       = gdi;
    c->fb_w      = (int)gdi->width;
    c->fb_h      = (int)gdi->height;
    c->fb_stride = (int)gdi->stride;
    pthread_mutex_unlock(&c->fb_mtx);

    /* Initialize the keyboard layout tables. Without this,
     * freerdp_keyboard_get_rdp_scancode_from_x11_keycode() returns 0
     * for every keycode and no keystrokes ever reach the remote. */
    {
        rdpSettings *s = instance->context->settings;
        UINT32 layout = freerdp_settings_get_uint32(s, FreeRDP_KeyboardLayout);
        layout = freerdp_keyboard_init_ex(
            layout,
            freerdp_settings_get_string(s, FreeRDP_KeyboardRemappingList));
        freerdp_settings_set_uint32(s, FreeRDP_KeyboardLayout, layout);
    }

    /* Override EndPaint to extract dirty rects + signal "frame
     * ready". We do not chain - the default is a no-op pass-through
     * once we take ownership of the dirty bookkeeping. */
    instance->context->update->EndPaint = rdp_end_paint;

    /* Server-initiated resolution change (e.g. ack to our DispDyn
     * SendMonitorLayout). gdi_resize re-allocates primary_buffer at
     * the new dimensions; the widget picks up the new fb size on
     * the next on_frame. */
    instance->context->update->DesktopResize = rdp_desktop_resize;

    return TRUE;
}

static void post_disconnect(freerdp *instance)
{
    if (instance == NULL || instance->context == NULL) {
        return;
    }
    rt_rdp_freerdp_context_t *fctx = (rt_rdp_freerdp_context_t *)instance->context;
    rt_rdp_ctx_t             *c    = fctx->self;

    if (instance->context->gdi != NULL) {
        gdi_free(instance);
    }

    pthread_mutex_lock(&c->fb_mtx);
    c->gdi = NULL;
    pthread_mutex_unlock(&c->fb_mtx);
}

/* ------------------------------------------------------------------ */
/* EndPaint: read dirty rects, emit on_frame                          */
/* ------------------------------------------------------------------ */

static BOOL rdp_end_paint(rdpContext *context)
{
    rt_rdp_freerdp_context_t *fctx = (rt_rdp_freerdp_context_t *)context;
    rt_rdp_ctx_t             *c    = fctx->self;
    rdpGdi                   *gdi  = context->gdi;

    if (gdi == NULL || gdi->primary == NULL ||
        gdi->primary->hdc == NULL || gdi->primary->hdc->hwnd == NULL) {
        return TRUE;
    }

    INT32     ninvalid = gdi->primary->hdc->hwnd->ninvalid;
    HGDI_RGN  cinvalid = gdi->primary->hdc->hwnd->cinvalid;
    if (ninvalid < 1 || cinvalid == NULL) {
        return TRUE;
    }

    /* Union all dirty regions into one bounding rect. The widget's
     * draw path scales the whole frame anyway; tracking sub-region
     * invalidations would only matter for partial blits, which we
     * don't do in v1. */
    INT32 x0 = INT32_MAX, y0 = INT32_MAX, x1 = 0, y1 = 0;
    for (INT32 i = 0; i < ninvalid; i++) {
        INT32 ix = cinvalid[i].x;
        INT32 iy = cinvalid[i].y;
        INT32 iw = cinvalid[i].w;
        INT32 ih = cinvalid[i].h;
        if (ix < x0) x0 = ix;
        if (iy < y0) y0 = iy;
        if (ix + iw > x1) x1 = ix + iw;
        if (iy + ih > y1) y1 = iy + ih;
    }

    rt_remote_frame_t frame = {
        .width   = c->fb_w,
        .height  = c->fb_h,
        .dirty_x = x0,
        .dirty_y = y0,
        .dirty_w = x1 - x0,
        .dirty_h = y1 - y0,
    };
    emit_frame(c, &frame);

    /* Reset dirty bookkeeping for the next paint pass. */
    gdi->primary->hdc->hwnd->invalid->null = TRUE;
    gdi->primary->hdc->hwnd->ninvalid       = 0;

    return TRUE;
}

/* ------------------------------------------------------------------ */
/* CLIPRDR                                                            */
/* ------------------------------------------------------------------ */

static void channel_connected(void *context, const ChannelConnectedEventArgs *e)
{
    rt_rdp_freerdp_context_t *fctx = (rt_rdp_freerdp_context_t *)context;
    rt_rdp_ctx_t             *c    = fctx->self;

    if (e == NULL || e->name == NULL) {
        return;
    }

    if (strcmp(e->name, CLIPRDR_SVC_CHANNEL_NAME) == 0) {
        CliprdrClientContext *clip = (CliprdrClientContext *)e->pInterface;
        clip->custom = c;

        clip->MonitorReady             = on_clip_monitor_ready;
        clip->ServerCapabilities       = on_clip_server_capabilities;
        clip->ServerFormatList         = on_clip_server_format_list;
        clip->ServerFormatListResponse = on_clip_server_format_list_response;
        clip->ServerFormatDataRequest  = on_clip_server_format_data_request;
        clip->ServerFormatDataResponse = on_clip_server_format_data_response;

        c->cliprdr = clip;
    }
    else if (strcmp(e->name, DISP_DVC_CHANNEL_NAME) == 0) {
        DispClientContext *disp = (DispClientContext *)e->pInterface;
        disp->custom = c;
        disp->DisplayControlCaps = on_disp_caps;
        c->disp = disp;
    }
}

static void channel_disconnected(void *context, const ChannelDisconnectedEventArgs *e)
{
    rt_rdp_freerdp_context_t *fctx = (rt_rdp_freerdp_context_t *)context;
    rt_rdp_ctx_t             *c    = fctx->self;

    if (e == NULL || e->name == NULL) {
        return;
    }
    if (strcmp(e->name, CLIPRDR_SVC_CHANNEL_NAME) == 0) {
        c->cliprdr       = NULL;
        c->cliprdr_ready = 0;
    }
    else if (strcmp(e->name, DISP_DVC_CHANNEL_NAME) == 0) {
        c->disp                = NULL;
        c->disp_caps_received  = 0;
    }
}

static UINT on_clip_monitor_ready(CliprdrClientContext *clipboard,
                                  const CLIPRDR_MONITOR_READY *ready)
{
    (void)ready;
    rt_rdp_ctx_t *c = (rt_rdp_ctx_t *)clipboard->custom;

    /* Send our capabilities first (long format names). */
    CLIPRDR_GENERAL_CAPABILITY_SET general = {
        .capabilitySetType   = CB_CAPSTYPE_GENERAL,
        .capabilitySetLength = 12,
        .version             = CB_CAPS_VERSION_2,
        .generalFlags        = CB_USE_LONG_FORMAT_NAMES,
    };
    CLIPRDR_CAPABILITIES caps = {
        .cCapabilitiesSets = 1,
        .capabilitySets    = (CLIPRDR_CAPABILITY_SET *)&general,
    };
    if (clipboard->ClientCapabilities != NULL) {
        clipboard->ClientCapabilities(clipboard, &caps);
    }

    /* Empty initial format list - we have nothing to offer yet. */
    CLIPRDR_FORMAT_LIST list = {
        .common.msgType  = CB_FORMAT_LIST,
        .common.msgFlags = 0,
        .numFormats      = 0,
        .formats         = NULL,
    };
    if (clipboard->ClientFormatList != NULL) {
        clipboard->ClientFormatList(clipboard, &list);
    }

    c->cliprdr_ready = 1;
    return CHANNEL_RC_OK;
}

static UINT on_clip_server_capabilities(CliprdrClientContext *clipboard,
                                        const CLIPRDR_CAPABILITIES *caps)
{
    (void)clipboard; (void)caps;
    return CHANNEL_RC_OK;
}

static UINT send_format_list_response(CliprdrClientContext *clipboard, UINT16 flags)
{
    CLIPRDR_FORMAT_LIST_RESPONSE r = {
        .common.msgType  = CB_FORMAT_LIST_RESPONSE,
        .common.msgFlags = flags,
        .common.dataLen  = 0,
    };
    if (clipboard->ClientFormatListResponse != NULL) {
        return clipboard->ClientFormatListResponse(clipboard, &r);
    }
    return CHANNEL_RC_OK;
}

/* Server announced clipboard formats. Ack with OK; if text is on
 * offer, request CF_UNICODETEXT so we can mirror it locally. */
static UINT on_clip_server_format_list(CliprdrClientContext *clipboard,
                                       const CLIPRDR_FORMAT_LIST *list)
{
    rt_rdp_ctx_t *c = (rt_rdp_ctx_t *)clipboard->custom;
    (void)c;

    send_format_list_response(clipboard, CB_RESPONSE_OK);

    if (list == NULL || list->formats == NULL) {
        return CHANNEL_RC_OK;
    }

    int wants = 0;
    for (UINT32 i = 0; i < list->numFormats; i++) {
        if (list->formats[i].formatId == CF_UNICODETEXT) {
            wants = 1;
            break;
        }
    }
    if (!wants) {
        /* Could fall back to CF_TEXT here, but Windows always offers
         * CF_UNICODETEXT for text. Skip to keep code small. */
        return CHANNEL_RC_OK;
    }

    CLIPRDR_FORMAT_DATA_REQUEST req = {
        .common.msgType        = CB_FORMAT_DATA_REQUEST,
        .common.msgFlags       = 0,
        .common.dataLen        = 4,
        .requestedFormatId     = CF_UNICODETEXT,
    };
    if (clipboard->ClientFormatDataRequest != NULL) {
        clipboard->ClientFormatDataRequest(clipboard, &req);
    }
    return CHANNEL_RC_OK;
}

static UINT on_clip_server_format_list_response(CliprdrClientContext *clipboard,
                                                const CLIPRDR_FORMAT_LIST_RESPONSE *r)
{
    (void)clipboard; (void)r;
    return CHANNEL_RC_OK;
}

/* Server is asking for our clipboard data. Currently we only ever
 * advertise CF_UNICODETEXT, so we satisfy that one and reject
 * anything else. */
static UINT on_clip_server_format_data_request(CliprdrClientContext *clipboard,
                                               const CLIPRDR_FORMAT_DATA_REQUEST *req)
{
    rt_rdp_ctx_t *c = (rt_rdp_ctx_t *)clipboard->custom;

    BYTE  *out_data = NULL;
    UINT32 out_len  = 0;
    UINT16 flags    = CB_RESPONSE_FAIL;

    if (req != NULL && req->requestedFormatId == CF_UNICODETEXT) {
        pthread_mutex_lock(&c->clip_mtx);
        const char *text = c->pending_clip_utf8;
        size_t      tlen = c->pending_clip_len;

        if (text != NULL) {
            /* UTF-8 -> UTF-16LE, with NUL terminator. */
            SSIZE_T wneeded = ConvertUtf8NToWChar(text, tlen, NULL, 0);
            if (wneeded >= 0) {
                size_t  wbytes = ((size_t)wneeded + 1) * sizeof(WCHAR);
                BYTE   *buf    = (BYTE *)calloc(1, wbytes);
                if (buf != NULL) {
                    SSIZE_T w = ConvertUtf8NToWChar(text, tlen,
                                                    (WCHAR *)buf,
                                                    (size_t)wneeded + 1);
                    if (w >= 0) {
                        out_data = buf;
                        out_len  = (UINT32)wbytes;
                        flags    = CB_RESPONSE_OK;
                    } else {
                        free(buf);
                    }
                }
            }
        }
        pthread_mutex_unlock(&c->clip_mtx);
    }

    CLIPRDR_FORMAT_DATA_RESPONSE resp = {
        .common.msgType  = CB_FORMAT_DATA_RESPONSE,
        .common.msgFlags = flags,
        .common.dataLen  = out_len,
        .requestedFormatData = out_data,
    };
    UINT rc = CHANNEL_RC_OK;
    if (clipboard->ClientFormatDataResponse != NULL) {
        rc = clipboard->ClientFormatDataResponse(clipboard, &resp);
    }
    free(out_data);
    return rc;
}

/* Server delivered the clipboard data we requested. Decode UTF-16LE
 * to UTF-8 and emit on_clipboard_text. NEVER log the contents. */
static UINT on_clip_server_format_data_response(CliprdrClientContext *clipboard,
                                                const CLIPRDR_FORMAT_DATA_RESPONSE *resp)
{
    rt_rdp_ctx_t *c = (rt_rdp_ctx_t *)clipboard->custom;

    if (resp == NULL ||
        (resp->common.msgFlags & CB_RESPONSE_FAIL) ||
        resp->requestedFormatData == NULL ||
        resp->common.dataLen < sizeof(WCHAR)) {
        return CHANNEL_RC_OK;
    }

    const WCHAR *wstr = (const WCHAR *)resp->requestedFormatData;
    size_t       wlen = resp->common.dataLen / sizeof(WCHAR);

    /* Strip a trailing NUL if present. */
    while (wlen > 0 && wstr[wlen - 1] == 0) {
        wlen--;
    }
    if (wlen == 0) {
        return CHANNEL_RC_OK;
    }

    SSIZE_T need = ConvertWCharNToUtf8(wstr, wlen, NULL, 0);
    if (need <= 0) {
        return CHANNEL_RC_OK;
    }
    char *utf8 = (char *)malloc((size_t)need + 1);
    if (utf8 == NULL) {
        return CHANNEL_RC_OK;
    }
    SSIZE_T got = ConvertWCharNToUtf8(wstr, wlen, utf8, (size_t)need + 1);
    if (got > 0) {
        utf8[got] = '\0';
        if (c->cb.on_clipboard_text != NULL) {
            c->cb.on_clipboard_text(c->cb_user, utf8, (size_t)got);
        }
    }
    /* Wipe before free; we don't keep clipboard data around. */
    explicit_bzero(utf8, (size_t)need + 1);
    free(utf8);
    return CHANNEL_RC_OK;
}

/* Announce CF_UNICODETEXT to the server (called from worker when
 * the UI thread has queued a clipboard out). */
static void announce_local_clipboard(rt_rdp_ctx_t *c)
{
    if (!c->cliprdr_ready || c->cliprdr == NULL ||
        c->cliprdr->ClientFormatList == NULL) {
        return;
    }

    CLIPRDR_FORMAT fmt = {
        .formatId   = CF_UNICODETEXT,
        .formatName = NULL,
    };
    CLIPRDR_FORMAT_LIST list = {
        .common.msgType  = CB_FORMAT_LIST,
        .common.msgFlags = 0,
        .numFormats      = 1,
        .formats         = &fmt,
    };
    c->cliprdr->ClientFormatList(c->cliprdr, &list);
}

/* ------------------------------------------------------------------ */
/* DispDyn (Display Control)                                          */
/* ------------------------------------------------------------------ */

static UINT on_disp_caps(DispClientContext *disp,
                         UINT32 max_num_monitors,
                         UINT32 max_factor_a,
                         UINT32 max_factor_b)
{
    rt_rdp_ctx_t *c = (rt_rdp_ctx_t *)disp->custom;
    c->disp_max_num_monitors = max_num_monitors;
    c->disp_max_factor_a     = max_factor_a;
    c->disp_max_factor_b     = max_factor_b;
    c->disp_caps_received    = 1;
    return CHANNEL_RC_OK;
}

/* Server told us the desktop changed size (typically because we
 * just sent a SendMonitorLayout, or the server initiated it). Resize
 * the GDI buffer in place, refresh our cached dims, and emit a full
 * frame so the widget invalidates and re-blits. */
static BOOL rdp_desktop_resize(rdpContext *context)
{
    rt_rdp_freerdp_context_t *fctx = (rt_rdp_freerdp_context_t *)context;
    rt_rdp_ctx_t             *c    = fctx->self;
    rdpSettings              *s    = context->settings;

    UINT32 new_w = freerdp_settings_get_uint32(s, FreeRDP_DesktopWidth);
    UINT32 new_h = freerdp_settings_get_uint32(s, FreeRDP_DesktopHeight);

    pthread_mutex_lock(&c->fb_mtx);
    BOOL ok = gdi_resize(c->gdi, new_w, new_h);
    if (ok && c->gdi != NULL) {
        c->fb_w      = (int)c->gdi->width;
        c->fb_h      = (int)c->gdi->height;
        c->fb_stride = (int)c->gdi->stride;
    }
    pthread_mutex_unlock(&c->fb_mtx);

    if (!ok) {
        return FALSE;
    }

    rt_remote_frame_t f = {
        .width   = (int)new_w,
        .height  = (int)new_h,
        .dirty_x = 0, .dirty_y = 0,
        .dirty_w = (int)new_w, .dirty_h = (int)new_h,
    };
    emit_frame(c, &f);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Cert TOFU                                                          */
/* ------------------------------------------------------------------ */

/* Returns malloc'd path "$HOME/.config/remoteTool/rdp_known_hosts"
 * after ensuring the directory exists. NULL on failure. */
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
    if (mkdir(cfg, 0700) != 0 && errno != EEXIST) {
        free(cfg);
        return NULL;
    }

    char *out = NULL;
    int n = asprintf(&out, "%s/rdp_known_hosts", cfg);
    free(cfg);
    return (n < 0) ? NULL : out;
}

/* Look up (host, port) in the known_hosts file. */
static kh_result_t known_hosts_lookup(const char *host, int port,
                                      const char *fingerprint)
{
    if (host == NULL || fingerprint == NULL) {
        return KH_ERROR;
    }
    char *path = known_hosts_path();
    if (path == NULL) {
        return KH_ERROR;
    }

    FILE *f = fopen(path, "r");
    free(path);
    if (f == NULL) {
        return (errno == ENOENT) ? KH_NOT_FOUND : KH_ERROR;
    }

    kh_result_t result = KH_NOT_FOUND;
    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        char file_host[256], file_fp[768];
        int  file_port = 0;
        /* Format: "host\tport\tfingerprint\n". %255s / %767s
         * reserve one byte for NUL. */
        if (sscanf(line, "%255s %d %767s",
                   file_host, &file_port, file_fp) != 3) {
            continue;
        }
        if (strcmp(file_host, host) == 0 && file_port == port) {
            result = (strcmp(file_fp, fingerprint) == 0) ? KH_OK : KH_CHANGED;
            break;
        }
    }
    fclose(f);
    return result;
}

/* Append a new (host, port, fingerprint) entry. Returns 0 on success. */
static int known_hosts_record(const char *host, int port,
                              const char *fingerprint)
{
    char *path = known_hosts_path();
    if (path == NULL) {
        return -1;
    }
    FILE *f = fopen(path, "a");
    free(path);
    if (f == NULL) {
        return -1;
    }
    int rc = fprintf(f, "%s %d %s\n", host, port, fingerprint);
    fclose(f);
    return (rc < 0) ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* Input dispatch (worker thread)                                     */
/* ------------------------------------------------------------------ */

static void dispatch_one_input(rt_rdp_ctx_t *c, const rt_input_event_t *e)
{
    rdpInput *input = c->instance->context->input;
    if (input == NULL) {
        return;
    }

    switch (e->kind) {
    case RT_INPUT_MOUSE_MOVE:
        freerdp_input_send_mouse_event(input, PTR_FLAGS_MOVE,
                                       (UINT16)e->x, (UINT16)e->y);
        break;

    case RT_INPUT_MOUSE_BUTTON: {
        UINT16 flags = 0;
        switch (e->button) {
        case 1: flags = PTR_FLAGS_BUTTON1; break;
        case 2: flags = PTR_FLAGS_BUTTON3; break; /* GTK middle = RDP3 */
        case 3: flags = PTR_FLAGS_BUTTON2; break; /* GTK right  = RDP2 */
        default: return;
        }
        if (e->pressed) flags |= PTR_FLAGS_DOWN;
        freerdp_input_send_mouse_event(input, flags,
                                       (UINT16)e->x, (UINT16)e->y);
        break;
    }

    case RT_INPUT_MOUSE_WHEEL: {
        int delta = e->wheel_delta;
        if (delta == 0) return;
        UINT16 flags = PTR_FLAGS_WHEEL;
        if (delta < 0) {
            flags |= PTR_FLAGS_WHEEL_NEGATIVE;
            delta = -delta;
        }
        /* RDP wheel rotation: low byte is the magnitude. Cap to
         * 0x78 (one notch) to match common server expectations. */
        if (delta > 0x78) delta = 0x78;
        flags |= (UINT16)(delta & 0xFF);
        freerdp_input_send_mouse_event(input, flags,
                                       (UINT16)e->x, (UINT16)e->y);
        break;
    }

    case RT_INPUT_KEY: {
        DWORD scancode = freerdp_keyboard_get_rdp_scancode_from_x11_keycode(
            e->keycode);
        if (scancode == 0) return;

        UINT16 flags = e->pressed ? KBD_FLAGS_DOWN : KBD_FLAGS_RELEASE;
        if (scancode & KBDEXT) {
            flags |= KBD_FLAGS_EXTENDED;
        }
        freerdp_input_send_keyboard_event(input, flags,
                                          (UINT16)(scancode & 0xFF));
        break;
    }

    case RT_INPUT_UNICODE: {
        UINT16 flags = e->pressed ? KBD_FLAGS_DOWN : KBD_FLAGS_RELEASE;
        freerdp_input_send_unicode_keyboard_event(input, flags,
                                                  (UINT16)e->unicode_cp);
        break;
    }
    }
}

static void drain_input(rt_rdp_ctx_t *c)
{
    /* Swap the buffer under the lock, dispatch outside the lock. */
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

static void drain_resize(rt_rdp_ctx_t *c)
{
    pthread_mutex_lock(&c->resize_mtx);
    int      pending = c->resize_pending;
    UINT32   want_w  = (UINT32)c->pending_resize_w;
    UINT32   want_h  = (UINT32)c->pending_resize_h;
    c->resize_pending = 0;
    pthread_mutex_unlock(&c->resize_mtx);

    if (!pending) {
        return;
    }

    /* If the disp dynamic channel never came up (server doesn't
     * advertise it, or the channel addin failed to load) we silently
     * fall back to the widget's client-side cairo scaling. The
     * widget never sees a DesktopResize callback in that case, so
     * the local scale stays in effect. */
    if (c->disp == NULL || !c->disp_caps_received ||
        c->disp->SendMonitorLayout == NULL) {
        return;
    }

    /* Clamp + round to the protocol's required even-multiple. */
    if (want_w < DISPLAY_CONTROL_MIN_MONITOR_WIDTH)
        want_w = DISPLAY_CONTROL_MIN_MONITOR_WIDTH;
    if (want_h < DISPLAY_CONTROL_MIN_MONITOR_HEIGHT)
        want_h = DISPLAY_CONTROL_MIN_MONITOR_HEIGHT;
    if (c->disp_max_factor_a && want_w > c->disp_max_factor_a)
        want_w = c->disp_max_factor_a;
    if (c->disp_max_factor_b && want_h > c->disp_max_factor_b)
        want_h = c->disp_max_factor_b;
    want_w &= ~1U;
    want_h &= ~1U;
    if (want_w == 0 || want_h == 0) {
        return;
    }

    /* Skip if nothing actually changed. */
    if ((int)want_w == c->fb_w && (int)want_h == c->fb_h) {
        return;
    }

    DISPLAY_CONTROL_MONITOR_LAYOUT layout = {
        .Flags              = DISPLAY_CONTROL_MONITOR_PRIMARY,
        .Left               = 0,
        .Top                = 0,
        .Width              = want_w,
        .Height             = want_h,
        .PhysicalWidth      = 0,
        .PhysicalHeight     = 0,
        .Orientation        = ORIENTATION_LANDSCAPE,
        .DesktopScaleFactor = 100,
        .DeviceScaleFactor  = 100,
    };
    c->disp->SendMonitorLayout(c->disp, 1, &layout);
}

static void drain_clipboard_out(rt_rdp_ctx_t *c)
{
    pthread_mutex_lock(&c->clip_mtx);
    int dirty = c->clip_dirty;
    c->clip_dirty = 0;
    pthread_mutex_unlock(&c->clip_mtx);

    if (dirty && c->clipboard_enabled) {
        announce_local_clipboard(c);
    }
}

/* ------------------------------------------------------------------ */
/* Worker thread                                                      */
/* ------------------------------------------------------------------ */

static void *worker_main(void *arg)
{
    rt_rdp_ctx_t *c = arg;

    emit_state(c, RT_PROTO_STATE_CONNECTING, NULL);

    if (!freerdp_connect(c->instance)) {
        /* Prefer a cert-specific message if the verify callback set
         * one - it's far more useful than the generic
         * AUTHENTICATION_FAILURE that FreeRDP would return. */
        if (c->cert_error != NULL) {
            emit_state(c, RT_PROTO_STATE_ERROR, c->cert_error);
            free(c->cert_error);
            c->cert_error = NULL;
        } else {
            UINT32 err = freerdp_get_last_error(c->instance->context);
            char   buf[160];
            const char *name = freerdp_get_last_error_name(err);
            snprintf(buf, sizeof(buf), "Connect failed (%s)",
                     name ? name : "unknown");
            emit_state(c, RT_PROTO_STATE_ERROR, buf);
        }
        /* Wipe credentials we no longer need. */
        if (c->password != NULL) {
            explicit_bzero(c->password, strlen(c->password));
            free(c->password);
            c->password = NULL;
        }
        return NULL;
    }

    /* Wipe the password copy as soon as the connect handshake is
     * complete - it lives on inside FreeRDP's settings if NLA needs
     * to renegotiate, but our copy is no longer required. */
    if (c->password != NULL) {
        explicit_bzero(c->password, strlen(c->password));
        free(c->password);
        c->password = NULL;
    }

    emit_state(c, RT_PROTO_STATE_CONNECTED, NULL);

    /* Main event loop. We add our own wake handle to the wait set so
     * UI-side enqueues (input / resize / clipboard) can interrupt
     * the network poll instead of waiting for the timeout. */
    HANDLE handles[64];
    while (!atomic_load(&c->stop)) {
        DWORD nh = freerdp_get_event_handles(c->instance->context, handles,
                                             (sizeof(handles) / sizeof(handles[0])) - 1);
        if (nh == 0) {
            emit_state(c, RT_PROTO_STATE_ERROR, "No FreeRDP event handles");
            break;
        }
        handles[nh++] = c->wake;

        DWORD r = WaitForMultipleObjects(nh, handles, FALSE,
                                         RT_RDP_WAIT_TIMEOUT_MS);
        if (r == WAIT_FAILED) {
            emit_state(c, RT_PROTO_STATE_ERROR, "Wait failed");
            break;
        }
        /* Manual-reset wake: clear so the next SetEvent re-arms. */
        ResetEvent(c->wake);

        if (!freerdp_check_event_handles(c->instance->context)) {
            UINT32 err = freerdp_get_last_error(c->instance->context);
            if (err != FREERDP_ERROR_SUCCESS) {
                char buf[160];
                const char *name = freerdp_get_last_error_name(err);
                snprintf(buf, sizeof(buf), "Disconnected (%s)",
                         name ? name : "unknown");
                emit_state(c, RT_PROTO_STATE_ERROR, buf);
            } else {
                emit_state(c, RT_PROTO_STATE_DISCONNECTED, NULL);
            }
            break;
        }

        drain_input(c);
        drain_resize(c);
        drain_clipboard_out(c);
    }

    freerdp_disconnect(c->instance);
    emit_state(c, RT_PROTO_STATE_DISCONNECTED, NULL);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Lifecycle: open / send_input / resize / clipboard / close          */
/* ------------------------------------------------------------------ */

static int validate_conn(const rt_connection_t *conn)
{
    if (conn == NULL || conn->host == NULL || conn->host[0] == '\0') {
        return -1;
    }
    if (conn->port == 0) {
        return -1;
    }
    if (conn->rdp == NULL) {
        return -1;
    }
    if (conn->rdp->width <= 0 || conn->rdp->height <= 0) {
        return -1;
    }
    if (conn->rdp->color_depth != 16 &&
        conn->rdp->color_depth != 24 &&
        conn->rdp->color_depth != 32) {
        return -1;
    }
    return 0;
}

static rt_rdp_ctx_t *ctx_new(const rt_connection_t *conn,
                             const char            *password,
                             const rt_proto_callbacks_t *cb,
                             void                  *user)
{
    rt_rdp_ctx_t *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    if (cb != NULL) {
        c->cb = *cb;
    }
    c->cb_user = user;

    pthread_mutex_init(&c->fb_mtx,     NULL);
    pthread_mutex_init(&c->input_mtx,  NULL);
    pthread_mutex_init(&c->resize_mtx, NULL);
    pthread_mutex_init(&c->clip_mtx,   NULL);
    atomic_init(&c->stop, 0);

    /* Manual-reset event (winpr on Linux historically didn't
     * implement auto-reset). The worker calls ResetEvent at the top
     * of each loop iteration, so semantics are equivalent. */
    c->wake = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (c->wake == NULL) {
        goto fail;
    }

    c->fb_handle.base.vtbl = &RDP_FB_VTBL;
    c->fb_handle.owner     = c;

    c->host     = dup_str(conn->host);
    c->username = dup_str(conn->username);
    c->password = dup_str(password);
    c->domain   = dup_str(conn->rdp->domain);
    if (c->host == NULL ||
        (conn->username != NULL && c->username == NULL) ||
        (password       != NULL && c->password == NULL) ||
        (conn->rdp->domain != NULL && c->domain == NULL)) {
        goto fail;
    }
    c->port              = conn->port;
    c->width             = conn->rdp->width;
    c->height            = conn->rdp->height;
    c->color_depth       = conn->rdp->color_depth;
    c->insecure_cert     = conn->rdp->insecure_cert_bypass ? 1 : 0;
    c->clipboard_enabled = conn->rdp->clipboard_enabled    ? 1 : 0;

    return c;

fail:
    if (c->wake != NULL) {
        CloseHandle(c->wake);
    }
    pthread_mutex_destroy(&c->fb_mtx);
    pthread_mutex_destroy(&c->input_mtx);
    pthread_mutex_destroy(&c->resize_mtx);
    pthread_mutex_destroy(&c->clip_mtx);
    if (c->password != NULL) {
        explicit_bzero(c->password, strlen(c->password));
    }
    free(c->host); free(c->username); free(c->password); free(c->domain);
    free(c);
    return NULL;
}

static void ctx_free(rt_rdp_ctx_t *c)
{
    if (c == NULL) {
        return;
    }
    if (c->instance != NULL) {
        freerdp_context_free(c->instance);
        freerdp_free(c->instance);
    }
    if (c->wake != NULL) {
        CloseHandle(c->wake);
    }
    free(c->input_buf);
    free(c->host);
    free(c->username);
    if (c->password != NULL) {
        explicit_bzero(c->password, strlen(c->password));
        free(c->password);
    }
    free(c->domain);
    if (c->pending_clip_utf8 != NULL) {
        explicit_bzero(c->pending_clip_utf8, c->pending_clip_len);
        free(c->pending_clip_utf8);
    }
    free(c->cert_error);
    pthread_mutex_destroy(&c->fb_mtx);
    pthread_mutex_destroy(&c->input_mtx);
    pthread_mutex_destroy(&c->resize_mtx);
    pthread_mutex_destroy(&c->clip_mtx);
    free(c);
}

static rt_protocol_ctx_t *rdp_open(const rt_connection_t      *conn,
                                   const char                 *password,
                                   const rt_proto_callbacks_t *cb,
                                   void                       *user)
{
    if (validate_conn(conn) != 0 || password == NULL) {
        return NULL;
    }

    rt_rdp_ctx_t *c = ctx_new(conn, password, cb, user);
    if (c == NULL) {
        return NULL;
    }

    /* Spin up FreeRDP. Subclass rdpContext so callbacks can recover
     * our ctx via instance->context->self. */
    c->instance = freerdp_new();
    if (c->instance == NULL) {
        ctx_free(c);
        return NULL;
    }
    c->instance->ContextSize    = sizeof(rt_rdp_freerdp_context_t);
    c->instance->PreConnect     = pre_connect;
    c->instance->PostConnect    = post_connect;
    c->instance->PostDisconnect = post_disconnect;
    c->instance->Authenticate   = authenticate;
    c->instance->VerifyCertificateEx        = verify_certificate_ex;
    c->instance->VerifyChangedCertificateEx = verify_changed_certificate_ex;
    /* CRITICAL: tell FreeRDP how to load channels. Without this hook
     * channels get registered in settings but never actually attached
     * during the connect handshake - so ChannelConnected events never
     * fire and DVCs (cliprdr / disp / etc.) silently don't work.
     * `freerdp_client_context_new` sets this for you; we use the
     * lower-level freerdp_new path so we wire it manually. */
    c->instance->LoadChannels   = freerdp_client_load_channels;

    /* Register the static-addin lookup provider that the channel
     * loader consults before falling back to dlopen. Same reason: the
     * common-client setup does this for free, we don't. */
    freerdp_register_addin_provider(freerdp_channels_load_static_addin_entry, 0);

    if (!freerdp_context_new(c->instance)) {
        emit_state(c, RT_PROTO_STATE_ERROR, "freerdp_context_new failed");
        freerdp_free(c->instance);
        c->instance = NULL;
        ctx_free(c);
        return NULL;
    }
    ((rt_rdp_freerdp_context_t *)c->instance->context)->self = c;

    /* Worker performs the actual connect so the UI never blocks. */
    if (pthread_create(&c->thread, NULL, worker_main, c) != 0) {
        emit_state(c, RT_PROTO_STATE_ERROR, "Failed to start worker thread");
        ctx_free(c);
        return NULL;
    }
    c->thread_started = 1;

    return c;
}

static int rdp_send_input(rt_protocol_ctx_t *c, const rt_input_event_t *evt)
{
    if (c == NULL || evt == NULL) {
        return -1;
    }
    if (atomic_load(&c->stop)) {
        return -1;
    }

    pthread_mutex_lock(&c->input_mtx);
    if (c->input_len + 1 > c->input_cap) {
        size_t new_cap = c->input_cap ? c->input_cap * 2 : RT_RDP_INPUT_CAP_HINT;
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

    SetEvent(c->wake);
    return 0;
}

static void rdp_resize(rt_protocol_ctx_t *c, unsigned cols, unsigned rows)
{
    if (c == NULL || cols == 0 || rows == 0) {
        return;
    }
    /* For RDP, "cols" / "rows" carry pixel dimensions of the viewport
     * (the rt_rdp_view widget reports those). v1 stores them but does
     * not request a remote resize - the UI scales locally instead. */
    pthread_mutex_lock(&c->resize_mtx);
    c->pending_resize_w = (int)cols;
    c->pending_resize_h = (int)rows;
    c->resize_pending   = 1;
    pthread_mutex_unlock(&c->resize_mtx);
    SetEvent(c->wake);
}

static int rdp_set_clipboard_text(rt_protocol_ctx_t *c,
                                  const char *utf8, size_t len)
{
    if (c == NULL || utf8 == NULL) {
        return -1;
    }
    if (!c->clipboard_enabled) {
        return -1;
    }

    char *copy = malloc(len + 1);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, utf8, len);
    copy[len] = '\0';

    pthread_mutex_lock(&c->clip_mtx);
    if (c->pending_clip_utf8 != NULL) {
        explicit_bzero(c->pending_clip_utf8, c->pending_clip_len);
        free(c->pending_clip_utf8);
    }
    c->pending_clip_utf8 = copy;
    c->pending_clip_len  = len;
    c->clip_dirty        = 1;
    pthread_mutex_unlock(&c->clip_mtx);

    SetEvent(c->wake);
    return 0;
}

static rt_remote_framebuffer_t *rdp_get_framebuffer(rt_protocol_ctx_t *c)
{
    if (c == NULL) {
        return NULL;
    }
    return &c->fb_handle.base;
}

static void rdp_close(rt_protocol_ctx_t *c)
{
    if (c == NULL) {
        return;
    }
    atomic_store(&c->stop, 1);
    if (c->wake != NULL) {
        SetEvent(c->wake);
    }
    if (c->thread_started) {
        pthread_join(c->thread, NULL);
        c->thread_started = 0;
    }
    ctx_free(c);
}

/* ------------------------------------------------------------------ */
/* Public ops table                                                   */
/* ------------------------------------------------------------------ */

static const rt_protocol_ops_t RDP_OPS = {
    .name               = "rdp",
    .open               = rdp_open,
    .send               = NULL,            /* RDP is not byte-stream */
    .send_input         = rdp_send_input,
    .resize             = rdp_resize,
    .set_clipboard_text = rdp_set_clipboard_text,
    .get_framebuffer    = rdp_get_framebuffer,
    .close              = rdp_close,
};

const rt_protocol_ops_t *rt_rdp_get_ops(void)
{
    return &RDP_OPS;
}

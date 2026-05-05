/*
 * RDP viewer widget. See header for the widget tree and contract.
 *
 * Drawing
 * =======
 * Each draw handler call locks the session's remote framebuffer,
 * wraps the BGRA32 pixels in a cairo image surface, and paints
 * either at 1:1 (ORIGINAL) or with an aspect-preserving scale
 * (SCALE_TO_FIT). The lock is held only for the duration of the
 * draw - the worker thread is free to keep updating the buffer
 * between paints.
 *
 * Input forwarding
 * ================
 * Mouse + keyboard events are translated from widget coordinates to
 * remote-screen coordinates using the same scale/offset the draw
 * handler computed. The handlers feed rt_input_event_t into
 * rt_session_send_input(), which queues to the protocol's worker.
 *
 * Clipboard
 * =========
 * Local -> remote: GtkClipboard's "owner-change" signal triggers a
 * text request. If the resulting string differs from the last known
 * remote text, we push it to rt_session_set_clipboard_text(). This
 * content-based dedup is what prevents a loop with the
 * remote-clipboard branch.
 *
 * Remote -> local: rt_rdp_view_set_remote_clipboard() stores the
 * text under "last_remote_text" and writes it to the GTK clipboard.
 * The next owner-change re-fetches and compares - it'll match and
 * be dropped.
 */

#include "ui/rdp_view.h"
#include "core/session.h"
#include "protocols/protocol.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

struct rt_rdp_view {
    rt_session_t *session;          /* not owned */

    GtkWidget    *box;              /* top-level */
    GtkWidget    *status;
    GtkWidget    *combo;
    GtkWidget    *scrolled;
    GtkWidget    *area;             /* GtkDrawingArea */

    /* Latest framebuffer dims. Updated from on_frame. */
    int           fb_w, fb_h;

    /* Cached layout from last draw, used by input handlers. */
    double        scale;
    double        offset_x, offset_y;

    rt_rdp_scale_mode_t  mode;
    gboolean             input_enabled;

    /* Last text we received FROM the remote, used to dedupe local
     * clipboard pushes. Heap, owned. */
    char         *last_remote_text;

    /* GTK clipboard handler id so we can unhook on destroy. */
    gulong        owner_change_id;
    GtkClipboard *clipboard;

    /* Viewport-resize debounce. Each size-allocate restarts the
     * timer; when it fires we forward the latest viewport dims to
     * the session (which the RDP back-end translates to a DispDyn
     * SendMonitorLayout if the server advertised the channel). */
    guint         resize_timeout_id;
    int           pending_viewport_w;
    int           pending_viewport_h;
    int           last_sent_w;
    int           last_sent_h;
};

#define RT_RDP_RESIZE_DEBOUNCE_MS 250

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static void compute_layout(rt_rdp_view_t *v, int alloc_w, int alloc_h)
{
    if (v->fb_w <= 0 || v->fb_h <= 0) {
        v->scale = 1.0;
        v->offset_x = v->offset_y = 0;
        return;
    }
    if (v->mode == RT_RDP_SCALE_ORIGINAL) {
        v->scale    = 1.0;
        v->offset_x = 0;
        v->offset_y = 0;
        return;
    }
    /* SCALE_TO_FIT, preserve aspect. */
    double sx = (double)alloc_w / (double)v->fb_w;
    double sy = (double)alloc_h / (double)v->fb_h;
    v->scale  = (sx < sy) ? sx : sy;
    if (v->scale <= 0.0) {
        v->scale = 1.0;
    }
    v->offset_x = ((double)alloc_w - (double)v->fb_w * v->scale) / 2.0;
    v->offset_y = ((double)alloc_h - (double)v->fb_h * v->scale) / 2.0;
}

static void widget_to_remote(rt_rdp_view_t *v, double wx, double wy,
                             int *rx, int *ry)
{
    if (v->scale <= 0.0) {
        *rx = *ry = 0;
        return;
    }
    double rxf = (wx - v->offset_x) / v->scale;
    double ryf = (wy - v->offset_y) / v->scale;
    if (rxf < 0)              rxf = 0;
    if (ryf < 0)              ryf = 0;
    if (rxf > v->fb_w - 1)    rxf = v->fb_w - 1;
    if (ryf > v->fb_h - 1)    ryf = v->fb_h - 1;
    *rx = (int)rxf;
    *ry = (int)ryf;
}

/* ------------------------------------------------------------------ */
/* Draw                                                                */
/* ------------------------------------------------------------------ */

static gboolean on_draw(GtkWidget *widget, cairo_t *cr, gpointer user)
{
    rt_rdp_view_t *v = user;
    rt_remote_framebuffer_t *fb = rt_session_get_framebuffer(v->session);

    GtkAllocation alloc;
    gtk_widget_get_allocation(widget, &alloc);

    /* Solid background so letterbox bars in FIT mode aren't garbage. */
    cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
    cairo_rectangle(cr, 0, 0, alloc.width, alloc.height);
    cairo_fill(cr);

    if (fb == NULL) {
        return FALSE;
    }

    int                 w = 0, h = 0, stride = 0;
    rt_frame_format_t   fmt = RT_FRAME_FORMAT_BGRA32;
    const uint8_t      *pixels = rt_remote_framebuffer_lock(
        fb, &w, &h, &stride, &fmt);

    if (pixels == NULL || w <= 0 || h <= 0) {
        rt_remote_framebuffer_release(fb);
        return FALSE;
    }

    if (w != v->fb_w || h != v->fb_h) {
        v->fb_w = w;
        v->fb_h = h;
        if (v->mode == RT_RDP_SCALE_ORIGINAL) {
            gtk_widget_set_size_request(v->area, w, h);
        }
    }
    compute_layout(v, alloc.width, alloc.height);

    /* CAIRO_FORMAT_ARGB32 byte order on little-endian == BGRA.
     * Cast away const: cairo treats the buffer as read/write but we
     * never modify it, and the framebuffer is locked for the
     * duration of this call so no other thread can either. */
    cairo_surface_t *surf = cairo_image_surface_create_for_data(
        (unsigned char *)(uintptr_t)pixels, CAIRO_FORMAT_ARGB32,
        w, h, stride);

    if (surf != NULL) {
        cairo_save(cr);
        cairo_translate(cr, v->offset_x, v->offset_y);
        if (v->scale != 1.0) {
            cairo_scale(cr, v->scale, v->scale);
            cairo_pattern_set_filter(cairo_get_source(cr),
                                     CAIRO_FILTER_BILINEAR);
        }
        cairo_set_source_surface(cr, surf, 0, 0);
        cairo_paint(cr);
        cairo_restore(cr);
        cairo_surface_destroy(surf);
    }

    rt_remote_framebuffer_release(fb);
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Input handlers                                                     */
/* ------------------------------------------------------------------ */

static gboolean on_motion(GtkWidget *w, GdkEventMotion *e, gpointer user)
{
    (void)w;
    rt_rdp_view_t *v = user;
    if (!v->input_enabled) return FALSE;
    int rx, ry;
    widget_to_remote(v, e->x, e->y, &rx, &ry);
    rt_input_event_t ev = { .kind = RT_INPUT_MOUSE_MOVE, .x = rx, .y = ry };
    rt_session_send_input(v->session, &ev);
    return TRUE;
}

static gboolean on_button(GtkWidget *w, GdkEventButton *e, gpointer user)
{
    rt_rdp_view_t *v = user;
    if (!v->input_enabled) return FALSE;
    /* Take focus on click so key events flow afterwards. */
    if (e->type == GDK_BUTTON_PRESS) {
        gtk_widget_grab_focus(w);
    }
    if (e->type != GDK_BUTTON_PRESS && e->type != GDK_BUTTON_RELEASE) {
        return FALSE; /* ignore double/triple-click synthetics */
    }
    int rx, ry;
    widget_to_remote(v, e->x, e->y, &rx, &ry);
    rt_input_event_t ev = {
        .kind    = RT_INPUT_MOUSE_BUTTON,
        .x       = rx, .y = ry,
        .button  = (int)e->button,
        .pressed = (e->type == GDK_BUTTON_PRESS) ? 1 : 0,
    };
    rt_session_send_input(v->session, &ev);
    return TRUE;
}

static gboolean on_scroll(GtkWidget *w, GdkEventScroll *e, gpointer user)
{
    (void)w;
    rt_rdp_view_t *v = user;
    if (!v->input_enabled) return FALSE;
    int rx, ry;
    widget_to_remote(v, e->x, e->y, &rx, &ry);
    int delta = 0;
    switch (e->direction) {
    case GDK_SCROLL_UP:    delta = +0x78; break;
    case GDK_SCROLL_DOWN:  delta = -0x78; break;
    case GDK_SCROLL_SMOOTH: {
        gdouble dx = 0, dy = 0;
        if (gdk_event_get_scroll_deltas((GdkEvent *)e, &dx, &dy)) {
            delta = (int)(-dy * 0x78);
        }
        break;
    }
    default: return FALSE;
    }
    if (delta == 0) return FALSE;
    rt_input_event_t ev = {
        .kind        = RT_INPUT_MOUSE_WHEEL,
        .x           = rx, .y = ry,
        .wheel_delta = delta,
    };
    rt_session_send_input(v->session, &ev);
    return TRUE;
}

static gboolean on_key(GtkWidget *w, GdkEventKey *e, gpointer user)
{
    (void)w;
    rt_rdp_view_t *v = user;
    if (!v->input_enabled) return FALSE;
    rt_input_event_t ev = {
        .kind    = RT_INPUT_KEY,
        .keycode = e->hardware_keycode,
        .pressed = (e->type == GDK_KEY_PRESS) ? 1 : 0,
    };
    rt_session_send_input(v->session, &ev);
    return TRUE;  /* swallow - don't let GTK navigate via Tab/arrows */
}

/* ------------------------------------------------------------------ */
/* Clipboard local -> remote                                          */
/* ------------------------------------------------------------------ */

static void on_local_text_received(GtkClipboard *clip, const gchar *text,
                                   gpointer user)
{
    (void)clip;
    rt_rdp_view_t *v = user;
    if (text == NULL || v->session == NULL) {
        return;
    }
    /* Dedup against the last text we received from the remote. */
    if (v->last_remote_text != NULL &&
        strcmp(text, v->last_remote_text) == 0) {
        return;
    }
    rt_session_set_clipboard_text(v->session, text, strlen(text));
}

static void on_clipboard_owner_change(GtkClipboard *clip,
                                      GdkEvent *event, gpointer user)
{
    (void)event;
    rt_rdp_view_t *v = user;
    if (v->session == NULL) {
        return;
    }
    gtk_clipboard_request_text(clip, on_local_text_received, v);
}

/* ------------------------------------------------------------------ */
/* Mode switch                                                        */
/* ------------------------------------------------------------------ */

static void apply_mode(rt_rdp_view_t *v)
{
    if (v->mode == RT_RDP_SCALE_ORIGINAL) {
        if (v->fb_w > 0 && v->fb_h > 0) {
            gtk_widget_set_size_request(v->area, v->fb_w, v->fb_h);
        }
    } else {
        gtk_widget_set_size_request(v->area, -1, -1);
    }
    gtk_widget_queue_draw(v->area);
}

static void on_combo_changed(GtkComboBox *combo, gpointer user)
{
    rt_rdp_view_t *v = user;
    const char *id = gtk_combo_box_get_active_id(combo);
    v->mode = (id != NULL && strcmp(id, "fit") == 0)
                ? RT_RDP_SCALE_TO_FIT
                : RT_RDP_SCALE_ORIGINAL;
    apply_mode(v);
}

/* Debounce timer fires once after RT_RDP_RESIZE_DEBOUNCE_MS of
 * quiet on the size-allocate signal. Sends the latest viewport dims
 * to the session - the RDP back-end will issue a SendMonitorLayout
 * iff the server advertised DispDyn; otherwise it's a no-op and we
 * keep cairo-scaling locally. */
static gboolean fire_resize(gpointer user)
{
    rt_rdp_view_t *v = user;
    v->resize_timeout_id = 0;

    int w = v->pending_viewport_w;
    int h = v->pending_viewport_h;
    if (w <= 0 || h <= 0 || v->session == NULL) {
        return G_SOURCE_REMOVE;
    }
    if (w == v->last_sent_w && h == v->last_sent_h) {
        return G_SOURCE_REMOVE;
    }
    v->last_sent_w = w;
    v->last_sent_h = h;
    rt_session_resize(v->session, (unsigned)w, (unsigned)h);
    return G_SOURCE_REMOVE;
}

/* When the viewport allocation changes in FIT mode, recompute and
 * redraw, and schedule a debounced DispDyn resize. ORIGINAL mode
 * never resizes the remote - the user explicitly picked a fixed
 * resolution at connect time. */
static void on_size_allocate(GtkWidget *w, GdkRectangle *alloc, gpointer user)
{
    (void)w;
    rt_rdp_view_t *v = user;

    if (v->mode != RT_RDP_SCALE_TO_FIT) {
        return;
    }
    gtk_widget_queue_draw(v->area);

    if (alloc == NULL || alloc->width <= 0 || alloc->height <= 0) {
        return;
    }
    /* Reasonable minimum so a half-laid-out window doesn't trigger
     * a wasted resize round-trip. */
    if (alloc->width < 320 || alloc->height < 200) {
        return;
    }

    v->pending_viewport_w = alloc->width;
    v->pending_viewport_h = alloc->height;

    if (v->resize_timeout_id != 0) {
        g_source_remove(v->resize_timeout_id);
    }
    v->resize_timeout_id = g_timeout_add(RT_RDP_RESIZE_DEBOUNCE_MS,
                                         fire_resize, v);
}

/* ------------------------------------------------------------------ */
/* Lifetime                                                            */
/* ------------------------------------------------------------------ */

static void wrapper_free(gpointer data)
{
    rt_rdp_view_t *v = data;
    if (v->resize_timeout_id != 0) {
        g_source_remove(v->resize_timeout_id);
        v->resize_timeout_id = 0;
    }
    if (v->clipboard != NULL && v->owner_change_id != 0) {
        g_signal_handler_disconnect(v->clipboard, v->owner_change_id);
    }
    free(v->last_remote_text);
    g_free(v);
}

rt_rdp_view_t *rt_rdp_view_new(rt_session_t *session)
{
    rt_rdp_view_t *v = g_new0(rt_rdp_view_t, 1);
    v->session       = session;
    v->mode          = RT_RDP_SCALE_TO_FIT;
    v->scale         = 1.0;
    v->input_enabled = FALSE;

    v->box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_top   (v->box, 4);
    gtk_widget_set_margin_bottom(v->box, 4);
    gtk_widget_set_margin_start (v->box, 4);
    gtk_widget_set_margin_end   (v->box, 4);

    /* Toolbar */
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    v->status = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(v->status), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(v->status), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(v->status, TRUE);

    v->combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(v->combo), "fit",  "Scale to fit");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(v->combo), "orig", "Original size");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(v->combo), "fit");

    gtk_box_pack_start(GTK_BOX(bar), v->status, TRUE,  TRUE,  0);
    gtk_box_pack_end  (GTK_BOX(bar), v->combo,  FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v->box), bar, FALSE, FALSE, 0);

    /* Drawing surface inside a scrolled window. */
    v->scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(v->scrolled),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(v->scrolled, TRUE);
    gtk_widget_set_hexpand(v->scrolled, TRUE);

    v->area = gtk_drawing_area_new();
    gtk_widget_set_can_focus(v->area, TRUE);
    gtk_widget_set_focus_on_click(v->area, TRUE);
    gtk_widget_set_hexpand(v->area, TRUE);
    gtk_widget_set_vexpand(v->area, TRUE);
    gtk_widget_add_events(v->area,
        GDK_BUTTON_PRESS_MASK | GDK_BUTTON_RELEASE_MASK |
        GDK_POINTER_MOTION_MASK | GDK_SCROLL_MASK | GDK_SMOOTH_SCROLL_MASK |
        GDK_KEY_PRESS_MASK | GDK_KEY_RELEASE_MASK |
        GDK_ENTER_NOTIFY_MASK);

    gtk_container_add(GTK_CONTAINER(v->scrolled), v->area);
    gtk_box_pack_start(GTK_BOX(v->box), v->scrolled, TRUE, TRUE, 0);

    /* Wire signals. */
    g_signal_connect(v->area, "draw",
                     G_CALLBACK(on_draw), v);
    g_signal_connect(v->area, "motion-notify-event",
                     G_CALLBACK(on_motion), v);
    g_signal_connect(v->area, "button-press-event",
                     G_CALLBACK(on_button), v);
    g_signal_connect(v->area, "button-release-event",
                     G_CALLBACK(on_button), v);
    g_signal_connect(v->area, "scroll-event",
                     G_CALLBACK(on_scroll), v);
    g_signal_connect(v->area, "key-press-event",
                     G_CALLBACK(on_key), v);
    g_signal_connect(v->area, "key-release-event",
                     G_CALLBACK(on_key), v);
    g_signal_connect(v->scrolled, "size-allocate",
                     G_CALLBACK(on_size_allocate), v);
    g_signal_connect(v->combo, "changed",
                     G_CALLBACK(on_combo_changed), v);

    /* Clipboard hookup. */
    v->clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    v->owner_change_id = g_signal_connect(
        v->clipboard, "owner-change",
        G_CALLBACK(on_clipboard_owner_change), v);

    /* Tie wrapper lifetime to top-level widget. */
    g_object_set_data_full(G_OBJECT(v->box), "rt-rdp-view-wrapper",
                           v, (GDestroyNotify)wrapper_free);
    return v;
}

void rt_rdp_view_free(rt_rdp_view_t *v)
{
    /* Lifetime owned by the top-level widget; see rt_rdp_view_new. */
    (void)v;
}

GtkWidget *rt_rdp_view_get_widget(rt_rdp_view_t *v)
{
    return v->box;
}

void rt_rdp_view_set_session(rt_rdp_view_t *v, rt_session_t *session)
{
    if (v == NULL) return;
    v->session = session;
}

void rt_rdp_view_on_frame(rt_rdp_view_t *v,
                          int frame_w, int frame_h,
                          int dx, int dy, int dw, int dh)
{
    if (v == NULL) return;

    if (frame_w != v->fb_w || frame_h != v->fb_h) {
        v->fb_w = frame_w;
        v->fb_h = frame_h;
        if (v->mode == RT_RDP_SCALE_ORIGINAL) {
            gtk_widget_set_size_request(v->area, frame_w, frame_h);
        }
    }

    if (v->mode == RT_RDP_SCALE_ORIGINAL) {
        /* 1:1 - direct queue_draw_area on the dirty rect. */
        if (dw > 0 && dh > 0) {
            gtk_widget_queue_draw_area(v->area, dx, dy, dw, dh);
        } else {
            gtk_widget_queue_draw(v->area);
        }
    } else {
        /* Scaled - dirty rect must be expanded by the scale factor.
         * Cheap approximation: redraw the whole area. The cost is
         * bounded by the viewport size, which is usually smaller
         * than the remote framebuffer at typical scales. */
        gtk_widget_queue_draw(v->area);
    }
}

void rt_rdp_view_set_status(rt_rdp_view_t *v, const char *status)
{
    if (v == NULL) return;
    gtk_label_set_text(GTK_LABEL(v->status), status ? status : "");
}

void rt_rdp_view_set_remote_clipboard(rt_rdp_view_t *v,
                                      const char *utf8, size_t len)
{
    if (v == NULL || utf8 == NULL) return;

    /* Stash so the next owner-change can dedup. */
    free(v->last_remote_text);
    v->last_remote_text = malloc(len + 1);
    if (v->last_remote_text != NULL) {
        memcpy(v->last_remote_text, utf8, len);
        v->last_remote_text[len] = '\0';
    }

    if (v->clipboard != NULL) {
        gtk_clipboard_set_text(v->clipboard, utf8, (gint)len);
    }
}

void rt_rdp_view_set_input_enabled(rt_rdp_view_t *v, gboolean enabled)
{
    if (v == NULL) return;
    v->input_enabled = enabled;
    if (enabled) {
        gtk_widget_grab_focus(v->area);
    }
}

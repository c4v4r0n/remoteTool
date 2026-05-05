/*
 * VNC viewer widget. See header for the widget tree and contract.
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
 * Remote -> local: rt_vnc_view_set_remote_clipboard() stores the
 * text under "last_remote_text" and writes it to the GTK clipboard.
 * The next owner-change re-fetches and compares - it'll match and
 * be dropped.
 */

#include "ui/vnc_view.h"
#include "core/session.h"
#include "protocols/protocol.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

struct rt_vnc_view {
    rt_session_t *session;          /* not owned */

    GtkWidget    *box;              /* top-level */
    GtkWidget    *toolbar;          /* top row holding status + buttons */
    GtkWidget    *status;
    GtkWidget    *combo;
    GtkWidget    *scrolled;
    GtkWidget    *area;             /* GtkDrawingArea */

    /* Latest framebuffer dims. Updated from on_frame. */
    int           fb_w, fb_h;

    /* Cached layout from last draw, used by input handlers. */
    double        scale;
    double        offset_x, offset_y;

    rt_vnc_scale_mode_t  mode;
    gboolean             input_enabled;

    /* Last text we received FROM the remote, used to dedupe local
     * clipboard pushes. Heap, owned. */
    char         *last_remote_text;

    /* GTK clipboard handler id so we can unhook on destroy. */
    gulong        owner_change_id;
    GtkClipboard *clipboard;

    /* Viewport-resize debounce. Each size-allocate restarts the
     * timer; when it fires we forward the latest viewport dims to
     * the session (which the VNC back-end translates to a DispDyn
     * no-op for VNC, kept for symmetry). */
    guint         resize_timeout_id;
    int           pending_viewport_w;
    int           pending_viewport_h;
    int           last_sent_w;
    int           last_sent_h;

    /* Manual clipboard dialog. NULL when closed; non-NULL means the
     * dialog is up and rt_vnc_view_set_remote_clipboard should mirror
     * incoming server text into clip_buffer. */
    GtkWidget    *clip_dialog;
    GtkTextBuffer *clip_buffer;
};

#define RT_VNC_RESIZE_DEBOUNCE_MS 250

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static void compute_layout(rt_vnc_view_t *v, int alloc_w, int alloc_h)
{
    if (v->fb_w <= 0 || v->fb_h <= 0) {
        v->scale = 1.0;
        v->offset_x = v->offset_y = 0;
        return;
    }
    if (v->mode == RT_VNC_SCALE_ORIGINAL) {
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

static void widget_to_remote(rt_vnc_view_t *v, double wx, double wy,
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
    rt_vnc_view_t *v = user;
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
        if (v->mode == RT_VNC_SCALE_ORIGINAL) {
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
    rt_vnc_view_t *v = user;
    if (!v->input_enabled) return FALSE;
    int rx, ry;
    widget_to_remote(v, e->x, e->y, &rx, &ry);
    rt_input_event_t ev = { .kind = RT_INPUT_MOUSE_MOVE, .x = rx, .y = ry };
    rt_session_send_input(v->session, &ev);
    return TRUE;
}

static gboolean on_button(GtkWidget *w, GdkEventButton *e, gpointer user)
{
    rt_vnc_view_t *v = user;
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
    rt_vnc_view_t *v = user;
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

/* ------------------------------------------------------------------ */
/* Send-special-keys (Ctrl+Alt+Del menu)                              */
/* ------------------------------------------------------------------ */

#define RT_VNC_CHORD_MAX 4

typedef struct {
    const char *label;
    guint       keysyms[RT_VNC_CHORD_MAX]; /* GDK keysyms, NUL-terminated */
} rt_vnc_chord_t;

/* Standard remote-desktop "send-special-keys" set, modeled on the
 * VMware Workstation menu. Each entry is press-all-then-release-all,
 * release order reversed so modifier keys come up last. */
static const rt_vnc_chord_t RT_VNC_SPECIAL_CHORDS[] = {
    { "Ctrl+Alt+Del",
      { GDK_KEY_Control_L, GDK_KEY_Alt_L, GDK_KEY_Delete } },
    { "Ctrl+Alt+End  (alias for Ctrl+Alt+Del)",
      { GDK_KEY_Control_L, GDK_KEY_Alt_L, GDK_KEY_Delete } },
    { "Ctrl+Shift+Esc  (Task Manager)",
      { GDK_KEY_Control_L, GDK_KEY_Shift_L, GDK_KEY_Escape } },
    { "Ctrl+Esc  (Start menu)",
      { GDK_KEY_Control_L, GDK_KEY_Escape } },
    { "Alt+Tab",
      { GDK_KEY_Alt_L, GDK_KEY_Tab } },
    { "Alt+F4",
      { GDK_KEY_Alt_L, GDK_KEY_F4 } },
    { "Win  (Start)",
      { GDK_KEY_Super_L } },
    { "Print Screen",
      { GDK_KEY_Print } },
};

/* Resolve a GDK keysym to the X11 hardware keycode the local keymap
 * uses for it, so the chord goes through the same dispatch path as a
 * normal physical keypress. Returns 0 if the keysym isn't bound. */
static guint keysym_to_keycode(guint keysym)
{
    GdkKeymap     *km   = gdk_keymap_get_for_display(gdk_display_get_default());
    GdkKeymapKey  *keys = NULL;
    gint           n    = 0;
    guint          out  = 0;

    if (gdk_keymap_get_entries_for_keyval(km, keysym, &keys, &n) && n > 0) {
        out = keys[0].keycode;
    }
    g_free(keys);
    return out;
}

static void send_chord(rt_vnc_view_t *v, const guint *keysyms)
{
    if (!v->input_enabled || v->session == NULL) {
        return;
    }

    guint keycodes[RT_VNC_CHORD_MAX];
    int   n = 0;
    for (int i = 0; i < RT_VNC_CHORD_MAX && keysyms[i] != 0; i++) {
        guint kc = keysym_to_keycode(keysyms[i]);
        if (kc == 0) {
            return;  /* unmapped key on this layout - bail rather than send a partial chord */
        }
        keycodes[n++] = kc;
    }
    if (n == 0) {
        return;
    }

    /* Press in order, release in reverse so modifiers stay held while
     * the action key fires and come up cleanly afterwards. The VNC
     * back-end consumes .keysym; .keycode is included only because
     * the event struct is shared with the RDP back-end. */
    for (int i = 0; i < n; i++) {
        rt_input_event_t ev = {
            .kind    = RT_INPUT_KEY,
            .keycode = keycodes[i],
            .keysym  = keysyms[i],
            .pressed = 1,
        };
        rt_session_send_input(v->session, &ev);
    }
    for (int i = n - 1; i >= 0; i--) {
        rt_input_event_t ev = {
            .kind    = RT_INPUT_KEY,
            .keycode = keycodes[i],
            .keysym  = keysyms[i],
            .pressed = 0,
        };
        rt_session_send_input(v->session, &ev);
    }

    /* Restore canvas focus so subsequent typing still goes there. */
    gtk_widget_grab_focus(v->area);
}

static void on_special_key_clicked(GtkMenuItem *item, gpointer user_data)
{
    rt_vnc_view_t        *v     = user_data;
    const rt_vnc_chord_t *chord = g_object_get_data(G_OBJECT(item),
                                                    "rt-chord");
    if (chord != NULL) {
        send_chord(v, chord->keysyms);
    }
}

/* Build the popup menu attached to the "Send Keys" toolbar button. */
static GtkWidget *build_special_keys_menu(rt_vnc_view_t *v)
{
    GtkWidget *menu = gtk_menu_new();
    for (size_t i = 0;
         i < sizeof(RT_VNC_SPECIAL_CHORDS) / sizeof(RT_VNC_SPECIAL_CHORDS[0]);
         i++) {
        const rt_vnc_chord_t *chord = &RT_VNC_SPECIAL_CHORDS[i];
        GtkWidget *item = gtk_menu_item_new_with_label(chord->label);
        /* Drop the const through uintptr_t to satisfy -Wcast-qual.
         * The handler treats the pointer as read-only - the table is
         * static const. */
        g_object_set_data(G_OBJECT(item), "rt-chord",
                          (gpointer)(uintptr_t)chord);
        g_signal_connect(item, "activate",
                         G_CALLBACK(on_special_key_clicked), v);
        gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
    }
    gtk_widget_show_all(menu);
    return menu;
}

/* ------------------------------------------------------------------ */
/* Key events from the canvas                                         */
/* ------------------------------------------------------------------ */

static gboolean on_key(GtkWidget *w, GdkEventKey *e, gpointer user)
{
    (void)w;
    rt_vnc_view_t *v = user;
    /* F11 is reserved for the local fullscreen toggle - let it
     * propagate up to the main window without forwarding to the
     * remote. */
    if (e->keyval == GDK_KEY_F11) {
        return FALSE;
    }
    if (!v->input_enabled) return FALSE;
    rt_input_event_t ev = {
        .kind    = RT_INPUT_KEY,
        .keycode = e->hardware_keycode,    /* unused by VNC; kept for symmetry */
        .keysym  = e->keyval,              /* GDK keyval == X11 keysym */
        .pressed = (e->type == GDK_KEY_PRESS) ? 1 : 0,
    };
    rt_session_send_input(v->session, &ev);
    return TRUE;  /* swallow - don't let GTK navigate via Tab/arrows */
}

/* Mouse entered the canvas - grab focus so subsequent key events flow
 * here without the user having to click first. */
static gboolean on_enter(GtkWidget *w, GdkEventCrossing *e, gpointer user)
{
    (void)e; (void)user;
    if (!gtk_widget_has_focus(w)) {
        gtk_widget_grab_focus(w);
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Clipboard local -> remote                                          */
/* ------------------------------------------------------------------ */

static void on_local_text_received(GtkClipboard *clip, const gchar *text,
                                   gpointer user)
{
    (void)clip;
    rt_vnc_view_t *v = user;
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
    rt_vnc_view_t *v = user;
    if (v->session == NULL) {
        return;
    }
    gtk_clipboard_request_text(clip, on_local_text_received, v);
}

/* ------------------------------------------------------------------ */
/* Mode switch                                                        */
/* ------------------------------------------------------------------ */

static void apply_mode(rt_vnc_view_t *v)
{
    if (v->mode == RT_VNC_SCALE_ORIGINAL) {
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
    rt_vnc_view_t *v = user;
    const char *id = gtk_combo_box_get_active_id(combo);
    v->mode = (id != NULL && strcmp(id, "fit") == 0)
                ? RT_VNC_SCALE_TO_FIT
                : RT_VNC_SCALE_ORIGINAL;
    apply_mode(v);
}

/* Debounce timer fires once after RT_VNC_RESIZE_DEBOUNCE_MS of
 * quiet on the size-allocate signal. Sends the latest viewport dims
 * to the session - the VNC back-end will issue a SendMonitorLayout
 * iff the server advertised DispDyn; otherwise it's a no-op and we
 * keep cairo-scaling locally. */
static gboolean fire_resize(gpointer user)
{
    rt_vnc_view_t *v = user;
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
    rt_vnc_view_t *v = user;

    if (v->mode != RT_VNC_SCALE_TO_FIT) {
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
    v->resize_timeout_id = g_timeout_add(RT_VNC_RESIZE_DEBOUNCE_MS,
                                         fire_resize, v);
}

/* ------------------------------------------------------------------ */
/* Manual clipboard dialog                                            */
/* ------------------------------------------------------------------ */
/*
 * Workaround for VNC servers whose RFB cut-text bridge isn't reliable
 * (some Windows builds): a non-modal dialog with a single text buffer
 * the user can paste into and read from.
 *
 * Send to remote: read the current buffer and call
 *   rt_session_set_clipboard_text(), which queues a SendClientCutText
 *   on the worker thread.
 * Receive from remote: rt_vnc_view_set_remote_clipboard() (called
 *   from on_clipboard_text on the GTK main thread) refreshes the
 *   buffer in addition to its existing GTK-clipboard write.
 *
 * One dialog per view. Reopening focuses the existing instance.
 */

static void on_clip_dialog_destroyed(GtkWidget *w, gpointer user)
{
    (void)w;
    rt_vnc_view_t *v = user;
    v->clip_dialog = NULL;
    v->clip_buffer = NULL;
}

static void on_clip_send_clicked(GtkButton *btn, gpointer user)
{
    (void)btn;
    rt_vnc_view_t *v = user;
    if (v->clip_buffer == NULL || v->session == NULL) {
        return;
    }
    GtkTextIter start, end;
    gtk_text_buffer_get_start_iter(v->clip_buffer, &start);
    gtk_text_buffer_get_end_iter  (v->clip_buffer, &end);
    gchar *text = gtk_text_buffer_get_text(v->clip_buffer, &start, &end, FALSE);
    if (text != NULL) {
        size_t n = strlen(text);
        if (n > 0) {
            /* Stash as last_remote_text so the GTK-clipboard
             * owner-change path doesn't loop the same payload. */
            free(v->last_remote_text);
            v->last_remote_text = g_strdup(text);
            rt_session_set_clipboard_text(v->session, text, n);
        }
        g_free(text);
    }
}

static void on_clip_button_clicked(GtkButton *btn, gpointer user)
{
    (void)btn;
    rt_vnc_view_t *v = user;

    if (v->clip_dialog != NULL) {
        gtk_window_present(GTK_WINDOW(v->clip_dialog));
        return;
    }

    GtkWidget *parent = gtk_widget_get_toplevel(v->box);
    GtkWidget *dlg = gtk_dialog_new();
    gtk_window_set_title(GTK_WINDOW(dlg), "Manual clipboard");
    if (GTK_IS_WINDOW(parent)) {
        gtk_window_set_transient_for(GTK_WINDOW(dlg), GTK_WINDOW(parent));
    }
    gtk_window_set_modal(GTK_WINDOW(dlg), FALSE);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 520, 320);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_widget_set_margin_top   (content, 8);
    gtk_widget_set_margin_bottom(content, 8);
    gtk_widget_set_margin_start (content, 8);
    gtk_widget_set_margin_end   (content, 8);

    GtkWidget *info = gtk_label_new(
        "Paste here, then 'Send to remote'. Text the remote sends "
        "back appears here automatically (Ctrl+C to take it locally).");
    gtk_label_set_xalign(GTK_LABEL(info), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(info), TRUE);
    gtk_box_pack_start(GTK_BOX(content), info, FALSE, FALSE, 0);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);

    GtkWidget *tv = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(tv), GTK_WRAP_WORD_CHAR);
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tv));

    /* Pre-populate with the most recently received remote text, if
     * any - saves the user one keystroke after seeing a copy. */
    if (v->last_remote_text != NULL) {
        gtk_text_buffer_set_text(buf, v->last_remote_text, -1);
    }

    gtk_container_add(GTK_CONTAINER(scroll), tv);
    gtk_box_pack_start(GTK_BOX(content), scroll, TRUE, TRUE, 0);

    /* Action row */
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_margin_top(bar, 6);
    gtk_box_pack_end(GTK_BOX(content), bar, FALSE, FALSE, 0);

    GtkWidget *send  = gtk_button_new_with_label("Send to remote");
    gtk_style_context_add_class(gtk_widget_get_style_context(send),
                                "suggested-action");
    GtkWidget *close = gtk_button_new_with_label("Close");
    gtk_box_pack_end(GTK_BOX(bar), send,  FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(bar), close, FALSE, FALSE, 0);

    g_signal_connect(send,  "clicked",
                     G_CALLBACK(on_clip_send_clicked), v);
    g_signal_connect_swapped(close, "clicked",
                             G_CALLBACK(gtk_widget_destroy), dlg);
    g_signal_connect(dlg, "destroy",
                     G_CALLBACK(on_clip_dialog_destroyed), v);

    v->clip_dialog = dlg;
    v->clip_buffer = buf;

    gtk_widget_show_all(dlg);
}

/* ------------------------------------------------------------------ */
/* Lifetime                                                            */
/* ------------------------------------------------------------------ */

static void wrapper_free(gpointer data)
{
    rt_vnc_view_t *v = data;
    if (v->resize_timeout_id != 0) {
        g_source_remove(v->resize_timeout_id);
        v->resize_timeout_id = 0;
    }
    if (v->clipboard != NULL && v->owner_change_id != 0) {
        g_signal_handler_disconnect(v->clipboard, v->owner_change_id);
    }
    /* Tear down the manual clipboard dialog if it's still open;
     * its destroy handler clears v->clip_dialog/buffer for us. */
    if (v->clip_dialog != NULL) {
        gtk_widget_destroy(v->clip_dialog);
    }
    free(v->last_remote_text);
    g_free(v);
}

rt_vnc_view_t *rt_vnc_view_new(rt_session_t *session)
{
    rt_vnc_view_t *v = g_new0(rt_vnc_view_t, 1);
    v->session       = session;
    v->mode          = RT_VNC_SCALE_TO_FIT;
    v->scale         = 1.0;
    v->input_enabled = FALSE;

    v->box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_top   (v->box, 4);
    gtk_widget_set_margin_bottom(v->box, 4);
    gtk_widget_set_margin_start (v->box, 4);
    gtk_widget_set_margin_end   (v->box, 4);

    /* Toolbar */
    v->toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *bar = v->toolbar;
    v->status = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(v->status), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(v->status), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(v->status, TRUE);

    v->combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(v->combo), "fit",  "Scale to fit");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(v->combo), "orig", "Original size");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(v->combo), "fit");

    /* "Send Keys" menu button - lets the user fire combinations the
     * local OS / WM intercepts (Ctrl+Alt+Del, Win, Alt+F4, etc.). */
    GtkWidget *send_btn = gtk_menu_button_new();
    gtk_button_set_label(GTK_BUTTON(send_btn), "Send Keys");
    gtk_widget_set_tooltip_text(send_btn,
        "Send a special key combination to the remote desktop");
    gtk_widget_set_focus_on_click(send_btn, FALSE);
    gtk_menu_button_set_popup(GTK_MENU_BUTTON(send_btn),
                              build_special_keys_menu(v));

    /* "Clipboard" - manual bidirectional buffer when the server's
     * RFB cut-text bridge is unreliable (common on Windows VNC). */
    GtkWidget *clip_btn = gtk_button_new_with_label("Clipboard");
    gtk_widget_set_tooltip_text(clip_btn,
        "Open a manual clipboard buffer (paste here to send to the "
        "remote; remote-copied text appears here)");
    gtk_widget_set_focus_on_click(clip_btn, FALSE);
    g_signal_connect(clip_btn, "clicked",
                     G_CALLBACK(on_clip_button_clicked), v);

    gtk_box_pack_start(GTK_BOX(bar), v->status,   TRUE,  TRUE,  0);
    gtk_box_pack_end  (GTK_BOX(bar), v->combo,    FALSE, FALSE, 0);
    gtk_box_pack_end  (GTK_BOX(bar), send_btn,    FALSE, FALSE, 0);
    gtk_box_pack_end  (GTK_BOX(bar), clip_btn,    FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v->box), bar, FALSE, FALSE, 0);

    /* Drawing surface inside a scrolled window. */
    v->scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(v->scrolled),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    /* Stop the scrolled window from eating arrow / Page Up/Down /
     * Home / End keys for its own scrolling - the remote desktop
     * needs them. */
    gtk_scrolled_window_set_capture_button_press(
        GTK_SCROLLED_WINDOW(v->scrolled), FALSE);
    gtk_widget_set_can_focus(v->scrolled, FALSE);
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
    g_signal_connect(v->area, "enter-notify-event",
                     G_CALLBACK(on_enter), v);
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
    g_object_set_data_full(G_OBJECT(v->box), "rt-vnc-view-wrapper",
                           v, (GDestroyNotify)wrapper_free);
    return v;
}

void rt_vnc_view_free(rt_vnc_view_t *v)
{
    /* Lifetime owned by the top-level widget; see rt_vnc_view_new. */
    (void)v;
}

GtkWidget *rt_vnc_view_get_widget(rt_vnc_view_t *v)
{
    return v->box;
}

void rt_vnc_view_set_session(rt_vnc_view_t *v, rt_session_t *session)
{
    if (v == NULL) return;
    v->session = session;
}

void rt_vnc_view_on_frame(rt_vnc_view_t *v,
                          int frame_w, int frame_h,
                          int dx, int dy, int dw, int dh)
{
    if (v == NULL) return;

    if (frame_w != v->fb_w || frame_h != v->fb_h) {
        v->fb_w = frame_w;
        v->fb_h = frame_h;
        if (v->mode == RT_VNC_SCALE_ORIGINAL) {
            gtk_widget_set_size_request(v->area, frame_w, frame_h);
        }
    }

    if (v->mode == RT_VNC_SCALE_ORIGINAL) {
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

void rt_vnc_view_set_status(rt_vnc_view_t *v, const char *status)
{
    if (v == NULL) return;
    gtk_label_set_text(GTK_LABEL(v->status), status ? status : "");
}

void rt_vnc_view_set_remote_clipboard(rt_vnc_view_t *v,
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

    /* Mirror into the manual clipboard dialog if the user has it
     * open. We pass `len` explicitly so embedded NULs don't truncate. */
    if (v->clip_buffer != NULL) {
        gtk_text_buffer_set_text(v->clip_buffer, utf8, (gint)len);
    }
}

void rt_vnc_view_set_input_enabled(rt_vnc_view_t *v, gboolean enabled)
{
    if (v == NULL) return;
    v->input_enabled = enabled;
    if (enabled) {
        gtk_widget_grab_focus(v->area);
    }
}

void rt_vnc_view_set_chrome_visible(rt_vnc_view_t *v, gboolean visible)
{
    if (v == NULL || v->toolbar == NULL) return;
    gtk_widget_set_visible(v->toolbar, visible);
}

void rt_vnc_view_set_scale_mode(rt_vnc_view_t *v, rt_vnc_scale_mode_t mode)
{
    if (v == NULL || v->combo == NULL) return;
    /* Use the combo as the source of truth so the visible UI stays in
     * sync. The combo's "changed" handler does the rest. */
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(v->combo),
                                (mode == RT_VNC_SCALE_TO_FIT) ? "fit" : "orig");
}

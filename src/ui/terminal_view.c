/*
 * Terminal-style widget backed by VteTerminal. See header for the
 * widget tree and contract.
 *
 * Resize handling: VteTerminal does not emit a "rows/cols changed"
 * signal directly. We listen on its size-allocate (and on
 * char-size-changed for font/zoom changes) and dispatch to the
 * registered handler only when the (cols, rows) pair actually
 * changes. This avoids spamming the protocol with redundant resize
 * messages when the parent reflows for unrelated reasons.
 */

#include "ui/terminal_view.h"

#include <string.h>

/* VTE's public header declares a 64-bit enum value, which trips
 * -Wpedantic on pre-C2x compilers. Suppress just for the include. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <vte/vte.h>
#pragma GCC diagnostic pop

#define RT_TERM_SCROLLBACK_LINES 10000
#define RT_TERM_FONT             "Monospace 11"

struct rt_terminal {
    GtkWidget *box;        /* top-level, returned by get_widget */
    GtkWidget *status;
    GtkWidget *vte;        /* VteTerminal */

    rt_terminal_input_cb_t  input_cb;
    void                   *input_user;
    rt_terminal_resize_cb_t resize_cb;
    void                   *resize_user;

    /* Last reported size, used to dedupe resize callbacks. */
    long last_cols;
    long last_rows;
};

static void maybe_emit_resize(rt_terminal_t *t)
{
    if (t->resize_cb == NULL) {
        return;
    }
    long cols = vte_terminal_get_column_count(VTE_TERMINAL(t->vte));
    long rows = vte_terminal_get_row_count   (VTE_TERMINAL(t->vte));
    if (cols <= 0 || rows <= 0) {
        return;
    }
    if (cols == t->last_cols && rows == t->last_rows) {
        return;
    }
    t->last_cols = cols;
    t->last_rows = rows;
    t->resize_cb((unsigned)cols, (unsigned)rows, t->resize_user);
}

static void on_vte_commit(VteTerminal *vte, gchar *text, guint size, gpointer user)
{
    (void)vte;
    rt_terminal_t *t = user;
    if (t->input_cb != NULL && text != NULL && size > 0) {
        t->input_cb(text, size, t->input_user);
    }
}

static void on_vte_size_allocate(GtkWidget *w, GdkRectangle *alloc, gpointer user)
{
    (void)w; (void)alloc;
    maybe_emit_resize((rt_terminal_t *)user);
}

static void on_vte_char_size_changed(VteTerminal *vte, guint w, guint h, gpointer user)
{
    (void)vte; (void)w; (void)h;
    maybe_emit_resize((rt_terminal_t *)user);
}

rt_terminal_t *rt_terminal_new(void)
{
    rt_terminal_t *t = g_new0(rt_terminal_t, 1);

    t->box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_top   (t->box, 6);
    gtk_widget_set_margin_bottom(t->box, 6);
    gtk_widget_set_margin_start (t->box, 6);
    gtk_widget_set_margin_end   (t->box, 6);

    /* Status */
    t->status = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(t->status), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(t->status), PANGO_ELLIPSIZE_END);
    gtk_box_pack_start(GTK_BOX(t->box), t->status, FALSE, FALSE, 0);

    /* Terminal + scrollbar in a horizontal row. */
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_vexpand(row, TRUE);
    gtk_widget_set_hexpand(row, TRUE);

    t->vte = vte_terminal_new();
    gtk_widget_set_vexpand(t->vte, TRUE);
    gtk_widget_set_hexpand(t->vte, TRUE);

    vte_terminal_set_scrollback_lines(VTE_TERMINAL(t->vte),
                                      RT_TERM_SCROLLBACK_LINES);
    vte_terminal_set_scroll_on_keystroke(VTE_TERMINAL(t->vte), TRUE);
    vte_terminal_set_scroll_on_output   (VTE_TERMINAL(t->vte), FALSE);
    vte_terminal_set_mouse_autohide     (VTE_TERMINAL(t->vte), TRUE);
    vte_terminal_set_cursor_blink_mode  (VTE_TERMINAL(t->vte),
                                         VTE_CURSOR_BLINK_ON);

    PangoFontDescription *font = pango_font_description_from_string(RT_TERM_FONT);
    if (font != NULL) {
        vte_terminal_set_font(VTE_TERMINAL(t->vte), font);
        pango_font_description_free(font);
    }

    /* Disable input until the session reports CONNECTED. */
    vte_terminal_set_input_enabled(VTE_TERMINAL(t->vte), FALSE);

    GtkWidget *sb = gtk_scrollbar_new(
        GTK_ORIENTATION_VERTICAL,
        gtk_scrollable_get_vadjustment(GTK_SCROLLABLE(t->vte)));

    gtk_box_pack_start(GTK_BOX(row), t->vte, TRUE,  TRUE,  0);
    gtk_box_pack_start(GTK_BOX(row), sb,     FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(t->box), row, TRUE,  TRUE,  0);

    g_signal_connect(t->vte, "commit",
                     G_CALLBACK(on_vte_commit), t);
    g_signal_connect(t->vte, "size-allocate",
                     G_CALLBACK(on_vte_size_allocate), t);
    g_signal_connect(t->vte, "char-size-changed",
                     G_CALLBACK(on_vte_char_size_changed), t);

    /* Tie the wrapper's lifetime to the top-level widget. */
    g_object_set_data_full(G_OBJECT(t->box), "rt-terminal-wrapper",
                           t, (GDestroyNotify)g_free);

    return t;
}

void rt_terminal_free(rt_terminal_t *t)
{
    /* Lifetime is owned by the top-level widget; see rt_terminal_new. */
    (void)t;
}

GtkWidget *rt_terminal_get_widget(rt_terminal_t *t)
{
    return t->box;
}

void rt_terminal_feed_output(rt_terminal_t *t, const char *data, size_t len)
{
    if (t == NULL || data == NULL || len == 0) {
        return;
    }
    vte_terminal_feed(VTE_TERMINAL(t->vte), data, (gssize)len);
}

void rt_terminal_set_status(rt_terminal_t *t, const char *status)
{
    if (t == NULL) {
        return;
    }
    gtk_label_set_text(GTK_LABEL(t->status), status ? status : "");
}

void rt_terminal_set_input_enabled(rt_terminal_t *t, gboolean enabled)
{
    if (t == NULL) {
        return;
    }
    vte_terminal_set_input_enabled(VTE_TERMINAL(t->vte), enabled);
    if (enabled) {
        gtk_widget_grab_focus(t->vte);
    }
}

void rt_terminal_set_chrome_visible(rt_terminal_t *t, gboolean visible)
{
    if (t == NULL || t->status == NULL) {
        return;
    }
    gtk_widget_set_visible(t->status, visible);
}

void rt_terminal_set_input_handler(rt_terminal_t         *t,
                                   rt_terminal_input_cb_t cb,
                                   void                  *user)
{
    if (t == NULL) {
        return;
    }
    t->input_cb   = cb;
    t->input_user = user;
}

void rt_terminal_set_resize_handler(rt_terminal_t          *t,
                                    rt_terminal_resize_cb_t cb,
                                    void                   *user)
{
    if (t == NULL) {
        return;
    }
    t->resize_cb   = cb;
    t->resize_user = user;
    /* Fire once immediately if we already know our size, so the
     * caller can establish the initial PTY geometry. */
    maybe_emit_resize(t);
}

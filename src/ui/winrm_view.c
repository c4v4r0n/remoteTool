/*
 * Terminal-style widget for the WinRM tab.
 *
 * Output is a read-only GtkTextView under a GtkScrolledWindow. New
 * remote bytes are appended at the end; auto-scroll snaps to the
 * bottom when the user is already at the bottom (so they can scroll
 * up to look at history without being yanked back on every chunk).
 *
 * Input is a GtkEntry; pressing Enter or clicking Send sends one
 * line. The local output is echoed with a "> " prefix so the user
 * always sees what they ran. The protocol module re-splits on '\n'
 * even though we always send exactly one line, so this widget is
 * free to evolve (e.g. multi-line paste) without protocol changes.
 *
 * Lifetime: the wrapper is g_object_set_data_full'd onto the top-
 * level box, so it dies with its widget.
 */

#include "ui/winrm_view.h"

#include <stdlib.h>
#include <string.h>

#define RT_WINRM_FONT      "Monospace 11"

struct rt_winrm_view {
    GtkWidget *box;
    GtkWidget *status;
    GtkWidget *scroll;
    GtkWidget *text_view;
    GtkTextBuffer *buf;
    GtkWidget *cmd_entry;
    GtkWidget *send_btn;

    rt_winrm_view_input_cb_t input_cb;
    void                    *input_user;

    int input_enabled;
};

/* ------------------------------------------------------------------ */
/* Append helpers                                                     */
/* ------------------------------------------------------------------ */

/* Ensure UTF-8 validity before sending into GtkTextBuffer. WinRM
 * output is normally CP437/UTF-8 for cmd.exe; we treat invalid
 * sequences as opaque bytes to avoid losing data, replacing each
 * invalid byte with U+FFFD (which is what GLib's validation would
 * have us do anyway). */
static char *sanitize_utf8(const char *data, size_t len, size_t *out_len)
{
    /* g_utf8_make_valid does exactly what we want; available since
     * glib 2.52 which we already depend on transitively via GTK3. */
    char *valid = g_utf8_make_valid(data, (gssize)len);
    if (valid != NULL && out_len != NULL) {
        *out_len = strlen(valid);
    }
    return valid;
}

static int at_bottom(rt_winrm_view_t *v)
{
    GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(
        GTK_SCROLLED_WINDOW(v->scroll));
    if (adj == NULL) return 1;
    double upper   = gtk_adjustment_get_upper(adj);
    double size    = gtk_adjustment_get_page_size(adj);
    double value   = gtk_adjustment_get_value(adj);
    return (value + size + 4.0 >= upper);
}

static void scroll_to_end(rt_winrm_view_t *v)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(v->buf, &end);
    GtkTextMark *m = gtk_text_buffer_create_mark(v->buf, NULL, &end, FALSE);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(v->text_view), m);
    gtk_text_buffer_delete_mark(v->buf, m);
}

static void append_text(rt_winrm_view_t *v, const char *utf8, size_t len)
{
    if (v == NULL || utf8 == NULL || len == 0) return;
    gboolean stick = at_bottom(v);
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(v->buf, &end);
    gtk_text_buffer_insert(v->buf, &end, utf8, (gint)len);
    if (stick) {
        scroll_to_end(v);
    }
}

/* ------------------------------------------------------------------ */
/* Input handlers                                                     */
/* ------------------------------------------------------------------ */

static void submit_command(rt_winrm_view_t *v)
{
    if (!v->input_enabled || v->input_cb == NULL) {
        return;
    }
    const char *txt = gtk_entry_get_text(GTK_ENTRY(v->cmd_entry));
    if (txt == NULL || txt[0] == '\0') {
        return;
    }

    /* Echo locally so the user sees what they ran. */
    char *line = g_strdup_printf("> %s\n", txt);
    append_text(v, line, strlen(line));
    g_free(line);

    /* Send "<cmd>\n" to the protocol. */
    char *out = g_strdup_printf("%s\n", txt);
    v->input_cb(out, strlen(out), v->input_user);
    /* Wipe after send: we don't keep a copy. */
    if (out != NULL) {
        memset(out, 0, strlen(out));
        g_free(out);
    }

    gtk_entry_set_text(GTK_ENTRY(v->cmd_entry), "");
}

static void on_entry_activate(GtkEntry *e, gpointer user)
{
    (void)e;
    submit_command((rt_winrm_view_t *)user);
}

static void on_send_clicked(GtkButton *b, gpointer user)
{
    (void)b;
    submit_command((rt_winrm_view_t *)user);
}

/* ------------------------------------------------------------------ */
/* Construction                                                       */
/* ------------------------------------------------------------------ */

rt_winrm_view_t *rt_winrm_view_new(void)
{
    rt_winrm_view_t *v = g_new0(rt_winrm_view_t, 1);
    v->input_enabled = 0;

    v->box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_top   (v->box, 6);
    gtk_widget_set_margin_bottom(v->box, 6);
    gtk_widget_set_margin_start (v->box, 6);
    gtk_widget_set_margin_end   (v->box, 6);

    /* Status */
    v->status = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(v->status), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(v->status), PANGO_ELLIPSIZE_END);
    gtk_box_pack_start(GTK_BOX(v->box), v->status, FALSE, FALSE, 0);

    /* Output area */
    v->buf = gtk_text_buffer_new(NULL);
    v->text_view = gtk_text_view_new_with_buffer(v->buf);
    g_object_unref(v->buf);  /* view holds the only ref now */

    gtk_text_view_set_editable    (GTK_TEXT_VIEW(v->text_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(v->text_view), FALSE);
    gtk_text_view_set_monospace   (GTK_TEXT_VIEW(v->text_view), TRUE);
    gtk_text_view_set_wrap_mode   (GTK_TEXT_VIEW(v->text_view),
                                   GTK_WRAP_WORD_CHAR);

    /* Apply the monospace font via a CSS provider scoped to this
     * widget; gtk_widget_override_font is deprecated and would warn
     * in -Wdeprecated-declarations. */
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css,
        "textview { font-family: \"Monospace\"; font-size: 11pt; }",
        -1, NULL);
    gtk_style_context_add_provider(
        gtk_widget_get_style_context(v->text_view),
        GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);

    v->scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(v->scroll),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(v->scroll, TRUE);
    gtk_widget_set_hexpand(v->scroll, TRUE);
    gtk_container_add(GTK_CONTAINER(v->scroll), v->text_view);
    gtk_box_pack_start(GTK_BOX(v->box), v->scroll, TRUE, TRUE, 0);

    /* Input row */
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *prompt = gtk_label_new(">");
    gtk_widget_set_margin_start(prompt, 4);
    v->cmd_entry = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(v->cmd_entry), 8192);
    gtk_widget_set_hexpand(v->cmd_entry, TRUE);
    v->send_btn = gtk_button_new_with_label("Send");

    gtk_box_pack_start(GTK_BOX(row), prompt,       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), v->cmd_entry, TRUE,  TRUE,  0);
    gtk_box_pack_start(GTK_BOX(row), v->send_btn,  FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v->box), row, FALSE, FALSE, 0);

    g_signal_connect(v->cmd_entry, "activate",
                     G_CALLBACK(on_entry_activate), v);
    g_signal_connect(v->send_btn, "clicked",
                     G_CALLBACK(on_send_clicked), v);

    /* Disabled until session reports CONNECTED. */
    gtk_widget_set_sensitive(v->cmd_entry, FALSE);
    gtk_widget_set_sensitive(v->send_btn,  FALSE);

    g_object_set_data_full(G_OBJECT(v->box), "rt-winrm-view-wrapper",
                           v, (GDestroyNotify)g_free);
    return v;
}

void rt_winrm_view_free(rt_winrm_view_t *v)
{
    /* Lifetime owned by the top-level widget. */
    (void)v;
}

GtkWidget *rt_winrm_view_get_widget(rt_winrm_view_t *v)
{
    return (v != NULL) ? v->box : NULL;
}

/* ------------------------------------------------------------------ */
/* Public ops                                                         */
/* ------------------------------------------------------------------ */

void rt_winrm_view_feed_output(rt_winrm_view_t *v, const char *data, size_t len)
{
    if (v == NULL || data == NULL || len == 0) return;
    size_t out_len = 0;
    char *clean = sanitize_utf8(data, len, &out_len);
    if (clean == NULL) return;
    append_text(v, clean, out_len);
    g_free(clean);
}

void rt_winrm_view_set_status(rt_winrm_view_t *v, const char *status)
{
    if (v == NULL) return;
    gtk_label_set_text(GTK_LABEL(v->status), status ? status : "");
}

void rt_winrm_view_set_input_enabled(rt_winrm_view_t *v, gboolean enabled)
{
    if (v == NULL) return;
    v->input_enabled = enabled ? 1 : 0;
    gtk_widget_set_sensitive(v->cmd_entry, enabled);
    gtk_widget_set_sensitive(v->send_btn,  enabled);
    if (enabled) {
        gtk_widget_grab_focus(v->cmd_entry);
    }
}

void rt_winrm_view_set_chrome_visible(rt_winrm_view_t *v, gboolean visible)
{
    if (v == NULL) return;
    gtk_widget_set_visible(v->status, visible);
}

void rt_winrm_view_set_input_handler(rt_winrm_view_t          *v,
                                     rt_winrm_view_input_cb_t  cb,
                                     void                     *user)
{
    if (v == NULL) return;
    v->input_cb   = cb;
    v->input_user = user;
}

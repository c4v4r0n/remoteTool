/*
 * Main window: header bar with "+ New Connection" + a notebook of
 * tabs. This file is the only place that knows how form, session,
 * and the per-protocol viewer widget fit together.
 *
 * Submit flow:
 *   1. User fills form, clicks Connect.
 *   2. Form raises on_form_submit (this file), handing over the
 *      connection model + a heap-allocated password copy.
 *   3. We pick the right viewer widget for the protocol:
 *        - SSH/byte-stream  -> rt_terminal      (VTE)
 *        - RDP/framebuffer  -> rt_rdp_view      (cairo blit)
 *      and build a session whose UI callbacks point at it.
 *   4. Password copy is wiped and freed immediately.
 *   5. The form's tab is replaced by the viewer widget.
 *
 * Cleanup flow (tab close):
 *   - The viewer widget owns a tab_bundle_t via g_object_set_data_full.
 *   - When the widget is destroyed, bundle_destroy runs:
 *       a. rt_session_close()  -> joins worker, drops pending UI events
 *       b. free the bundle
 *   - The viewer wrapper struct is owned by its own widget and freed
 *     by GTK after our destroy notify runs.
 */

#include "ui/main_window.h"
#include "ui/tab_manager.h"
#include "ui/connection_form.h"
#include "ui/terminal_view.h"
#include "ui/rdp_view.h"
#include "core/session.h"
#include "core/connection.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero */

#define RT_WINDOW_TITLE          "remoteTool"
#define RT_WINDOW_DEFAULT_WIDTH  1100
#define RT_WINDOW_DEFAULT_HEIGHT 720
#define RT_NEW_TAB_TITLE         "New Connection"

/* ------------------------------------------------------------------ */
/* tab_bundle_t: per-connected-tab cleanup hook                       */
/* ------------------------------------------------------------------ */

typedef struct {
    rt_session_t *session;
} tab_bundle_t;

static void bundle_destroy(gpointer data)
{
    tab_bundle_t *b = data;
    /* Tear down the session BEFORE the viewer widget goes away.
     * After session_close returns, no callbacks can touch the
     * viewer wrapper struct. */
    rt_session_close(b->session);
    g_free(b);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static void wipe_and_free(char *s)
{
    if (s == NULL) {
        return;
    }
    explicit_bzero(s, strlen(s));
    g_free(s);
}

static void make_status_line(char *buf, size_t buflen,
                             rt_proto_state_t state, const char *msg)
{
    if (msg != NULL && msg[0] != '\0') {
        snprintf(buf, buflen, "[%s] %s",
                 rt_proto_state_to_string(state), msg);
    } else {
        snprintf(buf, buflen, "[%s]",
                 rt_proto_state_to_string(state));
    }
}

/* ------------------------------------------------------------------ */
/* SSH viewer wiring                                                  */
/* ------------------------------------------------------------------ */

static void ssh_on_data(void *user, const char *data, size_t len)
{
    rt_terminal_feed_output((rt_terminal_t *)user, data, len);
}

static void ssh_on_state(void *user, rt_proto_state_t state, const char *msg)
{
    rt_terminal_t *t = user;
    char buf[256];
    make_status_line(buf, sizeof(buf), state, msg);
    rt_terminal_set_status(t, buf);
    rt_terminal_set_input_enabled(t, state == RT_PROTO_STATE_CONNECTED);
}

static void ssh_on_terminal_input(const char *bytes, size_t len, void *user)
{
    rt_session_send_data((rt_session_t *)user, bytes, len);
}

static void ssh_on_terminal_resize(unsigned cols, unsigned rows, void *user)
{
    rt_session_resize((rt_session_t *)user, cols, rows);
}

/* ------------------------------------------------------------------ */
/* RDP viewer wiring                                                  */
/* ------------------------------------------------------------------ */

static void rdp_on_state(void *user, rt_proto_state_t state, const char *msg)
{
    rt_rdp_view_t *v = user;
    char buf[256];
    make_status_line(buf, sizeof(buf), state, msg);
    rt_rdp_view_set_status(v, buf);
    rt_rdp_view_set_input_enabled(v, state == RT_PROTO_STATE_CONNECTED);
}

static void rdp_on_frame(void *user, const rt_remote_frame_t *frame)
{
    rt_rdp_view_t *v = user;
    rt_rdp_view_on_frame(v, frame->width, frame->height,
                         frame->dirty_x, frame->dirty_y,
                         frame->dirty_w, frame->dirty_h);
}

static void rdp_on_clipboard_text(void *user, const char *utf8, size_t len)
{
    rt_rdp_view_set_remote_clipboard((rt_rdp_view_t *)user, utf8, len);
}

/* ------------------------------------------------------------------ */
/* Per-protocol session bring-up                                      */
/* ------------------------------------------------------------------ */

/* Returns the new viewer widget on success and writes the session
 * to *out_session. On failure: NULL and *out_session = NULL; caller
 * still owns conn. */
static GtkWidget *build_ssh_session(rt_connection_t *conn,
                                    char            *password,
                                    rt_session_t   **out_session)
{
    rt_terminal_t *term = rt_terminal_new();
    rt_terminal_set_status(term, "[connecting]");

    rt_session_ui_callbacks_t ui = {
        .on_data  = ssh_on_data,
        .on_state = ssh_on_state,
    };
    rt_session_t *session = rt_session_new(conn, password, &ui, term);
    if (session == NULL) {
        gtk_widget_destroy(rt_terminal_get_widget(term));
        *out_session = NULL;
        return NULL;
    }

    rt_terminal_set_input_handler (term, ssh_on_terminal_input,  session);
    rt_terminal_set_resize_handler(term, ssh_on_terminal_resize, session);

    *out_session = session;
    return rt_terminal_get_widget(term);
}

static GtkWidget *build_rdp_session(rt_connection_t *conn,
                                    char            *password,
                                    rt_session_t   **out_session)
{
    /* Create the view before the session - the session's UI callbacks
     * point at the view. We bind them together with set_session()
     * once both exist. */
    rt_rdp_view_t *view = rt_rdp_view_new(NULL);
    rt_rdp_view_set_status(view, "[connecting]");

    rt_session_ui_callbacks_t ui = {
        .on_state          = rdp_on_state,
        .on_frame          = rdp_on_frame,
        .on_clipboard_text = rdp_on_clipboard_text,
    };
    rt_session_t *session = rt_session_new(conn, password, &ui, view);
    if (session == NULL) {
        gtk_widget_destroy(rt_rdp_view_get_widget(view));
        *out_session = NULL;
        return NULL;
    }

    rt_rdp_view_set_session(view, session);

    *out_session = session;
    return rt_rdp_view_get_widget(view);
}

/* ------------------------------------------------------------------ */
/* Form submit                                                         */
/* ------------------------------------------------------------------ */

static void on_form_submit(GtkWidget       *form_widget,
                           rt_connection_t *conn,
                           char            *password,
                           void            *user)
{
    rt_tab_manager_t *tm = user;

    rt_session_t *session   = NULL;
    GtkWidget    *viewer    = NULL;

    switch (conn->protocol) {
    case RT_PROTOCOL_SSH:
        viewer = build_ssh_session(conn, password, &session);
        break;
    case RT_PROTOCOL_RDP:
        viewer = build_rdp_session(conn, password, &session);
        break;
    default: {
        char err[128];
        snprintf(err, sizeof(err), "Protocol '%s' is not implemented yet.",
                 rt_protocol_to_string(conn->protocol));
        rt_connection_form_show_error(form_widget, err);
        wipe_and_free(password);
        rt_connection_free(conn);
        return;
    }
    }

    /* Password is no longer needed in this scope - the session has
     * its own (also wiped) copy that's already been consumed by
     * open(). */
    wipe_and_free(password);

    if (session == NULL) {
        char err[256];
        snprintf(err, sizeof(err),
                 "Could not open %s session to %s:%u",
                 rt_protocol_to_string(conn->protocol),
                 conn->host ? conn->host : "?",
                 (unsigned)conn->port);
        rt_connection_form_show_error(form_widget, err);
        rt_connection_free(conn);
        return;
    }

    /* Cleanup hook on the viewer widget: when the tab is closed
     * (GTK destroys the widget), the bundle's destroy notify joins
     * the session's worker thread before anything else is freed. */
    tab_bundle_t *bundle = g_new0(tab_bundle_t, 1);
    bundle->session = session;
    g_object_set_data_full(G_OBJECT(viewer), "rt-tab-bundle",
                           bundle, bundle_destroy);

    /* Build the new tab title. session now owns conn, but its
     * accessor lets us peek. */
    const rt_connection_t *c = rt_session_connection(session);
    char title[128];
    snprintf(title, sizeof(title), "%s@%s",
             (c->username && c->username[0]) ? c->username
                                             : rt_protocol_to_string(c->protocol),
             c->host ? c->host : "?");

    if (rt_tab_manager_replace_content(tm, form_widget, viewer, title) != 0) {
        gtk_widget_destroy(viewer);
    }
}

/* ------------------------------------------------------------------ */
/* Header bar / window construction                                   */
/* ------------------------------------------------------------------ */

static void on_new_connection_clicked(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    rt_tab_manager_t *tm = user_data;

    GtkWidget *form = rt_connection_form_new(on_form_submit, tm);
    gint page = rt_tab_manager_add_tab(tm, RT_NEW_TAB_TITLE, form);
    gtk_notebook_set_current_page(
        GTK_NOTEBOOK(rt_tab_manager_get_widget(tm)), page);
}

static GtkWidget *build_header_bar(rt_tab_manager_t *tm)
{
    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), RT_WINDOW_TITLE);

    GtkWidget *new_btn = gtk_button_new_from_icon_name(
        "tab-new-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(new_btn, "New connection");
    g_signal_connect(new_btn, "clicked",
                     G_CALLBACK(on_new_connection_clicked), tm);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), new_btn);

    return header;
}

static void tab_manager_destroy_cb(gpointer data)
{
    rt_tab_manager_free((rt_tab_manager_t *)data);
}

GtkWidget *rt_main_window_new(GtkApplication *app)
{
    GtkWidget *win = gtk_application_window_new(app);
    gtk_window_set_default_size(GTK_WINDOW(win),
                                RT_WINDOW_DEFAULT_WIDTH,
                                RT_WINDOW_DEFAULT_HEIGHT);
    gtk_window_set_title(GTK_WINDOW(win), RT_WINDOW_TITLE);

    rt_tab_manager_t *tm = rt_tab_manager_new();
    g_object_set_data_full(G_OBJECT(win), "rt-tab-manager",
                           tm, tab_manager_destroy_cb);

    gtk_window_set_titlebar(GTK_WINDOW(win), build_header_bar(tm));
    gtk_container_add(GTK_CONTAINER(win), rt_tab_manager_get_widget(tm));

    /* Open one connection tab on launch so the UI isn't empty. */
    GtkWidget *form = rt_connection_form_new(on_form_submit, tm);
    rt_tab_manager_add_tab(tm, RT_NEW_TAB_TITLE, form);

    return win;
}

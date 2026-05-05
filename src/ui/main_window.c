/*
 * Main window: header bar with "+ New" and "Saved" buttons + a
 * notebook of tabs. The only place that knows how the form, dialog,
 * session, storage, and viewer widgets fit together.
 *
 * Three connection-launch paths, all converging on start_session():
 *   - on_form_submit / RT_FORM_INTENT_CONNECT
 *       Plain new connection. No persistence side effects.
 *   - on_form_submit / RT_FORM_INTENT_SAVE_AND_CONNECT
 *       Persist the profile + credential first, then connect.
 *   - on_dialog_connect (from the Saved Connections modal)
 *       Load the profile from DB, fetch the password from libsecret,
 *       hand off to start_session.
 *
 * Edit path (no connect):
 *   - on_form_submit / RT_FORM_INTENT_SAVE
 *       Update the profile row + (if a new password was typed)
 *       update the keyring entry. Close the form tab.
 *
 * Tab cleanup is unchanged from earlier phases: each viewer widget
 * carries a tab_bundle_t whose destroy notify joins the session
 * worker before anything else is freed.
 */

#include "ui/main_window.h"
#include "ui/tab_manager.h"
#include "ui/connection_form.h"
#include "ui/connection_dialog.h"
#include "ui/terminal_view.h"
#include "ui/rdp_view.h"
#include "ui/vnc_view.h"
#include "core/session.h"
#include "core/connection.h"
#include "storage/profile.h"
#include "storage/credentials.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero */

#define RT_WINDOW_TITLE          "remoteTool"
#define RT_WINDOW_DEFAULT_WIDTH  1100
#define RT_WINDOW_DEFAULT_HEIGHT 720
#define RT_NEW_TAB_TITLE         "New Connection"
#define RT_EDIT_TAB_TITLE        "Edit Connection"

/* Per-window state keys. */
#define RT_KEY_FULLSCREEN        "rt-fullscreen-state"
#define RT_KEY_HEADER_BAR        "rt-header-bar"

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

/* Walk up from any descendant widget to find the GtkWindow that owns
 * the tab manager, so dialogs can use it as their transient_for. */
static GtkWindow *toplevel_window(GtkWidget *child)
{
    GtkWidget *root = gtk_widget_get_toplevel(child);
    return GTK_IS_WINDOW(root) ? GTK_WINDOW(root) : NULL;
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
/* VNC viewer wiring                                                  */
/* ------------------------------------------------------------------ */

static void vnc_on_state(void *user, rt_proto_state_t state, const char *msg)
{
    rt_vnc_view_t *v = user;
    char buf[256];
    make_status_line(buf, sizeof(buf), state, msg);
    rt_vnc_view_set_status(v, buf);
    rt_vnc_view_set_input_enabled(v, state == RT_PROTO_STATE_CONNECTED);
}

static void vnc_on_frame(void *user, const rt_remote_frame_t *frame)
{
    rt_vnc_view_t *v = user;
    rt_vnc_view_on_frame(v, frame->width, frame->height,
                         frame->dirty_x, frame->dirty_y,
                         frame->dirty_w, frame->dirty_h);
}

static void vnc_on_clipboard_text(void *user, const char *utf8, size_t len)
{
    rt_vnc_view_set_remote_clipboard((rt_vnc_view_t *)user, utf8, len);
}

/* ------------------------------------------------------------------ */
/* Per-protocol session bring-up                                      */
/* ------------------------------------------------------------------ */

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

static GtkWidget *build_vnc_session(rt_connection_t *conn,
                                    char            *password,
                                    rt_session_t   **out_session)
{
    rt_vnc_view_t *view = rt_vnc_view_new(NULL);
    rt_vnc_view_set_status(view, "[connecting]");

    /* Apply persisted scale-mode preference (if the connection came
     * from a saved profile that recorded one). Defaults stay if not. */
    if (conn->vnc != NULL) {
        rt_vnc_view_set_scale_mode(view,
            conn->vnc->scale_mode_fit ? RT_VNC_SCALE_TO_FIT
                                       : RT_VNC_SCALE_ORIGINAL);
    }

    rt_session_ui_callbacks_t ui = {
        .on_state          = vnc_on_state,
        .on_frame          = vnc_on_frame,
        .on_clipboard_text = vnc_on_clipboard_text,
    };
    rt_session_t *session = rt_session_new(conn, password, &ui, view);
    if (session == NULL) {
        gtk_widget_destroy(rt_vnc_view_get_widget(view));
        *out_session = NULL;
        return NULL;
    }
    rt_vnc_view_set_session(view, session);

    *out_session = session;
    return rt_vnc_view_get_widget(view);
}

/* Open a session and either replace `current_widget` (if non-NULL,
 * usually a form) with the viewer or push it as a new tab. Takes
 * ownership of `conn` and `password` regardless of outcome. */
static int start_session(rt_tab_manager_t *tm,
                         GtkWidget        *current_widget,
                         rt_connection_t  *conn,
                         char             *password)
{
    rt_session_t *session = NULL;
    GtkWidget    *viewer  = NULL;

    switch (conn->protocol) {
    case RT_PROTOCOL_SSH:
        viewer = build_ssh_session(conn, password, &session);
        break;
    case RT_PROTOCOL_RDP:
        viewer = build_rdp_session(conn, password, &session);
        break;
    case RT_PROTOCOL_VNC:
        viewer = build_vnc_session(conn, password, &session);
        break;
    default:
        wipe_and_free(password);
        rt_connection_free(conn);
        return -1;
    }

    /* Session has either consumed conn (success) or returned NULL
     * (we still own conn). Either way, password is no longer needed. */
    wipe_and_free(password);

    if (session == NULL) {
        rt_connection_free(conn);
        return -1;
    }

    tab_bundle_t *bundle = g_new0(tab_bundle_t, 1);
    bundle->session = session;
    g_object_set_data_full(G_OBJECT(viewer), "rt-tab-bundle",
                           bundle, bundle_destroy);

    /* Tab title: "PROTOCOL host" (e.g. "RDP dc01.contoso.com").
     * Protocol is uppercased; rt_protocol_to_string returns lowercase
     * ("ssh"/"rdp") so we transform inline. */
    const rt_connection_t *c = rt_session_connection(session);
    const char *proto_lc = rt_protocol_to_string(c->protocol);
    char proto_uc[8];
    size_t pi = 0;
    for (; proto_lc[pi] != '\0' && pi + 1 < sizeof(proto_uc); pi++) {
        proto_uc[pi] = (char)((proto_lc[pi] >= 'a' && proto_lc[pi] <= 'z')
                              ? proto_lc[pi] - 32 : proto_lc[pi]);
    }
    proto_uc[pi] = '\0';
    char title[128];
    snprintf(title, sizeof(title), "%s %s",
             proto_uc,
             c->host ? c->host : "?");

    if (current_widget != NULL) {
        if (rt_tab_manager_replace_content(tm, current_widget, viewer, title) != 0) {
            gtk_widget_destroy(viewer);
            return -1;
        }
    } else {
        gint page = rt_tab_manager_add_tab(tm, title, viewer);
        gtk_notebook_set_current_page(
            GTK_NOTEBOOK(rt_tab_manager_get_widget(tm)), page);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Persistence helpers                                                */
/* ------------------------------------------------------------------ */

/* Build a profile from form-derived `conn` plus `name` and persist
 * both the row and (if password supplied) the credential. Returns 0
 * on success, -1 on failure. On success p->id is the new rowid. */
static int persist_new_profile(const rt_connection_t *conn,
                               const char            *name,
                               const char            *password,
                               int64_t               *out_id)
{
    rt_profile_t *p = rt_profile_new();
    if (p == NULL) {
        return -1;
    }
    p->protocol = conn->protocol;
    p->port     = conn->port;
    p->name     = g_strdup(name);
    p->host     = g_strdup(conn->host ? conn->host : "");
    if (conn->username != NULL) {
        p->username = g_strdup(conn->username);
    }
    if (conn->rdp != NULL) {
        p->rdp = rt_rdp_options_new();
        p->rdp->width                = conn->rdp->width;
        p->rdp->height               = conn->rdp->height;
        p->rdp->color_depth          = conn->rdp->color_depth;
        p->rdp->insecure_cert_bypass = conn->rdp->insecure_cert_bypass;
        p->rdp->clipboard_enabled    = conn->rdp->clipboard_enabled;
        if (conn->rdp->domain != NULL) {
            p->domain = g_strdup(conn->rdp->domain);
            rt_rdp_options_set_domain(p->rdp, conn->rdp->domain);
        }
    }
    if (conn->vnc != NULL) {
        p->vnc = rt_vnc_options_new();
        p->vnc->view_only         = conn->vnc->view_only;
        p->vnc->clipboard_enabled = conn->vnc->clipboard_enabled;
        p->vnc->scale_mode_fit    = conn->vnc->scale_mode_fit;
    }
    /* Allocate a credential id only when there's actually a password
     * to store. Empty passwords stay un-keyringed. */
    if (password != NULL && password[0] != '\0') {
        p->credential_id = rt_credentials_new_id();
        if (p->credential_id != NULL) {
            char label[160];
            snprintf(label, sizeof(label), "remoteTool: %s", name);
            if (rt_credentials_store(p->credential_id, label, password) != 0) {
                /* Keyring failed - keep profile but drop the broken id. */
                free(p->credential_id);
                p->credential_id = NULL;
            }
        }
    }

    if (rt_profile_save(p) != 0) {
        /* Best-effort cleanup of the keyring entry we already wrote. */
        if (p->credential_id != NULL) {
            rt_credentials_delete(p->credential_id);
        }
        rt_profile_free(p);
        return -1;
    }
    if (out_id != NULL) {
        *out_id = p->id;
    }
    rt_profile_free(p);
    return 0;
}

/* Update an existing profile row from form-derived `conn`. If
 * `password` is non-empty, also update the keyring entry (creating
 * one on the fly if the row didn't have one before). */
static int persist_edit_profile(int64_t                profile_id,
                                const char            *name,
                                const rt_connection_t *conn,
                                const char            *password)
{
    rt_profile_t *p = rt_profile_load(profile_id);
    if (p == NULL) {
        return -1;
    }

    /* Apply edits onto p. */
    g_free(p->name);     p->name     = g_strdup(name);
    g_free(p->host);     p->host     = g_strdup(conn->host ? conn->host : "");
    g_free(p->username); p->username = (conn->username && conn->username[0])
                                       ? g_strdup(conn->username) : NULL;
    p->protocol = conn->protocol;
    p->port     = conn->port;

    if (conn->rdp != NULL) {
        if (p->rdp == NULL) p->rdp = rt_rdp_options_new();
        p->rdp->width                = conn->rdp->width;
        p->rdp->height               = conn->rdp->height;
        p->rdp->color_depth          = conn->rdp->color_depth;
        p->rdp->insecure_cert_bypass = conn->rdp->insecure_cert_bypass;
        p->rdp->clipboard_enabled    = conn->rdp->clipboard_enabled;
        g_free(p->domain);
        p->domain = (conn->rdp->domain && conn->rdp->domain[0])
                    ? g_strdup(conn->rdp->domain) : NULL;
        rt_rdp_options_set_domain(p->rdp, p->domain);
    } else {
        rt_rdp_options_free(p->rdp);
        p->rdp = NULL;
        g_free(p->domain);
        p->domain = NULL;
    }

    if (conn->vnc != NULL) {
        if (p->vnc == NULL) p->vnc = rt_vnc_options_new();
        p->vnc->view_only         = conn->vnc->view_only;
        p->vnc->clipboard_enabled = conn->vnc->clipboard_enabled;
        p->vnc->scale_mode_fit    = conn->vnc->scale_mode_fit;
    } else {
        rt_vnc_options_free(p->vnc);
        p->vnc = NULL;
    }

    /* Replace credential iff user typed a new password. */
    if (password != NULL && password[0] != '\0') {
        if (p->credential_id == NULL) {
            p->credential_id = rt_credentials_new_id();
        }
        if (p->credential_id != NULL) {
            char label[160];
            snprintf(label, sizeof(label), "remoteTool: %s", name);
            rt_credentials_store(p->credential_id, label, password);
        }
    }

    int rc = rt_profile_save(p);
    rt_profile_free(p);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Form submit                                                         */
/* ------------------------------------------------------------------ */

static void on_form_submit(GtkWidget        *form_widget,
                           rt_form_intent_t  intent,
                           int64_t           profile_id,
                           const char       *save_name,
                           rt_connection_t  *conn,
                           char             *password,
                           void             *user)
{
    rt_tab_manager_t *tm = user;

    if (intent == RT_FORM_INTENT_SAVE) {
        /* Edit-only path: persist updates, close the form tab. */
        if (persist_edit_profile(profile_id, save_name, conn, password) != 0) {
            wipe_and_free(password);
            rt_connection_free(conn);
            rt_connection_form_show_error(form_widget,
                "Failed to save profile changes.");
            return;
        }
        wipe_and_free(password);
        rt_connection_free(conn);
        /* Close the form tab now that the edit is committed. */
        gtk_widget_destroy(form_widget);
        return;
    }

    if (intent == RT_FORM_INTENT_SAVE_AND_CONNECT) {
        if (persist_new_profile(conn, save_name, password, NULL) != 0) {
            /* Save failure is non-fatal for the connect attempt: warn
             * and continue with the in-flight session. */
            rt_connection_form_show_error(form_widget,
                "Profile not saved (continuing with one-shot connection).");
        }
    }

    /* Both CONNECT and SAVE_AND_CONNECT now open the session. */
    if (start_session(tm, form_widget, conn, password) != 0) {
        char err[256];
        snprintf(err, sizeof(err),
                 "Could not open session.");
        rt_connection_form_show_error(form_widget, err);
    }
}

/* ------------------------------------------------------------------ */
/* Saved-connections dialog callbacks                                 */
/* ------------------------------------------------------------------ */

static void on_dialog_connect(int64_t profile_id, void *user)
{
    rt_tab_manager_t *tm = user;
    rt_profile_t *p = rt_profile_load(profile_id);
    if (p == NULL) {
        return;
    }
    rt_connection_t *conn = rt_profile_to_connection(p);
    if (conn == NULL) {
        rt_profile_free(p);
        return;
    }
    /* Fetch the password from the keyring, if any. */
    char *pw_copy = NULL;
    if (p->credential_id != NULL) {
        rt_secret_t *s = rt_credentials_load(p->credential_id);
        const char *pw = rt_secret_password(s);
        if (pw != NULL) {
            pw_copy = g_strdup(pw);
        }
        rt_secret_free(s);
    }
    if (pw_copy == NULL) {
        pw_copy = g_strdup("");
    }
    rt_profile_free(p);

    /* Open as a fresh tab (no form to replace). */
    start_session(tm, NULL, conn, pw_copy);
}

static void on_dialog_edit(int64_t profile_id, void *user)
{
    rt_tab_manager_t *tm = user;
    rt_profile_t *p = rt_profile_load(profile_id);
    if (p == NULL) {
        return;
    }
    GtkWidget *form = rt_connection_form_new_for_edit(p, on_form_submit, tm);
    rt_profile_free(p);

    gint page = rt_tab_manager_add_tab(tm, RT_EDIT_TAB_TITLE, form);
    gtk_notebook_set_current_page(
        GTK_NOTEBOOK(rt_tab_manager_get_widget(tm)), page);
}

/* ------------------------------------------------------------------ */
/* Fullscreen toggle                                                  */
/* ------------------------------------------------------------------ */

/* Apply the chrome-visible flag to every viewer currently in the
 * notebook. Walks every page and dispatches based on which wrapper
 * type the page widget carries. */
static void apply_chrome_to_all_tabs(rt_tab_manager_t *tm, gboolean visible)
{
    GtkNotebook *nb = GTK_NOTEBOOK(rt_tab_manager_get_widget(tm));
    gint n = gtk_notebook_get_n_pages(nb);
    for (gint i = 0; i < n; i++) {
        GtkWidget *page = gtk_notebook_get_nth_page(nb, i);
        if (page == NULL) continue;
        rt_rdp_view_t *rv = g_object_get_data(G_OBJECT(page), "rt-rdp-view-wrapper");
        if (rv != NULL) {
            rt_rdp_view_set_chrome_visible(rv, visible);
            continue;
        }
        rt_vnc_view_t *vv = g_object_get_data(G_OBJECT(page), "rt-vnc-view-wrapper");
        if (vv != NULL) {
            rt_vnc_view_set_chrome_visible(vv, visible);
            continue;
        }
        rt_terminal_t *t = g_object_get_data(G_OBJECT(page), "rt-terminal-wrapper");
        if (t != NULL) {
            rt_terminal_set_chrome_visible(t, visible);
        }
        /* Form/edit pages don't need chrome toggling. */
    }
}

/* Toggle fullscreen presentation: window goes fullscreen, header bar
 * disappears, notebook hides its tab strip, and every viewer hides
 * its top toolbar. F11 (or the header button when chrome is back)
 * exits. State lives on the window via RT_KEY_FULLSCREEN. */
static void toggle_fullscreen(GtkWindow *win)
{
    if (win == NULL) return;
    rt_tab_manager_t *tm = g_object_get_data(G_OBJECT(win), "rt-tab-manager");
    GtkWidget        *hb = g_object_get_data(G_OBJECT(win), RT_KEY_HEADER_BAR);
    gboolean         *fs = g_object_get_data(G_OBJECT(win), RT_KEY_FULLSCREEN);
    if (tm == NULL || fs == NULL) return;

    *fs = !*fs;

    if (*fs) {
        gtk_window_fullscreen(win);
        if (hb != NULL) gtk_widget_hide(hb);
        gtk_notebook_set_show_tabs(
            GTK_NOTEBOOK(rt_tab_manager_get_widget(tm)), FALSE);
        apply_chrome_to_all_tabs(tm, FALSE);
    } else {
        gtk_window_unfullscreen(win);
        if (hb != NULL) gtk_widget_show(hb);
        gtk_notebook_set_show_tabs(
            GTK_NOTEBOOK(rt_tab_manager_get_widget(tm)), TRUE);
        apply_chrome_to_all_tabs(tm, TRUE);
    }
}

static gboolean on_window_key_press(GtkWidget *w, GdkEventKey *e, gpointer user)
{
    (void)user;
    if (e->keyval == GDK_KEY_F11) {
        toggle_fullscreen(GTK_WINDOW(w));
        return TRUE;
    }
    return FALSE;
}

static void on_fullscreen_clicked(GtkButton *btn, gpointer user_data)
{
    (void)user_data;
    GtkWindow *win = toplevel_window(GTK_WIDGET(btn));
    toggle_fullscreen(win);
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

static void on_saved_clicked(GtkButton *btn, gpointer user_data)
{
    rt_tab_manager_t *tm = user_data;
    GtkWindow *parent = toplevel_window(GTK_WIDGET(btn));
    rt_connection_dialog_show(parent, on_dialog_connect, on_dialog_edit, tm);
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

    /* "Saved" opens the persistent-connections modal. */
    GtkWidget *saved_btn = gtk_button_new_with_label("Saved");
    gtk_widget_set_tooltip_text(saved_btn,
        "Open the list of saved connections");
    g_signal_connect(saved_btn, "clicked",
                     G_CALLBACK(on_saved_clicked), tm);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), saved_btn);

    /* Fullscreen toggle. Hides the tab strip + each viewer's chrome
     * so the remote canvas takes the whole window. F11 also toggles
     * (handled at the window level so it works even when the header
     * bar is hidden). */
    GtkWidget *fs_btn = gtk_button_new_from_icon_name(
        "view-fullscreen-symbolic", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(fs_btn,
        "Toggle fullscreen (F11)");
    g_signal_connect(fs_btn, "clicked",
                     G_CALLBACK(on_fullscreen_clicked), NULL);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), fs_btn);

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

    GtkWidget *header = build_header_bar(tm);
    gtk_window_set_titlebar(GTK_WINDOW(win), header);
    gtk_container_add(GTK_CONTAINER(win), rt_tab_manager_get_widget(tm));

    /* Per-window fullscreen state + a stable handle to the header
     * bar so toggle_fullscreen can show/hide it. */
    gboolean *fs_state = g_new0(gboolean, 1);
    *fs_state = FALSE;
    g_object_set_data_full(G_OBJECT(win), RT_KEY_FULLSCREEN,
                           fs_state, g_free);
    g_object_set_data(G_OBJECT(win), RT_KEY_HEADER_BAR, header);

    /* F11 toggles fullscreen even when the header is hidden. */
    g_signal_connect(win, "key-press-event",
                     G_CALLBACK(on_window_key_press), NULL);

    /* Open one connection tab on launch so the UI isn't empty. */
    GtkWidget *form = rt_connection_form_new(on_form_submit, tm);
    rt_tab_manager_add_tab(tm, RT_NEW_TAB_TITLE, form);

    return win;
}

/*
 * Connection form: protocol / host / port / username / password +
 * an RDP-only options block (domain, screen size, color depth,
 * insecure-cert toggle), and a "Save this profile" block (checkbox +
 * name) that lets the user persist the connection alongside opening
 * it.
 *
 * The form has no idea what "connecting" or "saving" means - it
 * gathers input, decides the user's intent (CONNECT / SAVE_AND_CONNECT
 * / SAVE), and hands it off via the submit callback. main_window
 * wires that intent to the session and storage layers.
 *
 * Two construction paths:
 *   rt_connection_form_new()           -> blank, primary action "Connect"
 *   rt_connection_form_new_for_edit()  -> pre-populated, primary action
 *                                         "Save changes"; saving with an
 *                                         empty password keeps the
 *                                         existing keyring entry.
 *
 * Password handling: the entry buffer is cleared as soon as we've
 * captured a copy. The caller is responsible for wiping the heap copy.
 */

#include "ui/connection_form.h"
#include "core/connection.h"

#include <stdlib.h>
#include <string.h>

#define RT_KEY_PROTO       "rt-proto-combo"
#define RT_KEY_HOST        "rt-host-entry"
#define RT_KEY_PORT        "rt-port-spin"
#define RT_KEY_USER        "rt-user-entry"
#define RT_KEY_PASS        "rt-pass-entry"
#define RT_KEY_STATUS      "rt-status-label"
#define RT_KEY_CB          "rt-submit-cb"

/* RDP block + its fields. */
#define RT_KEY_RDP_BOX        "rt-rdp-box"
#define RT_KEY_RDP_DOMAIN     "rt-rdp-domain"
#define RT_KEY_RDP_WIDTH      "rt-rdp-width"
#define RT_KEY_RDP_HEIGHT     "rt-rdp-height"
#define RT_KEY_RDP_DEPTH      "rt-rdp-depth"
#define RT_KEY_RDP_INSECURE   "rt-rdp-insecure"

/* VNC block + its fields. */
#define RT_KEY_VNC_BOX        "rt-vnc-box"
#define RT_KEY_VNC_VIEWONLY   "rt-vnc-viewonly"
#define RT_KEY_VNC_CLIPBOARD  "rt-vnc-clipboard"
#define RT_KEY_VNC_SCALE      "rt-vnc-scale"

/* WinRM block + its fields. */
#define RT_KEY_WINRM_BOX        "rt-winrm-box"
#define RT_KEY_WINRM_DOMAIN     "rt-winrm-domain"
#define RT_KEY_WINRM_TRANSPORT  "rt-winrm-transport"
#define RT_KEY_WINRM_AUTH       "rt-winrm-auth"
#define RT_KEY_WINRM_INSECURE   "rt-winrm-insecure"
#define RT_KEY_WINRM_SHELLMODE  "rt-winrm-shellmode"

/* Save-profile block. */
#define RT_KEY_SAVE_TOGGLE    "rt-save-toggle"
#define RT_KEY_SAVE_NAME      "rt-save-name"

/* Edit-mode metadata: profile_id (uint64 stashed via g_object_set_data
 * as GINT_TO_POINTER would clip on 32-bit, so we store it as a heap
 * int64_t pointed to by the object data). */
#define RT_KEY_EDIT_PROFILE_ID  "rt-edit-profile-id"

typedef struct {
    rt_connection_form_submit_cb_t cb;
    void                          *user;
} submit_ctx_t;

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static GtkWidget *make_label(const char *text)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_widget_set_halign(l, GTK_ALIGN_END);
    return l;
}

static guint default_port_for(rt_protocol_t p)
{
    switch (p) {
    case RT_PROTOCOL_SSH:   return 22;
    case RT_PROTOCOL_RDP:   return 3389;
    case RT_PROTOCOL_VNC:   return 5900;
    case RT_PROTOCOL_WINRM: return 5985;
    default:                return 0;
    }
}

static int64_t form_get_edit_id(GtkWidget *form)
{
    int64_t *p = g_object_get_data(G_OBJECT(form), RT_KEY_EDIT_PROFILE_ID);
    return (p != NULL) ? *p : 0;
}

static int form_is_edit_mode(GtkWidget *form)
{
    return form_get_edit_id(form) != 0;
}

static void on_proto_changed(GtkComboBox *combo, gpointer user_data)
{
    GtkWidget *form = GTK_WIDGET(user_data);
    GtkSpinButton *port  = g_object_get_data(G_OBJECT(form), RT_KEY_PORT);
    GtkWidget    *rdp    = g_object_get_data(G_OBJECT(form), RT_KEY_RDP_BOX);
    GtkWidget    *vnc    = g_object_get_data(G_OBJECT(form), RT_KEY_VNC_BOX);
    GtkWidget    *winrm  = g_object_get_data(G_OBJECT(form), RT_KEY_WINRM_BOX);

    rt_protocol_t p = rt_protocol_from_string(gtk_combo_box_get_active_id(combo));
    if (!form_is_edit_mode(form)) {
        guint def = default_port_for(p);
        if (def != 0) {
            gtk_spin_button_set_value(port, (gdouble)def);
        }
    }
    if (rdp   != NULL) gtk_widget_set_visible(rdp,   p == RT_PROTOCOL_RDP);
    if (vnc   != NULL) gtk_widget_set_visible(vnc,   p == RT_PROTOCOL_VNC);
    if (winrm != NULL) gtk_widget_set_visible(winrm, p == RT_PROTOCOL_WINRM);
}

/* WinRM transport changed: snap the port to the protocol-standard
 * default for the chosen transport (5985 / 5986). Done only when the
 * port still matches the *other* default, so we don't clobber a port
 * the user explicitly typed. Skipped in edit mode for the same
 * reason. */
static void on_winrm_transport_changed(GtkComboBox *combo, gpointer user_data)
{
    GtkWidget *form = GTK_WIDGET(user_data);
    if (form_is_edit_mode(form)) return;
    GtkSpinButton *port = g_object_get_data(G_OBJECT(form), RT_KEY_PORT);
    if (port == NULL) return;

    rt_winrm_transport_t t =
        rt_winrm_transport_from_string(gtk_combo_box_get_active_id(combo));
    int cur = gtk_spin_button_get_value_as_int(port);
    if (t == RT_WINRM_TRANSPORT_HTTPS && cur == 5985) {
        gtk_spin_button_set_value(port, 5986.0);
    } else if (t == RT_WINRM_TRANSPORT_HTTP && cur == 5986) {
        gtk_spin_button_set_value(port, 5985.0);
    }
}

/* Save-toggle changed: enable/disable the Name entry alongside it. */
static void on_save_toggled(GtkToggleButton *toggle, gpointer user_data)
{
    GtkWidget *name = user_data;
    gtk_widget_set_sensitive(name, gtk_toggle_button_get_active(toggle));
}

/* ------------------------------------------------------------------ */
/* read_form: form widgets -> rt_connection_t                         */
/* ------------------------------------------------------------------ */

static rt_connection_t *read_form(GtkWidget *form)
{
    GtkComboBox   *proto = g_object_get_data(G_OBJECT(form), RT_KEY_PROTO);
    GtkEntry      *host  = g_object_get_data(G_OBJECT(form), RT_KEY_HOST);
    GtkSpinButton *port  = g_object_get_data(G_OBJECT(form), RT_KEY_PORT);
    GtkEntry      *user  = g_object_get_data(G_OBJECT(form), RT_KEY_USER);

    const char *host_text = gtk_entry_get_text(host);
    if (host_text == NULL || host_text[0] == '\0') {
        return NULL;
    }
    /* Reject host strings with embedded whitespace / control chars. */
    for (const char *p = host_text; *p; ++p) {
        if ((unsigned char)*p < 0x20 || *p == ' ') {
            return NULL;
        }
    }

    rt_connection_t *conn = rt_connection_new();
    if (conn == NULL) {
        return NULL;
    }
    conn->protocol = rt_protocol_from_string(gtk_combo_box_get_active_id(proto));
    conn->port     = (unsigned short)gtk_spin_button_get_value_as_int(port);

    if (rt_connection_set_host(conn, host_text) != 0) {
        rt_connection_free(conn);
        return NULL;
    }
    const char *user_text = gtk_entry_get_text(user);
    if (user_text != NULL && user_text[0] != '\0') {
        if (rt_connection_set_username(conn, user_text) != 0) {
            rt_connection_free(conn);
            return NULL;
        }
    }

    if (conn->protocol == RT_PROTOCOL_RDP) {
        rt_rdp_options_t *o = rt_rdp_options_new();
        if (o == NULL) {
            rt_connection_free(conn);
            return NULL;
        }
        GtkEntry      *dom    = g_object_get_data(G_OBJECT(form), RT_KEY_RDP_DOMAIN);
        GtkSpinButton *w_spin = g_object_get_data(G_OBJECT(form), RT_KEY_RDP_WIDTH);
        GtkSpinButton *h_spin = g_object_get_data(G_OBJECT(form), RT_KEY_RDP_HEIGHT);
        GtkComboBox   *depth  = g_object_get_data(G_OBJECT(form), RT_KEY_RDP_DEPTH);
        GtkToggleButton *inse = g_object_get_data(G_OBJECT(form), RT_KEY_RDP_INSECURE);

        const char *dom_text = gtk_entry_get_text(dom);
        if (dom_text != NULL && dom_text[0] != '\0') {
            if (rt_rdp_options_set_domain(o, dom_text) != 0) {
                rt_rdp_options_free(o);
                rt_connection_free(conn);
                return NULL;
            }
        }
        o->width                = gtk_spin_button_get_value_as_int(w_spin);
        o->height               = gtk_spin_button_get_value_as_int(h_spin);
        const char *id          = gtk_combo_box_get_active_id(depth);
        o->color_depth          = (id != NULL) ? atoi(id) : 32;
        o->insecure_cert_bypass = gtk_toggle_button_get_active(inse) ? 1 : 0;
        o->clipboard_enabled    = 1;

        conn->rdp = o;
    }

    if (conn->protocol == RT_PROTOCOL_VNC) {
        rt_vnc_options_t *o = rt_vnc_options_new();
        if (o == NULL) {
            rt_connection_free(conn);
            return NULL;
        }
        GtkToggleButton *vo  = g_object_get_data(G_OBJECT(form), RT_KEY_VNC_VIEWONLY);
        GtkToggleButton *cb  = g_object_get_data(G_OBJECT(form), RT_KEY_VNC_CLIPBOARD);
        GtkComboBox     *sm  = g_object_get_data(G_OBJECT(form), RT_KEY_VNC_SCALE);

        o->view_only         = gtk_toggle_button_get_active(vo) ? 1 : 0;
        o->clipboard_enabled = gtk_toggle_button_get_active(cb) ? 1 : 0;
        const char *sm_id    = gtk_combo_box_get_active_id(sm);
        o->scale_mode_fit    = (sm_id != NULL && strcmp(sm_id, "orig") == 0) ? 0 : 1;
        conn->vnc = o;
    }

    if (conn->protocol == RT_PROTOCOL_WINRM) {
        rt_winrm_options_t *o = rt_winrm_options_new();
        if (o == NULL) {
            rt_connection_free(conn);
            return NULL;
        }
        GtkEntry        *dom  = g_object_get_data(G_OBJECT(form), RT_KEY_WINRM_DOMAIN);
        GtkComboBox     *tr   = g_object_get_data(G_OBJECT(form), RT_KEY_WINRM_TRANSPORT);
        GtkComboBox     *au   = g_object_get_data(G_OBJECT(form), RT_KEY_WINRM_AUTH);
        GtkToggleButton *ins  = g_object_get_data(G_OBJECT(form), RT_KEY_WINRM_INSECURE);
        GtkToggleButton *shm  = g_object_get_data(G_OBJECT(form), RT_KEY_WINRM_SHELLMODE);

        const char *dom_text = gtk_entry_get_text(dom);
        if (dom_text != NULL && dom_text[0] != '\0') {
            if (rt_winrm_options_set_domain(o, dom_text) != 0) {
                rt_winrm_options_free(o);
                rt_connection_free(conn);
                return NULL;
            }
        }
        const char *tr_id = gtk_combo_box_get_active_id(tr);
        const char *au_id = gtk_combo_box_get_active_id(au);
        o->transport              = rt_winrm_transport_from_string(tr_id);
        o->auth_method            = rt_winrm_auth_from_string(au_id);
        o->ignore_cert_validation = gtk_toggle_button_get_active(ins) ? 1 : 0;
        o->shell_mode             = gtk_toggle_button_get_active(shm) ? 1 : 0;
        conn->winrm = o;
    }

    return conn;
}

/* ------------------------------------------------------------------ */
/* Submit                                                             */
/* ------------------------------------------------------------------ */

static void on_submit_clicked(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkWidget *form = GTK_WIDGET(user_data);

    rt_connection_t *conn = read_form(form);
    if (conn == NULL) {
        rt_connection_form_show_error(form,
            "Host is required and must contain no whitespace.");
        return;
    }

    GtkEntry *pass = g_object_get_data(G_OBJECT(form), RT_KEY_PASS);
    const char *pw_text = gtk_entry_get_text(pass);
    char *pw_copy = g_strdup(pw_text != NULL ? pw_text : "");
    gtk_entry_set_text(pass, "");

    /* Decide intent + name. */
    int64_t edit_id = form_get_edit_id(form);
    GtkToggleButton *save_toggle =
        g_object_get_data(G_OBJECT(form), RT_KEY_SAVE_TOGGLE);
    GtkEntry        *save_name_entry =
        g_object_get_data(G_OBJECT(form), RT_KEY_SAVE_NAME);

    rt_form_intent_t intent;
    const char      *save_name = NULL;

    if (edit_id != 0) {
        intent    = RT_FORM_INTENT_SAVE;
        save_name = (save_name_entry != NULL)
                    ? gtk_entry_get_text(save_name_entry) : NULL;
        if (save_name == NULL || save_name[0] == '\0') {
            if (pw_copy != NULL) {
                memset(pw_copy, 0, strlen(pw_copy));
                g_free(pw_copy);
            }
            rt_connection_free(conn);
            rt_connection_form_show_error(form, "Name is required.");
            return;
        }
    } else if (save_toggle != NULL &&
               gtk_toggle_button_get_active(save_toggle)) {
        intent    = RT_FORM_INTENT_SAVE_AND_CONNECT;
        save_name = (save_name_entry != NULL)
                    ? gtk_entry_get_text(save_name_entry) : NULL;
        if (save_name == NULL || save_name[0] == '\0') {
            if (pw_copy != NULL) {
                memset(pw_copy, 0, strlen(pw_copy));
                g_free(pw_copy);
            }
            rt_connection_free(conn);
            rt_connection_form_show_error(form,
                "A name is required to save this profile.");
            return;
        }
    } else {
        intent = RT_FORM_INTENT_CONNECT;
    }

    submit_ctx_t *ctx = g_object_get_data(G_OBJECT(form), RT_KEY_CB);
    if (ctx == NULL || ctx->cb == NULL) {
        if (pw_copy != NULL) {
            memset(pw_copy, 0, strlen(pw_copy));
            g_free(pw_copy);
        }
        rt_connection_free(conn);
        rt_connection_form_show_error(form, "Internal error: no submit handler.");
        return;
    }
    ctx->cb(form, intent, edit_id, save_name, conn, pw_copy, ctx->user);
}

/* ------------------------------------------------------------------ */
/* RDP options block                                                  */
/* ------------------------------------------------------------------ */

static GtkWidget *build_rdp_block(GtkWidget *form)
{
    GtkWidget *frame = gtk_frame_new("RDP Options");
    GtkWidget *grid  = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_widget_set_margin_top   (grid, 10);
    gtk_widget_set_margin_bottom(grid, 10);
    gtk_widget_set_margin_start (grid, 12);
    gtk_widget_set_margin_end   (grid, 12);
    gtk_container_add(GTK_CONTAINER(frame), grid);

    GtkWidget *domain = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(domain), "domain or workgroup (optional)");
    gtk_entry_set_max_length(GTK_ENTRY(domain), 128);
    gtk_widget_set_hexpand(domain, TRUE);
    gtk_grid_attach(GTK_GRID(grid), make_label("Domain:"), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), domain,                  1, 0, 3, 1);

    GtkWidget *width  = gtk_spin_button_new_with_range(640,  7680, 1);
    GtkWidget *height = gtk_spin_button_new_with_range(480,  4320, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(width),  1024);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(height), 768);
    gtk_grid_attach(GTK_GRID(grid), make_label("Width:"),  0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), width,                  1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_label("Height:"), 2, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), height,                 3, 1, 1, 1);

    GtkWidget *depth = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(depth), "16", "16 bpp");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(depth), "24", "24 bpp");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(depth), "32", "32 bpp");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(depth), "32");
    gtk_grid_attach(GTK_GRID(grid), make_label("Color depth:"), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), depth,                       1, 2, 1, 1);

    GtkWidget *insecure = gtk_check_button_new_with_label(
        "Ignore certificate validation (INSECURE - lab use only)");
    gtk_grid_attach(GTK_GRID(grid), insecure, 0, 3, 4, 1);

    g_object_set_data(G_OBJECT(form), RT_KEY_RDP_DOMAIN,   domain);
    g_object_set_data(G_OBJECT(form), RT_KEY_RDP_WIDTH,    width);
    g_object_set_data(G_OBJECT(form), RT_KEY_RDP_HEIGHT,   height);
    g_object_set_data(G_OBJECT(form), RT_KEY_RDP_DEPTH,    depth);
    g_object_set_data(G_OBJECT(form), RT_KEY_RDP_INSECURE, insecure);

    return frame;
}

/* ------------------------------------------------------------------ */
/* VNC options block                                                  */
/* ------------------------------------------------------------------ */

static GtkWidget *build_vnc_block(GtkWidget *form)
{
    GtkWidget *frame = gtk_frame_new("VNC Options");
    GtkWidget *grid  = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_widget_set_margin_top   (grid, 10);
    gtk_widget_set_margin_bottom(grid, 10);
    gtk_widget_set_margin_start (grid, 12);
    gtk_widget_set_margin_end   (grid, 12);
    gtk_container_add(GTK_CONTAINER(frame), grid);

    GtkWidget *view_only = gtk_check_button_new_with_label(
        "View only (suppress all keyboard / mouse forwarding)");
    gtk_grid_attach(GTK_GRID(grid), view_only, 0, 0, 2, 1);

    GtkWidget *clipboard = gtk_check_button_new_with_label(
        "Sync clipboard text (RFB cut-text)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(clipboard), TRUE);
    gtk_grid_attach(GTK_GRID(grid), clipboard, 0, 1, 2, 1);

    GtkWidget *scale = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(scale), "fit",  "Scale to fit");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(scale), "orig", "Original size");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(scale), "fit");
    gtk_grid_attach(GTK_GRID(grid), make_label("Scaling:"), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), scale,                   1, 2, 1, 1);

    g_object_set_data(G_OBJECT(form), RT_KEY_VNC_VIEWONLY,  view_only);
    g_object_set_data(G_OBJECT(form), RT_KEY_VNC_CLIPBOARD, clipboard);
    g_object_set_data(G_OBJECT(form), RT_KEY_VNC_SCALE,     scale);
    return frame;
}

/* ------------------------------------------------------------------ */
/* WinRM options block                                                */
/* ------------------------------------------------------------------ */

static GtkWidget *build_winrm_block(GtkWidget *form)
{
    GtkWidget *frame = gtk_frame_new("WinRM Options");
    GtkWidget *grid  = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_widget_set_margin_top   (grid, 10);
    gtk_widget_set_margin_bottom(grid, 10);
    gtk_widget_set_margin_start (grid, 12);
    gtk_widget_set_margin_end   (grid, 12);
    gtk_container_add(GTK_CONTAINER(frame), grid);

    GtkWidget *domain = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(domain),
                                   "domain (optional, e.g. CONTOSO)");
    gtk_entry_set_max_length(GTK_ENTRY(domain), 128);
    gtk_widget_set_hexpand(domain, TRUE);
    gtk_grid_attach(GTK_GRID(grid), make_label("Domain:"), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), domain,                 1, 0, 3, 1);

    GtkWidget *transport = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(transport),
                              "http",  "HTTP (5985)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(transport),
                              "https", "HTTPS (5986)");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(transport), "http");
    gtk_grid_attach(GTK_GRID(grid), make_label("Transport:"), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), transport,                  1, 1, 1, 1);

    GtkWidget *auth = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(auth), "basic", "Basic");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(auth), "ntlm",
                              "NTLM (requires libcurl NTLM support)");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(auth), "basic");
    gtk_grid_attach(GTK_GRID(grid), make_label("Auth:"), 2, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), auth,                  3, 1, 1, 1);

    GtkWidget *insecure = gtk_check_button_new_with_label(
        "Ignore certificate validation (HTTPS, INSECURE - lab use only)");
    gtk_grid_attach(GTK_GRID(grid), insecure, 0, 2, 4, 1);

    GtkWidget *shellmode = gtk_check_button_new_with_label(
        "Persistent shell (state preserved across commands)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(shellmode), TRUE);
    gtk_grid_attach(GTK_GRID(grid), shellmode, 0, 3, 4, 1);

    g_object_set_data(G_OBJECT(form), RT_KEY_WINRM_DOMAIN,    domain);
    g_object_set_data(G_OBJECT(form), RT_KEY_WINRM_TRANSPORT, transport);
    g_object_set_data(G_OBJECT(form), RT_KEY_WINRM_AUTH,      auth);
    g_object_set_data(G_OBJECT(form), RT_KEY_WINRM_INSECURE,  insecure);
    g_object_set_data(G_OBJECT(form), RT_KEY_WINRM_SHELLMODE, shellmode);

    g_signal_connect(transport, "changed",
                     G_CALLBACK(on_winrm_transport_changed), form);

    return frame;
}

/* ------------------------------------------------------------------ */
/* Save-profile block                                                 */
/* ------------------------------------------------------------------ */

/* Returns the GtkWidget* container; stashes the toggle + name entry
 * on the form via the RT_KEY_SAVE_* keys. */
static GtkWidget *build_save_block(GtkWidget *form, gboolean for_edit)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

    GtkWidget *toggle = gtk_check_button_new_with_label("Save this profile");
    GtkWidget *name   = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(name), "profile name (e.g. work-jumpbox)");
    gtk_entry_set_max_length(GTK_ENTRY(name), 128);
    gtk_widget_set_hexpand(name, TRUE);

    if (for_edit) {
        /* In edit mode there's no toggle - the form IS a save form.
         * Hide the toggle widget but keep the name entry visible.
         * Pre-mark the toggle "active" so the submit code reads the
         * name unconditionally (not strictly needed since edit mode
         * goes through a different intent path, but defensive). */
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(toggle), TRUE);
        gtk_widget_set_no_show_all(toggle, TRUE);
        gtk_widget_hide(toggle);
        gtk_widget_set_sensitive(name, TRUE);
    } else {
        gtk_widget_set_sensitive(name, FALSE);
        g_signal_connect(toggle, "toggled",
                         G_CALLBACK(on_save_toggled), name);
    }

    gtk_box_pack_start(GTK_BOX(box), toggle, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), name,   TRUE,  TRUE,  0);

    g_object_set_data(G_OBJECT(form), RT_KEY_SAVE_TOGGLE, toggle);
    g_object_set_data(G_OBJECT(form), RT_KEY_SAVE_NAME,   name);
    return box;
}

/* ------------------------------------------------------------------ */
/* Form construction (shared)                                          */
/* ------------------------------------------------------------------ */

static GtkWidget *form_build(rt_connection_form_submit_cb_t cb,
                             void                          *user,
                             const rt_profile_t            *edit_profile)
{
    int for_edit = (edit_profile != NULL) ? 1 : 0;

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 14);
    gtk_widget_set_margin_top   (grid, 32);
    gtk_widget_set_margin_bottom(grid, 32);
    gtk_widget_set_margin_start (grid, 32);
    gtk_widget_set_margin_end   (grid, 32);
    gtk_widget_set_halign(grid, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(grid, GTK_ALIGN_START);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
        for_edit
        ? "<span size='x-large' weight='bold'>Edit Connection</span>"
        : "<span size='x-large' weight='bold'>New Connection</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), title, 0, 0, 2, 1);

    GtkWidget *proto = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(proto), "ssh",   "SSH");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(proto), "rdp",   "RDP");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(proto), "vnc",   "VNC");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(proto), "winrm", "WinRM");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(proto), "ssh");
    gtk_grid_attach(GTK_GRID(grid), make_label("Protocol:"), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), proto,                    1, 1, 1, 1);

    GtkWidget *host = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(host), "host or ip");
    gtk_entry_set_max_length(GTK_ENTRY(host), 253);
    gtk_widget_set_hexpand(host, TRUE);
    gtk_grid_attach(GTK_GRID(grid), make_label("Host:"), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), host,                 1, 2, 1, 1);

    GtkWidget *port = gtk_spin_button_new_with_range(1, 65535, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(port),
                              (gdouble)default_port_for(RT_PROTOCOL_SSH));
    gtk_grid_attach(GTK_GRID(grid), make_label("Port:"), 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), port,                 1, 3, 1, 1);

    GtkWidget *username = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(username), "username");
    gtk_entry_set_max_length(GTK_ENTRY(username), 64);
    gtk_grid_attach(GTK_GRID(grid), make_label("Username:"), 0, 4, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), username,                 1, 4, 1, 1);

    GtkWidget *password = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(password),
                                   for_edit
                                   ? "password (blank = keep existing)"
                                   : "password");
    gtk_entry_set_visibility(GTK_ENTRY(password), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(password), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_max_length(GTK_ENTRY(password), 1024);
    gtk_grid_attach(GTK_GRID(grid), make_label("Password:"), 0, 5, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), password,                 1, 5, 1, 1);

    GtkWidget *rdp_block = build_rdp_block(grid);
    gtk_grid_attach(GTK_GRID(grid), rdp_block, 0, 6, 2, 1);

    GtkWidget *vnc_block = build_vnc_block(grid);
    gtk_grid_attach(GTK_GRID(grid), vnc_block, 0, 7, 2, 1);

    GtkWidget *winrm_block = build_winrm_block(grid);
    gtk_grid_attach(GTK_GRID(grid), winrm_block, 0, 8, 2, 1);

    GtkWidget *save_block = build_save_block(grid, for_edit);
    gtk_grid_attach(GTK_GRID(grid), save_block, 0, 9, 2, 1);

    GtkWidget *submit_btn = gtk_button_new_with_label(
        for_edit ? "Save changes" : "Connect");
    gtk_widget_set_halign(submit_btn, GTK_ALIGN_END);
    gtk_style_context_add_class(gtk_widget_get_style_context(submit_btn),
                                "suggested-action");
    gtk_grid_attach(GTK_GRID(grid), submit_btn, 1, 10, 1, 1);

    GtkWidget *status = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(status), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(status), TRUE);
    gtk_grid_attach(GTK_GRID(grid), status, 0, 11, 2, 1);

    /* Stash widget pointers and the submit ctx. ctx is heap-allocated
     * so it survives the constructor return; freed when the grid is
     * destroyed. */
    submit_ctx_t *ctx = g_new0(submit_ctx_t, 1);
    ctx->cb   = cb;
    ctx->user = user;

    g_object_set_data     (G_OBJECT(grid), RT_KEY_PROTO,   proto);
    g_object_set_data     (G_OBJECT(grid), RT_KEY_HOST,    host);
    g_object_set_data     (G_OBJECT(grid), RT_KEY_PORT,    port);
    g_object_set_data     (G_OBJECT(grid), RT_KEY_USER,    username);
    g_object_set_data     (G_OBJECT(grid), RT_KEY_PASS,    password);
    g_object_set_data     (G_OBJECT(grid), RT_KEY_STATUS,  status);
    g_object_set_data     (G_OBJECT(grid), RT_KEY_RDP_BOX,   rdp_block);
    g_object_set_data     (G_OBJECT(grid), RT_KEY_VNC_BOX,   vnc_block);
    g_object_set_data     (G_OBJECT(grid), RT_KEY_WINRM_BOX, winrm_block);
    g_object_set_data_full(G_OBJECT(grid), RT_KEY_CB,
                           ctx, (GDestroyNotify)g_free);

    g_signal_connect(proto,      "changed",
                     G_CALLBACK(on_proto_changed), grid);
    g_signal_connect(submit_btn, "clicked",
                     G_CALLBACK(on_submit_clicked), grid);
    g_signal_connect(password,   "activate",
                     G_CALLBACK(on_submit_clicked), grid);

    /* Hide all protocol-specific blocks initially. See earlier-phase
     * comment about no_show_all + show_all ordering. */
    gtk_widget_show_all(rdp_block);
    gtk_widget_set_no_show_all(rdp_block, TRUE);
    gtk_widget_hide(rdp_block);
    gtk_widget_show_all(vnc_block);
    gtk_widget_set_no_show_all(vnc_block, TRUE);
    gtk_widget_hide(vnc_block);
    gtk_widget_show_all(winrm_block);
    gtk_widget_set_no_show_all(winrm_block, TRUE);
    gtk_widget_hide(winrm_block);

    /* If we're editing, populate every field from the profile and
     * stash the id so submit knows it's an UPDATE. */
    if (for_edit) {
        int64_t *id_box = g_new0(int64_t, 1);
        *id_box = edit_profile->id;
        g_object_set_data_full(G_OBJECT(grid), RT_KEY_EDIT_PROFILE_ID,
                               id_box, g_free);

        gtk_combo_box_set_active_id(
            GTK_COMBO_BOX(proto),
            rt_protocol_to_string(edit_profile->protocol));
        gtk_entry_set_text(GTK_ENTRY(host), edit_profile->host ? edit_profile->host : "");
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(port),
                                  (gdouble)edit_profile->port);
        if (edit_profile->username != NULL) {
            gtk_entry_set_text(GTK_ENTRY(username), edit_profile->username);
        }
        if (edit_profile->name != NULL) {
            gtk_entry_set_text(
                GTK_ENTRY(g_object_get_data(G_OBJECT(grid), RT_KEY_SAVE_NAME)),
                edit_profile->name);
        }
        if (edit_profile->rdp != NULL) {
            GtkEntry        *dom = g_object_get_data(G_OBJECT(grid), RT_KEY_RDP_DOMAIN);
            GtkSpinButton   *w   = g_object_get_data(G_OBJECT(grid), RT_KEY_RDP_WIDTH);
            GtkSpinButton   *h   = g_object_get_data(G_OBJECT(grid), RT_KEY_RDP_HEIGHT);
            GtkComboBox     *d   = g_object_get_data(G_OBJECT(grid), RT_KEY_RDP_DEPTH);
            GtkToggleButton *ins = g_object_get_data(G_OBJECT(grid), RT_KEY_RDP_INSECURE);

            if (edit_profile->rdp->domain != NULL) {
                gtk_entry_set_text(dom, edit_profile->rdp->domain);
            }
            gtk_spin_button_set_value(w, (gdouble)edit_profile->rdp->width);
            gtk_spin_button_set_value(h, (gdouble)edit_profile->rdp->height);
            char buf[8];
            snprintf(buf, sizeof(buf), "%d", edit_profile->rdp->color_depth);
            gtk_combo_box_set_active_id(d, buf);
            gtk_toggle_button_set_active(ins,
                edit_profile->rdp->insecure_cert_bypass ? TRUE : FALSE);
        }
        if (edit_profile->vnc != NULL) {
            GtkToggleButton *vo   = g_object_get_data(G_OBJECT(grid), RT_KEY_VNC_VIEWONLY);
            GtkToggleButton *clip = g_object_get_data(G_OBJECT(grid), RT_KEY_VNC_CLIPBOARD);
            GtkComboBox     *sm   = g_object_get_data(G_OBJECT(grid), RT_KEY_VNC_SCALE);
            gtk_toggle_button_set_active(vo,
                edit_profile->vnc->view_only ? TRUE : FALSE);
            gtk_toggle_button_set_active(clip,
                edit_profile->vnc->clipboard_enabled ? TRUE : FALSE);
            gtk_combo_box_set_active_id(sm,
                edit_profile->vnc->scale_mode_fit ? "fit" : "orig");
        }
        if (edit_profile->winrm != NULL) {
            GtkEntry        *dom = g_object_get_data(G_OBJECT(grid), RT_KEY_WINRM_DOMAIN);
            GtkComboBox     *tr  = g_object_get_data(G_OBJECT(grid), RT_KEY_WINRM_TRANSPORT);
            GtkComboBox     *au  = g_object_get_data(G_OBJECT(grid), RT_KEY_WINRM_AUTH);
            GtkToggleButton *ins = g_object_get_data(G_OBJECT(grid), RT_KEY_WINRM_INSECURE);
            GtkToggleButton *shm = g_object_get_data(G_OBJECT(grid), RT_KEY_WINRM_SHELLMODE);
            if (edit_profile->winrm->domain != NULL) {
                gtk_entry_set_text(dom, edit_profile->winrm->domain);
            }
            gtk_combo_box_set_active_id(tr,
                rt_winrm_transport_to_string(edit_profile->winrm->transport));
            gtk_combo_box_set_active_id(au,
                rt_winrm_auth_to_string(edit_profile->winrm->auth_method));
            gtk_toggle_button_set_active(ins,
                edit_profile->winrm->ignore_cert_validation ? TRUE : FALSE);
            gtk_toggle_button_set_active(shm,
                edit_profile->winrm->shell_mode ? TRUE : FALSE);
        }
    }

    return grid;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

GtkWidget *rt_connection_form_new(rt_connection_form_submit_cb_t cb,
                                  void                          *user)
{
    return form_build(cb, user, NULL);
}

GtkWidget *rt_connection_form_new_for_edit(const rt_profile_t            *p,
                                           rt_connection_form_submit_cb_t cb,
                                           void                          *user)
{
    return form_build(cb, user, p);
}

void rt_connection_form_show_error(GtkWidget *form, const char *msg)
{
    if (form == NULL) {
        return;
    }
    GtkWidget *status = g_object_get_data(G_OBJECT(form), RT_KEY_STATUS);
    if (status == NULL) {
        return;
    }
    char *escaped = g_markup_escape_text(msg ? msg : "", -1);
    char *markup  = g_strdup_printf(
        "<span foreground='#c00'>%s</span>", escaped);
    gtk_label_set_markup(GTK_LABEL(status), markup);
    g_free(markup);
    g_free(escaped);
}

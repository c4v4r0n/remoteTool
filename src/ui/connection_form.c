/*
 * Connection form: protocol / host / port / username / password +
 * Connect, plus an RDP-only options block (domain, screen size,
 * color depth, insecure-cert toggle) that appears when "RDP" is
 * picked from the protocol combo. The form has no idea what
 * "connecting" means - it just gathers input and hands it off via
 * the user-supplied submit callback. main_window owns that callback
 * and wires it to the session layer.
 *
 * Password handling: the entry buffer is cleared as soon as we've
 * captured a copy. The caller (the submit callback) is responsible
 * for wiping the heap copy after use.
 */

#include "ui/connection_form.h"
#include "core/connection.h"

#include <stdlib.h>
#include <string.h>

#define RT_KEY_PROTO    "rt-proto-combo"
#define RT_KEY_HOST     "rt-host-entry"
#define RT_KEY_PORT     "rt-port-spin"
#define RT_KEY_USER     "rt-user-entry"
#define RT_KEY_PASS     "rt-pass-entry"
#define RT_KEY_STATUS   "rt-status-label"
#define RT_KEY_CB       "rt-submit-cb"
#define RT_KEY_CB_USER  "rt-submit-user"

/* RDP block + its fields. */
#define RT_KEY_RDP_BOX        "rt-rdp-box"
#define RT_KEY_RDP_DOMAIN     "rt-rdp-domain"
#define RT_KEY_RDP_WIDTH      "rt-rdp-width"
#define RT_KEY_RDP_HEIGHT     "rt-rdp-height"
#define RT_KEY_RDP_DEPTH      "rt-rdp-depth"
#define RT_KEY_RDP_INSECURE   "rt-rdp-insecure"

typedef struct {
    rt_connection_form_submit_cb_t cb;
    void                          *user;
} submit_ctx_t;

/* ---- helpers ---- */

static GtkWidget *make_label(const char *text)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_widget_set_halign(l, GTK_ALIGN_END);
    return l;
}

static guint default_port_for(rt_protocol_t p)
{
    switch (p) {
    case RT_PROTOCOL_SSH: return 22;
    case RT_PROTOCOL_RDP: return 3389;
    case RT_PROTOCOL_VNC: return 5900;
    default:              return 0;
    }
}

static void on_proto_changed(GtkComboBox *combo, gpointer user_data)
{
    GtkWidget *form = GTK_WIDGET(user_data);
    GtkSpinButton *port = g_object_get_data(G_OBJECT(form), RT_KEY_PORT);
    GtkWidget    *rdp  = g_object_get_data(G_OBJECT(form), RT_KEY_RDP_BOX);

    rt_protocol_t p = rt_protocol_from_string(gtk_combo_box_get_active_id(combo));
    guint def = default_port_for(p);
    if (def != 0) {
        gtk_spin_button_set_value(port, (gdouble)def);
    }
    /* Reveal the RDP options block only for RDP. The block has its
     * children pre-marked visible (see end of rt_connection_form_new)
     * so a plain show/hide on the frame is enough. */
    if (rdp != NULL) {
        gtk_widget_set_visible(rdp, p == RT_PROTOCOL_RDP);
    }
}

/* Build an rt_connection_t from the current form state. NULL on
 * empty/invalid host. */
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

    /* RDP options - only collected when RDP is the active protocol. */
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
        o->clipboard_enabled    = 1;  /* always on for now */

        conn->rdp = o;
    }

    return conn;
}

/* ---- signal handlers ---- */

static void on_connect_clicked(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    GtkWidget *form = GTK_WIDGET(user_data);

    rt_connection_t *conn = read_form(form);
    if (conn == NULL) {
        rt_connection_form_show_error(form,
            "Host is required and must contain no whitespace.");
        return;
    }

    /* Capture password and immediately overwrite the entry. */
    GtkEntry *pass = g_object_get_data(G_OBJECT(form), RT_KEY_PASS);
    const char *pw_text = gtk_entry_get_text(pass);
    char *pw_copy = g_strdup(pw_text != NULL ? pw_text : "");
    gtk_entry_set_text(pass, "");

    submit_ctx_t *ctx = g_object_get_data(G_OBJECT(form), RT_KEY_CB);
    if (ctx == NULL || ctx->cb == NULL) {
        /* No handler - clean up to avoid leaking. */
        if (pw_copy != NULL) {
            memset(pw_copy, 0, strlen(pw_copy));
            g_free(pw_copy);
        }
        rt_connection_free(conn);
        rt_connection_form_show_error(form, "Internal error: no submit handler.");
        return;
    }
    ctx->cb(form, conn, pw_copy, ctx->user);
}

/* ---- RDP options block builder ---- */

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

    /* Domain */
    GtkWidget *domain = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(domain), "domain or workgroup (optional)");
    gtk_entry_set_max_length(GTK_ENTRY(domain), 128);
    gtk_widget_set_hexpand(domain, TRUE);
    gtk_grid_attach(GTK_GRID(grid), make_label("Domain:"), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), domain,                  1, 0, 3, 1);

    /* Width / Height */
    GtkWidget *width  = gtk_spin_button_new_with_range(640,  7680, 1);
    GtkWidget *height = gtk_spin_button_new_with_range(480,  4320, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(width),  1024);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(height), 768);
    gtk_grid_attach(GTK_GRID(grid), make_label("Width:"),  0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), width,                  1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), make_label("Height:"), 2, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), height,                 3, 1, 1, 1);

    /* Color depth */
    GtkWidget *depth = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(depth), "16", "16 bpp");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(depth), "24", "24 bpp");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(depth), "32", "32 bpp");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(depth), "32");
    gtk_grid_attach(GTK_GRID(grid), make_label("Color depth:"), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), depth,                       1, 2, 1, 1);

    /* Insecure cert bypass (lab use only) */
    GtkWidget *insecure = gtk_check_button_new_with_label(
        "Ignore certificate validation (INSECURE - lab use only)");
    gtk_grid_attach(GTK_GRID(grid), insecure, 0, 3, 4, 1);

    /* Stash widget pointers on the form. */
    g_object_set_data(G_OBJECT(form), RT_KEY_RDP_DOMAIN,   domain);
    g_object_set_data(G_OBJECT(form), RT_KEY_RDP_WIDTH,    width);
    g_object_set_data(G_OBJECT(form), RT_KEY_RDP_HEIGHT,   height);
    g_object_set_data(G_OBJECT(form), RT_KEY_RDP_DEPTH,    depth);
    g_object_set_data(G_OBJECT(form), RT_KEY_RDP_INSECURE, insecure);

    return frame;
}

/* ---- public API ---- */

GtkWidget *rt_connection_form_new(rt_connection_form_submit_cb_t cb,
                                  void                          *user)
{
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
        "<span size='x-large' weight='bold'>New Connection</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), title, 0, 0, 2, 1);

    GtkWidget *proto = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(proto), "ssh", "SSH");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(proto), "rdp", "RDP");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(proto), "vnc", "VNC (TODO)");
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
    gtk_entry_set_placeholder_text(GTK_ENTRY(password), "password");
    gtk_entry_set_visibility(GTK_ENTRY(password), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(password), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_max_length(GTK_ENTRY(password), 1024);
    gtk_grid_attach(GTK_GRID(grid), make_label("Password:"), 0, 5, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), password,                 1, 5, 1, 1);

    /* RDP options block (hidden unless RDP is the active protocol). */
    GtkWidget *rdp_block = build_rdp_block(grid);
    gtk_grid_attach(GTK_GRID(grid), rdp_block, 0, 6, 2, 1);

    GtkWidget *connect_btn = gtk_button_new_with_label("Connect");
    gtk_widget_set_halign(connect_btn, GTK_ALIGN_END);
    gtk_style_context_add_class(gtk_widget_get_style_context(connect_btn),
                                "suggested-action");
    gtk_grid_attach(GTK_GRID(grid), connect_btn, 1, 7, 1, 1);

    GtkWidget *status = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(status), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(status), TRUE);
    gtk_grid_attach(GTK_GRID(grid), status, 0, 8, 2, 1);

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
    g_object_set_data     (G_OBJECT(grid), RT_KEY_RDP_BOX, rdp_block);
    g_object_set_data_full(G_OBJECT(grid), RT_KEY_CB,
                           ctx, (GDestroyNotify)g_free);

    g_signal_connect(proto,       "changed",
                     G_CALLBACK(on_proto_changed), grid);
    g_signal_connect(connect_btn, "clicked",
                     G_CALLBACK(on_connect_clicked), grid);
    /* Pressing Enter in the password field also submits. */
    g_signal_connect(password,    "activate",
                     G_CALLBACK(on_connect_clicked), grid);

    /* Hide the RDP block initially (default protocol is SSH).
     *
     * GTK quirk: gtk_widget_set_no_show_all on the frame would also
     * block its descendants from being marked visible, so even
     * gtk_widget_show(frame) later would render an empty frame.
     * Workaround: explicitly show_all the frame first (marks all
     * children visible), THEN set no_show_all on the frame so the
     * outer show_all doesn't undo our hide, THEN hide the frame.
     * Toggling visibility on the frame from on_proto_changed now
     * brings the (already-visible-marked) children along for free. */
    gtk_widget_show_all(rdp_block);
    gtk_widget_set_no_show_all(rdp_block, TRUE);
    gtk_widget_hide(rdp_block);

    return grid;
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

/*
 * "Saved Connections" modal dialog.
 *
 * Layout:
 *   GtkDialog (modal, transient_for parent)
 *   ├── GtkScrolledWindow
 *   │   └── GtkTreeView (Name / Protocol / Host:Port / User)
 *   └── action area: [Connect] [Edit] [Delete] [Close]
 *
 * Model is a GtkListStore reloaded from rt_profile_list() each time
 * the dialog opens or after a Delete. The first column is a hidden
 * int64 holding the profile id; visible columns are derived strings.
 */

#include "ui/connection_dialog.h"
#include "storage/profile.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

enum {
    COL_ID = 0,    /* int64, hidden */
    COL_NAME,      /* string */
    COL_PROTO,     /* string, uppercase */
    COL_HOST_PORT, /* string */
    COL_USER,      /* string */
    N_COLS
};

typedef struct {
    GtkWidget                          *dialog;
    GtkWidget                          *view;
    GtkListStore                       *store;
    rt_connection_dialog_connect_cb_t   on_connect;
    rt_connection_dialog_edit_cb_t      on_edit;
    void                               *user;
} dialog_ctx_t;

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/* Returns the selected profile id, or 0 if no row is selected. */
static int64_t get_selected_id(dialog_ctx_t *ctx)
{
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(ctx->view));
    GtkTreeModel     *model;
    GtkTreeIter       iter;
    if (!gtk_tree_selection_get_selected(sel, &model, &iter)) {
        return 0;
    }
    int64_t id = 0;
    gtk_tree_model_get(model, &iter, COL_ID, &id, -1);
    return id;
}

static void reload_store(dialog_ctx_t *ctx)
{
    gtk_list_store_clear(ctx->store);

    rt_profile_t **arr = NULL;
    size_t         n   = 0;
    if (rt_profile_list(&arr, &n) != 0) {
        return;
    }

    for (size_t i = 0; i < n; i++) {
        rt_profile_t *p = arr[i];
        char hp[160];
        snprintf(hp, sizeof(hp), "%s:%u",
                 p->host ? p->host : "?", (unsigned)p->port);

        const char *proto = rt_protocol_to_string(p->protocol);
        char protoU[16];
        size_t k = 0;
        for (; proto[k] != '\0' && k + 1 < sizeof(protoU); k++) {
            protoU[k] = (char)((proto[k] >= 'a' && proto[k] <= 'z')
                               ? proto[k] - 32 : proto[k]);
        }
        protoU[k] = '\0';

        GtkTreeIter iter;
        gtk_list_store_append(ctx->store, &iter);
        gtk_list_store_set(ctx->store, &iter,
                           COL_ID,        (gint64)p->id,
                           COL_NAME,      p->name ? p->name : "",
                           COL_PROTO,     protoU,
                           COL_HOST_PORT, hp,
                           COL_USER,      p->username ? p->username : "",
                           -1);
    }
    rt_profile_list_free(arr, n);
}

/* ------------------------------------------------------------------ */
/* Button handlers                                                    */
/* ------------------------------------------------------------------ */

static void do_connect(dialog_ctx_t *ctx)
{
    int64_t id = get_selected_id(ctx);
    if (id == 0) return;
    rt_connection_dialog_connect_cb_t cb = ctx->on_connect;
    void *user = ctx->user;
    /* Tear down the dialog before invoking the callback - the caller
     * will spawn a new tab and we want the modal out of the way. */
    gtk_widget_destroy(ctx->dialog);
    if (cb != NULL) cb(id, user);
}

static void do_edit(dialog_ctx_t *ctx)
{
    int64_t id = get_selected_id(ctx);
    if (id == 0) return;
    rt_connection_dialog_edit_cb_t cb = ctx->on_edit;
    void *user = ctx->user;
    gtk_widget_destroy(ctx->dialog);
    if (cb != NULL) cb(id, user);
}

static void do_delete(dialog_ctx_t *ctx)
{
    int64_t id = get_selected_id(ctx);
    if (id == 0) return;

    GtkWidget *confirm = gtk_message_dialog_new(
        GTK_WINDOW(ctx->dialog),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_OK_CANCEL,
        "Delete this saved connection?\n"
        "Stored credentials will also be removed from the keyring.");
    gint resp = gtk_dialog_run(GTK_DIALOG(confirm));
    gtk_widget_destroy(confirm);
    if (resp != GTK_RESPONSE_OK) {
        return;
    }
    rt_profile_delete(id);
    reload_store(ctx);
}

/* ------------------------------------------------------------------ */
/* Signals                                                            */
/* ------------------------------------------------------------------ */

static void on_connect_clicked(GtkButton *b, gpointer user) { (void)b; do_connect((dialog_ctx_t *)user); }
static void on_edit_clicked   (GtkButton *b, gpointer user) { (void)b; do_edit   ((dialog_ctx_t *)user); }
static void on_delete_clicked (GtkButton *b, gpointer user) { (void)b; do_delete ((dialog_ctx_t *)user); }
static void on_close_clicked  (GtkButton *b, gpointer user)
{
    (void)b;
    dialog_ctx_t *ctx = user;
    gtk_widget_destroy(ctx->dialog);
}

static void on_row_activated(GtkTreeView       *view,
                             GtkTreePath       *path,
                             GtkTreeViewColumn *col,
                             gpointer           user)
{
    (void)view; (void)path; (void)col;
    do_connect((dialog_ctx_t *)user);
}

/* Free the heap-allocated context when the dialog is destroyed. */
static void on_dialog_destroy(GtkWidget *w, gpointer user)
{
    (void)w;
    g_free(user);
}

/* ------------------------------------------------------------------ */
/* Construction                                                       */
/* ------------------------------------------------------------------ */

static void add_text_column(GtkTreeView *view, const char *title, int col_idx)
{
    GtkCellRenderer   *cell = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *col  = gtk_tree_view_column_new_with_attributes(
        title, cell, "text", col_idx, NULL);
    gtk_tree_view_column_set_resizable(col, TRUE);
    gtk_tree_view_append_column(view, col);
}

void rt_connection_dialog_show(GtkWindow                         *parent,
                               rt_connection_dialog_connect_cb_t  on_connect,
                               rt_connection_dialog_edit_cb_t     on_edit,
                               void                              *user)
{
    dialog_ctx_t *ctx = g_new0(dialog_ctx_t, 1);
    ctx->on_connect = on_connect;
    ctx->on_edit    = on_edit;
    ctx->user       = user;

    ctx->dialog = gtk_dialog_new();
    gtk_window_set_title(GTK_WINDOW(ctx->dialog), "Saved Connections");
    gtk_window_set_transient_for(GTK_WINDOW(ctx->dialog), parent);
    gtk_window_set_modal(GTK_WINDOW(ctx->dialog), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(ctx->dialog), 700, 380);

    /* Tree model + view */
    ctx->store = gtk_list_store_new(N_COLS,
                                    G_TYPE_INT64,  /* COL_ID (hidden) */
                                    G_TYPE_STRING, /* COL_NAME */
                                    G_TYPE_STRING, /* COL_PROTO */
                                    G_TYPE_STRING, /* COL_HOST_PORT */
                                    G_TYPE_STRING  /* COL_USER */);
    ctx->view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(ctx->store));
    /* The model holds a ref now; we can drop ours. */
    g_object_unref(ctx->store);

    add_text_column(GTK_TREE_VIEW(ctx->view), "Name",       COL_NAME);
    add_text_column(GTK_TREE_VIEW(ctx->view), "Protocol",   COL_PROTO);
    add_text_column(GTK_TREE_VIEW(ctx->view), "Host:Port",  COL_HOST_PORT);
    add_text_column(GTK_TREE_VIEW(ctx->view), "User",       COL_USER);

    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(ctx->view), TRUE);
    gtk_tree_selection_set_mode(
        gtk_tree_view_get_selection(GTK_TREE_VIEW(ctx->view)),
        GTK_SELECTION_SINGLE);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_set_hexpand(scroll, TRUE);
    gtk_container_add(GTK_CONTAINER(scroll), ctx->view);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(ctx->dialog));
    gtk_box_pack_start(GTK_BOX(content), scroll, TRUE, TRUE, 0);
    gtk_widget_set_margin_top   (scroll, 8);
    gtk_widget_set_margin_bottom(scroll, 8);
    gtk_widget_set_margin_start (scroll, 8);
    gtk_widget_set_margin_end   (scroll, 8);

    /* Action buttons. We build our own row at the bottom of the
     * content area instead of using gtk_dialog_get_action_area
     * (deprecated since 3.12). Plain GtkButtons (not dialog response
     * IDs) so each handler has full control over what closes the
     * dialog and what doesn't. */
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_margin_top   (bar, 4);
    gtk_widget_set_margin_bottom(bar, 8);
    gtk_widget_set_margin_start (bar, 8);
    gtk_widget_set_margin_end   (bar, 8);
    gtk_box_pack_end(GTK_BOX(content), bar, FALSE, FALSE, 0);

    GtkWidget *btn_delete = gtk_button_new_with_label("Delete");
    GtkWidget *btn_edit   = gtk_button_new_with_label("Edit");
    GtkWidget *btn_close  = gtk_button_new_with_label("Close");
    GtkWidget *btn_connect= gtk_button_new_with_label("Connect");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_connect),
                                "suggested-action");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_delete),
                                "destructive-action");

    gtk_box_pack_start(GTK_BOX(bar), btn_delete, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), btn_edit,   FALSE, FALSE, 0);
    gtk_box_pack_end  (GTK_BOX(bar), btn_connect,FALSE, FALSE, 0);
    gtk_box_pack_end  (GTK_BOX(bar), btn_close,  FALSE, FALSE, 0);

    g_signal_connect(btn_connect, "clicked", G_CALLBACK(on_connect_clicked), ctx);
    g_signal_connect(btn_edit,    "clicked", G_CALLBACK(on_edit_clicked),    ctx);
    g_signal_connect(btn_delete,  "clicked", G_CALLBACK(on_delete_clicked),  ctx);
    g_signal_connect(btn_close,   "clicked", G_CALLBACK(on_close_clicked),   ctx);

    g_signal_connect(ctx->view, "row-activated",
                     G_CALLBACK(on_row_activated), ctx);
    g_signal_connect(ctx->dialog, "destroy",
                     G_CALLBACK(on_dialog_destroy), ctx);

    reload_store(ctx);
    gtk_widget_show_all(ctx->dialog);
}

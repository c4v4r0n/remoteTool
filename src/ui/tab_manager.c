/*
 * GtkNotebook wrapper. Each tab gets a custom label widget: title +
 * close button. The close handler resolves the page index from the
 * stored content widget so reordering doesn't break it.
 */

#include "ui/tab_manager.h"

struct rt_tab_manager {
    GtkWidget *notebook;
};

static void on_close_clicked(GtkButton *btn, gpointer user_data)
{
    GtkWidget *content  = GTK_WIDGET(user_data);
    GtkWidget *notebook = gtk_widget_get_ancestor(GTK_WIDGET(btn),
                                                  GTK_TYPE_NOTEBOOK);
    if (notebook == NULL) {
        return;
    }
    gint page = gtk_notebook_page_num(GTK_NOTEBOOK(notebook), content);
    if (page >= 0) {
        gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), page);
    }
}

static GtkWidget *build_tab_label(const char *title, GtkWidget *content)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

    GtkWidget *label = gtk_label_new(title);
    gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
    /* Wide enough for "RDP some.long.fqdn.example.com" without
     * ellipsis; longer names still collapse cleanly. */
    gtk_label_set_max_width_chars(GTK_LABEL(label), 36);
    gtk_label_set_width_chars    (GTK_LABEL(label), 12);  /* don't shrink below this */
    /* Keep the full title available on hover. */
    gtk_widget_set_tooltip_text(label, title);

    GtkWidget *close = gtk_button_new_from_icon_name(
        "window-close-symbolic", GTK_ICON_SIZE_MENU);
    gtk_button_set_relief(GTK_BUTTON(close), GTK_RELIEF_NONE);
    gtk_widget_set_focus_on_click(close, FALSE);
    gtk_widget_set_tooltip_text(close, "Close tab");
    g_signal_connect(close, "clicked", G_CALLBACK(on_close_clicked), content);

    gtk_box_pack_start(GTK_BOX(box), label, TRUE,  TRUE,  0);
    gtk_box_pack_end  (GTK_BOX(box), close, FALSE, FALSE, 0);
    gtk_widget_show_all(box);
    return box;
}

rt_tab_manager_t *rt_tab_manager_new(void)
{
    rt_tab_manager_t *tm = g_new0(rt_tab_manager_t, 1);
    tm->notebook = gtk_notebook_new();
    gtk_notebook_set_scrollable(GTK_NOTEBOOK(tm->notebook), TRUE);
    gtk_notebook_set_show_border(GTK_NOTEBOOK(tm->notebook), FALSE);
    return tm;
}

void rt_tab_manager_free(rt_tab_manager_t *tm)
{
    if (tm == NULL) {
        return;
    }
    /* The notebook widget itself is owned by its parent container;
     * we only own the wrapper struct. */
    g_free(tm);
}

GtkWidget *rt_tab_manager_get_widget(rt_tab_manager_t *tm)
{
    return tm->notebook;
}

gint rt_tab_manager_add_tab(rt_tab_manager_t *tm,
                            const char       *title,
                            GtkWidget        *content)
{
    GtkWidget *label = build_tab_label(title, content);
    gint page = gtk_notebook_append_page(GTK_NOTEBOOK(tm->notebook),
                                         content, label);
    gtk_notebook_set_tab_reorderable(GTK_NOTEBOOK(tm->notebook),
                                     content, TRUE);
    gtk_widget_show_all(content);
    return page;
}

void rt_tab_manager_close_current(rt_tab_manager_t *tm)
{
    gint page = gtk_notebook_get_current_page(GTK_NOTEBOOK(tm->notebook));
    if (page >= 0) {
        gtk_notebook_remove_page(GTK_NOTEBOOK(tm->notebook), page);
    }
}

int rt_tab_manager_replace_content(rt_tab_manager_t *tm,
                                   GtkWidget        *current,
                                   GtkWidget        *replacement,
                                   const char       *new_title)
{
    GtkNotebook *nb = GTK_NOTEBOOK(tm->notebook);
    gint page = gtk_notebook_page_num(nb, current);
    if (page < 0) {
        return -1;
    }

    /* Hold a ref while we swap so removing the old page doesn't
     * destroy `current` before the caller is done with it. The
     * notebook drops its ref in remove_page; we drop ours after. */
    g_object_ref(replacement);

    GtkWidget *new_label = build_tab_label(new_title ? new_title : "",
                                           replacement);
    gtk_notebook_remove_page(nb, page);
    gint inserted = gtk_notebook_insert_page(nb, replacement, new_label, page);
    gtk_notebook_set_tab_reorderable(nb, replacement, TRUE);
    gtk_widget_show_all(replacement);
    gtk_notebook_set_current_page(nb, inserted);

    g_object_unref(replacement);
    return 0;
}

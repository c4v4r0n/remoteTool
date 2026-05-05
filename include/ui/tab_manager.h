#ifndef RT_UI_TAB_MANAGER_H
#define RT_UI_TAB_MANAGER_H

#include <gtk/gtk.h>

/*
 * Thin wrapper around GtkNotebook that gives every tab a closeable
 * label. Kept narrow on purpose so the rest of the UI never touches
 * the notebook directly.
 */
typedef struct rt_tab_manager rt_tab_manager_t;

rt_tab_manager_t *rt_tab_manager_new(void);
void              rt_tab_manager_free(rt_tab_manager_t *tm);

/* Underlying widget, to embed in a parent container. */
GtkWidget *rt_tab_manager_get_widget(rt_tab_manager_t *tm);

/* Append a tab; returns the page index. The notebook takes a
 * reference to `content` - caller does not need to ref it. */
gint rt_tab_manager_add_tab(rt_tab_manager_t *tm,
                            const char       *title,
                            GtkWidget        *content);

void rt_tab_manager_close_current(rt_tab_manager_t *tm);

/* Replace the content of the page currently holding `current` with
 * `replacement`, keeping the same index, and update the tab title.
 * Returns 0 on success, -1 if `current` is not in the notebook. */
int rt_tab_manager_replace_content(rt_tab_manager_t *tm,
                                   GtkWidget        *current,
                                   GtkWidget        *replacement,
                                   const char       *new_title);

#endif /* RT_UI_TAB_MANAGER_H */

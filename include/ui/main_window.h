#ifndef RT_UI_MAIN_WINDOW_H
#define RT_UI_MAIN_WINDOW_H

#include <gtk/gtk.h>

/*
 * Build the main GtkApplicationWindow: header bar with a "+ New
 * Connection" action and a GtkNotebook body. Ownership transfers to
 * GtkApplication once shown.
 */
GtkWidget *rt_main_window_new(GtkApplication *app);

#endif /* RT_UI_MAIN_WINDOW_H */

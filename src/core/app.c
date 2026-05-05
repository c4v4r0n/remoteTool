/*
 * Application lifecycle. Owns the GtkApplication and wires the
 * "activate" signal to main_window construction. No UI code here -
 * that lives in ui/.
 */

#include "core/app.h"
#include "ui/main_window.h"

#include <libssh/libssh.h>
#include <stdlib.h>

#define RT_APP_ID "org.remotetool.RemoteTool"

/* G_APPLICATION_DEFAULT_FLAGS was introduced in glib 2.74. Fall
 * back to the older spelling on systems that don't have it yet. */
#if !GLIB_CHECK_VERSION(2, 74, 0)
# define G_APPLICATION_DEFAULT_FLAGS G_APPLICATION_FLAGS_NONE
#endif

struct rt_app {
    GtkApplication *gtk_app;
};

static void on_activate(GtkApplication *gtk_app, gpointer user_data)
{
    (void)user_data;
    GtkWidget *win = rt_main_window_new(gtk_app);
    gtk_widget_show_all(win);
}

rt_app_t *rt_app_new(void)
{
    /* Required for thread-safe libssh use across multiple sessions. */
    if (ssh_init() != 0) {
        return NULL;
    }

    rt_app_t *app = calloc(1, sizeof(*app));
    if (app == NULL) {
        ssh_finalize();
        return NULL;
    }

    app->gtk_app = gtk_application_new(RT_APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    if (app->gtk_app == NULL) {
        free(app);
        ssh_finalize();
        return NULL;
    }

    g_signal_connect(app->gtk_app, "activate", G_CALLBACK(on_activate), app);
    return app;
}

int rt_app_run(rt_app_t *app, int argc, char **argv)
{
    return g_application_run(G_APPLICATION(app->gtk_app), argc, argv);
}

void rt_app_free(rt_app_t *app)
{
    if (app == NULL) {
        return;
    }
    if (app->gtk_app != NULL) {
        g_object_unref(app->gtk_app);
    }
    free(app);
    ssh_finalize();
}

#ifndef RT_CORE_APP_H
#define RT_CORE_APP_H

#include <gtk/gtk.h>

/*
 * rt_app_t - top-level application context.
 *
 * Owns the GtkApplication and any cross-cutting state shared between
 * subsystems. The struct is opaque so callers depend on the API, not
 * the layout.
 */
typedef struct rt_app rt_app_t;

rt_app_t *rt_app_new(void);
int       rt_app_run(rt_app_t *app, int argc, char **argv);
void      rt_app_free(rt_app_t *app);

#endif /* RT_CORE_APP_H */

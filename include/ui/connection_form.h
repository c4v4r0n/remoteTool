#ifndef RT_UI_CONNECTION_FORM_H
#define RT_UI_CONNECTION_FORM_H

#include <gtk/gtk.h>
#include "core/connection.h"

/*
 * Connection form widget.
 *
 * The form raises rt_connection_form_submit_cb_t when the user
 * clicks Connect. Ownership of `conn` and `password` transfers to
 * the callback - it must rt_connection_free() the connection and
 * wipe + g_free() the password (the form has already cleared its
 * own password entry by the time the callback fires).
 *
 * The form does not know about sessions, tabs or protocols - the
 * caller (main_window) wires it up.
 */

typedef void (*rt_connection_form_submit_cb_t)(GtkWidget       *form_widget,
                                               rt_connection_t *conn,
                                               char            *password,
                                               void            *user);

GtkWidget *rt_connection_form_new(rt_connection_form_submit_cb_t cb,
                                  void                          *user);

/* Show a message in the form's status area (red). */
void rt_connection_form_show_error(GtkWidget *form, const char *msg);

#endif /* RT_UI_CONNECTION_FORM_H */

#ifndef RT_UI_CONNECTION_DIALOG_H
#define RT_UI_CONNECTION_DIALOG_H

#include <gtk/gtk.h>
#include <stdint.h>

/*
 * Modal "Saved Connections" dialog.
 *
 * Lists every persisted profile in a table with Connect / Edit /
 * Delete actions. Selecting a row + Connect (or double-clicking)
 * fires `on_connect`. Edit fires `on_edit`. Delete is handled
 * internally (calls rt_profile_delete + refreshes the list, no
 * callback). Both action callbacks receive the profile's stable id;
 * the caller looks up details via storage/profile.h.
 *
 * Lifetime: the dialog tears itself down on Close, on a successful
 * Connect/Edit, or when the parent is destroyed. Caller does not
 * retain a handle.
 */

typedef void (*rt_connection_dialog_connect_cb_t)(int64_t profile_id, void *user);
typedef void (*rt_connection_dialog_edit_cb_t)   (int64_t profile_id, void *user);

void rt_connection_dialog_show(GtkWindow                          *parent,
                               rt_connection_dialog_connect_cb_t   on_connect,
                               rt_connection_dialog_edit_cb_t      on_edit,
                               void                               *user);

#endif /* RT_UI_CONNECTION_DIALOG_H */

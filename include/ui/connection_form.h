#ifndef RT_UI_CONNECTION_FORM_H
#define RT_UI_CONNECTION_FORM_H

#include <gtk/gtk.h>
#include <stdint.h>

#include "core/connection.h"
#include "storage/profile.h"

/*
 * Connection form widget.
 *
 * Two construction modes:
 *   rt_connection_form_new()          - blank form for a new connection.
 *   rt_connection_form_new_for_edit() - pre-populated for editing an
 *                                       existing saved profile; the
 *                                       primary action becomes Save.
 *
 * The submit callback fires with an `intent` describing what the user
 * asked for (just connect / save and connect / save changes only).
 * Ownership of `conn` and `password` transfers to the callback - it
 * must rt_connection_free() the connection and wipe + g_free() the
 * password (the form has already cleared its own password entry by
 * the time the callback fires). `password` may be empty in edit mode
 * meaning "keep the existing keyring entry untouched".
 *
 * The form does not know about sessions, tabs or storage internals -
 * the caller (main_window) wires the intent to the right action.
 */

typedef enum {
    RT_FORM_INTENT_CONNECT          = 0,  /* new form, just connect */
    RT_FORM_INTENT_SAVE_AND_CONNECT = 1,  /* new form, save profile + connect */
    RT_FORM_INTENT_SAVE             = 2   /* edit form, save changes only */
} rt_form_intent_t;

typedef void (*rt_connection_form_submit_cb_t)(GtkWidget        *form_widget,
                                               rt_form_intent_t  intent,
                                               int64_t           profile_id,
                                               const char       *save_name,
                                               rt_connection_t  *conn,
                                               char             *password,
                                               void             *user);

/* Build a blank form for a new connection. */
GtkWidget *rt_connection_form_new(rt_connection_form_submit_cb_t cb,
                                  void                          *user);

/* Build a form pre-populated from an existing profile. The primary
 * button reads "Save changes"; submit fires with intent=SAVE and
 * profile_id=p->id. Leaving the password blank means "don't touch
 * the keyring entry"; typing a new password replaces it. */
GtkWidget *rt_connection_form_new_for_edit(const rt_profile_t            *p,
                                           rt_connection_form_submit_cb_t cb,
                                           void                          *user);

/* Show a message in the form's status area (red). */
void rt_connection_form_show_error(GtkWidget *form, const char *msg);

#endif /* RT_UI_CONNECTION_FORM_H */

#ifndef RT_UI_RDP_VIEW_H
#define RT_UI_RDP_VIEW_H

#include <gtk/gtk.h>
#include <stddef.h>

#include "core/session.h"

/*
 * RDP viewer widget. Composition:
 *
 *   GtkBox (vertical) [returned to caller]
 *   ├── GtkBox (horizontal)  toolbar
 *   │   ├── GtkLabel         status
 *   │   └── GtkComboBox      scale mode (Original / Fit)
 *   └── GtkScrolledWindow
 *       └── GtkDrawingArea   pixel surface (Cairo blit from FB)
 *
 * The widget owns no pixels of its own; on each draw it locks the
 * session's framebuffer (rt_session_get_framebuffer) and blits via
 * cairo_image_surface_create_for_data. Resizing the widget never
 * blocks the network thread - we just queue_draw and re-blit.
 *
 * The widget binds to a session at construction. It does NOT own
 * the session - lifetime is managed by the tab bundle (same pattern
 * as the terminal view).
 */

typedef struct rt_rdp_view rt_rdp_view_t;

typedef enum {
    RT_RDP_SCALE_ORIGINAL = 0,
    RT_RDP_SCALE_TO_FIT
} rt_rdp_scale_mode_t;

/* Construct a view. `session` may be NULL; attach it later via
 * rt_rdp_view_set_session() once it has been opened (the view needs
 * to exist before the session does, because the session's UI
 * callbacks point at the view). */
rt_rdp_view_t *rt_rdp_view_new(rt_session_t *session);
void           rt_rdp_view_free(rt_rdp_view_t *v);
GtkWidget     *rt_rdp_view_get_widget(rt_rdp_view_t *v);

void rt_rdp_view_set_session(rt_rdp_view_t *v, rt_session_t *session);

/* Called by main_window from on_frame: invalidates the affected
 * region so GTK schedules a redraw. */
void rt_rdp_view_on_frame(rt_rdp_view_t *v,
                          int frame_w, int frame_h,
                          int dx, int dy, int dw, int dh);

/* Show a connection-state line above the canvas. */
void rt_rdp_view_set_status(rt_rdp_view_t *v, const char *status);

/* Receive a clipboard update from the remote and publish it to the
 * local GTK clipboard. */
void rt_rdp_view_set_remote_clipboard(rt_rdp_view_t *v,
                                      const char *utf8, size_t len);

/* When disabled, input forwarding (mouse/keyboard) is suppressed -
 * used while the connection is still being established. */
void rt_rdp_view_set_input_enabled(rt_rdp_view_t *v, gboolean enabled);

#endif /* RT_UI_RDP_VIEW_H */

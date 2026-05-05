#ifndef RT_UI_VNC_VIEW_H
#define RT_UI_VNC_VIEW_H

#include <gtk/gtk.h>
#include <stddef.h>

#include "core/session.h"

/*
 * VNC viewer widget.
 *
 * Mirror of rt_rdp_view (cairo blit canvas + toolbar + Send Keys
 * menu) kept as its own type so VNC-specific quirks (RFB cut-text
 * encoding, view-only signalling, etc.) can evolve without touching
 * the RDP path.
 *
 * Composition:
 *
 *   GtkBox (vertical) [returned to caller]
 *   ├── GtkBox (horizontal)  toolbar
 *   │   ├── GtkLabel         status
 *   │   ├── GtkMenuButton    "Send Keys"
 *   │   └── GtkComboBox      scale mode
 *   └── GtkScrolledWindow
 *       └── GtkDrawingArea   pixel surface
 */

typedef struct rt_vnc_view rt_vnc_view_t;

typedef enum {
    RT_VNC_SCALE_ORIGINAL = 0,
    RT_VNC_SCALE_TO_FIT
} rt_vnc_scale_mode_t;

rt_vnc_view_t *rt_vnc_view_new(rt_session_t *session);
void           rt_vnc_view_free(rt_vnc_view_t *v);
GtkWidget     *rt_vnc_view_get_widget(rt_vnc_view_t *v);

void rt_vnc_view_set_session(rt_vnc_view_t *v, rt_session_t *session);

/* Called by main_window from on_frame: invalidates the affected
 * region so GTK schedules a redraw. */
void rt_vnc_view_on_frame(rt_vnc_view_t *v,
                          int frame_w, int frame_h,
                          int dx, int dy, int dw, int dh);

void rt_vnc_view_set_status(rt_vnc_view_t *v, const char *status);

/* Receive a clipboard update from the remote and publish it to the
 * local GTK clipboard. */
void rt_vnc_view_set_remote_clipboard(rt_vnc_view_t *v,
                                      const char *text, size_t len);

/* Suppress input forwarding while the connection is establishing or
 * after view-only takes effect. */
void rt_vnc_view_set_input_enabled(rt_vnc_view_t *v, gboolean enabled);

/* Programmatic scale-mode override - main_window applies the saved
 * profile preference here. */
void rt_vnc_view_set_scale_mode(rt_vnc_view_t *v, rt_vnc_scale_mode_t mode);

/* Show/hide the top toolbar (used by the fullscreen toggle). */
void rt_vnc_view_set_chrome_visible(rt_vnc_view_t *v, gboolean visible);

#endif /* RT_UI_VNC_VIEW_H */

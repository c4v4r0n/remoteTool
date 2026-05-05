#ifndef RT_UI_WINRM_VIEW_H
#define RT_UI_WINRM_VIEW_H

#include <gtk/gtk.h>
#include <stddef.h>

/*
 * WinRM tab widget: terminal-style output area + a single-line
 * command entry + Send button + status label.
 *
 *   GtkBox (vertical) [returned to caller]
 *   ├── GtkLabel             status
 *   ├── GtkScrolledWindow
 *   │   └── GtkTextView      output (read-only, monospace)
 *   └── GtkBox (horizontal)
 *       ├── GtkLabel "> "
 *       ├── GtkEntry         command input
 *       └── GtkButton        Send
 *
 * Submitting a command (Enter or Send) appends "> CMD\n" to the
 * output area locally and forwards "CMD\n" to the input handler.
 * The protocol layer treats each newline-terminated line as one
 * command and streams output back via rt_winrm_view_feed_output.
 *
 * Lifetime is tied to the top-level widget.
 */

typedef struct rt_winrm_view rt_winrm_view_t;

typedef void (*rt_winrm_view_input_cb_t)(const char *bytes, size_t len, void *user);

rt_winrm_view_t *rt_winrm_view_new(void);
void             rt_winrm_view_free(rt_winrm_view_t *v);
GtkWidget       *rt_winrm_view_get_widget(rt_winrm_view_t *v);

/* Append remote bytes to the output area (server -> screen). */
void rt_winrm_view_feed_output(rt_winrm_view_t *v, const char *data, size_t len);

void rt_winrm_view_set_status(rt_winrm_view_t *v, const char *status);

/* When disabled the entry / send button are greyed out. */
void rt_winrm_view_set_input_enabled(rt_winrm_view_t *v, gboolean enabled);

/* Show/hide the top status label (used by fullscreen toggle). */
void rt_winrm_view_set_chrome_visible(rt_winrm_view_t *v, gboolean visible);

void rt_winrm_view_set_input_handler(rt_winrm_view_t          *v,
                                     rt_winrm_view_input_cb_t  cb,
                                     void                     *user);

#endif /* RT_UI_WINRM_VIEW_H */

#ifndef RT_UI_WINRM_VIEW_H
#define RT_UI_WINRM_VIEW_H

#include <gtk/gtk.h>
#include <stddef.h>

/*
 * WinRM tab widget: a real VTE-backed terminal with client-side line
 * editing.
 *
 *   GtkBox (vertical) [returned to caller]
 *   ├── GtkLabel        status
 *   └── GtkBox (horizontal)
 *       ├── VteTerminal       (renders ANSI from PowerShell)
 *       └── GtkScrollbar
 *
 * PSRP-over-WinRM is request/response: each Enter submits one line as
 * a discrete pipeline. The widget owns its own line buffer + history
 * because there's no remote readline. Keystrokes never go to the
 * server; only the full submitted line + '\n' does, via the input
 * handler. Server output is fed straight to VTE so colors, escapes
 * and Unicode all render natively.
 *
 * Lifetime is tied to the top-level widget.
 */

typedef struct rt_winrm_view rt_winrm_view_t;

typedef void (*rt_winrm_view_input_cb_t)(const char *bytes, size_t len, void *user);

rt_winrm_view_t *rt_winrm_view_new(void);
void             rt_winrm_view_free(rt_winrm_view_t *v);
GtkWidget       *rt_winrm_view_get_widget(rt_winrm_view_t *v);

/* Append remote bytes (server -> screen). Bytes are fed to VTE
 * verbatim; ANSI escape sequences are honored. */
void rt_winrm_view_feed_output(rt_winrm_view_t *v, const char *data, size_t len);

void rt_winrm_view_set_status(rt_winrm_view_t *v, const char *status);

/* Gate keystroke handling. When disabled, keys are dropped (terminal
 * stays visible for scrollback / selection). */
void rt_winrm_view_set_input_enabled(rt_winrm_view_t *v, gboolean enabled);

/* The protocol layer reports it has finished the previous pipeline
 * and is ready for the next command. The view paints a fresh prompt.
 * Idempotent within a single idle window. */
void rt_winrm_view_show_prompt(rt_winrm_view_t *v);

/* Show/hide the top status label (used by fullscreen toggle). */
void rt_winrm_view_set_chrome_visible(rt_winrm_view_t *v, gboolean visible);

void rt_winrm_view_set_input_handler(rt_winrm_view_t          *v,
                                     rt_winrm_view_input_cb_t  cb,
                                     void                     *user);

#endif /* RT_UI_WINRM_VIEW_H */

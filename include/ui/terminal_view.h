#ifndef RT_UI_TERMINAL_VIEW_H
#define RT_UI_TERMINAL_VIEW_H

#include <gtk/gtk.h>
#include <stddef.h>

/*
 * Terminal widget: a VteTerminal embedded under a status label.
 *
 *   GtkBox (vertical) [returned to caller]
 *   ├── GtkLabel        status
 *   └── GtkBox (horizontal)
 *       ├── VteTerminal       (full xterm emulation)
 *       └── GtkScrollbar      (driven by VTE's vadjustment)
 *
 * Bytes from the remote come in via rt_terminal_feed_output and are
 * fed straight to VTE. Keystrokes flow out through the input handler
 * (raw bytes, already encoded by VTE for the active modifiers).
 *
 * The wrapper struct's lifetime is tied to its top-level widget.
 */

typedef struct rt_terminal rt_terminal_t;

typedef void (*rt_terminal_input_cb_t) (const char *bytes, size_t len, void *user);
typedef void (*rt_terminal_resize_cb_t)(unsigned cols, unsigned rows, void *user);

rt_terminal_t *rt_terminal_new(void);
void           rt_terminal_free(rt_terminal_t *t);
GtkWidget     *rt_terminal_get_widget(rt_terminal_t *t);

/* Feed bytes from the remote into the terminal (server -> screen). */
void rt_terminal_feed_output(rt_terminal_t *t, const char *data, size_t len);

void rt_terminal_set_status(rt_terminal_t *t, const char *status);

/* When disabled, the terminal stops accepting keystrokes. */
void rt_terminal_set_input_enabled(rt_terminal_t *t, gboolean enabled);

/* Show/hide the top status label. Used in fullscreen mode so the
 * terminal canvas can use the freed vertical space. */
void rt_terminal_set_chrome_visible(rt_terminal_t *t, gboolean visible);

void rt_terminal_set_input_handler (rt_terminal_t *t,
                                    rt_terminal_input_cb_t cb, void *user);
void rt_terminal_set_resize_handler(rt_terminal_t *t,
                                    rt_terminal_resize_cb_t cb, void *user);

#endif /* RT_UI_TERMINAL_VIEW_H */

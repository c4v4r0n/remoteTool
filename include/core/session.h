#ifndef RT_CORE_SESSION_H
#define RT_CORE_SESSION_H

#include <stddef.h>
#include "core/connection.h"
#include "protocols/protocol.h"

/*
 * A session is a connection + protocol context + the marshaling
 * layer between the protocol's worker thread and the GTK main loop.
 *
 * Callers (the UI) deal only with this header. They never include
 * libssh / FreeRDP, never spawn threads, never see protocol-specific
 * types.
 *
 * UI callbacks in rt_session_ui_callbacks_t are guaranteed to be
 * invoked on the GTK main thread, so they may touch widgets directly.
 *
 * Modality:
 *   - Byte-stream sessions (SSH) emit on_data; ignore on_frame.
 *   - Framebuffer sessions (RDP) emit on_frame; ignore on_data.
 *   The session core delivers whichever the underlying protocol
 *   produces; widgets register only the callbacks they care about.
 */

typedef struct rt_session rt_session_t;

typedef struct {
    void (*on_data) (void *user, const char *data, size_t len);
    void (*on_state)(void *user, rt_proto_state_t state, const char *msg);

    /* New in phase 3. The frame describes which region of the shared
     * framebuffer changed; the widget reads pixels via
     * rt_session_get_framebuffer(). */
    void (*on_frame)(void *user, const rt_remote_frame_t *frame);

    /* Remote pushed a clipboard update. Text only, UTF-8. */
    void (*on_clipboard_text)(void *user, const char *utf8, size_t len);
} rt_session_ui_callbacks_t;

/*
 * Create and start a session.
 *
 * Ownership:
 *   - `conn` is taken by the session and freed in rt_session_close().
 *     On NULL return, the caller still owns `conn`.
 *   - `password` is copied internally (and the copy wiped on close);
 *     the caller may zero/free its buffer immediately after this
 *     call returns.
 *   - `ui` is copied; `user` is stored.
 *
 * Returns NULL if the protocol is unsupported or open() fails.
 */
rt_session_t *rt_session_new(rt_connection_t                 *conn,
                             const char                      *password,
                             const rt_session_ui_callbacks_t *ui,
                             void                            *user);

int  rt_session_send_data (rt_session_t *s, const void *data, size_t len);
int  rt_session_send_input(rt_session_t *s, const rt_input_event_t *evt);

/* Notify the underlying protocol that the user-facing terminal has
 * been resized. No-op if the protocol doesn't carry a PTY. */
void rt_session_resize(rt_session_t *s, unsigned cols, unsigned rows);

/* Push local clipboard text to the remote. No-op if the protocol
 * doesn't support clipboard. Returns 0 on success. */
int  rt_session_set_clipboard_text(rt_session_t *s,
                                   const char   *utf8, size_t len);

/* Lockable framebuffer handle for blitting. NULL on byte-stream
 * sessions. Lifetime equals the session's lifetime. */
rt_remote_framebuffer_t *rt_session_get_framebuffer(rt_session_t *s);

/* Synchronous shutdown: joins the protocol worker, drains queued UI
 * messages without dispatching them, and frees everything the
 * session owns (including conn and the wiped password copy). Safe
 * to call multiple times; second call is a no-op. */
void rt_session_close(rt_session_t *s);

const rt_connection_t *rt_session_connection(rt_session_t *s);

#endif /* RT_CORE_SESSION_H */

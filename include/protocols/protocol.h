#ifndef RT_PROTOCOLS_PROTOCOL_H
#define RT_PROTOCOLS_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include "core/connection.h"

/*
 * Generic protocol interface.
 *
 * A protocol is a back-end that knows how to talk a wire format
 * (SSH, RDP, VNC, ...). The session layer drives it through this
 * vtable; the UI layer never includes this header.
 *
 * Threading model:
 *   - open() may spawn a background thread / event loop owned by
 *     the protocol implementation.
 *   - Callbacks (on_data / on_state / on_frame / on_clipboard_text)
 *     are invoked on whatever thread the implementation chose. The
 *     session layer is responsible for marshaling them to the GTK
 *     main loop.
 *   - send(), send_input(), resize(), set_clipboard_text() must be
 *     safe to call from any thread.
 *   - close() is synchronous: by the time it returns, no further
 *     callbacks will fire.
 *
 * Modality:
 *   - Byte-stream protocols (SSH) emit on_data and consume send().
 *   - Framebuffer protocols (RDP, VNC) emit on_frame and consume
 *     send_input(). They expose a framebuffer accessor so the UI
 *     can blit the backing pixels under a lock without copying.
 *   Protocols are free to implement only the ops they need; unused
 *   slots are left NULL.
 */

typedef enum {
    RT_PROTO_STATE_DISCONNECTED = 0,
    RT_PROTO_STATE_CONNECTING,
    RT_PROTO_STATE_AUTHENTICATING,
    RT_PROTO_STATE_CONNECTED,
    RT_PROTO_STATE_ERROR
} rt_proto_state_t;

const char *rt_proto_state_to_string(rt_proto_state_t s);

/* ---------- frame model ---------- */

typedef enum {
    RT_FRAME_FORMAT_BGRA32 = 0  /* 32 bpp, little-endian B,G,R,A bytes */
} rt_frame_format_t;

/* "Frame ready" notification. The pixel buffer itself is NOT carried
 * here - the UI obtains it via the framebuffer accessor below. Only
 * the dirty region travels through the message queue. */
typedef struct {
    int width;
    int height;
    int dirty_x, dirty_y, dirty_w, dirty_h;  /* dirty rect in px */
} rt_remote_frame_t;

/* Opaque framebuffer handle. The protocol owns the pixel storage and
 * an internal mutex; callers lock for read, blit, then release. The
 * lifetime of the handle equals the lifetime of the protocol ctx. */
typedef struct rt_remote_framebuffer rt_remote_framebuffer_t;

const uint8_t *rt_remote_framebuffer_lock(rt_remote_framebuffer_t *fb,
                                          int *out_width,
                                          int *out_height,
                                          int *out_stride,
                                          rt_frame_format_t *out_format);
void           rt_remote_framebuffer_release(rt_remote_framebuffer_t *fb);

/* ---------- input model ---------- */

typedef enum {
    RT_INPUT_MOUSE_MOVE = 0,
    RT_INPUT_MOUSE_BUTTON,    /* button + pressed */
    RT_INPUT_MOUSE_WHEEL,     /* wheel_delta (>0 up, <0 down) */
    RT_INPUT_KEY,             /* hardware keycode + pressed */
    RT_INPUT_UNICODE          /* unicode_cp + pressed (fallback) */
} rt_input_kind_t;

typedef struct {
    rt_input_kind_t kind;

    /* Cursor position in remote-screen coordinates (always set for
     * mouse events; ignored for key events). */
    int x, y;

    /* MOUSE_BUTTON: 1=left, 2=middle, 3=right. */
    int button;

    /* MOUSE_BUTTON / KEY / UNICODE: 1=press, 0=release. */
    int pressed;

    /* MOUSE_WHEEL: in lines (sign matters; magnitude is clamped by
     * the back-end). */
    int wheel_delta;

    /* KEY: hardware keycode (GDK keycode == X11 keycode on Linux).
     * RDP back-end consumes this. Modifiers are NOT reapplied here -
     * the back-end tracks state from the press/release stream. */
    unsigned int keycode;

    /* KEY: GDK keyval, identical to X11 keysym. VNC back-end consumes
     * this (RFB transports keysyms, not scancodes). The widget fills
     * both fields; each back-end picks the one it needs. */
    unsigned int keysym;

    /* UNICODE: codepoint to inject. */
    unsigned int unicode_cp;
} rt_input_event_t;

/* ---------- callbacks (protocol -> session) ---------- */

typedef struct {
    void (*on_data) (void *user, const char *data, size_t len);
    void (*on_state)(void *user, rt_proto_state_t state, const char *msg);

    /* New in phase 3: framebuffer protocols emit this when a paint
     * pass completes. The pixels live in the protocol's framebuffer
     * (see rt_remote_framebuffer_*). */
    void (*on_frame)(void *user, const rt_remote_frame_t *frame);

    /* Remote sent us a clipboard update (text only, UTF-8). The
     * pointer is owned by the callee; it is valid only for the
     * duration of the call. */
    void (*on_clipboard_text)(void *user, const char *utf8, size_t len);

    /* The remote is idle and ready for the next user input. Used by
     * request/response protocols (WinRM PSRP) so the terminal can
     * draw a fresh prompt only after the previous pipeline has
     * finished streaming. May be NULL on protocols that don't have
     * a discrete idle boundary (SSH/RDP/VNC). */
    void (*on_idle)(void *user);
} rt_proto_callbacks_t;

typedef struct rt_protocol_ctx rt_protocol_ctx_t;

typedef struct {
    const char *name;

    /* Open a session. `password` may be NULL for protocols/auth
     * methods that don't need it. The protocol implementation must
     * NOT retain the password pointer past this call - the caller
     * is free to wipe it as soon as open() returns.
     *
     * Returns NULL on failure (callbacks may still have fired with
     * an error state before NULL is returned). */
    rt_protocol_ctx_t *(*open)(const rt_connection_t      *conn,
                               const char                 *password,
                               const rt_proto_callbacks_t *cb,
                               void                       *user);

    /* Send raw bytes to the remote endpoint. Used by byte-stream
     * protocols (SSH). Thread-safe. May be NULL.
     * Returns 0 on success, -1 on error. */
    int (*send)(rt_protocol_ctx_t *ctx, const void *data, size_t len);

    /* Send a structured input event. Used by framebuffer protocols
     * (RDP). Thread-safe. May be NULL. Returns 0 on success. */
    int (*send_input)(rt_protocol_ctx_t *ctx, const rt_input_event_t *evt);

    /* Notify the protocol that the user-facing terminal/viewport has
     * been resized. Thread-safe. May be NULL. */
    void (*resize)(rt_protocol_ctx_t *ctx, unsigned cols, unsigned rows);

    /* Push local clipboard text to the remote. Thread-safe.
     * May be NULL on protocols without clipboard support. */
    int (*set_clipboard_text)(rt_protocol_ctx_t *ctx,
                              const char *utf8, size_t len);

    /* Return the framebuffer handle for blitting. May be NULL on
     * non-framebuffer protocols. The returned handle is owned by
     * the protocol ctx and lives until close(). */
    rt_remote_framebuffer_t *(*get_framebuffer)(rt_protocol_ctx_t *ctx);

    /* Synchronous shutdown. Joins worker threads, releases all
     * resources. After return, no further callbacks will fire. */
    void (*close)(rt_protocol_ctx_t *ctx);
} rt_protocol_ops_t;

/* Returns the registered ops table for `protocol`, or NULL if no
 * implementation is compiled in. */
const rt_protocol_ops_t *rt_protocol_lookup(rt_protocol_t protocol);

#endif /* RT_PROTOCOLS_PROTOCOL_H */

/*
 * Session: bridges the protocol's worker thread to the GTK main
 * loop.
 *
 * Marshaling: the protocol pushes events into a GAsyncQueue. The
 * first push wakes the UI by scheduling a one-shot g_idle source
 * (subsequent pushes coalesce - one idle drains all pending events).
 * On close we tear down the protocol first (joins its thread, so
 * no further pushes can occur), then cancel any pending idle and
 * free remaining queued events without dispatching.
 *
 * Frame messages carry only the dirty rect + dimensions; the actual
 * pixels live in the protocol-owned framebuffer. The widget locks
 * the framebuffer in its draw handler. This keeps the marshaling
 * cheap (no per-frame memcpy) and lets the UI throttle naturally
 * via gtk_widget_queue_draw_area coalescing.
 */

#include "core/session.h"

#include <gtk/gtk.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero on glibc */

typedef enum {
    UI_MSG_DATA,
    UI_MSG_STATE,
    UI_MSG_FRAME,
    UI_MSG_CLIP,
    UI_MSG_IDLE
} ui_msg_type_t;

typedef struct {
    ui_msg_type_t type;
    /* DATA */
    char    *data;
    size_t   len;
    /* STATE */
    rt_proto_state_t state;
    char            *msg;          /* may be NULL */
    /* FRAME */
    rt_remote_frame_t frame;
    /* CLIP (text payload reuses data/len) */
} ui_msg_t;

struct rt_session {
    rt_connection_t          *conn;     /* owned */
    char                     *password; /* owned, wiped on close */
    const rt_protocol_ops_t  *ops;
    rt_protocol_ctx_t        *ctx;

    rt_session_ui_callbacks_t ui;
    void                     *ui_user;

    GAsyncQueue              *queue;
    pthread_mutex_t           idle_mtx;
    guint                     idle_id;  /* 0 if none scheduled */
};

static void ui_msg_free(ui_msg_t *m)
{
    if (m == NULL) {
        return;
    }
    free(m->data);
    free(m->msg);
    free(m);
}

/* Idle handler. Runs on the GTK main thread. Drains the entire
 * queue, dispatching each event to the UI. Always returns
 * G_SOURCE_REMOVE - the next push schedules a fresh one. */
static gboolean drain_to_ui(gpointer user)
{
    rt_session_t *s = user;
    ui_msg_t     *m;

    while ((m = g_async_queue_try_pop(s->queue)) != NULL) {
        switch (m->type) {
        case UI_MSG_DATA:
            if (s->ui.on_data != NULL) {
                s->ui.on_data(s->ui_user, m->data, m->len);
            }
            break;
        case UI_MSG_STATE:
            if (s->ui.on_state != NULL) {
                s->ui.on_state(s->ui_user, m->state, m->msg);
            }
            break;
        case UI_MSG_FRAME:
            if (s->ui.on_frame != NULL) {
                s->ui.on_frame(s->ui_user, &m->frame);
            }
            break;
        case UI_MSG_CLIP:
            if (s->ui.on_clipboard_text != NULL) {
                s->ui.on_clipboard_text(s->ui_user, m->data, m->len);
            }
            break;
        case UI_MSG_IDLE:
            if (s->ui.on_idle != NULL) {
                s->ui.on_idle(s->ui_user);
            }
            break;
        }
        ui_msg_free(m);
    }

    pthread_mutex_lock(&s->idle_mtx);
    s->idle_id = 0;
    pthread_mutex_unlock(&s->idle_mtx);
    return G_SOURCE_REMOVE;
}

static void schedule_idle(rt_session_t *s)
{
    pthread_mutex_lock(&s->idle_mtx);
    if (s->idle_id == 0) {
        /* g_idle_add is thread-safe; the source attaches to the
         * default main context, which is GTK's main loop. */
        s->idle_id = g_idle_add(drain_to_ui, s);
    }
    pthread_mutex_unlock(&s->idle_mtx);
}

/* ---- callbacks invoked by the protocol on its worker thread ---- */

static void on_proto_data(void *user, const char *data, size_t len)
{
    rt_session_t *s = user;
    ui_msg_t *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        return;
    }
    m->type = UI_MSG_DATA;
    m->data = malloc(len);
    if (m->data == NULL) {
        free(m);
        return;
    }
    memcpy(m->data, data, len);
    m->len = len;
    g_async_queue_push(s->queue, m);
    schedule_idle(s);
}

static void on_proto_state(void *user, rt_proto_state_t state, const char *msg)
{
    rt_session_t *s = user;
    ui_msg_t *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        return;
    }
    m->type  = UI_MSG_STATE;
    m->state = state;
    m->msg   = (msg != NULL) ? strdup(msg) : NULL;
    g_async_queue_push(s->queue, m);
    schedule_idle(s);
}

static void on_proto_frame(void *user, const rt_remote_frame_t *frame)
{
    rt_session_t *s = user;
    if (frame == NULL) {
        return;
    }
    ui_msg_t *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        return;
    }
    m->type  = UI_MSG_FRAME;
    m->frame = *frame;
    g_async_queue_push(s->queue, m);
    schedule_idle(s);
}

static void on_proto_clipboard(void *user, const char *utf8, size_t len)
{
    rt_session_t *s = user;
    ui_msg_t *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        return;
    }
    m->type = UI_MSG_CLIP;
    m->data = malloc(len + 1);
    if (m->data == NULL) {
        free(m);
        return;
    }
    memcpy(m->data, utf8, len);
    m->data[len] = '\0';
    m->len = len;
    g_async_queue_push(s->queue, m);
    schedule_idle(s);
}

static void on_proto_idle(void *user)
{
    rt_session_t *s = user;
    ui_msg_t *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        return;
    }
    m->type = UI_MSG_IDLE;
    g_async_queue_push(s->queue, m);
    schedule_idle(s);
}

/* ---- public API ---- */

rt_session_t *rt_session_new(rt_connection_t                 *conn,
                             const char                      *password,
                             const rt_session_ui_callbacks_t *ui,
                             void                            *user)
{
    if (conn == NULL || ui == NULL) {
        return NULL;
    }

    const rt_protocol_ops_t *ops = rt_protocol_lookup(conn->protocol);
    if (ops == NULL) {
        return NULL;
    }

    rt_session_t *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->ops      = ops;
    s->ui       = *ui;
    s->ui_user  = user;
    s->queue    = g_async_queue_new();
    pthread_mutex_init(&s->idle_mtx, NULL);

    if (password != NULL) {
        s->password = strdup(password);
        if (s->password == NULL) {
            g_async_queue_unref(s->queue);
            pthread_mutex_destroy(&s->idle_mtx);
            free(s);
            return NULL;
        }
    }

    rt_proto_callbacks_t pcb = {
        .on_data           = on_proto_data,
        .on_state          = on_proto_state,
        .on_frame          = on_proto_frame,
        .on_clipboard_text = on_proto_clipboard,
        .on_idle           = on_proto_idle,
    };
    s->ctx = ops->open(conn, s->password, &pcb, s);

    /* Wipe the password copy as soon as auth has been attempted. */
    if (s->password != NULL) {
        explicit_bzero(s->password, strlen(s->password));
        free(s->password);
        s->password = NULL;
    }

    if (s->ctx == NULL) {
        /* open() may have queued an error state via callbacks AND
         * registered an idle source via g_idle_add. Cancel that
         * source first - returning G_SOURCE_REMOVE from drain_to_ui
         * only takes effect when GLib invoked it, not when we call
         * it directly - then drain synchronously so the UI still
         * sees the error before we report failure. Without this
         * cancel, the idle would fire later against a freed `s`. */
        guint pending;
        pthread_mutex_lock(&s->idle_mtx);
        pending = s->idle_id;
        s->idle_id = 0;
        pthread_mutex_unlock(&s->idle_mtx);
        if (pending != 0) {
            g_source_remove(pending);
        }
        drain_to_ui(s);
        g_async_queue_unref(s->queue);
        pthread_mutex_destroy(&s->idle_mtx);
        free(s);
        return NULL;
    }

    /* Take ownership of conn now that we've successfully opened. */
    s->conn = conn;
    return s;
}

int rt_session_send_data(rt_session_t *s, const void *data, size_t len)
{
    if (s == NULL || s->ctx == NULL || s->ops->send == NULL) {
        return -1;
    }
    return s->ops->send(s->ctx, data, len);
}

int rt_session_send_input(rt_session_t *s, const rt_input_event_t *evt)
{
    if (s == NULL || s->ctx == NULL || s->ops->send_input == NULL || evt == NULL) {
        return -1;
    }
    return s->ops->send_input(s->ctx, evt);
}

void rt_session_resize(rt_session_t *s, unsigned cols, unsigned rows)
{
    if (s == NULL || s->ctx == NULL || s->ops->resize == NULL) {
        return;
    }
    s->ops->resize(s->ctx, cols, rows);
}

int rt_session_set_clipboard_text(rt_session_t *s, const char *utf8, size_t len)
{
    if (s == NULL || s->ctx == NULL || s->ops->set_clipboard_text == NULL) {
        return -1;
    }
    return s->ops->set_clipboard_text(s->ctx, utf8, len);
}

rt_remote_framebuffer_t *rt_session_get_framebuffer(rt_session_t *s)
{
    if (s == NULL || s->ctx == NULL || s->ops->get_framebuffer == NULL) {
        return NULL;
    }
    return s->ops->get_framebuffer(s->ctx);
}

void rt_session_close(rt_session_t *s)
{
    if (s == NULL) {
        return;
    }

    /* 1. Tear down the protocol. After this returns, the worker
     *    thread is joined and no further pushes can happen. */
    if (s->ctx != NULL) {
        s->ops->close(s->ctx);
        s->ctx = NULL;
    }

    /* 2. Cancel any pending idle source. We're on the UI thread
     *    here (caller invariant), so the source is either pending
     *    or finished - it can't be running concurrently. */
    guint id;
    pthread_mutex_lock(&s->idle_mtx);
    id = s->idle_id;
    s->idle_id = 0;
    pthread_mutex_unlock(&s->idle_mtx);
    if (id != 0) {
        g_source_remove(id);
    }

    /* 3. Drain remaining queued events without dispatching. The UI
     *    widget may already be torn down. */
    if (s->queue != NULL) {
        ui_msg_t *m;
        while ((m = g_async_queue_try_pop(s->queue)) != NULL) {
            ui_msg_free(m);
        }
        g_async_queue_unref(s->queue);
        s->queue = NULL;
    }

    pthread_mutex_destroy(&s->idle_mtx);
    rt_connection_free(s->conn);
    s->conn = NULL;

    /* Defensive: in case open() failed midway and password wasn't
     * wiped yet. */
    if (s->password != NULL) {
        explicit_bzero(s->password, strlen(s->password));
        free(s->password);
    }

    free(s);
}

const rt_connection_t *rt_session_connection(rt_session_t *s)
{
    return (s != NULL) ? s->conn : NULL;
}

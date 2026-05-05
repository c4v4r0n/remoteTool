#ifndef RT_CORE_CONNECTION_H
#define RT_CORE_CONNECTION_H

#include <stddef.h>

/*
 * Connection data model.
 *
 * Pure data + small accessors. No GTK, no network. The UI layer
 * builds these from form input; the protocols layer consumes them.
 * Credentials are intentionally NOT stored here - those will live
 * behind the storage/credentials interface.
 *
 * Per-protocol options are carried via tagged pointer fields (e.g.
 * `rdp` is NULL unless `protocol == RT_PROTOCOL_RDP`). This avoids
 * polluting the base struct with fields that mean nothing for other
 * back-ends.
 */

typedef enum {
    RT_PROTOCOL_NONE = 0,
    RT_PROTOCOL_SSH,
    RT_PROTOCOL_RDP,
    RT_PROTOCOL_VNC
} rt_protocol_t;

/* RDP-specific options. Sensible defaults are filled in by
 * rt_rdp_options_new(); callers override what they need. */
typedef struct {
    char *domain;              /* heap, may be NULL */
    int   width;               /* requested remote screen width  (px) */
    int   height;              /* requested remote screen height (px) */
    int   color_depth;         /* 16, 24, or 32 */
    int   insecure_cert_bypass;/* 0/1 - lab use only, clearly marked  */
    int   clipboard_enabled;   /* 0/1 - default 1 (CLIPRDR text only) */
} rt_rdp_options_t;

/* VNC-specific options. Defaults from rt_vnc_options_new():
 * view_only=0, clipboard_enabled=1, scale_mode_fit=1. */
typedef struct {
    int  view_only;            /* 0/1 - if 1, no input forwarded to remote */
    int  clipboard_enabled;    /* 0/1 - text cut/paste both directions     */
    int  scale_mode_fit;       /* 0=Original, 1=Scale to fit (default UI) */
} rt_vnc_options_t;

typedef struct {
    rt_protocol_t      protocol;
    char              *host;      /* heap, owned */
    unsigned short     port;
    char              *username;  /* heap, owned, may be NULL */
    rt_rdp_options_t  *rdp;       /* heap, owned, NULL unless RDP */
    rt_vnc_options_t  *vnc;       /* heap, owned, NULL unless VNC */
} rt_connection_t;

rt_connection_t *rt_connection_new(void);
void             rt_connection_free(rt_connection_t *conn);

/* Setters return 0 on success, -1 on allocation failure. They make
 * a private copy of the input string and free any prior value. */
int rt_connection_set_host(rt_connection_t *conn, const char *host);
int rt_connection_set_username(rt_connection_t *conn, const char *username);

/* RDP options helpers. Defaults: 1024x768, 32bpp, cert verification
 * ON, clipboard ON. Returns NULL on allocation failure. */
rt_rdp_options_t *rt_rdp_options_new(void);
void              rt_rdp_options_free(rt_rdp_options_t *opts);
int               rt_rdp_options_set_domain(rt_rdp_options_t *opts,
                                            const char *domain);

/* VNC options helpers. Defaults: view_only OFF, clipboard ON,
 * scale-mode = fit. Returns NULL on allocation failure. */
rt_vnc_options_t *rt_vnc_options_new(void);
void              rt_vnc_options_free(rt_vnc_options_t *opts);

const char   *rt_protocol_to_string(rt_protocol_t p);
rt_protocol_t rt_protocol_from_string(const char *s);

#endif /* RT_CORE_CONNECTION_H */

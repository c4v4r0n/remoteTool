#include "core/connection.h"

#include <stdlib.h>
#include <string.h>

/* strdup wrapper that tolerates NULL input by returning NULL. */
static char *dup_str(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, s, n);
    return out;
}

rt_connection_t *rt_connection_new(void)
{
    rt_connection_t *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    c->protocol = RT_PROTOCOL_NONE;
    return c;
}

void rt_connection_free(rt_connection_t *conn)
{
    if (conn == NULL) {
        return;
    }
    free(conn->host);
    free(conn->username);
    rt_rdp_options_free(conn->rdp);
    rt_vnc_options_free(conn->vnc);
    free(conn);
}

int rt_connection_set_host(rt_connection_t *conn, const char *host)
{
    char *copy = dup_str(host);
    if (host != NULL && copy == NULL) {
        return -1;
    }
    free(conn->host);
    conn->host = copy;
    return 0;
}

int rt_connection_set_username(rt_connection_t *conn, const char *username)
{
    char *copy = dup_str(username);
    if (username != NULL && copy == NULL) {
        return -1;
    }
    free(conn->username);
    conn->username = copy;
    return 0;
}

rt_rdp_options_t *rt_rdp_options_new(void)
{
    rt_rdp_options_t *o = calloc(1, sizeof(*o));
    if (o == NULL) {
        return NULL;
    }
    o->width                = 1024;
    o->height               = 768;
    o->color_depth          = 32;
    o->insecure_cert_bypass = 0;
    o->clipboard_enabled    = 1;
    return o;
}

void rt_rdp_options_free(rt_rdp_options_t *opts)
{
    if (opts == NULL) {
        return;
    }
    free(opts->domain);
    free(opts);
}

int rt_rdp_options_set_domain(rt_rdp_options_t *opts, const char *domain)
{
    if (opts == NULL) {
        return -1;
    }
    char *copy = dup_str(domain);
    if (domain != NULL && copy == NULL) {
        return -1;
    }
    free(opts->domain);
    opts->domain = copy;
    return 0;
}

rt_vnc_options_t *rt_vnc_options_new(void)
{
    rt_vnc_options_t *o = calloc(1, sizeof(*o));
    if (o == NULL) {
        return NULL;
    }
    o->view_only         = 0;
    o->clipboard_enabled = 1;
    o->scale_mode_fit    = 1;
    return o;
}

void rt_vnc_options_free(rt_vnc_options_t *opts)
{
    free(opts);
}

const char *rt_protocol_to_string(rt_protocol_t p)
{
    switch (p) {
    case RT_PROTOCOL_SSH:  return "ssh";
    case RT_PROTOCOL_RDP:  return "rdp";
    case RT_PROTOCOL_VNC:  return "vnc";
    case RT_PROTOCOL_NONE: /* fallthrough */
    default:               return "none";
    }
}

rt_protocol_t rt_protocol_from_string(const char *s)
{
    if (s == NULL)            return RT_PROTOCOL_NONE;
    if (strcmp(s, "ssh") == 0) return RT_PROTOCOL_SSH;
    if (strcmp(s, "rdp") == 0) return RT_PROTOCOL_RDP;
    if (strcmp(s, "vnc") == 0) return RT_PROTOCOL_VNC;
    return RT_PROTOCOL_NONE;
}

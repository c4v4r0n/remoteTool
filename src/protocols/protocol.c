/*
 * Protocol registry. Each concrete protocol exposes a single
 * get_ops() entry point; the registry maps the rt_protocol_t enum
 * onto those tables. Adding a new protocol means: add a case here +
 * the get_ops() function elsewhere.
 *
 * Also implements the public framebuffer accessor helpers as a thin
 * vtbl dispatch (see framebuffer_internal.h for the layout that
 * back-ends embed).
 */

#include "protocols/protocol.h"
#include "protocols/framebuffer_internal.h"
#include "protocols/ssh/ssh_protocol.h"
#include "protocols/rdp/rdp_protocol.h"
#include "protocols/vnc/vnc_protocol.h"
#include "protocols/winrm/winrm_protocol.h"

const uint8_t *rt_remote_framebuffer_lock(rt_remote_framebuffer_t *fb,
                                          int *out_width,
                                          int *out_height,
                                          int *out_stride,
                                          rt_frame_format_t *out_format)
{
    if (fb == NULL || fb->vtbl == NULL || fb->vtbl->lock == NULL) {
        return NULL;
    }
    const uint8_t *p = NULL;
    fb->vtbl->lock(fb, &p, out_width, out_height, out_stride, out_format);
    return p;
}

void rt_remote_framebuffer_release(rt_remote_framebuffer_t *fb)
{
    if (fb == NULL || fb->vtbl == NULL || fb->vtbl->release == NULL) {
        return;
    }
    fb->vtbl->release(fb);
}

const char *rt_proto_state_to_string(rt_proto_state_t s)
{
    switch (s) {
    case RT_PROTO_STATE_DISCONNECTED:   return "disconnected";
    case RT_PROTO_STATE_CONNECTING:     return "connecting";
    case RT_PROTO_STATE_AUTHENTICATING: return "authenticating";
    case RT_PROTO_STATE_CONNECTED:      return "connected";
    case RT_PROTO_STATE_ERROR:          return "error";
    default:                            return "unknown";
    }
}

const rt_protocol_ops_t *rt_protocol_lookup(rt_protocol_t protocol)
{
    switch (protocol) {
    case RT_PROTOCOL_SSH:   return rt_ssh_get_ops();
    case RT_PROTOCOL_RDP:   return rt_rdp_get_ops();
    case RT_PROTOCOL_VNC:   return rt_vnc_get_ops();
    case RT_PROTOCOL_WINRM: return rt_winrm_get_ops();
    case RT_PROTOCOL_NONE:
    default:
        return NULL;
    }
}

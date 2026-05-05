#ifndef RT_PROTOCOLS_FRAMEBUFFER_INTERNAL_H
#define RT_PROTOCOLS_FRAMEBUFFER_INTERNAL_H

#include <stdint.h>
#include "protocols/protocol.h"

/*
 * Internal layout of rt_remote_framebuffer_t.
 *
 * Public API treats this struct as opaque (see protocol.h). Back-ends
 * (RDP, future VNC) include this header so they can embed the header
 * as their first member and supply their own vtbl. The public lock /
 * release helpers in protocol.c just dispatch through the vtbl.
 */

struct rt_remote_framebuffer; /* forward declared in protocol.h */

typedef struct rt_remote_framebuffer_vtbl {
    /* Acquire the framebuffer for read. Output args are populated
     * with the current dimensions and a stable pointer to the pixel
     * buffer. The pointer is valid until the matching release(). */
    void (*lock)   (struct rt_remote_framebuffer *self,
                    const uint8_t **out_pixels,
                    int *out_width, int *out_height,
                    int *out_stride,
                    rt_frame_format_t *out_format);

    void (*release)(struct rt_remote_framebuffer *self);
} rt_remote_framebuffer_vtbl_t;

struct rt_remote_framebuffer {
    const rt_remote_framebuffer_vtbl_t *vtbl;
    /* concrete back-ends append their own fields after this */
};

#endif /* RT_PROTOCOLS_FRAMEBUFFER_INTERNAL_H */

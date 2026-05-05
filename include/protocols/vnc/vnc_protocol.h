#ifndef RT_PROTOCOLS_VNC_PROTOCOL_H
#define RT_PROTOCOLS_VNC_PROTOCOL_H

#include "protocols/protocol.h"

/* Single entry point exposed by the VNC back-end. The registry in
 * protocols/protocol.c is the only caller; libvncclient is private
 * to the .c file. */
const rt_protocol_ops_t *rt_vnc_get_ops(void);

#endif /* RT_PROTOCOLS_VNC_PROTOCOL_H */

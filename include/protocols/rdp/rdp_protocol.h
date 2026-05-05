#ifndef RT_PROTOCOLS_RDP_PROTOCOL_H
#define RT_PROTOCOLS_RDP_PROTOCOL_H

#include "protocols/protocol.h"

/* Single entry point exposed by the RDP back-end. Nothing else
 * should include FreeRDP transitively; the registry in
 * protocols/protocol.c is the only caller. */
const rt_protocol_ops_t *rt_rdp_get_ops(void);

#endif /* RT_PROTOCOLS_RDP_PROTOCOL_H */

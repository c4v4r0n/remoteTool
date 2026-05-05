#ifndef RT_PROTOCOLS_SSH_PROTOCOL_H
#define RT_PROTOCOLS_SSH_PROTOCOL_H

#include "protocols/protocol.h"

/* Single entry point exposed by the SSH back-end. The registry in
 * protocols/protocol.c is the only caller; nothing else should
 * include libssh transitively. */
const rt_protocol_ops_t *rt_ssh_get_ops(void);

#endif /* RT_PROTOCOLS_SSH_PROTOCOL_H */

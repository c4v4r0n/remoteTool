#ifndef RT_PROTOCOLS_WINRM_PROTOCOL_H
#define RT_PROTOCOLS_WINRM_PROTOCOL_H

#include "protocols/protocol.h"

/* Single entry point exposed by the WinRM back-end. The registry in
 * protocols/protocol.c is the only caller; nothing else should
 * include libcurl / libxml2 transitively. */
const rt_protocol_ops_t *rt_winrm_get_ops(void);

#endif /* RT_PROTOCOLS_WINRM_PROTOCOL_H */

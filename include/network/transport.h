#ifndef RT_NETWORK_TRANSPORT_H
#define RT_NETWORK_TRANSPORT_H

#include <stddef.h>
#include <sys/types.h>

/*
 * Transport abstraction.
 *
 * A transport is the byte pipe a protocol speaks over. Phase 1
 * declares only the interface so plain TCP and TLS can be swapped
 * underneath the protocols layer without it caring which is in use.
 *
 * Phase 2 provides:
 *   - rt_transport_tcp_new(host, port)
 *   - rt_transport_tls_new(host, port, tls_config)
 */

typedef struct rt_transport rt_transport_t;

typedef struct {
    ssize_t (*read) (rt_transport_t *t, void       *buf, size_t len);
    ssize_t (*write)(rt_transport_t *t, const void *buf, size_t len);
    int     (*close)(rt_transport_t *t);
} rt_transport_ops_t;

#endif /* RT_NETWORK_TRANSPORT_H */

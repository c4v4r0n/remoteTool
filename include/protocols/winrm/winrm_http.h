#ifndef RT_PROTOCOLS_WINRM_HTTP_H
#define RT_PROTOCOLS_WINRM_HTTP_H

#include <stdatomic.h>
#include <stddef.h>

#include "core/connection.h"

/*
 * Tiny libcurl wrapper used only by the WinRM back-end.
 *
 * Owns one curl easy handle per session. The handle is touched only
 * from the WinRM worker thread - never from the GTK main thread. The
 * abort flag lets close() interrupt an in-flight POST promptly.
 *
 * No state leaks past an rt_winrm_http_free(): the auth password
 * string is wiped before being released to the allocator.
 */

typedef struct rt_winrm_http rt_winrm_http_t;

/* Build a handle pre-configured for the given endpoint + credentials.
 * `password` is copied internally and wiped on free; the caller may
 * scrub its own buffer immediately. `abort_flag` is observed by the
 * curl progress callback and lets close() stop a request mid-flight.
 * Returns NULL on allocation/curl init failure. */
rt_winrm_http_t *rt_winrm_http_new(const char               *endpoint_url,
                                   const char               *username,
                                   const char               *domain,
                                   const char               *password,
                                   rt_winrm_auth_t           auth,
                                   int                       ignore_cert,
                                   atomic_int               *abort_flag);

void rt_winrm_http_free(rt_winrm_http_t *h);

/* POST `body` (UTF-8 SOAP envelope) to the endpoint with the SOAP
 * Content-Type header. On success, *out_resp is heap-allocated NUL-
 * terminated response bytes (caller frees). On HTTP/network/auth
 * failure, returns -1 and writes a short diagnostic into err_buf
 * (truncated; never NULL-deref). The HTTP status code (or 0 on
 * transport error) is returned via out_status. Aborts return -1
 * with status=0 and err_buf="aborted". */
int rt_winrm_http_post(rt_winrm_http_t *h,
                       const char       *body,
                       size_t            body_len,
                       char            **out_resp,
                       size_t           *out_resp_len,
                       long             *out_status,
                       char             *err_buf,
                       size_t            err_buf_len);

#endif /* RT_PROTOCOLS_WINRM_HTTP_H */

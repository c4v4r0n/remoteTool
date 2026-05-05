#ifndef RT_STORAGE_CREDENTIALS_H
#define RT_STORAGE_CREDENTIALS_H

#include <stddef.h>

/*
 * Credential storage interface.
 *
 * Credentials are deliberately kept out of rt_connection_t so we can
 * back this with libsecret / kwallet / an encrypted file in phase 2
 * without rewriting callers. Phase 1 only declares the shape.
 *
 * The opaque rt_secret_t is whatever the backend needs (handle,
 * encrypted blob, etc.). Plaintext is never written to disk.
 */

typedef struct rt_secret rt_secret_t;

rt_secret_t *rt_credentials_load(const char *connection_id);
int          rt_credentials_store(const char  *connection_id,
                                  const char  *username,
                                  const char  *secret_plaintext);
void         rt_secret_free(rt_secret_t *s);

#endif /* RT_STORAGE_CREDENTIALS_H */

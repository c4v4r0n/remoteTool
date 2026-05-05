/*
 * Credential storage placeholder. Phase 2 will back this with
 * libsecret (Secret Service API) so plaintext never hits disk and
 * the user's keyring handles encryption + unlock.
 */

#include "storage/credentials.h"

#include <stddef.h>

rt_secret_t *rt_credentials_load(const char *connection_id)
{
    (void)connection_id;
    return NULL;
}

int rt_credentials_store(const char *connection_id,
                         const char *username,
                         const char *secret_plaintext)
{
    (void)connection_id;
    (void)username;
    (void)secret_plaintext;
    return -1;
}

void rt_secret_free(rt_secret_t *s)
{
    (void)s;
}

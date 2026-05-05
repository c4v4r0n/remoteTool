#ifndef RT_STORAGE_CREDENTIALS_H
#define RT_STORAGE_CREDENTIALS_H

#include <stddef.h>

/*
 * Credential storage interface.
 *
 * Backed by libsecret (Secret Service API): plaintext never hits disk
 * and the user's keyring handles encryption + unlock. The DB only
 * stores a `credential_id` (UUID) that ties a profile to its keyring
 * entry; the password lives in the keyring.
 *
 * The opaque rt_secret_t holds the plaintext password in memory just
 * long enough for the caller to use it. rt_secret_free() wipes the
 * buffer (explicit_bzero) before releasing it.
 */

typedef struct rt_secret rt_secret_t;

/* Generate a fresh, unique credential id (UUID-style hex string).
 * Caller frees with free(). NULL on allocation failure. */
char *rt_credentials_new_id(void);

/* Store `secret_plaintext` in the keyring under `credential_id`.
 * `display_label` is what the user sees in keyring browsers (Seahorse).
 * Returns 0 on success, -1 on failure. */
int rt_credentials_store(const char *credential_id,
                         const char *display_label,
                         const char *secret_plaintext);

/* Look up the password previously stored under `credential_id`.
 * Returns NULL if not found or on error. Caller MUST rt_secret_free. */
rt_secret_t *rt_credentials_load(const char *credential_id);

/* Remove the keyring entry for this id. Returns 0 on success or if
 * no entry existed (idempotent), -1 on real failure. */
int rt_credentials_delete(const char *credential_id);

/* Read-only view of the secret. The pointer is valid until
 * rt_secret_free; do NOT outlive it. NULL if `s` is NULL. */
const char *rt_secret_password(const rt_secret_t *s);

void rt_secret_free(rt_secret_t *s);

#endif /* RT_STORAGE_CREDENTIALS_H */

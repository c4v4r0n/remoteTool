/*
 * libsecret credential storage.
 *
 * Schema: a single Secret Service collection entry per credential, keyed
 * by two attributes:
 *   app = "remoteTool"      (constant; lets us list-and-clear our entries)
 *   id  = "<uuid>"          (per-credential unique key)
 * The display label is set to whatever the caller passes, typically
 * "remoteTool: <name>" so the user can recognize it in Seahorse.
 *
 * We use the SYNCHRONOUS libsecret APIs (secret_password_*_sync) on
 * the main thread. They block until the keyring service responds; in
 * practice that's a few ms because the Secret Service runs locally
 * over D-Bus.
 *
 * Plaintext lifetime: the loaded secret is duplicated into our own
 * heap buffer with strdup, then explicit_bzero'd + freed in
 * rt_secret_free. The libsecret-allocated copy is freed via
 * secret_password_free immediately after the dup so the only live
 * plaintext is ours.
 */

#include "storage/credentials.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero */

#include <libsecret/secret.h>

/* ------------------------------------------------------------------ */
/* Schema                                                             */
/* ------------------------------------------------------------------ */

#define RT_CRED_APP_NAME "remoteTool"

static const SecretSchema RT_CRED_SCHEMA = {
    "com.remoteTool.Credential",
    SECRET_SCHEMA_NONE,
    {
        { "app", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { "id",  SECRET_SCHEMA_ATTRIBUTE_STRING },
        { NULL,  0 }
    },
    /* Explicit reserved padding so -Wmissing-field-initializers stays
     * quiet. The SecretSchema struct has 8 reserved fields after the
     * attributes table. */
    0, 0, 0, 0, 0, 0, 0, 0
};

/* ------------------------------------------------------------------ */
/* rt_secret_t                                                        */
/* ------------------------------------------------------------------ */

struct rt_secret {
    char  *password;  /* heap, owned, NUL-terminated */
    size_t password_len;
};

static rt_secret_t *secret_new(const char *plaintext)
{
    if (plaintext == NULL) {
        return NULL;
    }
    rt_secret_t *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->password_len = strlen(plaintext);
    s->password     = malloc(s->password_len + 1);
    if (s->password == NULL) {
        free(s);
        return NULL;
    }
    memcpy(s->password, plaintext, s->password_len + 1);
    return s;
}

const char *rt_secret_password(const rt_secret_t *s)
{
    return (s != NULL) ? s->password : NULL;
}

void rt_secret_free(rt_secret_t *s)
{
    if (s == NULL) {
        return;
    }
    if (s->password != NULL) {
        explicit_bzero(s->password, s->password_len);
        free(s->password);
    }
    free(s);
}

/* ------------------------------------------------------------------ */
/* UUID generation                                                    */
/* ------------------------------------------------------------------ */

char *rt_credentials_new_id(void)
{
    /* g_uuid_string_random pulls 16 random bytes from the platform's
     * cryptographic source and formats them as canonical
     * 8-4-4-4-12 hex. Stable since GLib 2.52. */
    return g_uuid_string_random();
}

/* ------------------------------------------------------------------ */
/* CRUD                                                               */
/* ------------------------------------------------------------------ */

int rt_credentials_store(const char *credential_id,
                         const char *display_label,
                         const char *secret_plaintext)
{
    if (credential_id == NULL || secret_plaintext == NULL) {
        return -1;
    }
    GError *err = NULL;
    gboolean ok = secret_password_store_sync(
        &RT_CRED_SCHEMA,
        SECRET_COLLECTION_DEFAULT,
        display_label ? display_label : RT_CRED_APP_NAME,
        secret_plaintext,
        NULL,           /* cancellable */
        &err,
        "app", RT_CRED_APP_NAME,
        "id",  credential_id,
        NULL);
    if (!ok) {
        if (err != NULL) {
            fprintf(stderr,
                    "[remoteTool/credentials] store failed: %s\n",
                    err->message);
            g_error_free(err);
        }
        return -1;
    }
    return 0;
}

rt_secret_t *rt_credentials_load(const char *credential_id)
{
    if (credential_id == NULL) {
        return NULL;
    }
    GError *err = NULL;
    gchar *plaintext = secret_password_lookup_sync(
        &RT_CRED_SCHEMA,
        NULL,           /* cancellable */
        &err,
        "app", RT_CRED_APP_NAME,
        "id",  credential_id,
        NULL);
    if (err != NULL) {
        fprintf(stderr,
                "[remoteTool/credentials] lookup failed: %s\n",
                err->message);
        g_error_free(err);
        return NULL;
    }
    if (plaintext == NULL) {
        return NULL;  /* no entry */
    }

    rt_secret_t *s = secret_new(plaintext);

    /* libsecret allocates plaintext using its own secure allocator;
     * it wipes on free. */
    secret_password_free(plaintext);
    return s;
}

int rt_credentials_delete(const char *credential_id)
{
    if (credential_id == NULL) {
        return -1;
    }
    GError *err = NULL;
    gboolean ok = secret_password_clear_sync(
        &RT_CRED_SCHEMA,
        NULL,
        &err,
        "app", RT_CRED_APP_NAME,
        "id",  credential_id,
        NULL);
    if (!ok && err != NULL) {
        /* "no matching item" is reported as success by libsecret,
         * so any err here is a real failure. */
        fprintf(stderr,
                "[remoteTool/credentials] delete failed: %s\n",
                err->message);
        g_error_free(err);
        return -1;
    }
    return 0;
}

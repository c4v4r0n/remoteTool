#ifndef RT_STORAGE_PROFILE_H
#define RT_STORAGE_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#include "core/connection.h"

/*
 * Persistent connection profile.
 *
 * rt_profile_t is the on-disk shape of a connection. rt_connection_t
 * (in core/connection.h) is the in-flight session input. They overlap
 * intentionally, but the profile carries DB-only fields (id, name,
 * credential_id) and handles ownership separately.
 *
 * All `char *` fields are heap-owned by the profile and freed in
 * rt_profile_free().
 *
 * SQLite + libsecret are encapsulated here; UI code includes only
 * this header (plus credentials.h to actually fetch a password before
 * connecting).
 */

typedef struct {
    int64_t              id;             /* 0 if not yet saved */
    char                *name;           /* user-facing label, required */
    rt_protocol_t        protocol;
    char                *host;
    unsigned short       port;
    char                *username;       /* may be NULL */
    char                *domain;         /* may be NULL (RDP/WinRM) */
    rt_rdp_options_t    *rdp;             /* NULL unless protocol == RDP */
    rt_vnc_options_t    *vnc;             /* NULL unless protocol == VNC */
    rt_winrm_options_t  *winrm;           /* NULL unless protocol == WINRM */
    char                *credential_id;  /* libsecret key, NULL if no saved password */
    int64_t              created_at;     /* unix epoch */
    int64_t              updated_at;
} rt_profile_t;

rt_profile_t *rt_profile_new(void);
void          rt_profile_free(rt_profile_t *p);

/* Save: INSERT if id == 0, UPDATE otherwise. Stamps created_at /
 * updated_at. On INSERT, populates p->id with the assigned rowid.
 * Returns 0 on success, -1 on error. */
int rt_profile_save(rt_profile_t *p);

/* Load by id. Returns NULL if not found. */
rt_profile_t *rt_profile_load(int64_t id);

/* List all profiles, newest-updated first. Caller frees with
 * rt_profile_list_free. *out_arr is NULL when out_n == 0. */
int  rt_profile_list(rt_profile_t ***out_arr, size_t *out_n);
void rt_profile_list_free(rt_profile_t **arr, size_t n);

/* Delete the profile and its associated credential entry (if any).
 * Returns 0 on success, -1 on error. */
int rt_profile_delete(int64_t id);

/* Convert a profile into a transient rt_connection_t suitable for
 * rt_session_new. Allocates a fresh rt_connection_t the caller owns
 * (freed via rt_connection_free as usual). Returns NULL on
 * allocation failure. Does NOT touch credentials - caller fetches
 * the password separately via rt_credentials_load(p->credential_id). */
rt_connection_t *rt_profile_to_connection(const rt_profile_t *p);

#endif /* RT_STORAGE_PROFILE_H */

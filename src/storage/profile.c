/*
 * Connection-profile CRUD.
 *
 * Uses prepared statements built per-call (the savings from caching
 * are negligible at this scale and reset_or_finalize is one more
 * thing to get wrong). Each `char *` we pull out of the result is
 * strdup'd into the profile so callers can free the profile
 * independently of statement lifetime.
 *
 * Delete cascades into libsecret: a profile with credential_id != NULL
 * triggers rt_credentials_delete() before the row goes away.
 */

#include "storage/profile.h"
#include "storage/db.h"
#include "storage/credentials.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3.h>

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static char *dup_str_or_null(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    if (out != NULL) {
        memcpy(out, s, n);
    }
    return out;
}

/* sqlite3_bind_text wants the lifetime hint. We always pass strings
 * that outlive the step (heap-owned by the profile or stack), so use
 * SQLITE_STATIC to avoid the per-call copy. */
static int bind_text_or_null(sqlite3_stmt *st, int col, const char *v)
{
    return (v != NULL)
        ? sqlite3_bind_text(st, col, v, -1, SQLITE_STATIC)
        : sqlite3_bind_null(st, col);
}

static int bind_int_or_null(sqlite3_stmt *st, int col, int v, int present)
{
    return present ? sqlite3_bind_int(st, col, v)
                   : sqlite3_bind_null(st, col);
}

static char *col_text(sqlite3_stmt *st, int col)
{
    const unsigned char *t = sqlite3_column_text(st, col);
    return (t != NULL) ? dup_str_or_null((const char *)t) : NULL;
}

/* ------------------------------------------------------------------ */
/* Construction / destruction                                         */
/* ------------------------------------------------------------------ */

rt_profile_t *rt_profile_new(void)
{
    rt_profile_t *p = calloc(1, sizeof(*p));
    if (p == NULL) {
        return NULL;
    }
    p->protocol = RT_PROTOCOL_NONE;
    return p;
}

void rt_profile_free(rt_profile_t *p)
{
    if (p == NULL) {
        return;
    }
    free(p->name);
    free(p->host);
    free(p->username);
    free(p->domain);
    free(p->credential_id);
    rt_rdp_options_free(p->rdp);
    rt_vnc_options_free(p->vnc);
    free(p);
}

/* ------------------------------------------------------------------ */
/* Row -> profile                                                     */
/* ------------------------------------------------------------------ */

static rt_profile_t *profile_from_row(sqlite3_stmt *st)
{
    rt_profile_t *p = rt_profile_new();
    if (p == NULL) {
        return NULL;
    }

    p->id            = sqlite3_column_int64(st, 0);
    p->name          = col_text(st, 1);
    char *proto_str  = col_text(st, 2);
    p->protocol      = rt_protocol_from_string(proto_str);
    free(proto_str);
    p->host          = col_text(st, 3);
    p->port          = (unsigned short)sqlite3_column_int(st, 4);
    p->username      = col_text(st, 5);
    p->domain        = col_text(st, 6);

    /* rdp_* columns: present together iff this is an RDP profile. */
    if (sqlite3_column_type(st, 7) != SQLITE_NULL) {
        p->rdp = rt_rdp_options_new();
        if (p->rdp == NULL) {
            rt_profile_free(p);
            return NULL;
        }
        p->rdp->width                = sqlite3_column_int(st, 7);
        p->rdp->height               = sqlite3_column_int(st, 8);
        p->rdp->color_depth          = sqlite3_column_int(st, 9);
        p->rdp->insecure_cert_bypass = sqlite3_column_int(st, 10);
        p->rdp->clipboard_enabled    = sqlite3_column_int(st, 11);
        if (p->domain != NULL) {
            rt_rdp_options_set_domain(p->rdp, p->domain);
        }
    }

    p->credential_id = col_text(st, 12);
    p->created_at    = sqlite3_column_int64(st, 13);
    p->updated_at    = sqlite3_column_int64(st, 14);

    /* vnc_* columns: present together iff this is a VNC profile. The
     * column existence comes from schema v2; older DBs are migrated. */
    if (sqlite3_column_type(st, 15) != SQLITE_NULL) {
        p->vnc = rt_vnc_options_new();
        if (p->vnc == NULL) {
            rt_profile_free(p);
            return NULL;
        }
        p->vnc->view_only         = sqlite3_column_int(st, 15);
        p->vnc->clipboard_enabled = sqlite3_column_int(st, 16);
        const unsigned char *sm   = sqlite3_column_text(st, 17);
        p->vnc->scale_mode_fit    = (sm != NULL && strcmp((const char *)sm, "orig") == 0)
                                    ? 0 : 1;
    }
    return p;
}

/* Column order for SELECT, INSERT, UPDATE - kept identical so any
 * future schema change touches one place. */
#define RT_COLS \
    "id, name, protocol, host, port, username, domain, " \
    "rdp_width, rdp_height, rdp_color_depth, rdp_insecure, rdp_clipboard, " \
    "credential_id, created_at, updated_at, " \
    "vnc_view_only, vnc_clipboard, vnc_scale_mode"

/* ------------------------------------------------------------------ */
/* save (INSERT or UPDATE)                                            */
/* ------------------------------------------------------------------ */

int rt_profile_save(rt_profile_t *p)
{
    if (p == NULL || p->name == NULL || p->host == NULL ||
        p->protocol == RT_PROTOCOL_NONE) {
        return -1;
    }
    sqlite3 *db = rt_db_handle();
    if (db == NULL) {
        return -1;
    }

    int64_t now      = (int64_t)time(NULL);
    int     has_rdp  = (p->rdp != NULL) ? 1 : 0;
    int     has_vnc  = (p->vnc != NULL) ? 1 : 0;
    const char *vnc_sm = has_vnc ? (p->vnc->scale_mode_fit ? "fit" : "orig")
                                 : NULL;

    sqlite3_stmt *st = NULL;
    int rc;

    if (p->id == 0) {
        /* INSERT */
        const char *sql =
            "INSERT INTO connections "
            "(name, protocol, host, port, username, domain, "
            " rdp_width, rdp_height, rdp_color_depth, rdp_insecure, rdp_clipboard, "
            " credential_id, created_at, updated_at, "
            " vnc_view_only, vnc_clipboard, vnc_scale_mode) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
            return -1;
        }
        bind_text_or_null(st, 1,  p->name);
        bind_text_or_null(st, 2,  rt_protocol_to_string(p->protocol));
        bind_text_or_null(st, 3,  p->host);
        sqlite3_bind_int (st, 4,  (int)p->port);
        bind_text_or_null(st, 5,  p->username);
        bind_text_or_null(st, 6,  p->domain);
        bind_int_or_null (st, 7,  has_rdp ? p->rdp->width                : 0, has_rdp);
        bind_int_or_null (st, 8,  has_rdp ? p->rdp->height               : 0, has_rdp);
        bind_int_or_null (st, 9,  has_rdp ? p->rdp->color_depth          : 0, has_rdp);
        bind_int_or_null (st, 10, has_rdp ? p->rdp->insecure_cert_bypass : 0, has_rdp);
        bind_int_or_null (st, 11, has_rdp ? p->rdp->clipboard_enabled    : 0, has_rdp);
        bind_text_or_null(st, 12, p->credential_id);
        sqlite3_bind_int64(st, 13, now);
        sqlite3_bind_int64(st, 14, now);
        bind_int_or_null (st, 15, has_vnc ? p->vnc->view_only         : 0, has_vnc);
        bind_int_or_null (st, 16, has_vnc ? p->vnc->clipboard_enabled : 0, has_vnc);
        bind_text_or_null(st, 17, vnc_sm);

        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            return -1;
        }
        p->id         = sqlite3_last_insert_rowid(db);
        p->created_at = now;
        p->updated_at = now;
        return 0;
    }

    /* UPDATE */
    const char *sql =
        "UPDATE connections SET "
        " name=?, protocol=?, host=?, port=?, username=?, domain=?, "
        " rdp_width=?, rdp_height=?, rdp_color_depth=?, "
        " rdp_insecure=?, rdp_clipboard=?, credential_id=?, "
        " updated_at=?, "
        " vnc_view_only=?, vnc_clipboard=?, vnc_scale_mode=? "
        "WHERE id=?;";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }
    bind_text_or_null(st, 1,  p->name);
    bind_text_or_null(st, 2,  rt_protocol_to_string(p->protocol));
    bind_text_or_null(st, 3,  p->host);
    sqlite3_bind_int (st, 4,  (int)p->port);
    bind_text_or_null(st, 5,  p->username);
    bind_text_or_null(st, 6,  p->domain);
    bind_int_or_null (st, 7,  has_rdp ? p->rdp->width                : 0, has_rdp);
    bind_int_or_null (st, 8,  has_rdp ? p->rdp->height               : 0, has_rdp);
    bind_int_or_null (st, 9,  has_rdp ? p->rdp->color_depth          : 0, has_rdp);
    bind_int_or_null (st, 10, has_rdp ? p->rdp->insecure_cert_bypass : 0, has_rdp);
    bind_int_or_null (st, 11, has_rdp ? p->rdp->clipboard_enabled    : 0, has_rdp);
    bind_text_or_null(st, 12, p->credential_id);
    sqlite3_bind_int64(st, 13, now);
    bind_int_or_null (st, 14, has_vnc ? p->vnc->view_only         : 0, has_vnc);
    bind_int_or_null (st, 15, has_vnc ? p->vnc->clipboard_enabled : 0, has_vnc);
    bind_text_or_null(st, 16, vnc_sm);
    sqlite3_bind_int64(st, 17, p->id);

    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        return -1;
    }
    p->updated_at = now;
    return 0;
}

/* ------------------------------------------------------------------ */
/* load                                                               */
/* ------------------------------------------------------------------ */

rt_profile_t *rt_profile_load(int64_t id)
{
    sqlite3 *db = rt_db_handle();
    if (db == NULL) {
        return NULL;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT " RT_COLS " FROM connections WHERE id=?;",
            -1, &st, NULL) != SQLITE_OK) {
        return NULL;
    }
    sqlite3_bind_int64(st, 1, id);

    rt_profile_t *p = NULL;
    if (sqlite3_step(st) == SQLITE_ROW) {
        p = profile_from_row(st);
    }
    sqlite3_finalize(st);
    return p;
}

/* ------------------------------------------------------------------ */
/* list                                                               */
/* ------------------------------------------------------------------ */

int rt_profile_list(rt_profile_t ***out_arr, size_t *out_n)
{
    if (out_arr == NULL || out_n == NULL) {
        return -1;
    }
    *out_arr = NULL;
    *out_n   = 0;

    sqlite3 *db = rt_db_handle();
    if (db == NULL) {
        return -1;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT " RT_COLS
            " FROM connections ORDER BY updated_at DESC, id DESC;",
            -1, &st, NULL) != SQLITE_OK) {
        return -1;
    }

    size_t cap = 0, n = 0;
    rt_profile_t **arr = NULL;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        rt_profile_t *p = profile_from_row(st);
        if (p == NULL) {
            continue;
        }
        if (n + 1 > cap) {
            size_t new_cap = cap ? cap * 2 : 8;
            rt_profile_t **na = realloc(arr, new_cap * sizeof(*na));
            if (na == NULL) {
                rt_profile_free(p);
                rt_profile_list_free(arr, n);
                sqlite3_finalize(st);
                return -1;
            }
            arr = na;
            cap = new_cap;
        }
        arr[n++] = p;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        rt_profile_list_free(arr, n);
        return -1;
    }
    *out_arr = arr;
    *out_n   = n;
    return 0;
}

void rt_profile_list_free(rt_profile_t **arr, size_t n)
{
    if (arr == NULL) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        rt_profile_free(arr[i]);
    }
    free(arr);
}

/* ------------------------------------------------------------------ */
/* delete                                                             */
/* ------------------------------------------------------------------ */

int rt_profile_delete(int64_t id)
{
    /* Read credential_id first so we can clear the keyring entry
     * BEFORE losing our reference to it. If the DB delete fails,
     * we'd rather leave an orphan keyring entry than orphan a row. */
    rt_profile_t *p = rt_profile_load(id);
    char *cred_id = (p != NULL) ? dup_str_or_null(p->credential_id) : NULL;
    rt_profile_free(p);

    sqlite3 *db = rt_db_handle();
    if (db == NULL) {
        free(cred_id);
        return -1;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db, "DELETE FROM connections WHERE id=?;", -1, &st, NULL)
        != SQLITE_OK) {
        free(cred_id);
        return -1;
    }
    sqlite3_bind_int64(st, 1, id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        free(cred_id);
        return -1;
    }

    if (cred_id != NULL) {
        rt_credentials_delete(cred_id);  /* best-effort */
        free(cred_id);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* profile -> connection                                              */
/* ------------------------------------------------------------------ */

rt_connection_t *rt_profile_to_connection(const rt_profile_t *p)
{
    if (p == NULL || p->host == NULL) {
        return NULL;
    }
    rt_connection_t *c = rt_connection_new();
    if (c == NULL) {
        return NULL;
    }
    c->protocol = p->protocol;
    c->port     = p->port;
    if (rt_connection_set_host(c, p->host) != 0) {
        goto fail;
    }
    if (p->username != NULL && rt_connection_set_username(c, p->username) != 0) {
        goto fail;
    }
    if (p->rdp != NULL) {
        c->rdp = rt_rdp_options_new();
        if (c->rdp == NULL) goto fail;
        c->rdp->width                = p->rdp->width;
        c->rdp->height               = p->rdp->height;
        c->rdp->color_depth          = p->rdp->color_depth;
        c->rdp->insecure_cert_bypass = p->rdp->insecure_cert_bypass;
        c->rdp->clipboard_enabled    = p->rdp->clipboard_enabled;
        if (p->domain != NULL &&
            rt_rdp_options_set_domain(c->rdp, p->domain) != 0) {
            goto fail;
        }
    }
    if (p->vnc != NULL) {
        c->vnc = rt_vnc_options_new();
        if (c->vnc == NULL) goto fail;
        c->vnc->view_only         = p->vnc->view_only;
        c->vnc->clipboard_enabled = p->vnc->clipboard_enabled;
        c->vnc->scale_mode_fit    = p->vnc->scale_mode_fit;
    }
    return c;

fail:
    rt_connection_free(c);
    return NULL;
}

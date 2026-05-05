/*
 * SQLite handle owner + schema migration.
 *
 * Migration model: PRAGMA user_version. Each version step has its own
 * static SQL string in MIGRATIONS[]. open() walks the table from the
 * file's current user_version up to RT_DB_SCHEMA_VERSION, executing
 * each step inside a transaction. New versions = append a new entry
 * to MIGRATIONS[] and bump RT_DB_SCHEMA_VERSION; never edit existing
 * entries (that would break users with old DBs).
 *
 * Performance knobs: WAL journal + NORMAL synchronous. WAL gives us
 * concurrent readers without blocking writes; NORMAL trades a tiny
 * crash-window risk for ~5x write throughput. Both are safe defaults
 * for a desktop app where the entire DB is single-process.
 */

#include "storage/db.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define RT_DB_SCHEMA_VERSION 1

/* Per-version migration SQL. MIGRATIONS[i] is the SQL that takes the
 * DB from version i to version i+1. */
static const char *const MIGRATIONS[] = {
    /* v0 -> v1: initial schema. */
    "CREATE TABLE connections ("
    "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name            TEXT NOT NULL,"
    "  protocol        TEXT NOT NULL,"
    "  host            TEXT NOT NULL,"
    "  port            INTEGER NOT NULL,"
    "  username        TEXT,"
    "  domain          TEXT,"
    "  rdp_width       INTEGER,"
    "  rdp_height      INTEGER,"
    "  rdp_color_depth INTEGER,"
    "  rdp_insecure    INTEGER,"
    "  rdp_clipboard   INTEGER,"
    "  credential_id   TEXT,"
    "  created_at      INTEGER NOT NULL,"
    "  updated_at      INTEGER NOT NULL"
    ");"
    "CREATE INDEX idx_connections_name ON connections(name);",
};

static sqlite3 *g_db = NULL;

/* Build $HOME/.config/remoteTool/connections.db, creating the directory
 * with 0700 perms if needed. Returns malloc'd path or NULL. */
static char *db_path(void)
{
    const char *home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        return NULL;
    }
    char *cfg = NULL;
    if (asprintf(&cfg, "%s/.config/remoteTool", home) < 0) {
        return NULL;
    }
    if (mkdir(cfg, 0700) != 0 && errno != EEXIST) {
        free(cfg);
        return NULL;
    }
    char *path = NULL;
    int n = asprintf(&path, "%s/connections.db", cfg);
    free(cfg);
    return (n < 0) ? NULL : path;
}

static int exec_simple(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[remoteTool/db] SQL failed: %s\n",
                err ? err : sqlite3_errmsg(db));
        sqlite3_free(err);
    }
    return rc;
}

static int run_migrations(sqlite3 *db)
{
    /* Read current schema version. */
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &stmt, NULL)
        != SQLITE_OK) {
        return -1;
    }
    int current = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        current = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (current > RT_DB_SCHEMA_VERSION) {
        fprintf(stderr,
                "[remoteTool/db] DB schema version %d is newer than "
                "this binary (%d). Refusing to open - upgrade the app.\n",
                current, RT_DB_SCHEMA_VERSION);
        return -1;
    }

    for (int v = current; v < RT_DB_SCHEMA_VERSION; v++) {
        if (exec_simple(db, "BEGIN;") != SQLITE_OK)         return -1;
        if (exec_simple(db, MIGRATIONS[v]) != SQLITE_OK) {
            exec_simple(db, "ROLLBACK;");
            return -1;
        }
        char buf[64];
        snprintf(buf, sizeof(buf), "PRAGMA user_version = %d;", v + 1);
        if (exec_simple(db, buf) != SQLITE_OK) {
            exec_simple(db, "ROLLBACK;");
            return -1;
        }
        if (exec_simple(db, "COMMIT;") != SQLITE_OK)        return -1;
    }
    return 0;
}

int rt_db_open(void)
{
    if (g_db != NULL) {
        return 0;
    }
    char *path = db_path();
    if (path == NULL) {
        return -1;
    }

    int rc = sqlite3_open_v2(path, &g_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                             NULL);
    free(path);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[remoteTool/db] sqlite3_open: %s\n",
                g_db ? sqlite3_errmsg(g_db) : "unknown");
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    /* Tighten file perms - sqlite3_open creates with the umask, which
     * is usually 0644. Profiles (host, username) are sensitive enough
     * that 0600 is a reasonable default. */
    /* (Best-effort; ignore failure - the DB still works.) */
    char *p = db_path();
    if (p != NULL) { (void)chmod(p, 0600); free(p); }

    /* Performance / durability defaults - safe for a desktop app. */
    exec_simple(g_db, "PRAGMA journal_mode = WAL;");
    exec_simple(g_db, "PRAGMA synchronous  = NORMAL;");
    exec_simple(g_db, "PRAGMA foreign_keys = ON;");

    if (run_migrations(g_db) != 0) {
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }
    return 0;
}

void rt_db_close(void)
{
    if (g_db != NULL) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
}

sqlite3 *rt_db_handle(void)
{
    return g_db;
}

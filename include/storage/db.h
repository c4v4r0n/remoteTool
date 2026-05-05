#ifndef RT_STORAGE_DB_H
#define RT_STORAGE_DB_H

#include <sqlite3.h>

/*
 * Singleton SQLite handle for connection profiles.
 *
 * The DB lives at $HOME/.config/remoteTool/connections.db. The first
 * rt_db_open() opens the file (creating it if absent), runs any
 * required schema migrations, and stores a process-wide handle.
 * Subsequent calls are idempotent.
 *
 * Other storage modules (storage/profile.c) borrow the handle via
 * rt_db_handle(); they don't open or close it themselves. The UI never
 * touches sqlite3 directly - it goes through profile / credentials.
 *
 * Threading: the handle is NOT shared across threads. All sqlite3_*
 * calls happen on the GTK main thread (the only thread that issues
 * profile CRUD). If we ever push CRUD onto a worker we'll switch to
 * SQLITE_OPEN_FULLMUTEX or per-thread connections.
 */

int       rt_db_open(void);
void      rt_db_close(void);
sqlite3  *rt_db_handle(void);

#endif /* RT_STORAGE_DB_H */

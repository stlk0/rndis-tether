/* Settings changed while the service runs, without sudo: a UNIX socket that only root
 * and one group (admin on a real system) may open, mode 0660. The peer's uid is
 * checked again on every connection; nothing is read from anyone else.
 *
 * One request per connection, one line each way:
 *   set <name> <value>\n   ->   ok\n   or   error: <why>\n
 * A client has two seconds to send its line; connections are served one at a time.
 */
#ifndef ADMIN_H
#define ADMIN_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* Applies one setting for user uid; false and why when it is refused. */
typedef bool (*AdminSet)(uid_t uid, const char *name, const char *value, char *why, size_t why_size);

/* Exactly yes or no, for a command that is not a setting (`set paused`); false and why. */
bool admin_yes_no(const char *name, const char *value, bool *out, char *why, size_t why_size);
/* Root, or a member of group gid. */
bool admin_allowed(uid_t uid, gid_t gid);
/* Creates the socket at path for root and group gid, prepared in dir (runtime.h);
 * false if it cannot be set up. */
bool admin_serve(const char *dir, const char *path, gid_t gid, AdminSet set);

#endif

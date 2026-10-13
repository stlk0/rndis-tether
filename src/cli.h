/* Everything the command-line tool does besides running the bridge: installing the
 * service, showing its state and changing settings.
 */
#ifndef CLI_H
#define CLI_H

#include <stdbool.h>
#include <stddef.h>

/* The running daemon's state as "name=value" lines; false when no daemon answers. */
bool status_query(char *text, size_t size);

int cli_install(void);
int cli_uninstall(void);
int cli_restart(void);
int cli_status(bool raw);
int cli_monitor(void);
int cli_config(int argc, char **argv); /* arguments after "config" */

#endif

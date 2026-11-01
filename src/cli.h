/* Everything the command-line tool does besides running the bridge: installing the
 * service, showing its state and changing settings.
 */
#ifndef CLI_H
#define CLI_H

#include <stdbool.h>

int cli_install(void);
int cli_uninstall(void);
int cli_restart(void);
int cli_status(bool raw);
int cli_monitor(void);
/* disconnect (true) or connect (false), through the running service; no file changes. */
int cli_set_paused(bool paused);
int cli_config(int argc, char **argv); /* arguments after "config" */

#endif

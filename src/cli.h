/* Everything the command-line tool does besides running the bridge: installing the
 * service, showing its state and changing settings.
 */
#ifndef CLI_H
#define CLI_H

#include <stdbool.h>
#include <stddef.h>

int cli_install(void);
int cli_uninstall(void);
int cli_restart(void);
int cli_status(bool raw);
int cli_monitor(void);
/* disconnect (true) or connect (false), through the running service; no file changes. */
int cli_pause(bool paused);
#define CLI_NOT_ASKED 2 /* for cli_pause_message: nothing sent to the service yet */
#define CLI_PAUSE_DENIED "only administrators of this Mac can disconnect or connect the phone"
/* What cli_pause says, and *code its exit code. First with asked = CLI_NOT_ASKED and the
 * status read before (NULL: send the request); then with ask_service's answer (1 done,
 * 0 refused because of why, -1 no answer) and the status read after it. */
const char *cli_pause_message(const char *status, bool paused, int asked, const char *why, int *code);
/* The daemon's status lines in words, on stdout; down/up < 0: no speed line. */
void cli_print_status(const char *text, double down, double up);
int cli_config(int argc, char **argv); /* arguments after "config" */

#endif

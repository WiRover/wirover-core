#ifndef CALLBACK_H
#define CALLBACK_H

/*
 * The callbacks defined here are mechanisms for triggering external scripts
 * when certain events happen within wigateway or wicontroller.  These scripts
 * should be placed in '/etc/wirover.d/' and have the following names and
 * arguments.
 *
 * lease <node_id>
 *  Called when a lease is obtained from the root server.
 */

#define CALLBACK_DIR    "/etc/wirover.d"
#define CALL_ON_LEASE   "lease"

int call_script(const char *cmd, char *const argv[]);
int call_on_lease(int node_id);

#endif /* CALLBACK_H */


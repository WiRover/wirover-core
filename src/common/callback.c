#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "callback.h"

/*
 * Fork and execute callback script.
 *
 * TODO: Before the execve call, we should close all duplicated file descriptors
 * from the parent process for security.
 */
int call_script(const char *cmd, char *const argv[])
{
    char *const child_env[] = { NULL };

    pid_t pid = fork();
    if(pid == 0) {
        /* Child process here. */
        char *path = malloc(BUFSIZ);
        if(!path)
            exit(1);

        snprintf(path, BUFSIZ, "%s/%s", CALLBACK_DIR, cmd);

        execve(path, argv, child_env);

        /* Fail */
        free(path);
        exit(1);
    }

    return 0;
}

/*
 * Execute callback when a lease is obtained from the root server.
 */
int call_on_lease(int node_id)
{
    char node_id_str[16];
    snprintf(node_id_str, sizeof(node_id_str), "%d", node_id);

    char *args[] = {CALL_ON_LEASE, node_id_str, NULL};

    return call_script(CALL_ON_LEASE, args);
}



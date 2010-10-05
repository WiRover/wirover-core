#include <stdio.h>

#include "debug.h"
#include "remote_nodes.h"

int change_remote_node_table(struct virt_proc_remote_node* change)
{
    int ret = SUCCESS;

    FILE* file = fopen(PROC_FILE_REMOTE_NODES, "w");
    if(!file) {
        ERROR_MSG("Failed to open proc file %s", PROC_FILE_REMOTE_NODES);
        ret = FAILURE;
        goto done;
    }

    int completed = fwrite(change, sizeof(*change), 1, file);
    if(completed < 1) {
        DEBUG_MSG("Failed to write to proc file %s", PROC_FILE_REMOTE_NODES);
        ret = FAILURE;
        goto close_file;
    }

close_file:
    fclose(file);
done:
    return ret;
}

int change_remote_link_table(struct virt_proc_remote_link* change)
{
    int ret = SUCCESS;

    FILE* file = fopen(PROC_FILE_REMOTE_LINKS, "w");
    if(!file) {
        ERROR_MSG("Failed to open proc file %s", PROC_FILE_REMOTE_LINKS);
        ret = FAILURE;
        goto done;
    }

    int completed = fwrite(change, sizeof(*change), 1, file);
    if(completed < 1) {
        DEBUG_MSG("Failed to write to proc file %s", PROC_FILE_REMOTE_LINKS);
        ret = FAILURE;
        goto close_file;
    }

close_file:
    fclose(file);
done:
    return ret;

}



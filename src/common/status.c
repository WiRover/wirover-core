#include "config.h"
#include "configuration.h"
#include "constants.h"
#include "debug.h"
#include "flow_table.h"
#include "interface.h"
#include "timing.h"
#ifdef GATEWAY
#include "state.h"
#endif

static void* status_thread_func(void* arg);

static int          status_log_enabled = 0;
static long         status_interval = USECS_PER_SEC;
static int          running = 0;
static pthread_t    status_thread;

int start_status_thread()
{
    status_log_enabled = get_status_log_enabled();
    if(!status_log_enabled) 
        return SUCCESS;

    if(running) {
        DEBUG_MSG("Status thread already running");
        return 0;
    }

    pthread_attr_t attr;

    // Initialize and set thread detached attribute
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int result = pthread_create(&status_thread, &attr, status_thread_func, 0);
    if(result != 0) {
        ERROR_MSG("Creating thread failed");
        return FAILURE;
    }

    running = 1;

    pthread_attr_destroy(&attr);
    return SUCCESS;
}


void* status_thread_func(void* arg)
{
    while(1)
    {
        obtain_read_lock(&interface_list_lock);
        dump_interfaces_to_file(interface_list, "/var/lib/wirover/ife_list");
        release_read_lock(&interface_list_lock);

        dump_flow_table_to_file("/var/lib/wirover/flow_table");
#ifdef GATEWAY
        FILE *ft_file = fopen("/var/lib/wirover/state", "w");
        fprintf(ft_file, "%d\n", state);
        fclose(ft_file);
#endif

        safe_usleep(status_interval);
    }
    return NULL;
}
#include <stdio.h>
#include <getopt.h>

#include "arguments.h"

static struct option long_options[] = {
    {"debug",     no_argument, 0, 'd'},
    {0,           0,           0, 0  },
};

static struct arguments arguments = {
    .debug_on       = 0,
};

static void print_usage(const char *cmd)
{
    printf("Usage: %s [--debug]\n", cmd);
}

int parse_arguments(int argc, char *argv[])
{
    int c;
    while(1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "", long_options, &option_index);
        if(c == -1)
            break;

            switch(c) {
                case 'd':
                    arguments.debug_on = 1;
                    break;
                default:
                    print_usage(argv[0]);
                    return -1;
        }
    }

    return 0;
}

const struct arguments *get_arguments()
{
    return &arguments;
}


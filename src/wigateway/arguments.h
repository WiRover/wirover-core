#ifndef ARGUMENTS_H
#define ARGUMENTS_H

struct arguments {
    int debug_on;
};

int parse_arguments(int argc, char *argv[]);
const struct arguments *get_arguments();

#define ARGS (*get_arguments())

#endif /* ARGUMENTS_H */


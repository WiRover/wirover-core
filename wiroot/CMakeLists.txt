add_executable(wiroot
    wiroot.c
    lease.c
    controllers.c
    ${COMMON}/debug.c
    ${COMMON}/sockets.c
)

# Link in libconfig, a flexible config file parser
target_link_libraries(wiroot config)

add_executable(test
    test.c
    ${COMMON}/debug.c
    ${COMMON}/sockets.c
)


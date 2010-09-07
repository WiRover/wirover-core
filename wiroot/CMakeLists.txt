add_executable(wiroot
    wiroot.c
    database.c
    lease.c
    controllers.c
    ${COMMON}/debug.c
    ${COMMON}/sockets.c
)

target_link_libraries(wiroot config mysqlclient)


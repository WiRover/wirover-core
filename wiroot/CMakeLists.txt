set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DROOT")

add_executable(wiroot
    wiroot.c
    database.c
    lease.c
    controllers.c
    ${COMMON}/configuration.c
    ${COMMON}/debug.c
    ${COMMON}/sockets.c
)

target_link_libraries(wiroot config mysqlclient)


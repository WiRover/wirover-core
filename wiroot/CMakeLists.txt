set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DROOT")

add_executable(wiroot
    wiroot.c
    database.c
    lease.c
    controllers.c
    ${COMMON}/configuration.c
    ${COMMON}/debug.c
    ${COMMON}/ipaddr.c
    ${COMMON}/sockets.c
    ${COMMON}/format.c
)

target_link_libraries(wiroot config mysqlclient)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wiroot DESTINATION /usr/bin)
install(FILES wiroot.conf DESTINATION /etc)


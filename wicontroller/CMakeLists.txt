set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONTROLLER")

add_executable(wicontroller
    wicontroller.c
    bandwidth.c
    contchan.c
    database.c
    gateway.c
    ping.c
    ${COMMON}/configuration.c
    ${COMMON}/debug.c
    ${COMMON}/interface.c
    ${COMMON}/ipaddr.c
    ${COMMON}/ping.c
    ${COMMON}/rootchan.c
    ${COMMON}/rwlock.c
    ${COMMON}/sockets.c
    ${COMMON}/timing.c
    ${COMMON}/kernel.c
    ${COMMON}/format.c
)

target_link_libraries(wicontroller pthread config mysqlclient ssl crypto)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wicontroller DESTINATION /usr/bin)
install(FILES wicontroller.conf DESTINATION /etc)


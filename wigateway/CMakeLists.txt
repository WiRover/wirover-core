set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DGATEWAY")

add_executable(wigateway
    wigateway.c
    contchan.c
    ping.c
    ${COMMON}/configuration.c
    ${COMMON}/debug.c
    ${COMMON}/interface.c
    ${COMMON}/netlink.c
    ${COMMON}/rootchan.c
    ${COMMON}/rwlock.c
    ${COMMON}/sockets.c
    ${COMMON}/kernel.c
)

target_link_libraries(wigateway pthread config)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wigateway DESTINATION /usr/bin)
install(FILES wigateway.conf DESTINATION /etc)


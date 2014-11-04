set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}/wigateway -DGATEWAY")

add_executable(wigateway
    wigateway.c
    bandwidth.c
    contchan.c
    gps_handler.c
	netlink.c
    ping.c
    arguments.c
	select_interface.c
    ${COMMON}/bandwidth.c
    ${COMMON}/configuration.c
    ${COMMON}/debug.c
	${COMMON}/datapath.c
	${COMMON}/flow_table.c
    ${COMMON}/headers.c
    ${COMMON}/interface.c
    ${COMMON}/ipaddr.c
    ${COMMON}/ping.c
	${COMMON}/remote_node.c
    ${COMMON}/rootchan.c
    ${COMMON}/rwlock.c
    ${COMMON}/sockets.c
    ${COMMON}/status.c
    ${COMMON}/timing.c
	${COMMON}/packet_buffer
    ${COMMON}/tunnel.c
    ${COMMON}/callback.c
    ${COMMON}/format.c
    ${COMMON}/version.c
	${COMMON}/util.c
	${COMMON}/policy_table.c
)

target_link_libraries(wigateway pthread config gps ssl crypto m json)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wigateway DESTINATION /usr/bin)
install(FILES wigateway_upstart.conf DESTINATION /etc/init RENAME wigateway.conf)
install(FILES wigateway.conf DESTINATION /etc)


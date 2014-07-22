set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}/wicontroller -DCONTROLLER")

add_executable(wicontroller
    wicontroller.c
    bandwidth.c
    contchan.c
    database.c
    dbq.c
    ping.c
	select_interface.c
    ${COMMON}/bandwidth.c
    ${COMMON}/configuration.c
    ${COMMON}/debug.c
	${COMMON}/datapath.c
	${COMMON}/flow_table.c
    ${COMMON}/interface.c
    ${COMMON}/ipaddr.c
    ${COMMON}/netlink.c
    ${COMMON}/ping.c
	${COMMON}/remote_node.c
    ${COMMON}/rootchan.c
    ${COMMON}/rwlock.c
    ${COMMON}/sockets.c
    ${COMMON}/timing.c
	${COMMON}/tunnel.c
	${COMMON}/select_interface.c
    ${COMMON}/format.c
	${COMMON}/packetBuffer.c
	${COMMON}/util.c
	${POLICY}/policyTable.c
)

target_link_libraries(wicontroller pthread config mysqlclient ssl crypto m)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wicontroller DESTINATION /usr/bin)
install(FILES wicontroller.conf DESTINATION /etc)


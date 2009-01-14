set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}/wigateway -DGATEWAY")

add_executable(wigateway
    wigateway.c
    bandwidth.c
    contchan.c
	datapath.c
    gps_handler.c
    ping.c
    arguments.c
    ${COMMON}/bandwidth.c
    ${COMMON}/configuration.c
    ${COMMON}/debug.c
	${COMMON}/flowTable.c
    ${COMMON}/interface.c
    ${COMMON}/ipaddr.c
    ${COMMON}/netlink.c
    ${COMMON}/ping.c
    ${COMMON}/rootchan.c
    ${COMMON}/rwlock.c
    ${COMMON}/sockets.c
    ${COMMON}/timing.c
	${COMMON}/packetBuffer
    ${COMMON}/tunnelInterface.c
    ${COMMON}/callback.c
    ${COMMON}/format.c
    ${COMMON}/version.c
    ${COMMON}/pathperf.c
	${COMMON}/util.c
	${POLICY}/policyTable.c
)

target_link_libraries(wigateway pthread config gps ssl crypto m)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wigateway DESTINATION /usr/bin)
install(FILES wigateway.conf DESTINATION /etc)


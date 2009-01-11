set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}/wicontroller -DCONTROLLER -rdynamic -I/usr/include/mysql -L/usr/lib/mysql")

add_executable(wicontroller
    main
    contChan
    selectInterface
    algoPerConnWrr
    gatewayUpdater
    udp_ping
    active_bw
    ${COMMON}/parameters
    ${COMMON}/utils
    ${COMMON}/interface
    ${COMMON}/tunnelInterface
    ${COMMON}/packet_debug
    ${COMMON}/reOrderPackets
    ${COMMON}/contChan
    ${COMMON}/udp_ping
    ${COMMON}/active_bw
    ${COMMON}/link
    ${COMMON}/sockets
    ${COMMON}/special
    ${COMMON}/time_utils
    ${COMMON}/passive_bw
    ${COMMON}/debug
    ${COMMON}/flowTable
    ${COMMON}/headerParse
    ${COMMON}/packetBuffer
    ${COMMON}/policyRet
)

target_link_libraries(wicontroller pthread config mysqlclient ssl crypto m)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wicontroller DESTINATION /usr/bin)
install(FILES wicontroller.conf DESTINATION /etc)

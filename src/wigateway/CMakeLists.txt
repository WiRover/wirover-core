set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}/wigateway -DGATEWAY")

add_executable(wigateway
    active_bw.c
    algoPerConnWrr.c
    contChan.c
    gpsHandler.c
    interface
    main.c
    netlink.c
    pcapSniff.c
    scan.c
    selectInterface.c
    udp_ping.c
    ${COMMON}/active_bw
    ${COMMON}/contChan
    ${COMMON}/debug
    ${COMMON}/flowTable
    ${COMMON}/handleTransfer
    ${COMMON}/headerParse
    ${COMMON}/interface
    ${COMMON}/link
    ${COMMON}/link_priority
    ${COMMON}/myssl
    ${COMMON}/packetBuffer
    ${COMMON}/packet_debug
    ${COMMON}/parameters
    ${COMMON}/passive_bw
    ${COMMON}/policy/policyFunctions
    ${COMMON}/policyRet
    ${COMMON}/reOrderPackets
    ${COMMON}/sockets
    ${COMMON}/special
    ${COMMON}/time_utils
    ${COMMON}/tunnelInterface
    ${COMMON}/udp_ping
    ${COMMON}/utils
)

target_link_libraries(wigateway pthread config gps ssl crypto m pcap crypto rt)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wigateway DESTINATION /usr/bin)
install(FILES wigateway.conf DESTINATION /etc)

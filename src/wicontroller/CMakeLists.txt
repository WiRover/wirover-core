include(FindBacktrace)

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
    ${COMMON}/circular_buffer.c
    ${COMMON}/configuration.c
    ${COMMON}/debug.c
    ${COMMON}/datapath.c
    ${COMMON}/flow_table.c
    ${COMMON}/interface.c
    ${COMMON}/ipaddr.c
    ${COMMON}/headers.c
    ${COMMON}/ping.c
    ${COMMON}/rate_control.c
    ${COMMON}/rateinfer.c
    ${COMMON}/remote_node.c
    ${COMMON}/rootchan.c
    ${COMMON}/rwlock.c
    ${COMMON}/select_interface.c
    ${COMMON}/sockets.c
    ${COMMON}/status.c
    ${COMMON}/timing.c
    ${COMMON}/tunnel.c
    ${COMMON}/format.c
    ${COMMON}/packet.c
    ${COMMON}/packet_buffer.c
    ${COMMON}/util.c
    ${COMMON}/version.c
    ${COMMON}/policy_table.c
)

target_link_libraries(wicontroller pthread config mysqlclient ssl crypto m json ${Backtrace_LIBRARIES})

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wicontroller DESTINATION /usr/bin)
install(FILES wicontroller.conf DESTINATION /etc)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wicontroller.conf ${CMAKE_CURRENT_BINARY_DIR}/wicontroller.conf COPYONLY)

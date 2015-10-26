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
    ${COMMON}/timing.c
    ${COMMON}/util.c
    ${COMMON}/version.c
)
target_link_libraries(wiroot config mysqlclient json)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wiroot DESTINATION /usr/bin)
install(FILES wiroot_upstart.conf DESTINATION /etc/init RENAME wiroot.conf)
install(FILES wiroot.conf DESTINATION /etc)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wiroot.conf ${CMAKE_CURRENT_BINARY_DIR}/wiroot.conf COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wiroot_upstart.conf ${CMAKE_CURRENT_BINARY_DIR}/wiroot_upstart.conf COPYONLY)

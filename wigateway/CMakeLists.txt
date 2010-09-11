set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DGATEWAY")

add_executable(wigateway
    wigateway.c
    contchan.c
    ${COMMON}/debug.c
    ${COMMON}/interface.c
    ${COMMON}/netlink.c
    ${COMMON}/rootchan.c
    ${COMMON}/rwlock.c
    ${COMMON}/sockets.c
    ${COMMON}/virtInterface.c
)

target_link_libraries(wigateway pthread)


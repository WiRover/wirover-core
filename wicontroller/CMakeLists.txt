set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONTROLLER")

add_executable(wicontroller
    wicontroller.c
    contchan.c
    gateway.c
    ping.c
    ${COMMON}/configuration.c
    ${COMMON}/debug.c
    ${COMMON}/interface.c
    ${COMMON}/rootchan.c
    ${COMMON}/rwlock.c
    ${COMMON}/sockets.c
    ${COMMON}/virtInterface.c
)

target_link_libraries(wicontroller pthread config)


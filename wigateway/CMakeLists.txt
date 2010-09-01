set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DGATEWAY")

add_executable(wigateway
    wigateway.c
    ${COMMON}/contchan.c
    ${COMMON}/debug.c
    ${COMMON}/sockets.c
    ${COMMON}/virtInterface.c
)


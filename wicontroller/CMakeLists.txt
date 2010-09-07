set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONTROLLER")

add_executable(wicontroller
    wicontroller.c
    ${COMMON}/debug.c
    ${COMMON}/netlink.c
    ${COMMON}/rootchan.c
    ${COMMON}/sockets.c
    ${COMMON}/virtInterface.c
)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}/policy -DPOLICY")

add_executable(vpolicy
    vpolicy.c
	policyTable.c
    ${COMMON}/debug.c
	${COMMON}/flowTable.c
)

target_link_libraries(vpolicy m)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wigateway DESTINATION /usr/bin)
install(FILES wigateway.conf DESTINATION /etc)


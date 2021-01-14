cmake_minimum_required(VERSION 2.6)

PROJECT(xdp-ipstats C)
INCLUDE(GNUInstallDirs)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations -D__KERNEL__)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

ADD_EXECUTABLE(xdp-ipstats xdp-ipstats.c prog.c net.c map.c)
TARGET_LINK_LIBRARIES(xdp-ipstats bpf nl-tiny)
INSTALL(TARGETS xdp-ipstats
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

add_custom_target(ipstats_kern ALL)
add_custom_command(TARGET ipstats_kern
	COMMAND clang -O2 -target $ENV{BPF_TARGET} -I$ENV{STAGING_DIR}/usr/include/ -I$ENV{STAGING_DIR}/usr/include/bpf/ -emit-llvm -c ${CMAKE_CURRENT_SOURCE_DIR}/ipstats_kern.c -o - | llc -march=$ENV{BPF_TARGET} -filetype=obj -o ipstats_kern.o)
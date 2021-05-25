cmake_minimum_required(VERSION 3.5)

project(redplane-store)

set(CMAKE_CXX_COMPILER g++)
add_definitions(-std=c++11 -march=native -O3)
add_definitions(-Wall -Wextra -Werror -pedantic -Wsign-conversion -Wold-style-cast)
add_definitions(-Wno-unused-function -Wno-nested-anon-types -Wno-keyword-macro)

set(LIBRARIES ${LIBRARIES} rt numa pthread gflags)

find_library(IBVERBS_LIB ibverbs)
if(NOT IBVERBS_LIB)
message(FATAL_ERROR "ibverbs library not found")
endif()

set(LIBRARIES ${LIBRARIES} ibverbs)

#Generate the shared library from the library sources
add_library(raw_transport SHARED
    raw_transport/raw_transport.cc
)
target_include_directories(raw_transport
    PUBLIC
        ${PROJECT_SOURCE_DIR}
)

target_link_libraries(raw_transport ${LIBRARIES})

# Add an executable with the above sources
#add_executable(sender
#    apps/transport_test/sender.cc
#)
#add_executable(receiver
#    apps/transport_test/receiver.cc
#)
#add_executable(test_cc
#    apps/test/test.cc
#)

add_executable(store_main
    apps/state_store/store_main.cc
)
add_executable(store_chain
    apps/state_store/store_chain.cc
)
add_executable(store_tester
    apps/state_store/store_tester.cc
)
add_executable(raw_pktgen_lat
    apps/pktgen/pktgen_lat.cc
)
add_executable(raw_pktgen_bw
    apps/pktgen/pktgen_bw.cc
)
add_executable(server_nat
    apps/server_nat/nat_main.cc
)
add_executable(nat_chain
    apps/server_nat/store_chain.cc
)

# link the new hello_library target with the hello_binary target
#target_link_libraries(sender
#    PRIVATE
#        raw_transport
#)
#target_link_libraries(receiver
#    PRIVATE
#        raw_transport
#)

target_link_libraries(store_main
    PRIVATE
        raw_transport
)

target_link_libraries(store_chain
    PRIVATE
        raw_transport
)

target_link_libraries(store_tester
    PRIVATE
        raw_transport
)

target_link_libraries(raw_pktgen_lat
    PRIVATE
        raw_transport
)
target_link_libraries(raw_pktgen_bw
    PRIVATE
        raw_transport
)

target_link_libraries(server_nat
    PRIVATE
        raw_transport
)
target_link_libraries(nat_chain
    PRIVATE
        raw_transport
)

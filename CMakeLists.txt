cmake_minimum_required(VERSION 3.15)
project(Handmade_Protocol_Stack_Based_Web_Server)

# set(CMAKE_CXX_FLAGS "$ {CMAKE_CXX_FLAGS} -fPIC")

set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

include_directories(${PROJECT_SOURCE_DIR}/src/net_data)
include_directories(${PROJECT_SOURCE_DIR}/src/net_app)
include_directories(${PROJECT_SOURCE_DIR}/src/pcap_device)
link_directories(${PROJECT_SOURCE_DIR}/lib)

add_subdirectory(src)



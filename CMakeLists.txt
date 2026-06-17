cmake_minimum_required(VERSION 4.0)
project(PortMonitoring)

set(CMAKE_CXX_STANDARD 20)

add_executable(PortMonitoring main.cpp
        PortMonitor.cpp
        PortMonitor.h)

if(WIN32)
    target_link_libraries(PortMonitoring ws2_32 iphlpapi version)
endif()
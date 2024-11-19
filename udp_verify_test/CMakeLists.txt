cmake_minimum_required(VERSION 3.5.0)

project(UdpVerifyTest VERSION 0.1.0 LANGUAGES C)

if(WIN32)
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build")
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")
elseif(UNIX)
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build")
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/lib")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/lib")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")
endif()

if(CMAKE_VERSION VERSION_LESS "3.7.0")
    set(CMAKE_INCLUDE_CURRENT_DIR ON)
endif()

if(MINGW)
    add_definitions(-D_MINGW)
endif(MINGW)

if(WIN32)
    add_definitions(-D_WIN32)
endif(WIN32)

if(UNIX)
    add_definitions(-D_UNIX)
endif(UNIX)

add_executable(UdpSender
    testutil.c
    udpsender.c
)
set_target_properties(UdpSender PROPERTIES WIN32_EXECUTABLE OFF)
target_link_libraries(UdpSender zzutil::zzmessage)

add_executable(UdpReceiver
    testutil.c
    udpreceiver.c
)
set_target_properties(UdpReceiver PROPERTIES WIN32_EXECUTABLE OFF)
target_link_libraries(UdpReceiver zzutil::zzmessage)

add_executable(CacheTest
    testutil.c
    cachetest.c
)
set_target_properties(CacheTest PROPERTIES WIN32_EXECUTABLE OFF)
target_link_libraries(CacheTest zzutil::zzcache)


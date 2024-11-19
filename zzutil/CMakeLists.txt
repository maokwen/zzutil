cmake_minimum_required(VERSION 3.5.0)

project(zzutil VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)

# if(WIN32)
#     SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build")
#     SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")
#     SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build")
#     SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")
#     SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build")
#     SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")
# elseif(UNIX)
#     SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build")
#     SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")
#     SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/lib")
#     SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/lib")
#     SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/build")
#     SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/build")
# endif()

if(MINGW)
    add_definitions(-D_MINGW)
endif(MINGW)

if(WIN32)
    add_definitions(-D_WIN32)
    add_definitions(-D_WIN32_WINNT=0x0600) # Windows Vista and up
endif(WIN32)

if(UNIX)
    add_definitions(-D_UNIX)
endif(UNIX)

add_library(zzmessage
    message/zzmessage.c
    util/basetype.c
)

target_include_directories(zzmessage PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(WIN32)
    set(ZZMESSAGE_ADDITIONAL_LIBS wsock32 ws2_32 iphlpapi)
endif(WIN32)

target_link_libraries(zzmessage ${ZZMESSAGE_ADDITIONAL_LIBS}) 

add_library(zzcache
    cache/zzcache.c
    util/basetype.c
)

target_include_directories(zzcache PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(UNIX)
    set(ZZCACHE_ADDITIONAL_LIBS pthread)
endif(UNIX)

target_link_libraries(zzcache ${ZZCACHE_ADDITIONAL_LIBS})

add_library(zzutil::zzmessage ALIAS zzmessage)
add_library(zzutil::zzcache ALIAS zzcache)

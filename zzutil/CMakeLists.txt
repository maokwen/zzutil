cmake_minimum_required(VERSION 3.5.0)

project(zzutil VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

if(WIN32)
    add_definitions(-D_WIN32)
    add_definitions(-D_WIN32_WINNT=0x0600) # Windows Vista and up
    if(MINGW)
        add_definitions(-D_MINGW)
    endif(MINGW)
endif(WIN32)

if(UNIX)
    add_definitions(-D_UNIX)
endif(UNIX)

# if(WIN32)
#     if(CMAKE_SIZEOF_VOID_P EQUAL 8) # x64
#         set(CMAKE_SHARED_LIBRARY_SUFFIX _x86_64.dll)
#     elseif(CMAKE_SIZEOF_VOID_P EQUAL 4) # x86
#         set(CMAKE_SHARED_LIBRARY_SUFFIX _x86.dll)
#     endif()
# endif()

add_library(zzmessage SHARED
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

add_library(zzcache SHARED
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

# install

include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/zzutilConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/zzutilConfig.cmake
    INSTALL_DESTINATION share/zzutil
)

install(TARGETS zzmessage zzcache
    EXPORT zzutil-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY
    ${CMAKE_CURRENT_SOURCE_DIR}/include/zzutil
    DESTINATION include
)

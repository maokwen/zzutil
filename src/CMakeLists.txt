cmake_minimum_required(VERSION 3.10.0)

project(zzutil VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)

include(lib/usbkey/cmake/usbkey.cmake)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_LIST_DIR}/build")
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_LIST_DIR}/build")
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_LIST_DIR}/build")
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_LIST_DIR}/build")
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_LIST_DIR}/build")
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_LIST_DIR}/build")

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


#####
# hex

add_library(zzhex SHARED
    src/zzhex.c
)

set_property(TARGET zzhex PROPERTY VERSION ${version})
set_property(TARGET zzhex PROPERTY SOVERSION 3)
set_property(TARGET zzhex PROPERTY
  INTERFACE_zzhex_MAJOR_VERSION 3)
set_property(TARGET zzhex APPEND PROPERTY
  COMPATIBLE_INTERFACE_STRING MathFunctions_MAJOR_VERSION
)

target_include_directories(zzhex
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

#####
# crypt

add_library(zzcrypt SHARED
    src/zzcrypt.c
)
set_property(TARGET zzcrypt PROPERTY VERSION ${version})
set_property(TARGET zzcrypt PROPERTY SOVERSION 3)
set_property(TARGET zzcrypt PROPERTY
  INTERFACE_zzcrypt_MAJOR_VERSION 3)
set_property(TARGET zzcrypt APPEND PROPERTY
  COMPATIBLE_INTERFACE_STRING MathFunctions_MAJOR_VERSION
)

target_include_directories(zzcrypt
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(zzcrypt usbkey zzhex)

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

#####
# Test

add_subdirectory(test)

#####
# Install

install(TARGETS zzhex zzcrypt zzmessage zzcache
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

install(EXPORT zzutil-targets
    FILE zzutil-targets.cmake
    NAMESPACE zzutil::
    DESTINATION lib/cmake/zzutil
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/zzutil-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/zzutil-config.cmake
    INSTALL_DESTINATION lib/cmake/zzutil
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/zzutil-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cmake/zzutil-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/cmake/zzutil-config-version.cmake
    DESTINATION lib/cmake/zzutil
)


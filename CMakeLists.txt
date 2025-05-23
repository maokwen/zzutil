cmake_minimum_required(VERSION 3.10.0)

project(
  zzutil
  VERSION 0.1.0
  LANGUAGES C)

set(CMAKE_C_STANDARD 99)

include(lib/skf/cmake/skf.cmake)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_COLOR_DIAGNOSTICS ON)

if(WIN32)
    add_definitions(-DNOMINMAX)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
      set(CMAKE_C_FLAGS_RELEASE "-O2 -s")
      set(CMAKE_CXX_FLAGS_RELEASE "-O2 -s")
    endif()
endif()

set(EXECUTABLE_OUTPUT_PATH "${CMAKE_CURRENT_LIST_DIR}/build")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_LIST_DIR}/build")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_LIST_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_LIST_DIR}/build")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_LIST_DIR}/build")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_LIST_DIR}/build")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_LIST_DIR}/build")

if(WIN32)
    add_definitions(-D_WIN32)
    add_definitions(-D_WIN32_WINNT=0x0600) # Windows Vista and up
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)
    if(MINGW)
        add_definitions(-D_MINGW)
    endif()
endif()

if(UNIX)
    add_definitions(-D_UNIX)
endif()

add_compile_definitions($<$<CONFIG:Debug>:ZZUTIL_DEBUG>
                        $<$<CONFIG:Debug>:ZZUTIL_BYPASS>)

# ====== depends

if(UNIX)
    set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/openssl")
    set(OPENSSL_USE_STATIC_LIBS TRUE)
elseif(WIN32)
    set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/openssl/win32")
    set(OPENSSL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/openssl/win32/include")
    set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/lib/openssl/win32/lib/crypto")
    set(OPENSSL_SSL_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/lib/openssl/win32/lib/ssl")
    endif()
message(OPENSSL_ROOT_DIR: ${OPENSSL_ROOT_DIR})
find_package(OpenSSL REQUIRED)

# set(FFMPEG_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/ffmpeg")
# set(FFMPEG_USE_STATIC_LIBS TRUE)
# find_package(FFmpeg REQUIRED)

include(depends/ffmpeg.cmake)

get_property(
  importTargets
  DIRECTORY "${CMAKE_SOURCE_DIR}"
  PROPERTY IMPORTED_TARGETS)
message("importTargets: " ${importTargets})

# ====== common

add_library(zzcommon STATIC src/common/helper.c)

target_include_directories(zzcommon
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
set_target_properties(zzcommon
    PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 0
        INTERFACE_zzcommon_MAJOR_VERSION 1
)

# ====== hex

add_library(zzhex SHARED src/zzhex.c)
add_library(zzutil::zzhex ALIAS zzhex)

set_target_properties(zzhex
    PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 0
        INTERFACE_zzhex_MAJOR_VERSION 1
)

target_include_directories(zzhex
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(zzhex
    PRIVATE
        zzcommon
)

# ====== crypt

add_library(zzcrypt SHARED src/zzcrypt.c)
add_library(zzutil::zzcrypt ALIAS zzcrypt)

set_target_properties(zzcrypt
    PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 0
        INTERFACE_zzcrypt_MAJOR_VERSION 1
)

get_target_property(SKF_INCLUDE_DIR skf INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(zzcrypt
    PRIVATE
        ${SKF_INCLUDE_DIR}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(zzcrypt
    PRIVATE
        zzcommon
        OpenSSL::SSL
        OpenSSL::Crypto
)

if(WIN32)
    add_custom_command(
        OUTPUT
            ${PROJECT_BINARY_DIR}/skf.dll
        COMMAND
            ${CMAKE_COMMAND} -E copy $<TARGET_FILE:skf>
            ${PROJECT_BINARY_DIR}/skf.dll
        COMMENT
            "Copying dll to build directory")
    add_custom_target(skf_runtime DEPENDS ${PROJECT_BINARY_DIR}/skf.dll)
elseif(UNIX)
    add_custom_command(
        OUTPUT
            ${PROJECT_BINARY_DIR}/libskf.so
        COMMAND
            ${CMAKE_COMMAND} -E copy $<TARGET_FILE:skf>
            ${PROJECT_BINARY_DIR}/libskf.so
        COMMENT
            "Copying so to build directory")
    add_custom_target(skf_runtime DEPENDS ${PROJECT_BINARY_DIR}/libskf.so)
endif()
add_dependencies(zzcrypt skf_runtime)

# ====== message

add_library(zzmessage SHARED src/zzmessage.c)
add_library(zzutil::zzmessage ALIAS zzmessage)

set_target_properties(zzmessage
    PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 0
        INTERFACE_zzcrypt_MAJOR_VERSION 1
)

target_include_directories(zzmessage
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

if(WIN32)
    set(ZZMESSAGE_ADDITIONAL_LIBS wsock32 ws2_32 iphlpapi)
endif(WIN32)

target_link_libraries(zzmessage
    PRIVATE
        zzcommon
        ${ZZMESSAGE_ADDITIONAL_LIBS}
)

# ====== cache

add_library(zzcache SHARED src/zzcache.c)
add_library(zzutil::zzcache ALIAS zzcache)

set_target_properties(zzcache
    PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 0
        INTERFACE_zzcrypt_MAJOR_VERSION 1
)

target_include_directories(zzcache
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(UNIX)
    set(ZZCACHE_ADDITIONAL_LIBS pthread)
endif()

target_link_libraries(zzcache
    PRIVATE
        zzcommon
        ${ZZCACHE_ADDITIONAL_LIBS}
)

# ====== capture

add_library(zzcapture SHARED src/zzcapture.c)
add_library(zzutil::zzcapture ALIAS zzcapture)

set_target_properties(zzcapture
    PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 0
        INTERFACE_zzcrypt_MAJOR_VERSION 1
)

target_include_directories(zzcapture
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(zzcapture
    PRIVATE
        ffmpeg::avformat # should before avcodec for `av_bitstream_filter_filter`
        ffmpeg::avcodec
        ffmpeg::avdevice
        ffmpeg::avutil
        ffmpeg::swscale
        ${FFMPEG_ADDITIONAL_LIBS}
)

if(UNIX)
    add_custom_command(
        TARGET zzcapture
        POST_BUILD
        COMMAND
            ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:openh264>
                $<TARGET_FILE_DIR:zzcapture>
        COMMENT "copy openh264 to output directory"
    )
endif()

if(UNIX)
    add_custom_command(
        TARGET zzcapture
        POST_BUILD
        COMMAND
            ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:openh264>
                $<TARGET_FILE_DIR:zzcapture>
        COMMENT "copy openh264 to output directory"
    )
endif()


# ====== Cross compile

# if(UNIX) set_target_properties(zzcommon PROPERTIES LINK_OPTIONS
# "-Wl,--dynamic-linker,./ld-linux-x86-64.so.2") set_target_properties(zzcache
# PROPERTIES LINK_OPTIONS "-Wl,--dynamic-linker,./ld-linux-x86-64.so.2")
# set_target_properties(zzmessage PROPERTIES LINK_OPTIONS
# "-Wl,--dynamic-linker,./ld-linux-x86-64.so.2") set_target_properties(zzcrypt
# PROPERTIES LINK_OPTIONS "-Wl,--dynamic-linker,./ld-linux-x86-64.so.2")
# set_target_properties(zzhex PROPERTIES LINK_OPTIONS
# "-Wl,--dynamic-linker,./ld-linux-x86-64.so.2") endif()

# ====== Test

add_subdirectory(test)

# ====== Install

set(CMAKE_INSTALL_PREFIX
    ${CMAKE_CURRENT_LIST_DIR}/../zzmaint/lib/zzutil)

install(
  TARGETS zzhex zzcrypt zzmessage zzcache zzcapture
  EXPORT zzutil-targets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES DESTINATION include)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/zzutil
        DESTINATION include)

install(
  EXPORT zzutil-targets
  FILE zzutil-targets.cmake
  NAMESPACE zzutil::
  DESTINATION lib/cmake/zzutil)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/zzutil-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/zzutil-config.cmake
  INSTALL_DESTINATION lib/cmake/zzutil)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/zzutil-config-version.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zzutil-config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/zzutil-config-version.cmake
        DESTINATION lib/cmake/zzutil)

if(WIN32)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/skf.dll DESTINATION bin)
    install(FILES
                $<TARGET_FILE:ffmpeg::avcodec>
                $<TARGET_FILE:ffmpeg::avdevice>
                $<TARGET_FILE:ffmpeg::avfilter>
                $<TARGET_FILE:ffmpeg::avformat>
                $<TARGET_FILE:ffmpeg::avutil>
                $<TARGET_FILE:ffmpeg::swresample>
                $<TARGET_FILE:ffmpeg::swscale>
                $<TARGET_FILE:ffmpeg::postproc>
                ${CMAKE_CURRENT_SOURCE_DIR}/lib/openssl/win32/bin/libssl-3.dll
                ${CMAKE_CURRENT_SOURCE_DIR}/lib/openssl/win32/bin/libcrypto-3.dll
                $<TARGET_FILE:openh264>
        DESTINATION bin
    )
elseif(UNIX)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libskf.so DESTINATION bin)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libopenh264.so.2.5.0 DESTINATION lib)
    # install(TARGETS zzcapture
    #     RUNTIME_DEPENDENCIES
    #     DESTINATION lib
    # )
endif()


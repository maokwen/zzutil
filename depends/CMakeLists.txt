cmake_minimum_required(VERSION 3.10)
project(zzutil_depends)
include(ExternalProject)

cmake_policy(SET CMP0135 NEW)

ExternalProject_Add(ffmpeg
    URL https://ffmpeg.org/releases/ffmpeg-4.4.5.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ./configure --enable-static --enable-pic --prefix=${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg
)

ExternalProject_Add(openssl
    URL https://github.com/openssl/openssl/releases/download/openssl-3.0.15/openssl-3.0.15.tar.gz
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ./Configure no-shared no-deprecated --prefix=${CMAKE_CURRENT_SOURCE_DIR}/../lib/openssl
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg/cmake/ffmpeg.cmake
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/ffmpeg.cmake ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg/cmake/ffmpeg.cmake
)
add_custom_target(
    copy_ffmpeg_cmake ALL
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg/cmake/ffmpeg.cmake
)


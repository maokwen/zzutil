cmake_minimum_required(VERSION 3.10)
project(zzutil_depends)
include(ExternalProject)

cmake_policy(SET CMP0135 NEW)

ExternalProject_Add(ffmpeg
    URL https://ffmpeg.org/releases/ffmpeg-4.4.5.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ./configure
        --prefix=${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg
        --enable-static
        --enable-libxcb
        --enable-pic
        --disable-all
        --disable-shared
        --disable-network
        --disable-autodetect
        --disable-debug
        --disable-asm
        --enable-avformat
        --enable-avdevice
        --enable-avcodec
        --enable-swscale
        --enable-swresample
        --enable-xlib
        --disable-doc
        --enable-indev=xcbgrab
        --enable-decoder=rawvideo
        --enable-muxer=mpegts
        --enable-encoder=libopenh264
        --enable-libopenh264
        # --enable-bsf=remove_extradata
    BUILD_COMMAND make -j
)

ExternalProject_Add(openssl
    URL https://github.com/openssl/openssl/releases/download/openssl-3.0.15/openssl-3.0.15.tar.gz
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ./Configure
        no-shared
        no-deprecated
        --prefix=${CMAKE_CURRENT_SOURCE_DIR}/../lib/openssl
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg/cmake/ffmpeg.cmake
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/ffmpeg.cmake ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg/cmake/ffmpeg.cmake
)
add_custom_target(
    copy_ffmpeg_cmake ALL
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg/cmake/ffmpeg.cmake
)


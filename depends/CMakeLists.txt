cmake_minimum_required(VERSION 3.25)
project(zzutil_depends)
include(ExternalProject)

ExternalProject_Add(nasm
    URL https://www.nasm.us/pub/nasm/releasebuilds/2.16/nasm-2.16.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP false
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND
        ./configure
        --prefix=${CMAKE_CURRENT_SOURCE_DIR}/local
    BUILD_COMMAND make -j
)

ExternalProject_Add(openh264
    URL https://github.com/cisco/openh264/archive/refs/tags/v2.5.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP false
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND echo ...
    BUILD_COMMAND
        PATH=${CMAKE_CURRENT_SOURCE_DIR}/local/bin:$ENV{PATH}
        make -j
    INSTALL_COMMAND
        make install PREFIX=${CMAKE_CURRENT_SOURCE_DIR}/../lib/openh264
    )

ExternalProject_Add(ffmpeg
    URL https://ffmpeg.org/releases/ffmpeg-4.4.5.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP false
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env PATH=${CMAKE_CURRENT_SOURCE_DIR}/local/bin:$ENV{PATH}
        ./configure
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
    DOWNLOAD_EXTRACT_TIMESTAMP false
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env PATH=${CMAKE_CURRENT_SOURCE_DIR}/local/bin:$ENV{PATH}
        ./Configure
            --prefix=${CMAKE_CURRENT_SOURCE_DIR}/../lib/openssl
            no-shared
            no-deprecated
            --release
            no-deprecated
            no-legacy
            no-shared
            no-afalgeng
            no-async
            no-autoalginit
            no-autoerrinit
            no-cached-fetch
            no-capieng
            no-cmp
            no-cms
            no-comp
            no-ct
            no-dgram
            no-dgram
            no-dso
            no-engine
            no-err
            no-filenames
            no-gost
            no-module
            no-nextprotoneg
            no-ocsp
            no-padlockeng
            no-pinshared
            no-psk
            no-rfc3779
            no-sock
            no-srp
            no-srtp
            no-sse2
            no-ssl-trace
            no-static-engine
            no-stdio
            no-tests
            no-threads
            no-ts
            no-ui-console
            no-uplink
            no-tls
            no-dtls
            no-aria
            no-bf
            no-blake2
            no-camellia
            no-cast
            no-chacha
            no-cmac
            no-des
            no-dh
            no-dsa
            no-ecdh
            no-ecdsa
            no-idea
            no-md4
            no-mdc2
            no-ocb
            no-poly1305
            no-rc2
            no-rc4
            no-rmd160
            no-scrypt
            no-seed
            no-siphash
            no-siv
            no-whirlpool
    BUILD_COMMAND make -j
    INSTALL_COMMAND make install_sw
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg/cmake/ffmpeg.cmake
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/ffmpeg.cmake ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg/cmake/ffmpeg.cmake
)
add_custom_target(
    copy_ffmpeg_cmake ALL
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../lib/ffmpeg/cmake/ffmpeg.cmake
)

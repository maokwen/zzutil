if(WIN32)
    add_library(ffmpeg::avcodec SHARED IMPORTED)
    add_library(ffmpeg::avdevice SHARED IMPORTED)
    add_library(ffmpeg::avfilter SHARED IMPORTED)
    add_library(ffmpeg::avformat SHARED IMPORTED)
    add_library(ffmpeg::avutil SHARED IMPORTED)
    add_library(ffmpeg::swresample SHARED IMPORTED)
    add_library(ffmpeg::swscale SHARED IMPORTED)
    add_library(ffmpeg::postproc SHARED IMPORTED)
    add_library(openh264 SHARED IMPORTED)

    set_target_properties(
        ffmpeg::avcodec
        ffmpeg::avdevice
        ffmpeg::avfilter
        ffmpeg::avformat
        ffmpeg::avutil
        ffmpeg::swresample
        ffmpeg::swscale
        ffmpeg::postproc
        PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    set_target_properties(ffmpeg::avcodec
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avcodec-58.dll
            IMPORTED_IMPLIB
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avcodec.lib
    )
    set_target_properties(ffmpeg::avformat
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avformat-58.dll
            IMPORTED_IMPLIB
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avformat.lib
    )
    set_target_properties(ffmpeg::avutil
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avutil-56.dll
            IMPORTED_IMPLIB
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avutil.lib)

    set_target_properties(ffmpeg::avdevice
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avdevice-58.dll
            IMPORTED_IMPLIB
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avdevice.lib)
    set_target_properties(
        ffmpeg::avfilter
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avfilter-7.dll
            IMPORTED_IMPLIB
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avfilter.lib)

    set_target_properties(
        ffmpeg::swresample
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/swresample-3.dll
            IMPORTED_IMPLIB
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/swresample.lib)

    set_target_properties(
        ffmpeg::swscale
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/swscale-5.dll
            IMPORTED_IMPLIB
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/swscale.lib)

    set_target_properties(
        ffmpeg::postproc
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/postproc-55.dll
            IMPORTED_IMPLIB
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/postproc.lib)

    set_target_properties(
        openh264
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/openh264/libwin32/libopenh264-7.dll
            IMPORTED_IMPLIB
            ${CMAKE_SOURCE_DIR}/lib/openh264/libwin32/libopenh264.dll.a)

    set(FFMPEG_ADDITIONAL_LIBS
        openh264
    )

elseif(UNIX)
    add_library(ffmpeg::avcodec STATIC IMPORTED)
    add_library(ffmpeg::avdevice STATIC IMPORTED)
    add_library(ffmpeg::avfilter STATIC IMPORTED)
    add_library(ffmpeg::avformat STATIC IMPORTED)
    add_library(ffmpeg::avutil STATIC IMPORTED)
    add_library(ffmpeg::swresample STATIC IMPORTED)
    add_library(ffmpeg::swscale STATIC IMPORTED)
    add_library(openh264 SHARED IMPORTED)

    set_target_properties(
        ffmpeg::avcodec
        ffmpeg::avdevice
        ffmpeg::avfilter
        ffmpeg::avformat
        ffmpeg::avutil
        ffmpeg::swresample
        ffmpeg::swscale
        ffmpeg::avcodec
        PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    set_target_properties(ffmpeg::avcodec
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libavcodec.a
    )
    set_target_properties(ffmpeg::avformat
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libavformat.a
    )
    set_target_properties(ffmpeg::avutil
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libavutil.a
    )
    set_target_properties(ffmpeg::avdevice
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libavdevice.a
    )
    set_target_properties(ffmpeg::avfilter
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libavfilter.a
    )
    set_target_properties(ffmpeg::swresample
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libswresample.a
    )
    set_target_properties(ffmpeg::swscale
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libswscale.a
    )
    
    set_target_properties(openh264
        PROPERTIES
            IMPORTED_LOCATION
            ${CMAKE_SOURCE_DIR}/lib/openh264/lib/libopenh264.so.2.5.0
    )

    set(FFMPEG_ADDITIONAL_LIBS
        openh264
        m
        xcb
        rt
    )
endif()

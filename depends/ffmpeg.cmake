if(WIN32)
    add_library(ffmpeg::avcodec SHARED IMPORTED)
    set_target_properties(
  ffmpeg::avcodec PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::avdevice SHARED IMPORTED)
    set_target_properties(
  ffmpeg::avdevice PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                              ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::avfilter SHARED IMPORTED)
    set_target_properties(
  ffmpeg::avfilter PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                              ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::avformat SHARED IMPORTED)
    set_target_properties(
  ffmpeg::avformat PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                              ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::avutil SHARED IMPORTED)
    set_target_properties(
  ffmpeg::avutil PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::swresample SHARED IMPORTED)
    set_target_properties(
  ffmpeg::swresample PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                                ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::swscale SHARED IMPORTED)
    set_target_properties(
  ffmpeg::swscale PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    set_property(
    TARGET ffmpeg::avcodec
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avcodec-58.dll)
    set_property(
    TARGET ffmpeg::avcodec
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avcodec.lib)

    set_property(
    TARGET ffmpeg::avformat
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avformat-58.dll)
    set_property(
    TARGET ffmpeg::avformat
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avformat.lib)

    set_property(
    TARGET ffmpeg::avutil
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avutil-56.dll)
    set_property(
    TARGET ffmpeg::avutil
    PROPERTY IMPORTED_IMPLIB ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avutil.lib)

    set_property(
    TARGET ffmpeg::avdevice
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avdevice-58.dll)
    set_property(
    TARGET ffmpeg::avdevice
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avdevice.lib)

    set_property(
    TARGET ffmpeg::avfilter
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avfilter-7.dll)
    set_property(
    TARGET ffmpeg::avfilter
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/avfilter.lib)

    set_property(
    TARGET ffmpeg::swresample
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/swresample-3.dll)
    set_property(
    TARGET ffmpeg::swresample
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/swresample.lib)

    set_property(
    TARGET ffmpeg::swscale
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/swscale-5.dll)
    set_property(
    TARGET ffmpeg::swscale
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/libwin32/swscale.lib)

elseif(UNIX)
    add_library(ffmpeg::avcodec STATIC IMPORTED)
    set_target_properties(
  ffmpeg::avcodec PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::avdevice STATIC IMPORTED)
    set_target_properties(
  ffmpeg::avdevice PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                              ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::avfilter STATIC IMPORTED)
    set_target_properties(
  ffmpeg::avfilter PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                              ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::avformat STATIC IMPORTED)
    set_target_properties(
  ffmpeg::avformat PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                              ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::avutil STATIC IMPORTED)
    set_target_properties(
  ffmpeg::avutil PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                            ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::swresample STATIC IMPORTED)
    set_target_properties(
  ffmpeg::swresample PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                                ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    add_library(ffmpeg::swscale STATIC IMPORTED)
    set_target_properties(
  ffmpeg::swscale PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/include)

    set_property(
    TARGET ffmpeg::avcodec
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libavcodec.a)
    set_property(
    TARGET ffmpeg::avformat
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libavformat.a)
    set_property(
    TARGET ffmpeg::avutil
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libavutil.a)
    set_property(
    TARGET ffmpeg::avdevice
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libavdevice.a)
    set_property(
    TARGET ffmpeg::avfilter
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libavfilter.a)
    set_property(
    TARGET ffmpeg::swresample
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libswresample.a)
    set_property(
    TARGET ffmpeg::swscale
    PROPERTY IMPORTED_LOCATION
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/lib/libswscale.a)

    set(ZZCAPTURE_ADDITIONAL_LIBS
        openh264
        m
        xcb
    )
endif()

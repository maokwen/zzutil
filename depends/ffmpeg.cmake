add_library(ffmpeg::avcodec STATIC IMPORTED)
set_target_properties(
  ffmpeg::avcodec PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                             ${CMAKE_CURRENT_LIST_DIR}/../include)

add_library(ffmpeg::avdevice STATIC IMPORTED)
set_target_properties(
  ffmpeg::avdevice PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                              ${CMAKE_CURRENT_LIST_DIR}/../include)

add_library(ffmpeg::avfilter STATIC IMPORTED)
set_target_properties(
  ffmpeg::avfilter PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                              ${CMAKE_CURRENT_LIST_DIR}/../include)

add_library(ffmpeg::avformat STATIC IMPORTED)
set_target_properties(
  ffmpeg::avformat PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                              ${CMAKE_CURRENT_LIST_DIR}/../include)

add_library(ffmpeg::avutil STATIC IMPORTED)
set_target_properties(
  ffmpeg::avutil PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                            ${CMAKE_CURRENT_LIST_DIR}/../include)

add_library(ffmpeg::swresample STATIC IMPORTED)
set_target_properties(
  ffmpeg::swresample PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                                ${CMAKE_CURRENT_LIST_DIR}/../include)

add_library(ffmpeg::swscale STATIC IMPORTED)
set_target_properties(
  ffmpeg::swscale PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                             ${CMAKE_CURRENT_LIST_DIR}/../include)

if(WIN32)
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
    set_property(
    TARGET ffmpeg::avcodec
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/linux/lib/libavcodec.a)
    set_property(
    TARGET ffmpeg::avformat
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/linux/lib/libavformat.a)
    set_property(
    TARGET ffmpeg::avutil
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/linux/lib/libavutil.a)
    set_property(
    TARGET ffmpeg::avdevice
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/linux/lib/libavdevice.a)
    set_property(
    TARGET ffmpeg::avfilter
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/linux/lib/libavfilter.a)
    set_property(
    TARGET ffmpeg::swresample
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/linux/lib/libswresample.a)
    set_property(
    TARGET ffmpeg::swscale
    PROPERTY IMPORTED_IMPLIB
             ${CMAKE_SOURCE_DIR}/lib/ffmpeg/linux/lib/libswscale.a)
endif()

cmake_minimum_required(VERSION 3.10.0)

project(
  zzutil
  VERSION 0.1.0
  LANGUAGES C)

set(CMAKE_C_STANDARD 99)

include(lib/skf/cmake/skf.cmake)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

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

# ====== common

add_library(zzcommon STATIC src/common/helper.c)

target_include_directories(
  zzcommon PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                  $<INSTALL_INTERFACE:include>)
set_property(TARGET zzcommon PROPERTY VERSION ${version})
set_property(TARGET zzcommon PROPERTY SOVERSION 0)
set_property(TARGET zzcommon PROPERTY INTERFACE_zzcommon_MAJOR_VERSION 1)

# ====== hex

add_library(zzhex SHARED src/zzhex.c)
set_property(TARGET zzhex PROPERTY VERSION ${version})
set_property(TARGET zzhex PROPERTY SOVERSION 0)
set_property(TARGET zzhex PROPERTY INTERFACE_zzhex_MAJOR_VERSION 1)

target_include_directories(
  zzhex PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
               $<INSTALL_INTERFACE:include>)

target_link_libraries(zzhex zzcommon)

# ====== crypt

add_library(zzcrypt SHARED src/zzcrypt.c)
set_property(TARGET zzcrypt PROPERTY VERSION ${version})
set_property(TARGET zzcrypt PROPERTY SOVERSION 0)
set_property(TARGET zzcrypt PROPERTY INTERFACE_zzcrypt_MAJOR_VERSION 1)

target_include_directories(
  zzcrypt PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                 $<INSTALL_INTERFACE:include>)

target_link_libraries(zzcrypt skf zzhex zzcommon)

# ====== message

add_library(zzmessage SHARED src/zzmessage.c)
set_property(TARGET zzmessage PROPERTY VERSION ${version})
set_property(TARGET zzmessage PROPERTY SOVERSION 0)
set_property(TARGET zzmessage PROPERTY INTERFACE_zzmessage_MAJOR_VERSION 1)

target_include_directories(
  zzmessage PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                   $<INSTALL_INTERFACE:include>)

if(WIN32)
  set(ZZMESSAGE_ADDITIONAL_LIBS wsock32 ws2_32 iphlpapi)
endif(WIN32)

target_link_libraries(zzmessage zzcommon ${ZZMESSAGE_ADDITIONAL_LIBS})

# ====== cache

add_library(zzcache SHARED src/zzcache.c)
set_property(TARGET zzcache PROPERTY VERSION ${version})
set_property(TARGET zzcache PROPERTY SOVERSION 0)
set_property(TARGET zzcache PROPERTY INTERFACE_zzcache_MAJOR_VERSION 1)

target_include_directories(
  zzcache PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                 $<INSTALL_INTERFACE:include>)

if(UNIX)
  set(ZZCACHE_ADDITIONAL_LIBS pthread)
endif()

target_link_libraries(zzcache zzcommon ${ZZCACHE_ADDITIONAL_LIBS})

add_library(zzutil::zzmessage ALIAS zzmessage)
add_library(zzutil::zzcache ALIAS zzcache)

# ====== Test

add_subdirectory(test)

# ====== Install

set(CMAKE_INSTALL_PREFIX
    ${CMAKE_CURRENT_LIST_DIR}/../ZZMaintenanceTool/lib/zzutil)

install(
  TARGETS zzcommon zzhex zzcrypt zzmessage zzcache
  EXPORT zzutil-targets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES
  DESTINATION include)

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

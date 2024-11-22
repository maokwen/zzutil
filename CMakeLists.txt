cmake_minimum_required(VERSION 3.5.0)
set(CMAKE_WARN_DEPRECATED OFF CACHE BOOL "" FORCE)

project(zzutil-all)

add_subdirectory(zzutil)
add_subdirectory(example)

add_dependencies(zzmessage zzcache)

set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/install)

set(SKF_LIB_WIN32
    ${CMAKE_CURRENT_LIST_DIR}/../lib/SKF_ukey_i686_1.6.21.0728.lib)
set(SKF_LIB_WIN64
    ${CMAKE_CURRENT_LIST_DIR}/../lib/SKF_ukey_x86_64_1.6.21.0728.lib)
set(SKF_RUN_WIN32
    ${CMAKE_CURRENT_LIST_DIR}/../bin/SKF_ukey_i686_1.7.22.0117.dll)
set(SKF_RUN_WIN64
    ${CMAKE_CURRENT_LIST_DIR}/../bin/SKF_ukey_x86_64_1.7.22.0117.dll)

set(SKF_LIB_UNIX_x86_32
    ${CMAKE_CURRENT_LIST_DIR}/../lib/libSKF_ms_x86_32_1.6.22.0118.so)
set(SKF_LIB_UNIX_x86_64
    ${CMAKE_CURRENT_LIST_DIR}/../lib/libSKF_ms_x86_64_1.6.21.1214.so)
set(SKF_LIB_UNIX_AMD64
    ${CMAKE_CURRENT_LIST_DIR}/../lib/libskf-amd64-glibc2.2.5.so)
set(SKF_LIB_UNIX_ARM64
    ${CMAKE_CURRENT_LIST_DIR}/../lib/libSKF_ms_gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu_1.6.21.1118.so
)

add_library(skf SHARED IMPORTED)
set_target_properties(skf PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
                                     ${CMAKE_CURRENT_LIST_DIR}/../include)

if(WIN32)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 64 bits
    set_property(TARGET skf PROPERTY IMPORTED_LOCATION ${SKF_RUN_WIN64})
    set_property(TARGET skf PROPERTY IMPORTED_IMPLIB ${SKF_LIB_WIN64})
  elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    # 32 bits
    set_property(TARGET skf PROPERTY IMPORTED_LOCATION ${SKF_RUN_WIN32})
    set_property(TARGET skf PROPERTY IMPORTED_IMPLIB ${SKF_LIB_WIN32})
  endif()
elseif(UNIX)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 64 bits
    set_property(TARGET skf PROPERTY IMPORTED_LOCATION ${SKF_LIB_UNIX_AMD64})
    set_property(TARGET skf PROPERTY IMPORTED_IMPLIB ${SKF_LIB_UNIX_AMD64})
  elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    # 32 bits
    set_property(TARGET skf PROPERTY IMPORTED_LOCATION ${SKF_LIB_UNIX_x86_32})
    set_property(TARGET skf PROPERTY IMPORTED_IMPLIB ${SKF_LIB_UNIX_x86_32})
  endif()
endif()

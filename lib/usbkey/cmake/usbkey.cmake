if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 64 bits
    add_library(usbkey SHARED IMPORTED)
    set_property(TARGET usbkey PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_LIST_DIR}/../bin/SKF_ukey_x86_64_1.7.22.0117.dll)
    set_property(TARGET usbkey PROPERTY IMPORTED_IMPLIB ${CMAKE_CURRENT_LIST_DIR}/../lib/SKF_ukey_x86_64_1.6.21.0728.lib)
    set_target_properties(usbkey PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_LIST_DIR}/../include)

    add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/SKF_ukey_x86_64_1.7.22.0117.dll
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/../bin/SKF_ukey_x86_64_1.7.22.0117.dll ${PROJECT_BINARY_DIR}/SKF_ukey_x86_64_1.7.22.0117.dll
        COMMENT "Copying dll to build directory"
    )

    add_custom_target(usbkey_runtime ALL DEPENDS ${PROJECT_BINARY_DIR}/SKF_ukey_x86_64_1.7.22.0117.dll) 
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    # 32 bits
    add_library(usbkey SHARED IMPORTED)
    set_property(TARGET usbkey PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_LIST_DIR}/../bin/SKF_ukey_i686_1.7.22.0117.dll)
    set_property(TARGET usbkey PROPERTY IMPORTED_IMPLIB ${CMAKE_CURRENT_LIST_DIR}/../lib/SKF_ukey_x86_64_1.6.21.0728.lib)
    set_target_properties(usbkey PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_LIST_DIR}/../include)

    add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/SKF_ukey_i686_1.7.22.0117.dll
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/../bin/SKF_ukey_i686_1.7.22.0117.dll ${PROJECT_BINARY_DIR}/SKF_ukey_i686_1.7.22.0117.dll
        COMMENT "Copying dll to build directory"
    )

    add_custom_target(usbkey_runtime ALL DEPENDS ${PROJECT_BINARY_DIR}/SKF_ukey_i686_1.7.22.0117.dll)
endif()

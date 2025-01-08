cmake_minimum_required(VERSION 3.10.0)

project(zzutil-test VERSION 0.1.0 LANGUAGES C)

# # # ##
# message

add_executable(test_udpsender
    testutil.c
    test_message_udpsender.c
)
set_target_properties(test_udpsender PROPERTIES WIN32_EXECUTABLE OFF)
target_link_libraries(test_udpsender zzutil::zzmessage)

add_executable(test_udpreceiver
    testutil.c
    test_message_udpreceiver.c
)
set_target_properties(test_udpreceiver PROPERTIES WIN32_EXECUTABLE OFF)
target_link_libraries(test_udpreceiver zzutil::zzmessage)

# # # ##
# cache

add_executable(test_cache
    testutil.c
    test_cache.c
)
set_target_properties(test_cache PROPERTIES WIN32_EXECUTABLE OFF)
target_link_libraries(test_cache zzutil::zzcache)

# # # ##
# crypt

add_executable(test_crypt
    testutil.c
    test_crypt.c
)

target_link_libraries(test_crypt zzcrypt zzhex)

# # # ##
# capture

add_executable(test_capture
    testutil.c
    test_capture.c
)

target_link_libraries(test_capture zzutil::zzcapture)


cmake_minimum_required(VERSION 3.10.0)

project(zzutil-test VERSION 0.1.0 LANGUAGES C)

#####
# message

add_executable(UdpSender
    testutil.c
    udpsender.c
)
set_target_properties(UdpSender PROPERTIES WIN32_EXECUTABLE OFF)
target_link_libraries(UdpSender zzutil::zzmessage)

add_executable(UdpReceiver
    testutil.c
    udpreceiver.c
)
set_target_properties(UdpReceiver PROPERTIES WIN32_EXECUTABLE OFF)
target_link_libraries(UdpReceiver zzutil::zzmessage)

#####
# cache

add_executable(CacheTest
    testutil.c
    cachetest.c
)
set_target_properties(CacheTest PROPERTIES WIN32_EXECUTABLE OFF)
target_link_libraries(CacheTest zzutil::zzcache)

#####
# crypt

add_executable(CryptTest
    crypt_test.c
)

target_link_libraries(CryptTest zzcrypt zzhex)

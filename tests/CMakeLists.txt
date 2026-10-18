cmake_minimum_required(VERSION 3.16)
project(bluetti_tests LANGUAGES CXX)

find_path(MBEDTLS_INCLUDE_DIR mbedtls/aes.h REQUIRED)
find_library(MBEDCRYPTO_LIBRARY mbedcrypto REQUIRED)

# Device K2 signatures cannot be manufactured in a test. Replace only the
# trust-anchor constant in a build-directory copy with the P-256 generator
# (test private key 1); production firmware keeps the original device key.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../components/bluetti/bluetti_encryption.cpp" CRYPTO_SOURCE)
string(REGEX MATCH "constexpr uint8_t PUBLIC_KEY_K2\\[65\\] = \\{[^}]*\\};" DEVICE_KEY "${CRYPTO_SOURCE}")
if(NOT DEVICE_KEY)
    message(FATAL_ERROR "Cannot locate the production K2 trust anchor")
endif()
set(TEST_KEY "constexpr uint8_t PUBLIC_KEY_K2[65] = {
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
    0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
    0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
    0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
    0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};")
string(REPLACE "${DEVICE_KEY}" "${TEST_KEY}" CRYPTO_SOURCE "${CRYPTO_SOURCE}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/crypto_under_test.cpp" "${CRYPTO_SOURCE}")

add_executable(bluetti_tests test_bluetti.cpp
    ../components/bluetti/bluetti.cpp "${CMAKE_CURRENT_BINARY_DIR}/crypto_under_test.cpp")
target_compile_features(bluetti_tests PRIVATE cxx_std_17)
target_include_directories(bluetti_tests PRIVATE stubs ../components/bluetti "${MBEDTLS_INCLUDE_DIR}")
target_link_libraries(bluetti_tests PRIVATE "${MBEDCRYPTO_LIBRARY}")
target_compile_options(bluetti_tests PRIVATE -Wall -Wextra -Werror -Wformat=2 -UNDEBUG)

option(SANITIZE "Run regression tests with AddressSanitizer and UndefinedBehaviorSanitizer" ON)
if(SANITIZE)
    target_compile_options(bluetti_tests PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(bluetti_tests PRIVATE -fsanitize=address,undefined)
endif()
enable_testing()
add_test(NAME protocol_and_state COMMAND bluetti_tests)

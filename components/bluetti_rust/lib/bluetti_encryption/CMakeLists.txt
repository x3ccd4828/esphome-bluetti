# The archive is built for xtensa-esp32-none-elf with the c_ffi feature.
idf_component_register()

if(NOT IDF_TARGET STREQUAL "esp32")
    message(FATAL_ERROR "The bundled Bluetti Rust archive only supports classic ESP32")
endif()

add_prebuilt_library(bluetti_rust_archive "${CMAKE_CURRENT_LIST_DIR}/../libbluetti_encryption.a")
target_link_libraries(${COMPONENT_LIB} INTERFACE bluetti_rust_archive)

cmake_minimum_required(VERSION 3.20.0)

# Explicitly set overlay file
set(DTC_OVERLAY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/boards/esp32c6_devkitc.overlay")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(covekey)

target_sources(app PRIVATE 
    src/main.c
    src/bitchat_crypto.c
)

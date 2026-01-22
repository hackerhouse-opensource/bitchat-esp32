cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(bitchat_esp32c6)

target_sources(app PRIVATE 
    src/main.c
    src/bitchat_crypto.c
)

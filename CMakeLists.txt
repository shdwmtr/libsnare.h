cmake_minimum_required(VERSION 3.14)
project(snare LANGUAGES C CXX)

add_library(snare_ INTERFACE)
add_library(snare::snare ALIAS snare_)
target_include_directories(snare_ INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

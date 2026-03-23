cmake_minimum_required(VERSION 3.14)
project(CPU)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-O2 -g")

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build)

include_directories(.)
include_directories(Common)
include_directories(Struct)
include_directories(Algos)
include_directories(Bench)

add_executable(CPU main.cpp)

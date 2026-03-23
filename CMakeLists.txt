cmake_minimum_required(VERSION 3.14)
project(HuffmanSketch VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(src src/core src/hash src/io src/experiment)

# Find libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Adaptive Huffman Sketch executable
set(ADAPTIVE_SOURCES
    src/adaptive_main.cpp
    src/core/AdaptiveHuffmanTree.cpp
    src/core/AdaptiveHuffmanLearner.cpp
    src/core/TailSketch.cpp
    src/core/BloomFilter.cpp
    src/io/PcapReader.cpp
    src/experiment/AdaptiveExperimentRunner.cpp
    src/experiment/Logger.cpp
    src/hash/hash.cpp
)

add_executable(AdaptiveHuffmanSketch ${ADAPTIVE_SOURCES})
target_include_directories(AdaptiveHuffmanSketch PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(AdaptiveHuffmanSketch ${PCAP_LIBRARIES})

# Sketch Comparison executable
set(SKETCH_COMPARISON_SOURCES
    src/sketch_comparison.cpp
    src/core/AdaptiveHuffmanTree.cpp
    src/core/AdaptiveHuffmanLearner.cpp
    src/core/TailSketch.cpp
    src/io/PcapReader.cpp
    src/hash/hash.cpp
    src/external_sketches/adapters/USSAdapter.cpp
    src/external_sketches/adapters/CocoSketchAdapter.cpp
    src/external_sketches/adapters/HyperUSSAdapter.cpp
    src/external_sketches/adapters/SandwichSketchAdapter.cpp
)

add_executable(SketchComparison ${SKETCH_COMPARISON_SOURCES})
target_include_directories(SketchComparison PRIVATE
    ${PCAP_INCLUDE_DIRS}
    src
    src/core
    src/external_sketches/common
    src/external_sketches/adapters
    src/external_sketches/structs
    ${CMAKE_SOURCE_DIR}/ComparisonSchemes/CocoSketch/CPU/Common
    ${CMAKE_SOURCE_DIR}/ComparisonSchemes/CocoSketch/CPU/Multiple
    ${CMAKE_SOURCE_DIR}/ComparisonSchemes/CocoSketch/CPU/Struct
    ${CMAKE_SOURCE_DIR}/ComparisonSchemes/HyperUSS/CPU/Common
    ${CMAKE_SOURCE_DIR}/ComparisonSchemes/HyperUSS/CPU/Multiple
    ${CMAKE_SOURCE_DIR}/ComparisonSchemes/SandwichSketch/CPU/Algos
    ${CMAKE_SOURCE_DIR}/ComparisonSchemes/SandwichSketch/CPU/Common
)
target_link_libraries(SketchComparison ${PCAP_LIBRARIES})
# Allow multiple definitions due to external sketch headers
target_link_options(SketchComparison PRIVATE "-Wl,--allow-multiple-definition")

# Installation
install(TARGETS AdaptiveHuffmanSketch SketchComparison DESTINATION bin)

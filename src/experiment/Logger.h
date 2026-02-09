#pragma once
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstdint>

// Forward declarations (defined in Metrics.h for legacy code)
struct MetricsResult;
struct FlowRecoveryResult;

// Formatted output logger for experiment results
class Logger {
public:
    // Print header for results table
    static void printHeader();

    // Print a separator line
    static void printSeparator();

    // Print window results
    static void printWindowResults(int windowNum,
                                    int chunkSize,
                                    const std::string& method,
                                    const MetricsResult& metrics,
                                    double compressionRatio,
                                    size_t memoryBits);

    // Print flow recovery results
    static void printFlowRecoveryResults(int windowNum,
                                          int chunkSize,
                                          const FlowRecoveryResult& recovery);

    // Print detailed memory breakdown for flow ID storage
    static void printMemoryBreakdown(int windowNum,
                                      int chunkSize,
                                      size_t rawIDBits,
                                      size_t compressedIDBits,
                                      size_t treeBits,
                                      size_t totalFlows,
                                      size_t totalPackets);

    // Print summary statistics
    static void printSummary(const std::string& title,
                              double avgARE,
                              double avgAAE,
                              double avgCompression,
                              size_t totalFlows);

    // Print configuration
    static void printConfig(const std::string& pcapFile,
                             int packetsPerWindow,
                             int sketchWidth,
                             int sketchDepth,
                             const std::vector<int>& chunkSizes);

    // Log message with timestamp
    static void log(const std::string& message);

    // Log error message
    static void logError(const std::string& message);

    // Format IP address as string
    static std::string ipToString(uint32_t ip);
};

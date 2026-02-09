#include "Logger.h"
#include <chrono>
#include <ctime>

// Local definitions of MetricsResult and FlowRecoveryResult
// These match the definitions in Metrics.h but avoid including deleted dependencies
#ifndef METRICS_H_INCLUDED
struct MetricsResult {
    double are;
    double aae;
    double precision;
    double recall;
    double f1Score;
    size_t flowCount;
    size_t totalPackets;
};

struct FlowRecoveryResult {
    double precision;
    double recall;
    double f1Score;
    size_t totalRecovered;
    size_t correctRecovered;
    size_t totalActual;
    size_t decodeFailed;
};
#endif

void Logger::printHeader() {
    std::cout << std::setfill('-') << std::setw(100) << "-" << std::setfill(' ') << "\n";
    std::cout << std::setw(6) << "Window"
              << std::setw(8) << "Chunk"
              << std::setw(15) << "Method"
              << std::setw(12) << "ARE"
              << std::setw(12) << "AAE"
              << std::setw(10) << "Prec"
              << std::setw(10) << "Recall"
              << std::setw(12) << "Compress"
              << std::setw(12) << "Memory(KB)"
              << "\n";
    std::cout << std::setfill('-') << std::setw(100) << "-" << std::setfill(' ') << "\n";
}

void Logger::printSeparator() {
    std::cout << std::setfill('-') << std::setw(100) << "-" << std::setfill(' ') << "\n";
}

void Logger::printWindowResults(int windowNum,
                                 int chunkSize,
                                 const std::string& method,
                                 const MetricsResult& metrics,
                                 double compressionRatio,
                                 size_t memoryBits) {
    double memoryKB = memoryBits / 8.0 / 1024.0;

    std::cout << std::fixed << std::setprecision(4);
    std::cout << std::setw(6) << windowNum
              << std::setw(8) << chunkSize
              << std::setw(15) << method
              << std::setw(12) << metrics.are
              << std::setw(12) << metrics.aae
              << std::setw(10) << metrics.precision
              << std::setw(10) << metrics.recall
              << std::setw(12) << compressionRatio
              << std::setw(12) << std::setprecision(2) << memoryKB
              << "\n";
}

void Logger::printFlowRecoveryResults(int windowNum,
                                       int chunkSize,
                                       const FlowRecoveryResult& recovery) {
    std::cout << "  --- Flow ID Recovery (Window " << windowNum << ", Chunk " << chunkSize << ") ---\n";
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "    Total Actual Flows:   " << recovery.totalActual << "\n";
    std::cout << "    Total Recovered:      " << recovery.totalRecovered << "\n";
    std::cout << "    Correctly Recovered:  " << recovery.correctRecovered << "\n";
    std::cout << "    Decode Failures:      " << recovery.decodeFailed << "\n";
    std::cout << "    Precision:            " << recovery.precision
              << " (correct/recovered = " << recovery.correctRecovered << "/" << recovery.totalRecovered << ")\n";
    std::cout << "    Recall:               " << recovery.recall
              << " (correct/actual = " << recovery.correctRecovered << "/" << recovery.totalActual << ")\n";
    std::cout << "    F1 Score:             " << recovery.f1Score << "\n";
}

void Logger::printMemoryBreakdown(int windowNum,
                                   int chunkSize,
                                   size_t rawIDBits,
                                   size_t compressedIDBits,
                                   size_t treeBits,
                                   size_t totalFlows,
                                   size_t totalPackets) {
    double rawKB = rawIDBits / 8.0 / 1024.0;
    double compressedKB = compressedIDBits / 8.0 / 1024.0;
    double treeKB = treeBits / 8.0 / 1024.0;
    double totalCompressedKB = compressedKB + treeKB;
    double compressionRatio = (compressedIDBits + treeBits > 0) ?
        static_cast<double>(rawIDBits) / (compressedIDBits + treeBits) : 0.0;
    double avgBitsPerPacket = (totalPackets > 0) ?
        static_cast<double>(compressedIDBits) / totalPackets : 0.0;

    std::cout << "  --- Memory Breakdown (Window " << windowNum << ", Chunk " << chunkSize << ") ---\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "    Total Packets:        " << totalPackets << "\n";
    std::cout << "    Unique Flows:         " << totalFlows << "\n";
    std::cout << "    Raw Flow ID Memory:   " << std::setw(10) << rawKB << " KB ("
              << rawIDBits << " bits, 104 bits/pkt)\n";
    std::cout << "    Compressed ID Memory: " << std::setw(10) << compressedKB << " KB ("
              << compressedIDBits << " bits, " << std::setprecision(1) << avgBitsPerPacket << " bits/pkt)\n";
    std::cout << "    Huffman Tree Memory:  " << std::setw(10) << std::setprecision(2) << treeKB << " KB ("
              << treeBits << " bits)\n";
    std::cout << "    Total Compressed:     " << std::setw(10) << totalCompressedKB << " KB\n";
    std::cout << "    Compression Ratio:    " << std::setw(10) << std::setprecision(4) << compressionRatio << "x";
    if (compressionRatio > 1.0) {
        std::cout << " (saved " << std::setprecision(1) << (1.0 - 1.0/compressionRatio) * 100.0 << "%)";
    } else if (compressionRatio < 1.0 && compressionRatio > 0) {
        std::cout << " (overhead " << std::setprecision(1) << (1.0/compressionRatio - 1.0) * 100.0 << "%)";
    }
    std::cout << "\n";
}

void Logger::printSummary(const std::string& title,
                           double avgARE,
                           double avgAAE,
                           double avgCompression,
                           size_t totalFlows) {
    std::cout << "\n=== " << title << " ===\n";
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "Average ARE:         " << avgARE << "\n";
    std::cout << "Average AAE:         " << avgAAE << "\n";
    std::cout << "Average Compression: " << avgCompression << "x\n";
    std::cout << "Total Unique Flows:  " << totalFlows << "\n";
}

void Logger::printConfig(const std::string& pcapFile,
                          int packetsPerWindow,
                          int sketchWidth,
                          int sketchDepth,
                          const std::vector<int>& chunkSizes) {
    std::cout << "\n=== Huffman Sketch Experiment Configuration ===\n";
    std::cout << "PCAP File:           " << pcapFile << "\n";
    std::cout << "Packets per Window:  " << packetsPerWindow << "\n";
    std::cout << "Sketch Width:        " << sketchWidth << "\n";
    std::cout << "Sketch Depth:        " << sketchDepth << "\n";
    std::cout << "Chunk Sizes:         ";
    for (size_t i = 0; i < chunkSizes.size(); i++) {
        std::cout << chunkSizes[i];
        if (i < chunkSizes.size() - 1) std::cout << ", ";
    }
    std::cout << " bits\n";
    std::cout << std::setfill('=') << std::setw(50) << "=" << std::setfill(' ') << "\n\n";
}

void Logger::log(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    struct tm* tm_info = localtime(&time);

    char buffer[20];
    strftime(buffer, 20, "%H:%M:%S", tm_info);

    std::cout << "[" << buffer << "] " << message << "\n";
}

void Logger::logError(const std::string& message) {
    std::cerr << "[ERROR] " << message << "\n";
}

std::string Logger::ipToString(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
    return oss.str();
}

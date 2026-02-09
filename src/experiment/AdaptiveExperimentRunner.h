#ifndef ADAPTIVE_EXPERIMENT_RUNNER_H
#define ADAPTIVE_EXPERIMENT_RUNNER_H

#include "AdaptiveHuffmanLearner.h"
#include "FrequentTable.h"
#include "TailSketch.h"
#include "FIFOStorage.h"
#include "BloomFilter.h"
#include "Packet.h"
#include "PcapReader.h"
#include <array>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <memory>
#include <string>
#include <chrono>

/**
 * Configuration for the adaptive Huffman experiment.
 */
struct AdaptiveConfig {
    std::string pcapFile;
    int windowSize = 100000;         // Packets per time window
    int storageCapacityKB = 128;     // Storage capacity in KB (for ID FIFO)
    int frequentTableK = 1024;       // Top-K for frequent table
    int bloomFilterSize = 1000000;   // Bloom filter bits
    int sketchRowBytes = 65536;      // Memory per sketch row (64KB default)
    int elephantThreshold = 100;     // Heavy hitter threshold (theta)
};

/**
 * Results for a single window.
 */
struct AdaptiveWindowResult {
    int windowNum = 0;
    size_t packetCount = 0;
    size_t totalNewFlows = 0;          // Total new flows detected in this window
    size_t groundTruthFlowCount = 0;

    // Performance
    double throughputPps = 0.0;        // Packets per second (insertion time only)
    double insertionTimeMs = 0.0;      // Insertion time in milliseconds
    double encodingTimeMs = 0.0;       // Encoding delay in milliseconds

    // Storage counts (with same memory budget, compressed stores more)
    size_t rawStoredCount = 0;         // Flows stored in raw FIFO
    size_t compressedStoredCount = 0;  // Flows stored in compressed FIFO

    // Bandwidth (in bits) - for all new flows, not just stored
    size_t rawIDBandwidth = 0;
    size_t compressedIDBandwidth = 0;
    size_t treeOverheadBits = 0;
    double compressionRatio = 1.0;

    // ID Recovery precision/recall
    double rawPrecision = 0.0;
    double rawRecall = 0.0;
    double recoveredPrecision = 0.0;
    double recoveredRecall = 0.0;

    // Frequency Estimation Accuracy (over recovered flows)
    double aaeAll = 0.0;            // AAE for all recovered flows
    double areAll = 0.0;            // ARE for all recovered flows
    double aaeElephant = 0.0;       // AAE for heavy hitters (freq >= theta)
    double areElephant = 0.0;       // ARE for heavy hitters
    double aaeMouse = 0.0;          // AAE for mice (freq < theta)
    double areMouse = 0.0;          // ARE for mice
    size_t elephantCount = 0;       // Number of elephant flows in recovered set
    size_t mouseCount = 0;          // Number of mouse flows in recovered set

    // Tier statistics (global totals)
    size_t tier1Count = 0;
    size_t tier2Count = 0;
    size_t tier3Count = 0;

    // Tier statistics per field (5 fields: srcIP, dstIP, srcPort, dstPort, proto)
    std::array<size_t, 5> tier1CountByField = {0, 0, 0, 0, 0};
    std::array<size_t, 5> tier2CountByField = {0, 0, 0, 0, 0};
    std::array<size_t, 5> tier3CountByField = {0, 0, 0, 0, 0};
};

/**
 * AdaptiveExperimentRunner: Main orchestration for the adaptive Huffman experiment.
 *
 * Workflow:
 * 1. Initialization: Build frequent tables from entire file, initial Huffman freqs from first window
 * 2. Per-window: Build trees -> Process packets -> Evaluate -> Update freqs from recovered IDs
 */
class AdaptiveExperimentRunner {
public:
    explicit AdaptiveExperimentRunner(const AdaptiveConfig& config);
    ~AdaptiveExperimentRunner() = default;

    /**
     * Run the complete experiment.
     */
    void run();

    /**
     * Get results for all windows.
     */
    const std::vector<AdaptiveWindowResult>& getResults() const { return results_; }

private:
    AdaptiveConfig config_;

    // Frequent tables (built once during initialization)
    std::array<FrequentTable, 5> frequentTables_;

    // Huffman learner (rebuilt each window)
    std::unique_ptr<AdaptiveHuffmanLearner> learner_;

    // Frequency sketch for estimation
    std::unique_ptr<TailSketch> frequencySketch_;

    // Bloom filter for new flow detection
    std::unique_ptr<BloomFilter> bloomFilter_;

    // FIFO storage for raw and compressed IDs
    std::unique_ptr<FIFOStorage<Packet>> storedIDs_;
    std::unique_ptr<FIFOStorage<std::string>> storedCompressedIDs_;

    // Ground truth: flow ID -> packet count
    std::unordered_map<Packet, uint64_t, PacketHash> groundTruthFreq_;

    // Bandwidth counters
    size_t windowRawBits_;
    size_t windowCompressedBits_;

    // Timing
    uint64_t windowInsertionTimeNs_;
    size_t windowPacketCount_;

    // Results
    std::vector<AdaptiveWindowResult> results_;

    // ═══════════════════════════════════════════════════════════════════
    // Initialization
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Build frequent tables by scanning the entire PCAP file.
     */
    void buildFrequentTables();

    /**
     * Build initial Huffman frequencies from first window.
     */
    void buildInitialFrequencies(PcapReader& reader);

    // ═══════════════════════════════════════════════════════════════════
    // Per-Window Processing
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Process a single window of packets.
     * Returns true if there are more packets to process.
     */
    bool processWindow(int windowNum, PcapReader& reader);

    /**
     * Evaluate the current window and compute metrics.
     */
    AdaptiveWindowResult evaluateWindow(int windowNum);

    /**
     * Calculate AAE/ARE metrics for frequency estimation.
     */
    void calculateFrequencyMetrics(
        const std::unordered_set<Packet, PacketHash>& recoveredSet,
        AdaptiveWindowResult& result);

    /**
     * Prepare for the next window using recovered IDs.
     */
    void prepareNextWindow(const std::vector<Packet>& recoveredIDs);

    /**
     * Reset per-window state.
     */
    void resetWindow();

    // ═══════════════════════════════════════════════════════════════════
    // Output
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Print header for results table.
     */
    void printHeader() const;

    /**
     * Print a single window's results.
     */
    void printWindowResult(const AdaptiveWindowResult& result) const;

    /**
     * Print summary statistics.
     */
    void printSummary() const;
};

#endif // ADAPTIVE_EXPERIMENT_RUNNER_H

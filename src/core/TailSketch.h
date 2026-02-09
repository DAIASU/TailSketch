#ifndef TAIL_SKETCH_H
#define TAIL_SKETCH_H

#include "AdaptiveHuffmanTree.h"
#include "AdaptiveHuffmanLearner.h"
#include "FrequentTable.h"
#include "Packet.h"
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <array>

// ─────────────────────────────────────────────────────────────────────────────
// Configuration: Collision Strategy
// ─────────────────────────────────────────────────────────────────────────────
// Version 1: Probabilistic replacement (P = 1/freq)
// Version 2: Decay/HeavyKeeper (decrement freq, replace if freq==0)
#define STRATEGY_VERSION 1

// ─────────────────────────────────────────────────────────────────────────────
// Partial Key Structure for Wildcard Queries
// ─────────────────────────────────────────────────────────────────────────────

struct PartialKeyDebugInfo {
    size_t recoveredIDsSize = 0;
    uint64_t lowerBound = 0;
    std::vector<int> activeIndices;
    std::vector<double> betas;
    std::vector<uint64_t> N_prev;
    std::vector<uint64_t> N_curr;
    std::vector<uint64_t> N_joint;
    std::vector<uint32_t> sketchCounts;
    std::vector<double> probabilities;
    std::vector<double> terms;
    double product = 0;
    double estimate = 0;
    double result = 0;
};

struct PartialKey {
    uint32_t srcIP = 0;
    uint32_t dstIP = 0;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t proto = 0;
    uint8_t mask = 0;  // 5-bit mask: bit i = 1 means field i is wildcard
                       // Bit 0=srcIP, 1=dstIP, 2=srcPort, 3=dstPort, 4=proto

    bool operator==(const PartialKey& other) const {
        return srcIP == other.srcIP && dstIP == other.dstIP &&
               srcPort == other.srcPort && dstPort == other.dstPort &&
               proto == other.proto && mask == other.mask;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Physical Memory Structures (Packed & Aligned)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * OPTIMIZATION 1: Bit-Packed Bucket
 * Fixed-size Bucket representing a hardware slot.
 * Layout: [ Code (8 bytes) | Freq (2 bytes) | Meta (2 bytes) ]
 * Total Size: 12 bytes (96 bits) - More efficient than previous 16 bytes.
 */
#pragma pack(push, 1)
struct PhysicalBucket {
    uint64_t code;      // Compressed code (64 bits - sufficient for Huffman + Tier2/3)
    uint16_t frequency; // Frequency count
    uint8_t  code_len;  // Length of valid bits
    uint8_t  is_valid;  // Occupancy flag (1 = occupied, 0 = empty)

    void clear() {
        code = 0;
        frequency = 0;
        code_len = 0;
        is_valid = 0;
    }
};
#pragma pack(pop)

/**
 * Metadata to navigate the flat memory block.
 * Does not store data itself, just offsets.
 */
struct RowLayout {
    size_t memory_offset;      // Start index in the main byte array
    size_t tier1_count;        // Number of uint16_t counters
    size_t tier2_count;        // Number of PhysicalBucket slots

    // For logic mapping (simulating CAM/Decoder)
    // We use a flat vector for cache-friendly lookups instead of std::map
    std::vector<uint64_t> symbol_keys;   // Sorted symbols
};

// ─────────────────────────────────────────────────────────────────────────────
// Frequency Sketch Class
// ─────────────────────────────────────────────────────────────────────────────

class TailSketch {
public:
    static constexpr int NUM_FIELDS = 5;

    TailSketch();
    ~TailSketch() = default;

    void initialize(const std::array<AdaptiveHuffmanTree, NUM_FIELDS>& trees,
                    size_t totalBytesPerRow);

    void insertPacket(const Packet& pkt, const AdaptiveHuffmanLearner& learner);

    uint32_t queryField(int fieldIdx, uint32_t value,
                        const AdaptiveHuffmanTree& tree,
                        const FrequentTable& freqTable) const;

    double queryFlowFrequency(const Packet& pkt,
                              const AdaptiveHuffmanLearner& learner,
                              uint64_t totalPackets) const;

    // Correlation-based partial key query with recovered flow set
    // If providedBeta >= 0, use it instead of computing from recoveredIDs
    // recoveredIDs is always required for lower bound calculation
    double queryPartialKey(const PartialKey& partialKey,
                           const AdaptiveHuffmanLearner& learner,
                           uint64_t totalPackets,
                           const std::vector<Packet>& recoveredIDs,
                           double providedBeta = -1.0,
                           bool debug = false,
                           PartialKeyDebugInfo* debugInfo = nullptr) const;

    // Pattern-Global Beta: Pre-calculate beta once per pattern
    double computePatternBeta(uint8_t mask, const std::vector<Packet>& recoveredIDs,
                              std::vector<int>* activeIndicesOut = nullptr,
                              size_t* N1_out = nullptr,
                              size_t* N2_out = nullptr,
                              size_t* N_joint_out = nullptr) const;

    void clear();
    void printStructure(int windowNum) const;

    bool isInitialized() const { return initialized_; }

    size_t getTier1Count(int fieldIdx) const {
        return rows_[fieldIdx].tier1_count;
    }
    size_t getTier23BufferSize(int fieldIdx) const {
        return rows_[fieldIdx].tier2_count;
    }

    // Timing accessors
    uint64_t getEncodingTimeNs() const { return encodingTimeNs_; }
    uint64_t getInsertionTimeNs() const { return insertionTimeNs_; }
    void resetTiming() { encodingTimeNs_ = 0; insertionTimeNs_ = 0; }

    // Get all recovered flow IDs by decoding stored compressed codes
    std::vector<Packet> getRecoveredFlows(const AdaptiveHuffmanLearner& learner) const;

private:
    bool initialized_;

    // Timing accumulators (nanoseconds)
    uint64_t encodingTimeNs_;
    uint64_t insertionTimeNs_;

    // THE PHYSICAL MEMORY (One contiguous block)
    std::vector<uint8_t> memory_;

    // Logical layout descriptors
    std::array<RowLayout, NUM_FIELDS> rows_;

    // ─── Helpers for Flat Memory Access ───

    // Get pointer to Tier 1 Counter Array for a row
    inline uint16_t* getTier1Ptr(const RowLayout& row) {
        return reinterpret_cast<uint16_t*>(memory_.data() + row.memory_offset);
    }
    inline const uint16_t* getTier1Ptr(const RowLayout& row) const {
        return reinterpret_cast<const uint16_t*>(memory_.data() + row.memory_offset);
    }

    // Get pointer to Tier 2/3 Bucket Array for a row
    inline PhysicalBucket* getTier2Ptr(const RowLayout& row) {
        size_t t1_size = row.tier1_count * sizeof(uint16_t);
        return reinterpret_cast<PhysicalBucket*>(memory_.data() + row.memory_offset + t1_size);
    }
    inline const PhysicalBucket* getTier2Ptr(const RowLayout& row) const {
        size_t t1_size = row.tier1_count * sizeof(uint16_t);
        return reinterpret_cast<const PhysicalBucket*>(memory_.data() + row.memory_offset + t1_size);
    }

    // OPTIMIZATION 3: Helper to convert string code to uint64_t
    uint64_t stringToBinary(const std::string& codeStr) const;

    // OPTIMIZATION 4: Hash-mapped buffer insertion (direct-mapped with modulo)
    void insertIntoBuffer(PhysicalBucket* buckets, size_t count,
                          uint64_t code, uint8_t len);

    // Optimized lookup for Tier 1 index (Binary Search)
    int32_t getSymbolIndex(const RowLayout& row, uint64_t value) const;
};

#endif // TAIL_SKETCH_H

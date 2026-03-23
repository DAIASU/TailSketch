#ifndef ADAPTIVE_HUFFMAN_LEARNER_H
#define ADAPTIVE_HUFFMAN_LEARNER_H

#include "AdaptiveHuffmanTree.h"
#include "FrequentTable.h"
#include "Packet.h"
#include <array>
#include <vector>
#include <unordered_map>
#include <cstdint>

/**
 * AdaptiveHuffmanLearner: Three-tier encoding/decoding for flow IDs.
 *
 * Manages 5 Huffman trees (one per field) and references to 5 FrequentTables.
 * Implements three-tier encoding:
 *   Tier 1: Huffman code for known symbols
 *   Tier 2: NYT escape + fixed-length frequent table index
 *   Tier 3: UNKNOWN escape + raw field bits
 */
class AdaptiveHuffmanLearner {
public:
    // Field bit widths: srcIP(32), dstIP(32), srcPort(16), dstPort(16), proto(8)
    static constexpr int FIELD_BITS[5] = {32, 32, 16, 16, 8};
    static constexpr int NUM_FIELDS = 5;

    /**
     * Encoding statistics for analysis.
     * Tracks counts per field index and per tier.
     */
    struct EncodingStats {
        // Per-field counts for each tier [fieldIdx]
        std::array<size_t, NUM_FIELDS> tier1CountByField = {0, 0, 0, 0, 0};  // Symbols found in Huffman tree
        std::array<size_t, NUM_FIELDS> tier2CountByField = {0, 0, 0, 0, 0};  // Symbols found in frequent table (NYT)
        std::array<size_t, NUM_FIELDS> tier3CountByField = {0, 0, 0, 0, 0};  // Unknown symbols (UNKNOWN + raw bits)

        // Total counts across all fields
        size_t tier1Count = 0;
        size_t tier2Count = 0;
        size_t tier3Count = 0;

        void reset() {
            tier1CountByField.fill(0);
            tier2CountByField.fill(0);
            tier3CountByField.fill(0);
            tier1Count = tier2Count = tier3Count = 0;
        }
    };

    AdaptiveHuffmanLearner();
    ~AdaptiveHuffmanLearner() = default;

    // Move semantics
    AdaptiveHuffmanLearner(AdaptiveHuffmanLearner&& other) noexcept = default;
    AdaptiveHuffmanLearner& operator=(AdaptiveHuffmanLearner&& other) noexcept = default;

    // No copy (trees contain unique_ptr)
    AdaptiveHuffmanLearner(const AdaptiveHuffmanLearner&) = delete;
    AdaptiveHuffmanLearner& operator=(const AdaptiveHuffmanLearner&) = delete;

    /**
     * Set references to frequent tables (built once during initialization).
     * These are shared across all windows.
     */
    void setFrequentTables(const std::array<FrequentTable, 5>* tables);

    // ═══════════════════════════════════════════════════════════════════
    // Frequency Tracking
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Update frequency counts for a packet's fields.
     * Called for each new flow ID in a window.
     */
    void updateFrequency(const Packet& p);

    /**
     * Clear frequency maps (but keep trees intact).
     */
    void clearFrequencies();

    /**
     * Initialize frequencies from a set of recovered IDs.
     * Used at the end of each window to prepare for the next.
     */
    void initFromRecoveredIDs(const std::vector<Packet>& recoveredIDs);

    // ═══════════════════════════════════════════════════════════════════
    // Tree Operations
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Build Huffman trees from collected frequencies.
     * Automatically adds NYT=0 and UNKNOWN=0 to each tree.
     */
    void buildTrees();

    /**
     * Check if trees have been built.
     */
    bool hasBuiltTrees() const;

    /**
     * Clear everything (frequencies and trees).
     */
    void clearAll();

    // ═══════════════════════════════════════════════════════════════════
    // Three-Tier Encoding
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Encode a complete flow ID using three-tier encoding.
     * Returns concatenated Huffman codes for all 5 fields.
     */
    std::string encodeFlowID(const Packet& p);

    /**
     * Encode a single field using three-tier encoding.
     * Returns the encoded bit string.
     */
    std::string encodeField(int fieldIdx, uint32_t value);

    // ═══════════════════════════════════════════════════════════════════
    // Three-Tier Decoding
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Decode a compressed flow ID back to a Packet.
     * Returns true if decoding succeeded.
     */
    bool decodeFlowID(const std::string& compressed, Packet& outPacket) const;

    /**
     * Decode a single field from the bit stream.
     * Updates pos to point after the decoded bits.
     */
    uint32_t decodeField(int fieldIdx, const std::string& bits, size_t& pos) const;

    // ═══════════════════════════════════════════════════════════════════
    // Memory and Statistics
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Total memory overhead of all 5 Huffman trees in bits.
     */
    size_t treesMemoryBits() const;

    /**
     * Get encoding statistics.
     */
    const EncodingStats& getStats() const { return stats_; }

    /**
     * Reset encoding statistics.
     */
    void resetStats() { stats_.reset(); }

    /**
     * Get the Huffman trees (for TailSketch initialization).
     */
    const std::array<AdaptiveHuffmanTree, NUM_FIELDS>& getTrees() const {
        return trees_;
    }

    /**
     * Get the frequent tables reference.
     */
    const std::array<FrequentTable, 5>* getFrequentTables() const {
        return frequentTables_;
    }

    /**
     * Encode a single field (const version for querying).
     * Does not update statistics.
     */
    std::string encodeFieldConst(int fieldIdx, uint32_t value) const;

private:
    // Frequency maps for each field (uint64_t to match AdaptiveHuffmanTree)
    std::array<std::unordered_map<uint64_t, uint64_t>, NUM_FIELDS> fieldFreqs_;

    // Huffman trees for each field
    std::array<AdaptiveHuffmanTree, NUM_FIELDS> trees_;

    // Reference to global frequent tables (not owned)
    const std::array<FrequentTable, 5>* frequentTables_;

    // Encoding statistics
    EncodingStats stats_;

    // Helper: convert value to binary string
    static std::string toBinaryString(uint32_t value, int bits);
};

#endif // ADAPTIVE_HUFFMAN_LEARNER_H

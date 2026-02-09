#include "TailSketch.h"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <limits>
#include <chrono>
#include <cstdlib>  // For rand()
#include <unordered_set>

TailSketch::TailSketch()
    : initialized_(false), encodingTimeNs_(0), insertionTimeNs_(0) {}

// ─────────────────────────────────────────────────────────────────────────────
// OPTIMIZATION 2: Memory Layout Redistribution
// ─────────────────────────────────────────────────────────────────────────────
void TailSketch::initialize(
    const std::array<AdaptiveHuffmanTree, NUM_FIELDS>& trees,
    size_t totalBytesPerRow) {

    // First pass: Analyze Tier 1 requirements for all fields
    std::array<size_t, NUM_FIELDS> tier1_aligned_sizes;

    for (int i = 0; i < NUM_FIELDS; i++) {
        RowLayout& row = rows_[i];

        // Analyze Huffman Tree to build Tier 1 map
        const auto& codeDict = trees[i].getCodeDict();
        row.symbol_keys.clear();

        for (const auto& [symbol, code] : codeDict) {
            if (symbol != SYMBOL_NYT && symbol != SYMBOL_UNKNOWN) {
                row.symbol_keys.push_back(symbol);
            }
        }

        // Sort keys for binary search (O(log N))
        std::sort(row.symbol_keys.begin(), row.symbol_keys.end());
        row.tier1_count = row.symbol_keys.size();

        // Calculate aligned Tier 1 size
        size_t tier1_bytes = row.tier1_count * sizeof(uint16_t);
        tier1_aligned_sizes[i] = ((tier1_bytes + 7) / 8) * 8;
    }

    // OPTIMIZATION 2: Memory redistribution
    // Total budget across all 5 rows
    size_t total_budget = totalBytesPerRow * NUM_FIELDS;

    // Calculate total Tier 1 requirements
    size_t total_tier1_bytes = 0;
    for (size_t tier1_size : tier1_aligned_sizes) {
        total_tier1_bytes += tier1_size;
    }

    // Remaining memory for all Tier 2/3 buffers
    size_t total_tier2_budget = (total_budget > total_tier1_bytes)
                                 ? (total_budget - total_tier1_bytes) : 0;

    // Proto (field 4) gets minimal buffer: 1 bucket
    size_t proto_tier2_bytes = sizeof(PhysicalBucket);

    // Subtract proto's allocation from remaining budget
    size_t remaining_for_top4 = (total_tier2_budget > proto_tier2_bytes)
                                 ? (total_tier2_budget - proto_tier2_bytes) : 0;

    // Distribute remaining equally among top 4 fields (0-3)
    size_t bytes_per_top_field = remaining_for_top4 / 4;

    // Second pass: Allocate memory with calculated sizes
    size_t current_global_offset = 0;

    for (int i = 0; i < NUM_FIELDS; i++) {
        RowLayout& row = rows_[i];
        row.memory_offset = current_global_offset;

        size_t tier1_aligned = tier1_aligned_sizes[i];

        // Determine Tier 2/3 allocation
        size_t tier2_bytes;
        if (i == 4) {
            // Proto field: minimal (1 bucket)
            tier2_bytes = proto_tier2_bytes;
        } else {
            // Top 4 fields: equal share of remaining memory
            tier2_bytes = bytes_per_top_field;
        }

        // Calculate number of buckets (12 bytes each)
        row.tier2_count = std::max(size_t(1), tier2_bytes / sizeof(PhysicalBucket));

        // Actual tier2 bytes used
        size_t actual_tier2_bytes = row.tier2_count * sizeof(PhysicalBucket);

        // Advance offset
        current_global_offset += (tier1_aligned + actual_tier2_bytes);
    }

    // Single contiguous allocation
    memory_.resize(current_global_offset);
    std::fill(memory_.begin(), memory_.end(), 0);

    initialized_ = true;
}

// ─────────────────────────────────────────────────────────────────────────────
// OPTIMIZATION 3: Throughput Optimization (Pre-computation)
// ─────────────────────────────────────────────────────────────────────────────
void TailSketch::insertPacket(const Packet& pkt,
                                   const AdaptiveHuffmanLearner& learner) {
    if (!initialized_) return;

    uint32_t fields[NUM_FIELDS] = {
        pkt.srcIP, pkt.dstIP,
        static_cast<uint32_t>(pkt.srcPort),
        static_cast<uint32_t>(pkt.dstPort),
        static_cast<uint32_t>(pkt.proto)
    };

    for (int i = 0; i < NUM_FIELDS; i++) {
        RowLayout& row = rows_[i];
        uint32_t value = fields[i];

        // ═══════════════════════════════════════════════════════════
        // ENCODING PHASE: Symbol lookup, pointer computation, encoding
        // ═══════════════════════════════════════════════════════════
        auto encStart = std::chrono::high_resolution_clock::now();

        int32_t idx = getSymbolIndex(row, value);
        uint16_t* counters = nullptr;
        PhysicalBucket* buckets = nullptr;
        uint64_t code = 0;
        uint8_t len = 0;

        if (idx != -1) {
            // Tier 1: Get counter pointer
            counters = getTier1Ptr(row);
        } else {
            // Tier 2/3: Encode and PRE-COMPUTE binary code
            std::string key = learner.encodeFieldConst(i, value);
            code = stringToBinary(key);  // OPTIMIZATION 3: Pre-compute here
            len = static_cast<uint8_t>(key.length());
            buckets = getTier2Ptr(row);
        }

        auto encEnd = std::chrono::high_resolution_clock::now();
        encodingTimeNs_ += std::chrono::duration_cast<std::chrono::nanoseconds>(encEnd - encStart).count();

        // ═══════════════════════════════════════════════════════════
        // INSERTION PHASE: Actual memory write
        // ═══════════════════════════════════════════════════════════
        auto insStart = std::chrono::high_resolution_clock::now();

        if (idx != -1) {
            // PATH A: Tier 1 - Direct counter increment (unchanged)
            if (counters[idx] < 0xFFFF) {
                counters[idx]++;
            }
        } else {
            // PATH B: Tier 2/3 - OPTIMIZATION 4: Hash-mapped insertion
            insertIntoBuffer(buckets, row.tier2_count, code, len);
        }

        auto insEnd = std::chrono::high_resolution_clock::now();
        insertionTimeNs_ += std::chrono::duration_cast<std::chrono::nanoseconds>(insEnd - insStart).count();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OPTIMIZATION 4: Hash-Mapped Query (matching insertion logic)
// ─────────────────────────────────────────────────────────────────────────────
uint32_t TailSketch::queryField(int fieldIdx, uint32_t value,
                                     const AdaptiveHuffmanTree& tree,
                                     const FrequentTable& freqTable) const {
    if (!initialized_ || fieldIdx < 0 || fieldIdx >= NUM_FIELDS) return 0;

    const RowLayout& row = rows_[fieldIdx];

    // Tier 1 Check (unchanged)
    int32_t idx = getSymbolIndex(row, value);
    if (idx != -1) {
        const uint16_t* counters = getTier1Ptr(row);
        return counters[idx];
    }

    // Tier 2/3 Check - Build the key
    std::string key;
    if (freqTable.contains(value)) {
        key = tree.encode(SYMBOL_NYT) + freqTable.encode(value);
    } else {
        key = tree.encode(SYMBOL_UNKNOWN);
        int fieldBits = AdaptiveHuffmanLearner::FIELD_BITS[fieldIdx];
        for (int b = fieldBits - 1; b >= 0; b--) {
            key += ((value >> b) & 1) ? '1' : '0';
        }
    }

    uint64_t code = stringToBinary(key);
    uint8_t len = static_cast<uint8_t>(key.length());

    // OPTIMIZATION 4: Hash-mapped lookup (direct-mapped with modulo)
    const PhysicalBucket* buckets = getTier2Ptr(row);
    size_t idx_hash = code % row.tier2_count;

    if (buckets[idx_hash].is_valid &&
        buckets[idx_hash].code_len == len &&
        buckets[idx_hash].code == code) {
        return buckets[idx_hash].frequency;
    }

    // Conservative estimate if not found
    return 1;
}

double TailSketch::queryFlowFrequency(const Packet& pkt,
                                           const AdaptiveHuffmanLearner& learner,
                                           uint64_t totalPackets) const {
    if (!initialized_ || totalPackets == 0) {
        return 0.0;
    }

    const auto* freqTables = learner.getFrequentTables();
    if (!freqTables) return 0.0;

    const auto& trees = learner.getTrees();

    uint32_t fields[NUM_FIELDS] = {
        pkt.srcIP, pkt.dstIP,
        static_cast<uint32_t>(pkt.srcPort),
        static_cast<uint32_t>(pkt.dstPort),
        static_cast<uint32_t>(pkt.proto)
    };

    // Naive Bayes: f = N * prod(x_i / N)
    double product = 1.0;
    double N = static_cast<double>(totalPackets);

    for (int i = 0; i < NUM_FIELDS; i++) {
        uint32_t count = queryField(i, fields[i], trees[i], (*freqTables)[i]);

        // Early termination if any field has 0 count
        if (count == 0) {
            return 0.0;
        }

        product *= (static_cast<double>(count) / N);
    }

    // Estimated frequency: N * prod(x_i/N)
    return std::max(N * product, 1.0);
}

// ═════════════════════════════════════════════════════════════════════════════
// Correlation-Based Partial Key Query with Recovered Flow Set
// ═════════════════════════════════════════════════════════════════════════════

double TailSketch::queryPartialKey(const PartialKey& partialKey,
                                        const AdaptiveHuffmanLearner& learner,
                                        uint64_t totalPackets,
                                        const std::vector<Packet>& recoveredIDs,
                                        double providedBeta,
                                        bool debug,
                                        PartialKeyDebugInfo* debugInfo) const {
    if (!initialized_ || totalPackets == 0) {
        return 0.0;
    }

    const auto* freqTables = learner.getFrequentTables();
    if (!freqTables) return 0.0;

    const auto& trees = learner.getTrees();

    // ─────────────────────────────────────────────────────────────
    // Step 1: Identify Active Fields (mask bit == 0 means exact match)
    // ─────────────────────────────────────────────────────────────
    std::vector<int> activeIndices;
    for (int i = 0; i < NUM_FIELDS; i++) {
        if ((partialKey.mask & (1 << i)) == 0) {
            activeIndices.push_back(i);
        }
    }

    // If no active fields, all flows match (total packets)
    if (activeIndices.empty()) {
        if (debugInfo) {
            debugInfo->result = static_cast<double>(totalPackets);
        }
        return static_cast<double>(totalPackets);
    }

    if (debugInfo) {
        debugInfo->activeIndices = activeIndices;
        debugInfo->recoveredIDsSize = recoveredIDs.size();
    }

    // Field values for comparison
    uint32_t fields[NUM_FIELDS] = {
        partialKey.srcIP, partialKey.dstIP,
        static_cast<uint32_t>(partialKey.srcPort),
        static_cast<uint32_t>(partialKey.dstPort),
        static_cast<uint32_t>(partialKey.proto)
    };

    // Helper lambda to check if a packet matches the partial key
    auto matchesPartialKey = [&](const Packet& pkt) -> bool {
        uint32_t pktFields[NUM_FIELDS] = {
            pkt.srcIP, pkt.dstIP,
            static_cast<uint32_t>(pkt.srcPort),
            static_cast<uint32_t>(pkt.dstPort),
            static_cast<uint32_t>(pkt.proto)
        };
        for (int idx : activeIndices) {
            if (pktFields[idx] != fields[idx]) {
                return false;
            }
        }
        return true;
    };

    // ─────────────────────────────────────────────────────────────
    // Step 2: Single Pass Through recoveredIDs
    // Calculate: Lower Bound + Correlation Counts
    // ─────────────────────────────────────────────────────────────
    uint64_t min_freq = 0;  // Lower bound: exact matches in recoveredIDs

    // For correlation: count occurrences for each adjacent pair
    // counts[i][0] = N_prev, counts[i][1] = N_curr, counts[i][2] = N_joint
    std::vector<std::array<uint64_t, 3>> pairCounts(activeIndices.size());

    for (const auto& pkt : recoveredIDs) {
        // Check if this flow matches the partial key exactly
        if (matchesPartialKey(pkt)) {
            min_freq++;
        }

        // Gather counts for correlation calculation
        uint32_t pktFields[NUM_FIELDS] = {
            pkt.srcIP, pkt.dstIP,
            static_cast<uint32_t>(pkt.srcPort),
            static_cast<uint32_t>(pkt.dstPort),
            static_cast<uint32_t>(pkt.proto)
        };

        for (size_t t = 0; t < activeIndices.size(); t++) {
            int curr = activeIndices[t];

            // Count current field matches
            if (pktFields[curr] == fields[curr]) {
                pairCounts[t][1]++;  // N_curr

                // For t > 0, also check joint matches with previous field
                if (t > 0) {
                    int prev = activeIndices[t - 1];
                    if (pktFields[prev] == fields[prev]) {
                        pairCounts[t][2]++;  // N_joint
                    }
                }
            }

            // Count previous field matches (for t > 0)
            if (t > 0) {
                int prev = activeIndices[t - 1];
                if (pktFields[prev] == fields[prev]) {
                    pairCounts[t][0]++;  // N_prev
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Step 3: Calculate Correlation Exponents (Beta)
    // ─────────────────────────────────────────────────────────────
    std::vector<double> betas(activeIndices.size());

    if (debugInfo) {
        debugInfo->lowerBound = min_freq;
        debugInfo->betas.resize(activeIndices.size());
        debugInfo->N_prev.resize(activeIndices.size());
        debugInfo->N_curr.resize(activeIndices.size());
        debugInfo->N_joint.resize(activeIndices.size());
    }

    if (debug) {
        std::cout << "\n  [DEBUG] Correlation Calculation:\n";
        std::cout << "    RecoveredIDs size: " << recoveredIDs.size() << "\n";
        std::cout << "    Lower bound (exact matches): " << min_freq << "\n";
    }

    // Base case: first active field always has beta = 1.0
    betas[0] = 1.0;
    if (debugInfo) debugInfo->betas[0] = 1.0;

    if (debug && !activeIndices.empty()) {
        std::cout << "    Field[0] (idx=" << activeIndices[0] << "): beta = 1.0 (base case)\n";
    }

    // Decide beta calculation mode
    bool useProvidedBeta = (providedBeta >= 0.0) && (activeIndices.size() == 2);

    // Recursive case: subsequent fields
    for (size_t t = 1; t < activeIndices.size(); t++) {
        uint64_t N_curr = pairCounts[t][1];
        uint64_t N_prev = pairCounts[t][0];
        uint64_t N_joint = pairCounts[t][2];

        if (debugInfo) {
            debugInfo->N_prev[t] = N_prev;
            debugInfo->N_curr[t] = N_curr;
            debugInfo->N_joint[t] = N_joint;
        }

        // Use provided beta if available (for 2-field patterns)
        if (useProvidedBeta) {
            betas[t] = providedBeta;
        } else {
            // Compute beta from correlation
            if (N_curr > 0 && N_prev > 0) {
                betas[t] = static_cast<double>(N_joint) /
                          (static_cast<double>(N_curr) * static_cast<double>(N_prev));
            } else {
                betas[t] = 1.0;  // Default to independence assumption
            }
        }

        if (debugInfo) debugInfo->betas[t] = betas[t];

        if (debug) {
            std::cout << "    Field[" << t << "] (idx=" << activeIndices[t] << "):\n";
            if (useProvidedBeta) {
                std::cout << "      Using provided beta = " << betas[t] << "\n";
            } else {
                std::cout << "      N_prev = " << N_prev << "\n";
                std::cout << "      N_curr = " << N_curr << "\n";
                std::cout << "      N_joint = " << N_joint << "\n";
                std::cout << "      beta = " << N_joint << " / (" << N_curr << " * " << N_prev << ") = " << betas[t] << "\n";
            }
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Step 4: Calculate Correlation-Adjusted Estimate
    // ─────────────────────────────────────────────────────────────
    double product = 1.0;
    double N = static_cast<double>(totalPackets);

    if (debugInfo) {
        debugInfo->sketchCounts.resize(activeIndices.size());
        debugInfo->probabilities.resize(activeIndices.size());
        debugInfo->terms.resize(activeIndices.size());
    }

    if (debug) {
        std::cout << "    \n  [DEBUG] Product Calculation (N=" << N << "):\n";
    }

    for (size_t t = 0; t < activeIndices.size(); t++) {
        int fieldIdx = activeIndices[t];

        // Query sketch for this field
        uint32_t count = queryField(fieldIdx, fields[fieldIdx],
                                    trees[fieldIdx], (*freqTables)[fieldIdx]);

        // Early termination if any field has 0 count
        if (count == 0) {
            if (debug) {
                std::cout << "    Field[" << t << "] count = 0, returning lower bound = " << min_freq << "\n";
            }
            if (debugInfo) {
                debugInfo->result = static_cast<double>(min_freq);
            }
            return static_cast<double>(min_freq);
        }

        // Calculate probability for this field
        double p_i = static_cast<double>(count) / N;

        // Apply correlation exponent
        double term = std::pow(p_i, betas[t]);
        product *= term;

        if (debugInfo) {
            debugInfo->sketchCounts[t] = count;
            debugInfo->probabilities[t] = p_i;
            debugInfo->terms[t] = term;
        }

        if (debug) {
            std::cout << "    Field[" << t << "] (idx=" << activeIndices[t] << "):\n";
            std::cout << "      SketchCount = " << count << "\n";
            std::cout << "      p_i = " << count << " / " << N << " = " << p_i << "\n";
            std::cout << "      beta = " << betas[t] << "\n";
            std::cout << "      (p_i)^beta = " << p_i << "^" << betas[t] << " = " << term << "\n";
            std::cout << "      product *= " << term << " => " << product << "\n";
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Step 5: Final Result
    // ─────────────────────────────────────────────────────────────
    double estimate = N * product;
    double result = std::max(static_cast<double>(min_freq), estimate);

    if (debugInfo) {
        debugInfo->product = product;
        debugInfo->estimate = estimate;
        debugInfo->result = result;
    }

    if (debug) {
        std::cout << "    \n  Final Estimate = N * product = " << N << " * " << product << " = " << estimate << "\n";
        std::cout << "    Lower Bound = " << min_freq << "\n";
        std::cout << "    Result = max(" << min_freq << ", " << estimate << ") = " << result << "\n";
    }

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern-Global Beta Calculation
// ─────────────────────────────────────────────────────────────────────────────

double TailSketch::computePatternBeta(uint8_t mask, const std::vector<Packet>& recoveredIDs,
                                            std::vector<int>* activeIndicesOut,
                                            size_t* N1_out,
                                            size_t* N2_out,
                                            size_t* N_joint_out) const {
    // Identify active field indices from mask (bit i = 0 means field i is active/exact match)
    std::vector<int> activeIndices;
    for (int i = 0; i < 5; i++) {
        if (((mask >> i) & 1) == 0) {  // 0 = active
            activeIndices.push_back(i);
        }
    }

    if (activeIndicesOut) {
        *activeIndicesOut = activeIndices;
    }

    // Case 1: Single active field → β = 1.0 (no correlation adjustment needed)
    if (activeIndices.size() == 1) {
        if (N1_out) *N1_out = 0;
        if (N2_out) *N2_out = 0;
        if (N_joint_out) *N_joint_out = 0;
        return 1.0;
    }

    // Case 2: Two active fields → Calculate β = N_joint / (N₁ × N₂)
    if (activeIndices.size() == 2) {
        int idx1 = activeIndices[0];
        int idx2 = activeIndices[1];

        std::unordered_set<uint32_t> set1, set2;
        std::unordered_set<uint64_t> set_joint;

        for (const auto& pkt : recoveredIDs) {
            uint32_t v1 = 0, v2 = 0;

            // Extract field values based on index
            switch (idx1) {
                case 0: v1 = pkt.srcIP; break;
                case 1: v1 = pkt.dstIP; break;
                case 2: v1 = pkt.srcPort; break;
                case 3: v1 = pkt.dstPort; break;
                case 4: v1 = pkt.proto; break;
            }
            switch (idx2) {
                case 0: v2 = pkt.srcIP; break;
                case 1: v2 = pkt.dstIP; break;
                case 2: v2 = pkt.srcPort; break;
                case 3: v2 = pkt.dstPort; break;
                case 4: v2 = pkt.proto; break;
            }

            set1.insert(v1);
            set2.insert(v2);

            // Pack both values into uint64_t for joint set
            uint64_t joint_key = (static_cast<uint64_t>(v1) << 32) | v2;
            set_joint.insert(joint_key);
        }

        size_t N1 = set1.size();
        size_t N2 = set2.size();
        size_t N_joint = set_joint.size();

        if (N1_out) *N1_out = N1;
        if (N2_out) *N2_out = N2;
        if (N_joint_out) *N_joint_out = N_joint;

        // Safety check
        if (N1 == 0 || N2 == 0) return 1.0;

        double beta = static_cast<double>(N_joint) / (N1 * N2);
        return beta;
    }

    // Case 3: More than 2 fields (not supported for now)
    if (N1_out) *N1_out = 0;
    if (N2_out) *N2_out = 0;
    if (N_joint_out) *N_joint_out = 0;
    return 1.0;
}

void TailSketch::clear() {
    std::fill(memory_.begin(), memory_.end(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Print Structure
// ─────────────────────────────────────────────────────────────────────────────

void TailSketch::printStructure(int windowNum) const {
    const char* fieldNames[5] = {"srcIP", "dstIP", "srcPort", "dstPort", "proto"};

    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "TailSketch Structure - Window " << windowNum << " (Optimized)\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";

    for (int i = 0; i < NUM_FIELDS; i++) {
        const RowLayout& row = rows_[i];

        size_t tier1_bytes = row.tier1_count * sizeof(uint16_t);
        size_t tier1_aligned = ((tier1_bytes + 7) / 8) * 8;
        size_t tier2_bytes = row.tier2_count * sizeof(PhysicalBucket);
        size_t symbolKeysBytes = row.symbol_keys.size() * sizeof(uint64_t);

        std::cout << "\nField " << i << " (" << fieldNames[i] << "):\n";
        std::cout << "  Memory offset:     " << row.memory_offset << " bytes\n";
        std::cout << "  Tier 1 symbols:    " << row.tier1_count << "\n";
        std::cout << "  Tier 1 counters:   " << tier1_aligned << " bytes (aligned)\n";
        std::cout << "  Tier 2/3 buckets:  " << row.tier2_count << " x 12 bytes\n";
        std::cout << "  Tier 2/3 memory:   " << tier2_bytes << " bytes\n";
        std::cout << "  Symbol keys (RAM): " << symbolKeysBytes << " bytes\n";
    }

    std::cout << "\n───────────────────────────────────────────────────────────────\n";
    std::cout << "Physical memory block: " << memory_.size() << " bytes ("
              << std::fixed << std::setprecision(2) << (memory_.size() / 1024.0) << " KB)\n";
    std::cout << "Bucket size: " << sizeof(PhysicalBucket) << " bytes (optimized from 16)\n";
    std::cout << "Collision strategy: Version " << STRATEGY_VERSION << "\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Private Helpers
// ─────────────────────────────────────────────────────────────────────────────

int32_t TailSketch::getSymbolIndex(const RowLayout& row, uint64_t value) const {
    auto it = std::lower_bound(row.symbol_keys.begin(), row.symbol_keys.end(), value);
    if (it != row.symbol_keys.end() && *it == value) {
        return static_cast<int32_t>(std::distance(row.symbol_keys.begin(), it));
    }
    return -1;
}

// ─────────────────────────────────────────────────────────────────────────────
// OPTIMIZATION 3: String to Binary Conversion (returns uint64_t)
// ─────────────────────────────────────────────────────────────────────────────
uint64_t TailSketch::stringToBinary(const std::string& codeStr) const {
    uint64_t code = 0;
    size_t len = codeStr.length();

    // Convert string to 64-bit integer (sufficient for Huffman + Tier2/3)
    for (size_t i = 0; i < len && i < 64; i++) {
        if (codeStr[i] == '1') {
            code |= (1ULL << i);
        }
    }
    return code;
}

// ─────────────────────────────────────────────────────────────────────────────
// OPTIMIZATION 4: Hash-Mapped Insertion (Direct-Mapped with Modulo)
// ─────────────────────────────────────────────────────────────────────────────
void TailSketch::insertIntoBuffer(PhysicalBucket* buckets, size_t count,
                                       uint64_t code, uint8_t len) {
    if (count == 0) return;

    // Direct-mapped index using modulo
    size_t idx = code % count;

    if (!buckets[idx].is_valid) {
        // Empty slot - insert new
        buckets[idx].code = code;
        buckets[idx].code_len = len;
        buckets[idx].frequency = 1;
        buckets[idx].is_valid = 1;
        return;
    }

    if (buckets[idx].code == code && buckets[idx].code_len == len) {
        // Exact match - increment frequency
        if (buckets[idx].frequency < 0xFFFF) {
            buckets[idx].frequency++;
        }
        return;
    }

    // Collision detected
    #if STRATEGY_VERSION == 1
        // Version 1: Probabilistic Replacement
        // Increment frequency first
        if (buckets[idx].frequency < 0xFFFF) {
            buckets[idx].frequency++;
        }

        // Replace with probability P = 1 / freq
        if (rand() % buckets[idx].frequency == 0) {
            buckets[idx].code = code;
            buckets[idx].code_len = len;
            buckets[idx].frequency = 1;
        }
    #else
        // Version 2: Decay/HeavyKeeper
        // Decrement frequency
        buckets[idx].frequency--;

        // If frequency reaches 0, replace
        if (buckets[idx].frequency == 0) {
            buckets[idx].code = code;
            buckets[idx].code_len = len;
            buckets[idx].frequency = 1;
        }
    #endif
}

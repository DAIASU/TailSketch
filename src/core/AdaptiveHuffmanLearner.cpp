#include "AdaptiveHuffmanLearner.h"

// Static member definition
constexpr int AdaptiveHuffmanLearner::FIELD_BITS[5];

AdaptiveHuffmanLearner::AdaptiveHuffmanLearner()
    : frequentTables_(nullptr) {}

void AdaptiveHuffmanLearner::setFrequentTables(const std::array<FrequentTable, 5>* tables) {
    frequentTables_ = tables;
}

// ═══════════════════════════════════════════════════════════════════════════
// Frequency Tracking
// ═══════════════════════════════════════════════════════════════════════════

void AdaptiveHuffmanLearner::updateFrequency(const Packet& p) {
    // Update frequency for each field
    fieldFreqs_[0][p.srcIP]++;
    fieldFreqs_[1][p.dstIP]++;
    fieldFreqs_[2][p.srcPort]++;
    fieldFreqs_[3][p.dstPort]++;
    fieldFreqs_[4][p.proto]++;
}

void AdaptiveHuffmanLearner::clearFrequencies() {
    for (auto& freqMap : fieldFreqs_) {
        freqMap.clear();
    }
}

void AdaptiveHuffmanLearner::initFromRecoveredIDs(const std::vector<Packet>& recoveredIDs) {
    clearFrequencies();

    for (const auto& p : recoveredIDs) {
        updateFrequency(p);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tree Operations
// ═══════════════════════════════════════════════════════════════════════════

void AdaptiveHuffmanLearner::buildTrees() {
    for (int i = 0; i < NUM_FIELDS; i++) {
        // Copy frequency map (NYT and UNKNOWN will be added by AdaptiveHuffmanTree::build)
        trees_[i].build(fieldFreqs_[i]);
    }
}

bool AdaptiveHuffmanLearner::hasBuiltTrees() const {
    // Check if at least one tree is built
    for (const auto& tree : trees_) {
        if (tree.isBuilt()) {
            return true;
        }
    }
    return false;
}

void AdaptiveHuffmanLearner::clearAll() {
    clearFrequencies();
    for (auto& tree : trees_) {
        tree.clear();
    }
    stats_.reset();
}

// ═══════════════════════════════════════════════════════════════════════════
// Three-Tier Encoding
// ═══════════════════════════════════════════════════════════════════════════

std::string AdaptiveHuffmanLearner::encodeFlowID(const Packet& p) {
    std::string result;
    result.reserve(200);  // Pre-allocate for efficiency

    result += encodeField(0, p.srcIP);
    result += encodeField(1, p.dstIP);
    result += encodeField(2, p.srcPort);
    result += encodeField(3, p.dstPort);
    result += encodeField(4, p.proto);

    return result;
}

std::string AdaptiveHuffmanLearner::encodeField(int fieldIdx, uint32_t value) {
    // Tier 1: Check if value is in Huffman tree (as a regular symbol)
    if (trees_[fieldIdx].hasSymbol(value)) {
        stats_.tier1Count++;
        stats_.tier1CountByField[fieldIdx]++;
        return trees_[fieldIdx].encode(value);
    }

    // Tier 2: Check if value is in frequent table
    if (frequentTables_ && (*frequentTables_)[fieldIdx].contains(value)) {
        stats_.tier2Count++;
        stats_.tier2CountByField[fieldIdx]++;
        std::string nytCode = trees_[fieldIdx].encode(SYMBOL_NYT);
        std::string indexCode = (*frequentTables_)[fieldIdx].encode(value);
        return nytCode + indexCode;
    }

    // Tier 3: Unknown - escape with raw bits
    stats_.tier3Count++;
    stats_.tier3CountByField[fieldIdx]++;
    std::string unknownCode = trees_[fieldIdx].encode(SYMBOL_UNKNOWN);
    std::string rawBits = toBinaryString(value, FIELD_BITS[fieldIdx]);
    return unknownCode + rawBits;
}

// ═══════════════════════════════════════════════════════════════════════════
// Three-Tier Decoding
// ═══════════════════════════════════════════════════════════════════════════

bool AdaptiveHuffmanLearner::decodeFlowID(const std::string& compressed, Packet& outPacket) const {
    size_t pos = 0;

    // Decode each field in order
    outPacket.srcIP = decodeField(0, compressed, pos);
    outPacket.dstIP = decodeField(1, compressed, pos);
    outPacket.srcPort = static_cast<uint16_t>(decodeField(2, compressed, pos));
    outPacket.dstPort = static_cast<uint16_t>(decodeField(3, compressed, pos));
    outPacket.proto = static_cast<uint8_t>(decodeField(4, compressed, pos));

    // Check if we consumed the entire string (or close to it)
    return pos <= compressed.size();
}

uint32_t AdaptiveHuffmanLearner::decodeField(int fieldIdx, const std::string& bits, size_t& pos) const {
    if (!trees_[fieldIdx].isBuilt()) {
        // No tree - can't decode
        return 0;
    }

    // Decode symbol from Huffman tree
    uint64_t symbol = trees_[fieldIdx].decode(bits, pos);

    if (symbol == SYMBOL_NYT) {
        // Tier 2: Read fixed-length index from frequent table
        if (frequentTables_) {
            return (*frequentTables_)[fieldIdx].decode(bits, pos);
        }
        return 0;
    }
    else if (symbol == SYMBOL_UNKNOWN) {
        // Tier 3: Read raw field bits
        uint32_t value = 0;
        int numBits = FIELD_BITS[fieldIdx];

        for (int i = 0; i < numBits && pos < bits.size(); i++) {
            value = (value << 1) | (bits[pos++] - '0');
        }

        return value;
    }
    else {
        // Tier 1: Symbol is the value itself
        return static_cast<uint32_t>(symbol);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Memory and Statistics
// ═══════════════════════════════════════════════════════════════════════════

size_t AdaptiveHuffmanLearner::treesMemoryBits() const {
    size_t total = 0;
    for (const auto& tree : trees_) {
        total += tree.treeMemoryBits();
    }
    return total;
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

std::string AdaptiveHuffmanLearner::toBinaryString(uint32_t value, int bits) {
    std::string result(bits, '0');

    for (int i = bits - 1; i >= 0; i--) {
        result[bits - 1 - i] = ((value >> i) & 1) ? '1' : '0';
    }

    return result;
}

std::string AdaptiveHuffmanLearner::encodeFieldConst(int fieldIdx, uint32_t value) const {
    // Tier 1: Check if value is in Huffman tree (as a regular symbol)
    if (trees_[fieldIdx].hasSymbol(value)) {
        return trees_[fieldIdx].encode(value);
    }

    // Tier 2: Check if value is in frequent table
    if (frequentTables_ && (*frequentTables_)[fieldIdx].contains(value)) {
        std::string nytCode = trees_[fieldIdx].encode(SYMBOL_NYT);
        std::string indexCode = (*frequentTables_)[fieldIdx].encode(value);
        return nytCode + indexCode;
    }

    // Tier 3: Unknown - escape with raw bits
    std::string unknownCode = trees_[fieldIdx].encode(SYMBOL_UNKNOWN);
    std::string rawBits = toBinaryString(value, FIELD_BITS[fieldIdx]);
    return unknownCode + rawBits;
}

#ifndef FREQUENT_TABLE_H
#define FREQUENT_TABLE_H

#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cmath>
#include <string>
#include <cstdint>

/**
 * FrequentTable: Global dictionary of top-K frequent field values.
 *
 * Built once during initialization by scanning the entire PCAP file.
 * Provides fixed-length encoding for values in the table.
 */
class FrequentTable {
private:
    std::unordered_map<uint32_t, uint32_t> valueToIndex_;  // field_value -> index
    std::vector<uint32_t> indexToValue_;                   // index -> field_value
    int codeLength_;                                        // ceil(log2(K)) bits
    int capacity_;                                          // K (max entries)

public:
    explicit FrequentTable(int capacity = 1024)
        : codeLength_(0), capacity_(capacity) {
        if (capacity_ > 0) {
            codeLength_ = static_cast<int>(std::ceil(std::log2(capacity_)));
            if (codeLength_ == 0) codeLength_ = 1;  // At least 1 bit
        }
    }

    /**
     * Build the frequent table from a frequency map.
     * Sorts by frequency descending and keeps top-K entries.
     */
    void build(const std::unordered_map<uint32_t, uint64_t>& freqs) {
        valueToIndex_.clear();
        indexToValue_.clear();

        if (freqs.empty()) {
            codeLength_ = 0;
            return;
        }

        // Convert to vector for sorting
        std::vector<std::pair<uint32_t, uint64_t>> sortedFreqs(freqs.begin(), freqs.end());

        // Sort by frequency descending
        std::sort(sortedFreqs.begin(), sortedFreqs.end(),
            [](const auto& a, const auto& b) {
                return a.second > b.second;  // Higher frequency first
            });

        // Keep top-K entries
        int numEntries = std::min(static_cast<int>(sortedFreqs.size()), capacity_);
        indexToValue_.reserve(numEntries);

        for (int i = 0; i < numEntries; i++) {
            uint32_t value = sortedFreqs[i].first;
            valueToIndex_[value] = static_cast<uint32_t>(i);
            indexToValue_.push_back(value);
        }

        // Recalculate code length based on actual size, not capacity
        if (numEntries > 0) {
            codeLength_ = static_cast<int>(std::ceil(std::log2(numEntries)));
            if (codeLength_ == 0) codeLength_ = 1;  // At least 1 bit
        } else {
            codeLength_ = 0;
        }
    }

    /**
     * Check if a value is in the frequent table.
     */
    bool contains(uint32_t value) const {
        return valueToIndex_.find(value) != valueToIndex_.end();
    }

    /**
     * Encode a value to its fixed-length binary string.
     * Returns empty string if value not in table.
     */
    std::string encode(uint32_t value) const {
        auto it = valueToIndex_.find(value);
        if (it == valueToIndex_.end()) {
            return "";  // Not in table
        }

        uint32_t index = it->second;
        std::string result(codeLength_, '0');

        // Convert index to binary string (MSB first)
        for (int i = codeLength_ - 1; i >= 0; i--) {
            result[codeLength_ - 1 - i] = ((index >> i) & 1) ? '1' : '0';
        }

        return result;
    }

    /**
     * Decode from bit string at given position.
     * Reads codeLength_ bits and returns the corresponding value.
     * Updates pos to point after the read bits.
     */
    uint32_t decode(const std::string& bits, size_t& pos) const {
        if (pos + codeLength_ > bits.size()) {
            return 0;  // Not enough bits
        }

        uint32_t index = 0;
        for (int i = 0; i < codeLength_; i++) {
            index = (index << 1) | (bits[pos++] - '0');
        }

        if (index < indexToValue_.size()) {
            return indexToValue_[index];
        }

        return 0;  // Invalid index
    }

    // Accessors
    int getCodeLength() const { return codeLength_; }
    int getCapacity() const { return capacity_; }
    size_t size() const { return indexToValue_.size(); }
    bool empty() const { return indexToValue_.empty(); }

    /**
     * Memory overhead in bits for transmitting/storing the table.
     * Each entry needs: field_bits (value) + codeLength_ (index)
     * For simplicity, we estimate based on entry count and field size.
     */
    size_t memoryBits(int fieldBits) const {
        // Each entry: field value (fieldBits) + frequency (not needed for decode)
        // The decoder only needs the mapping, which is implicit in order
        // So memory = number_of_entries * fieldBits
        return indexToValue_.size() * fieldBits;
    }

    void clear() {
        valueToIndex_.clear();
        indexToValue_.clear();
    }
};

#endif // FREQUENT_TABLE_H

#pragma once
#include "hash/hash.h"
#include <vector>
#include <memory>
#include <cstdint>
#include <string>

// Optimized Bloom Filter with manual bit operations (1 bit per element)
// Uses std::vector<uint8_t> for better performance than std::vector<bool>
class BloomFilter {
public:
    explicit BloomFilter(size_t size);

    // Insert a key into the bloom filter
    void insert(const std::string& key);

    // Check if a key might be in the bloom filter
    bool contains(const std::string& key) const;

    // Clear the bloom filter
    void clear();

private:
    // Bit manipulation helpers (inline for performance)
    inline void setBit(size_t pos) {
        bytes_[pos >> 3] |= (1 << (pos & 7));
    }

    inline bool getBit(size_t pos) const {
        return (bytes_[pos >> 3] & (1 << (pos & 7))) != 0;
    }

    // Storage: 1 bit per element, packed into bytes
    std::vector<uint8_t> bytes_;
    size_t size_;  // Number of bits (not bytes)
    static constexpr int num_hashes_ = 3; // Number of hash functions
    std::vector<std::unique_ptr<BOBHash32>> hash_funcs_;
};

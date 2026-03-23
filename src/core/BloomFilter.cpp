#include "BloomFilter.h"
#include <algorithm>

BloomFilter::BloomFilter(size_t size) : size_(size) {
    // Calculate number of bytes needed to store 'size' bits
    // (size + 7) / 8 rounds up to the nearest byte
    size_t num_bytes = (size + 7) >> 3;  // Bitwise divide by 8, rounding up
    bytes_.resize(num_bytes, 0);  // Initialize all bits to 0

    // Initialize BOBHash32 functions with different prime indices
    for (int i = 0; i < num_hashes_; ++i) {
        hash_funcs_.push_back(std::make_unique<BOBHash32>(i));
    }
}

void BloomFilter::insert(const std::string& key) {
    for (int i = 0; i < num_hashes_; ++i) {
        uint32_t hash_val = hash_funcs_[i]->run(key.c_str(), key.length());
        size_t pos = hash_val % size_;
        setBit(pos);  // Use optimized bit manipulation
    }
}

bool BloomFilter::contains(const std::string& key) const {
    for (int i = 0; i < num_hashes_; ++i) {
        uint32_t hash_val = hash_funcs_[i]->run(key.c_str(), key.length());
        size_t pos = hash_val % size_;
        if (!getBit(pos)) {  // Use optimized bit manipulation
            return false;
        }
    }
    return true;
}

void BloomFilter::clear() {
    // Efficiently clear all bytes at once (faster than bit-by-bit clearing)
    std::fill(bytes_.begin(), bytes_.end(), 0);
}

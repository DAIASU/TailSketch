#pragma once
#include "hash/hash.h"
#include <vector>
#include <string>
#include <memory>
#include <algorithm>

class CountMinSketch {
public:
    CountMinSketch(int depth, int width);

    // Update count for a key
    void update(const std::string& key, int count = 1);

    // Query estimated count for a key
    uint32_t query(const std::string& key) const;

    // Clear all counters
    void clear();

    // Get memory usage in bytes
    size_t memoryBytes() const;

    int getDepth() const { return depth_; }
    int getWidth() const { return width_; }

private:
    int depth_;    // Number of rows (hash functions)
    int width_;    // Number of columns
    std::vector<std::vector<uint32_t>> sketch_;
    std::vector<std::unique_ptr<BOBHash32>> hashes_;
};

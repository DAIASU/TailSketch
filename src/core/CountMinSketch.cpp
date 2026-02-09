#include "CountMinSketch.h"

CountMinSketch::CountMinSketch(int depth, int width)
    : depth_(depth), width_(width) {
    // Initialize sketch array
    sketch_.resize(depth_, std::vector<uint32_t>(width_, 0));

    // Initialize hash functions with different seeds
    auto seeds = BOBHash32::get_random_prime_index_list(depth_);
    for (int i = 0; i < depth_; i++) {
        hashes_.push_back(std::make_unique<BOBHash32>(seeds[i]));
    }
}

void CountMinSketch::update(const std::string& key, int count) {
    for (int i = 0; i < depth_; i++) {
        uint32_t h = hashes_[i]->run(key.c_str(), key.length());
        uint32_t idx = h % width_;
        sketch_[i][idx] += count;
    }
}

uint32_t CountMinSketch::query(const std::string& key) const {
    uint32_t minCount = UINT32_MAX;
    for (int i = 0; i < depth_; i++) {
        uint32_t h = hashes_[i]->run(key.c_str(), key.length());
        uint32_t idx = h % width_;
        minCount = std::min(minCount, sketch_[i][idx]);
    }
    return minCount;
}

void CountMinSketch::clear() {
    for (auto& row : sketch_) {
        std::fill(row.begin(), row.end(), 0);
    }
}

size_t CountMinSketch::memoryBytes() const {
    return depth_ * width_ * sizeof(uint32_t);
}

#ifndef FIFO_STORAGE_H
#define FIFO_STORAGE_H

#include <deque>
#include <vector>
#include <cstddef>
#include <utility>

/**
 * FIFOStorage: Fixed-memory FIFO storage with auto-eviction.
 *
 * Capacity is specified in BITS. When adding a new item would exceed
 * the bit capacity, oldest items are evicted until there's room.
 * This allows fair comparison between raw IDs (104 bits each) and
 * compressed IDs (variable bits each) using the same memory budget.
 */
template<typename T>
class FIFOStorage {
private:
    struct Entry {
        T item;
        size_t bits;
    };

    std::deque<Entry> data_;
    size_t capacityBits_;   // Max bits allowed
    size_t totalBits_;      // Current bits used

public:
    /**
     * Create storage with capacity in bits.
     * @param capacityBits Maximum bits that can be stored
     */
    explicit FIFOStorage(size_t capacityBits)
        : capacityBits_(capacityBits), totalBits_(0) {}

    /**
     * Push an item with its bit size.
     * If adding this item would exceed capacity, evicts oldest items first.
     */
    void push(const T& item, size_t itemBits) {
        if (capacityBits_ == 0) return;

        // If single item is larger than capacity, don't store it
        if (itemBits > capacityBits_) return;

        // Evict oldest items until there's room
        while (!data_.empty() && (totalBits_ + itemBits > capacityBits_)) {
            totalBits_ -= data_.front().bits;
            data_.pop_front();
        }

        data_.push_back({item, itemBits});
        totalBits_ += itemBits;
    }

    /**
     * Push with move semantics.
     */
    void push(T&& item, size_t itemBits) {
        if (capacityBits_ == 0) return;

        if (itemBits > capacityBits_) return;

        while (!data_.empty() && (totalBits_ + itemBits > capacityBits_)) {
            totalBits_ -= data_.front().bits;
            data_.pop_front();
        }

        data_.push_back({std::move(item), itemBits});
        totalBits_ += itemBits;
    }

    /**
     * Clear all entries.
     */
    void clear() {
        data_.clear();
        totalBits_ = 0;
    }

    // Iteration support (returns items only, not Entry structs)
    class Iterator {
    private:
        typename std::deque<Entry>::const_iterator it_;
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using pointer = const T*;
        using reference = const T&;

        Iterator(typename std::deque<Entry>::const_iterator it) : it_(it) {}

        reference operator*() const { return it_->item; }
        pointer operator->() const { return &(it_->item); }

        Iterator& operator++() { ++it_; return *this; }
        Iterator operator++(int) { Iterator tmp = *this; ++it_; return tmp; }

        bool operator==(const Iterator& other) const { return it_ == other.it_; }
        bool operator!=(const Iterator& other) const { return it_ != other.it_; }
    };

    Iterator begin() const { return Iterator(data_.begin()); }
    Iterator end() const { return Iterator(data_.end()); }

    // Size queries
    size_t size() const { return data_.size(); }
    size_t capacityBits() const { return capacityBits_; }
    size_t totalBits() const { return totalBits_; }
    size_t remainingBits() const { return capacityBits_ > totalBits_ ? capacityBits_ - totalBits_ : 0; }
    bool empty() const { return data_.empty(); }

    /**
     * Get all items as a vector (for batch processing).
     */
    std::vector<T> toVector() const {
        std::vector<T> result;
        result.reserve(data_.size());
        for (const auto& entry : data_) {
            result.push_back(entry.item);
        }
        return result;
    }

    /**
     * Resize capacity in bits. If new capacity is smaller, evicts oldest entries.
     */
    void resizeBits(size_t newCapacityBits) {
        capacityBits_ = newCapacityBits;
        while (!data_.empty() && totalBits_ > capacityBits_) {
            totalBits_ -= data_.front().bits;
            data_.pop_front();
        }
    }
};

#endif // FIFO_STORAGE_H

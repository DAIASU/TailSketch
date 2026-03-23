#include "AdaptiveHuffmanTree.h"
#include <queue>
#include <functional>

AdaptiveHuffmanTree::AdaptiveHuffmanTree()
    : root_(nullptr), nodeCount_(0) {}

AdaptiveHuffmanTree::~AdaptiveHuffmanTree() = default;

AdaptiveHuffmanTree::AdaptiveHuffmanTree(AdaptiveHuffmanTree&& other) noexcept
    : root_(std::move(other.root_)),
      codeDict_(std::move(other.codeDict_)),
      nodeCount_(other.nodeCount_) {
    other.nodeCount_ = 0;
}

AdaptiveHuffmanTree& AdaptiveHuffmanTree::operator=(AdaptiveHuffmanTree&& other) noexcept {
    if (this != &other) {
        root_ = std::move(other.root_);
        codeDict_ = std::move(other.codeDict_);
        nodeCount_ = other.nodeCount_;
        other.nodeCount_ = 0;
    }
    return *this;
}

void AdaptiveHuffmanTree::clear() {
    root_.reset();
    codeDict_.clear();
    nodeCount_ = 0;
}

void AdaptiveHuffmanTree::build(const std::unordered_map<uint64_t, uint64_t>& freqs) {
    clear();

    // Create a copy of frequencies and ensure NYT and UNKNOWN are present
    std::unordered_map<uint64_t, uint64_t> allFreqs = freqs;
    allFreqs[SYMBOL_NYT] = 0;
    allFreqs[SYMBOL_UNKNOWN] = 0;

    // Handle edge case: only special symbols
    if (allFreqs.size() == 2) {
        // Only NYT and UNKNOWN - still need to build a valid tree
        // Add a dummy symbol to ensure tree structure
    }

    /**
     * Custom comparator for priority queue (defined as lambda).
     * - Lower frequency = higher priority (min-heap)
     * - For equal frequency: NYT > UNKNOWN > regular
     */
    auto nodeCompare = [](const std::unique_ptr<HuffmanNode>& a,
                          const std::unique_ptr<HuffmanNode>& b) {
        // Primary: lower frequency has higher priority
        if (a->freq != b->freq) {
            return a->freq > b->freq;  // Greater means lower priority in min-heap
        }

        // Secondary: for equal frequency, determine priority by symbol type
        bool aIsNYT = (a->symbol == SYMBOL_NYT);
        bool bIsNYT = (b->symbol == SYMBOL_NYT);
        bool aIsUnknown = (a->symbol == SYMBOL_UNKNOWN);
        bool bIsUnknown = (b->symbol == SYMBOL_UNKNOWN);

        // NYT has highest priority (pops first, becomes left child)
        if (aIsNYT && !bIsNYT) return false;  // a has higher priority
        if (!aIsNYT && bIsNYT) return true;   // b has higher priority

        // UNKNOWN has second highest priority (pops second, becomes right child)
        // This ensures NYT and UNKNOWN are always paired together as siblings
        if (aIsUnknown && !bIsUnknown) return false;  // a has higher priority
        if (!aIsUnknown && bIsUnknown) return true;   // b has higher priority

        // Regular symbols have lowest priority among equal frequencies
        return a->symbol > b->symbol;
    };

    // Create priority queue with custom comparator
    std::priority_queue<
        std::unique_ptr<HuffmanNode>,
        std::vector<std::unique_ptr<HuffmanNode>>,
        decltype(nodeCompare)
    > pq(nodeCompare);

    // Add all symbols as leaf nodes
    for (const auto& [symbol, freq] : allFreqs) {
        pq.push(std::make_unique<HuffmanNode>(symbol, freq));
        nodeCount_++;
    }

    // Edge case: single symbol
    if (pq.size() == 1) {
        root_ = std::move(const_cast<std::unique_ptr<HuffmanNode>&>(pq.top()));
        pq.pop();
        codeDict_[root_->symbol] = "0";
        return;
    }

    // Build tree by combining lowest frequency nodes
    while (pq.size() > 1) {
        auto left = std::move(const_cast<std::unique_ptr<HuffmanNode>&>(pq.top()));
        pq.pop();
        auto right = std::move(const_cast<std::unique_ptr<HuffmanNode>&>(pq.top()));
        pq.pop();

        // Create internal node with combined frequency
        auto internal = std::make_unique<HuffmanNode>(0, left->freq + right->freq);
        internal->left = std::move(left);
        internal->right = std::move(right);

        pq.push(std::move(internal));
        nodeCount_++;
    }

    // Root is the last remaining node
    root_ = std::move(const_cast<std::unique_ptr<HuffmanNode>&>(pq.top()));
    pq.pop();

    // Build encoding dictionary via DFS
    buildCodeDict(root_.get(), "");
}

void AdaptiveHuffmanTree::buildCodeDict(const HuffmanNode* node, const std::string& code) {
    if (!node) return;

    if (node->isLeaf()) {
        codeDict_[node->symbol] = code.empty() ? "0" : code;
        return;
    }

    buildCodeDict(node->left.get(), code + "0");
    buildCodeDict(node->right.get(), code + "1");
}

std::string AdaptiveHuffmanTree::encode(uint64_t symbol) const {
    auto it = codeDict_.find(symbol);
    if (it != codeDict_.end()) {
        return it->second;
    }
    return "";  // Symbol not found
}

uint64_t AdaptiveHuffmanTree::decode(const std::string& bits, size_t& pos) const {
    if (!root_) return 0;

    const HuffmanNode* current = root_.get();

    // Handle single-node tree
    if (current->isLeaf()) {
        if (pos < bits.size()) {
            pos++;  // Consume the '0' bit
        }
        return current->symbol;
    }

    // Traverse tree based on bits
    while (!current->isLeaf() && pos < bits.size()) {
        if (bits[pos] == '0') {
            current = current->left.get();
        } else {
            current = current->right.get();
        }
        pos++;
    }

    if (current && current->isLeaf()) {
        return current->symbol;
    }

    return 0;  // Decoding failed
}

bool AdaptiveHuffmanTree::hasSymbol(uint64_t symbol) const {
    // Check if symbol exists and is not a special symbol
    if (symbol == SYMBOL_NYT || symbol == SYMBOL_UNKNOWN) {
        return false;  // These are special symbols, not "regular" symbols
    }
    return codeDict_.find(symbol) != codeDict_.end();
}

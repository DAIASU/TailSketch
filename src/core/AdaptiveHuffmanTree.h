#ifndef ADAPTIVE_HUFFMAN_TREE_H
#define ADAPTIVE_HUFFMAN_TREE_H

#include <memory>
#include <unordered_map>
#include <string>
#include <cstdint>

// Special symbol constants (use high values unlikely to be real field values)
// Using uint64_t to distinguish from regular uint32_t field values
constexpr uint64_t SYMBOL_NYT = 0xFFFFFFFF00000000ULL;
constexpr uint64_t SYMBOL_UNKNOWN = 0xFFFFFFFF00000001ULL;

/**
 * AdaptiveHuffmanTree: Huffman tree with special symbols NYT and UNKNOWN.
 *
 * When building the tree:
 * - NYT and UNKNOWN always have frequency 0
 * - When frequencies are equal, priority is: NYT > regular symbols > UNKNOWN
 * - This ensures NYT gets a shorter or equal code compared to UNKNOWN
 */
class AdaptiveHuffmanTree {
public:
    AdaptiveHuffmanTree();
    ~AdaptiveHuffmanTree();

    // Move semantics
    AdaptiveHuffmanTree(AdaptiveHuffmanTree&& other) noexcept;
    AdaptiveHuffmanTree& operator=(AdaptiveHuffmanTree&& other) noexcept;

    // No copy
    AdaptiveHuffmanTree(const AdaptiveHuffmanTree&) = delete;
    AdaptiveHuffmanTree& operator=(const AdaptiveHuffmanTree&) = delete;

    /**
     * Build tree from frequency map.
     * The map should include regular field values and their frequencies.
     * NYT and UNKNOWN are automatically added with frequency 0.
     */
    void build(const std::unordered_map<uint64_t, uint64_t>& freqs);

    /**
     * Encode a symbol to its Huffman code.
     * Returns empty string if symbol not found.
     */
    std::string encode(uint64_t symbol) const;

    /**
     * Decode from bit string starting at pos.
     * Updates pos to point after the decoded symbol.
     * Returns the decoded symbol (could be NYT, UNKNOWN, or a regular value).
     */
    uint64_t decode(const std::string& bits, size_t& pos) const;

    /**
     * Check if a symbol exists in the tree (excluding NYT and UNKNOWN).
     */
    bool hasSymbol(uint64_t symbol) const;

    /**
     * Check if tree has been built.
     */
    bool isBuilt() const { return root_ != nullptr; }

    /**
     * Memory overhead in bits.
     * Each node: 8 bytes symbol + 8 bytes freq = 16 bytes = 128 bits
     */
    size_t treeMemoryBits() const { return nodeCount_ * 128; }

    /**
     * Number of nodes in the tree.
     */
    size_t nodeCount() const { return nodeCount_; }

    /**
     * Clear the tree.
     */
    void clear();

    /**
     * Get the code dictionary (symbol -> code mapping).
     * Useful for iterating over all symbols in the tree.
     */
    const std::unordered_map<uint64_t, std::string>& getCodeDict() const {
        return codeDict_;
    }

private:
    struct HuffmanNode {
        uint64_t symbol;
        uint64_t freq;
        std::unique_ptr<HuffmanNode> left;
        std::unique_ptr<HuffmanNode> right;

        HuffmanNode(uint64_t s, uint64_t f)
            : symbol(s), freq(f), left(nullptr), right(nullptr) {}

        bool isLeaf() const { return !left && !right; }
    };

    std::unique_ptr<HuffmanNode> root_;
    std::unordered_map<uint64_t, std::string> codeDict_;
    size_t nodeCount_;

    void buildCodeDict(const HuffmanNode* node, const std::string& code);
};

#endif // ADAPTIVE_HUFFMAN_TREE_H

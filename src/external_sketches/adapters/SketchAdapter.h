#ifndef SKETCH_ADAPTER_H
#define SKETCH_ADAPTER_H

#include "../../core/Packet.h"
#include "../../core/TailSketch.h"  // For PartialKey definition
#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>

/**
 * Base adapter interface for external sketch implementations.
 * Provides unified interface for fair comparison across different sketches.
 */
class SketchAdapter {
public:
    virtual ~SketchAdapter() = default;

    /**
     * Initialize sketch with memory budget in bytes.
     * @param memoryBytes Total memory budget for sketch
     */
    virtual void initialize(size_t memoryBytes) = 0;

    /**
     * Insert packet into sketch.
     * @param pkt Packet to insert
     */
    virtual void insert(const Packet& pkt) = 0;

    /**
     * Query partial key - sum of all flows matching the partial key.
     * @param key Partial key to query
     * @param totalPackets Total packets processed (for normalization)
     * @return Estimated frequency for the partial key
     */
    virtual double queryPartialKey(const PartialKey& key,
                                   uint64_t totalPackets) = 0;

    /**
     * Get all flows stored in the sketch (for efficient batch queries).
     * @return Map of flow -> estimated count
     */
    virtual std::unordered_map<Packet, double, PacketHash> getAllFlows() = 0;

    /**
     * Get sketch name for reporting.
     * @return Name of the sketch (e.g., "USS", "CocoSketch")
     */
    virtual std::string getName() const = 0;

    /**
     * Clear sketch state (reset counters).
     */
    virtual void clear() = 0;
};

/**
 * Helper function: Check if packet matches partial key.
 * Used by adapters for post-query filtering.
 */
inline bool matchesPartialKey(const Packet& pkt, const PartialKey& key) {
    // Check each field: mask bit 0 means exact match required
    if (!(key.mask & 0x01) && pkt.srcIP != key.srcIP) return false;
    if (!(key.mask & 0x02) && pkt.dstIP != key.dstIP) return false;
    if (!(key.mask & 0x04) && pkt.srcPort != key.srcPort) return false;
    if (!(key.mask & 0x08) && pkt.dstPort != key.dstPort) return false;
    if (!(key.mask & 0x10) && pkt.proto != key.proto) return false;
    return true;
}

#endif // SKETCH_ADAPTER_H

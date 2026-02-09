#ifndef SANDWICH_SKETCH_ADAPTER_H
#define SANDWICH_SKETCH_ADAPTER_H

#include "SketchAdapter.h"

// Forward declaration
class SandwichSketchAdapterImpl;

/**
 * Adapter for SandwichSketch sketch.
 * Wraps the external Ours_ItemFull implementation with unified SketchAdapter interface.
 * Two-tier architecture: TopK layer (90% memory) + CoCo layer (10% memory).
 */
class SandwichSketchAdapter : public SketchAdapter {
private:
    SandwichSketchAdapterImpl* pImpl;  // Pointer to implementation (hides SandwichSketch types)
    size_t memoryBytes;

public:
    SandwichSketchAdapter();
    ~SandwichSketchAdapter() override;

    void initialize(size_t memoryBytes) override;
    void insert(const Packet& pkt) override;
    double queryPartialKey(const PartialKey& key, uint64_t totalPackets) override;
    std::unordered_map<Packet, double, PacketHash> getAllFlows() override;
    std::string getName() const override;
    void clear() override;
};

#endif // SANDWICH_SKETCH_ADAPTER_H

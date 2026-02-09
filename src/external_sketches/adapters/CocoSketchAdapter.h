#ifndef COCO_SKETCH_ADAPTER_H
#define COCO_SKETCH_ADAPTER_H

#include "SketchAdapter.h"

// Forward declaration
class CocoSketchAdapterImpl;

/**
 * Adapter for CocoSketch sketch.
 * Wraps the external OurHard implementation with unified SketchAdapter interface.
 * Uses 4 hash tables with median aggregation.
 */
class CocoSketchAdapter : public SketchAdapter {
private:
    CocoSketchAdapterImpl* pImpl;  // Pointer to implementation (hides CocoSketch types)
    size_t memoryBytes;

public:
    CocoSketchAdapter();
    ~CocoSketchAdapter() override;

    void initialize(size_t memoryBytes) override;
    void insert(const Packet& pkt) override;
    double queryPartialKey(const PartialKey& key, uint64_t totalPackets) override;
    std::unordered_map<Packet, double, PacketHash> getAllFlows() override;
    std::string getName() const override;
    void clear() override;
};

#endif // COCO_SKETCH_ADAPTER_H

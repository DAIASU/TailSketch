#ifndef USS_ADAPTER_H
#define USS_ADAPTER_H

#include "SketchAdapter.h"

// Forward declaration
class USSAdapterImpl;

/**
 * Adapter for USS (Uniform Sample Sampler) sketch.
 * Wraps the external USS implementation with unified SketchAdapter interface.
 */
class USSAdapter : public SketchAdapter {
private:
    USSAdapterImpl* pImpl;  // Pointer to implementation (hides USS types)
    size_t memoryBytes;

public:
    USSAdapter();
    ~USSAdapter() override;

    void initialize(size_t memoryBytes) override;
    void insert(const Packet& pkt) override;
    double queryPartialKey(const PartialKey& key, uint64_t totalPackets) override;
    std::unordered_map<Packet, double, PacketHash> getAllFlows() override;
    std::string getName() const override;
    void clear() override;
};

#endif // USS_ADAPTER_H

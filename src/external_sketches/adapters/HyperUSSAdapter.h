#ifndef HYPER_USS_ADAPTER_H
#define HYPER_USS_ADAPTER_H

#include "SketchAdapter.h"

// Forward declaration
class HyperUSSAdapterImpl;

/**
 * Adapter for HyperUSS sketch (simplified mode).
 * Uses only values[0] dimension for packet counting.
 * Wraps the external OurHyper implementation with unified SketchAdapter interface.
 */
class HyperUSSAdapter : public SketchAdapter {
private:
    HyperUSSAdapterImpl* pImpl;  // Pointer to implementation (hides HyperUSS types)
    size_t memoryBytes;

public:
    HyperUSSAdapter();
    ~HyperUSSAdapter() override;

    void initialize(size_t memoryBytes) override;
    void insert(const Packet& pkt) override;
    double queryPartialKey(const PartialKey& key, uint64_t totalPackets) override;
    std::unordered_map<Packet, double, PacketHash> getAllFlows() override;
    std::string getName() const override;
    void clear() override;
};

#endif // HYPER_USS_ADAPTER_H

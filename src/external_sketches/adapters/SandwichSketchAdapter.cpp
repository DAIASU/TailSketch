#include "SandwichSketchAdapter.h"

#include <cassert>  // Required by SandwichSketch's Util.h

// Include SandwichSketch dependencies from ComparisonSchemes
#include "../../../../ComparisonSchemes/SandwichSketch/CPU/Common/Util.h"
#include "../../../../ComparisonSchemes/SandwichSketch/CPU/Algos/Abstract.h"
#include "../../../../ComparisonSchemes/SandwichSketch/CPU/Algos/Ours_ItemFull.h"

// Implementation
class SandwichSketchAdapterImpl {
public:
    Ours_ItemFull<TUPLES>* sketch;

    SandwichSketchAdapterImpl() : sketch(nullptr) {}

    ~SandwichSketchAdapterImpl() {
        if (sketch) delete sketch;
    }

    TUPLES packetToTuples(const Packet& pkt) {
        TUPLES t;
        memset(t.data, 0, TUPLES_LEN);
        *((uint32_t*)(t.data)) = pkt.srcIP;
        *((uint32_t*)(&t.data[4])) = pkt.dstIP;
        *((uint16_t*)(&t.data[8])) = pkt.srcPort;
        *((uint16_t*)(&t.data[10])) = pkt.dstPort;
        *((uint8_t*)(&t.data[12])) = pkt.proto;
        return t;
    }

    Packet tuplesToPacket(const TUPLES& t) {
        Packet pkt;
        pkt.srcIP = t.srcIP();
        pkt.dstIP = t.dstIP();
        pkt.srcPort = t.srcPort();
        pkt.dstPort = t.dstPort();
        pkt.proto = t.proto();
        return pkt;
    }
};

SandwichSketchAdapter::SandwichSketchAdapter() : pImpl(new SandwichSketchAdapterImpl()), memoryBytes(0) {}

SandwichSketchAdapter::~SandwichSketchAdapter() {
    delete pImpl;
}

void SandwichSketchAdapter::initialize(size_t memoryBytes) {
    this->memoryBytes = memoryBytes;
    pImpl->sketch = new Ours_ItemFull<TUPLES>(memoryBytes, "SandwichSketch");
}

void SandwichSketchAdapter::insert(const Packet& pkt) {
    TUPLES t = pImpl->packetToTuples(pkt);
    pImpl->sketch->Insert(t);
}

double SandwichSketchAdapter::queryPartialKey(const PartialKey& key, uint64_t totalPackets) {
    auto allFlows = pImpl->sketch->AllQuery();

    uint64_t totalCount = 0;
    for (const auto& [tuples, count] : allFlows) {
        Packet pkt = pImpl->tuplesToPacket(tuples);
        if (matchesPartialKey(pkt, key)) {
            totalCount += count;
        }
    }

    return static_cast<double>(totalCount);
}

std::unordered_map<Packet, double, PacketHash> SandwichSketchAdapter::getAllFlows() {
    auto allFlows = pImpl->sketch->AllQuery();

    std::unordered_map<Packet, double, PacketHash> result;
    for (const auto& [tuples, count] : allFlows) {
        Packet pkt = pImpl->tuplesToPacket(tuples);
        result[pkt] = static_cast<double>(count);
    }

    return result;
}

std::string SandwichSketchAdapter::getName() const {
    return "SandwichSketch";
}

void SandwichSketchAdapter::clear() {
    if (pImpl->sketch != nullptr) {
        delete pImpl->sketch;
        pImpl->sketch = new Ours_ItemFull<TUPLES>(memoryBytes, "SandwichSketch");
    }
}

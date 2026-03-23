#include "USSAdapter.h"

// Include USS dependencies from ComparisonSchemes
#include "../../../ComparisonSchemes/CocoSketch/CPU/Common/Util.h"
#include "../../../ComparisonSchemes/CocoSketch/CPU/Struct/StreamSummary.h"
#include "../../../ComparisonSchemes/CocoSketch/CPU/Multiple/MultiAbstract.h"
#include "../../../ComparisonSchemes/CocoSketch/CPU/Multiple/USS.h"

// Implementation
class USSAdapterImpl {
public:
    USS<TUPLES>* sketch;

    USSAdapterImpl() : sketch(nullptr) {}

    ~USSAdapterImpl() {
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

USSAdapter::USSAdapter() : pImpl(new USSAdapterImpl()), memoryBytes(0) {}

USSAdapter::~USSAdapter() {
    delete pImpl;
}

void USSAdapter::initialize(size_t memoryBytes) {
    this->memoryBytes = memoryBytes;
    pImpl->sketch = new USS<TUPLES>(memoryBytes, "USS");
}

void USSAdapter::insert(const Packet& pkt) {
    TUPLES t = pImpl->packetToTuples(pkt);
    pImpl->sketch->Insert(t);
}

double USSAdapter::queryPartialKey(const PartialKey& key, uint64_t totalPackets) {
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

std::unordered_map<Packet, double, PacketHash> USSAdapter::getAllFlows() {
    auto allFlows = pImpl->sketch->AllQuery();

    std::unordered_map<Packet, double, PacketHash> result;
    for (const auto& [tuples, count] : allFlows) {
        Packet pkt = pImpl->tuplesToPacket(tuples);
        result[pkt] = static_cast<double>(count);
    }

    return result;
}

std::string USSAdapter::getName() const {
    return "USS";
}

void USSAdapter::clear() {
    if (pImpl->sketch != nullptr) {
        delete pImpl->sketch;
        pImpl->sketch = new USS<TUPLES>(memoryBytes, "USS");
    }
}

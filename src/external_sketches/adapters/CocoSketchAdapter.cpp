#include "CocoSketchAdapter.h"

// Include CocoSketch dependencies from ComparisonSchemes
#include "../../../../ComparisonSchemes/CocoSketch/CPU/Common/Util.h"
#include "../../../../ComparisonSchemes/CocoSketch/CPU/Multiple/MultiAbstract.h"
#include "../../../../ComparisonSchemes/CocoSketch/CPU/Multiple/OurHard.h"

// Implementation
class CocoSketchAdapterImpl {
public:
    OurHard<TUPLES>* sketch;
    static constexpr uint32_t HASH_NUM = 4;

    CocoSketchAdapterImpl() : sketch(nullptr) {}

    ~CocoSketchAdapterImpl() {
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

CocoSketchAdapter::CocoSketchAdapter() : pImpl(new CocoSketchAdapterImpl()), memoryBytes(0) {}

CocoSketchAdapter::~CocoSketchAdapter() {
    delete pImpl;
}

void CocoSketchAdapter::initialize(size_t memoryBytes) {
    this->memoryBytes = memoryBytes;
    pImpl->sketch = new OurHard<TUPLES>(memoryBytes, CocoSketchAdapterImpl::HASH_NUM, "CocoSketch");
}

void CocoSketchAdapter::insert(const Packet& pkt) {
    TUPLES t = pImpl->packetToTuples(pkt);
    pImpl->sketch->Insert(t);
}

double CocoSketchAdapter::queryPartialKey(const PartialKey& key, uint64_t totalPackets) {
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

std::unordered_map<Packet, double, PacketHash> CocoSketchAdapter::getAllFlows() {
    auto allFlows = pImpl->sketch->AllQuery();

    std::unordered_map<Packet, double, PacketHash> result;
    for (const auto& [tuples, count] : allFlows) {
        Packet pkt = pImpl->tuplesToPacket(tuples);
        result[pkt] = static_cast<double>(count);
    }

    return result;
}

std::string CocoSketchAdapter::getName() const {
    return "CocoSketch";
}

void CocoSketchAdapter::clear() {
    if (pImpl->sketch != nullptr) {
        delete pImpl->sketch;
        pImpl->sketch = new OurHard<TUPLES>(memoryBytes, CocoSketchAdapterImpl::HASH_NUM, "CocoSketch");
    }
}

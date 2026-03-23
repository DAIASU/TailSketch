#include "HyperUSSAdapter.h"

// Include HyperUSS dependencies from ComparisonSchemes
#include "../../../ComparisonSchemes/HyperUSS/CPU/Common/Util.h"
#include "../../../ComparisonSchemes/HyperUSS/CPU/Multiple/Hyper.h"

// Implementation
class HyperUSSAdapterImpl {
public:
    OurHyper* sketch;
    static constexpr uint32_t HASH_NUM = 2;

    HyperUSSAdapterImpl() : sketch(nullptr) {}

    ~HyperUSSAdapterImpl() {
        if (sketch) delete sketch;
    }

    TUPLES_ID packetToTuplesID(const Packet& pkt) {
        TUPLES_ID id;
        id.key[0] = pkt.srcIP;
        id.key[1] = pkt.dstIP;
        id.key[2] = static_cast<uint32_t>(pkt.srcPort);
        id.key[3] = static_cast<uint32_t>(pkt.dstPort);
        id.key[4] = static_cast<uint32_t>(pkt.proto);
        return id;
    }

    Packet tuplesIDToPacket(const TUPLES_ID& id) {
        Packet pkt;
        pkt.srcIP = id.key[0];
        pkt.dstIP = id.key[1];
        pkt.srcPort = static_cast<uint16_t>(id.key[2]);
        pkt.dstPort = static_cast<uint16_t>(id.key[3]);
        pkt.proto = static_cast<uint8_t>(id.key[4]);
        return pkt;
    }

    TUPLES_VALUE createValue(double count) {
        TUPLES_VALUE val;
        val.values[0] = count;
        for (int i = 1; i < TUPLES_VALUES_ELEMENT_NUM; i++) {
            val.values[i] = 0.0;
        }
        return val;
    }
};

HyperUSSAdapter::HyperUSSAdapter() : pImpl(new HyperUSSAdapterImpl()), memoryBytes(0) {}

HyperUSSAdapter::~HyperUSSAdapter() {
    delete pImpl;
}

void HyperUSSAdapter::initialize(size_t memoryBytes) {
    this->memoryBytes = memoryBytes;
    pImpl->sketch = new OurHyper(memoryBytes, HyperUSSAdapterImpl::HASH_NUM, "HyperUSS");
}

void HyperUSSAdapter::insert(const Packet& pkt) {
    TUPLES t;
    t.id = pImpl->packetToTuplesID(pkt);
    t.value = pImpl->createValue(1.0);
    pImpl->sketch->Insert(t);
}

double HyperUSSAdapter::queryPartialKey(const PartialKey& key, uint64_t totalPackets) {
    auto allFlows = pImpl->sketch->AllQuery();

    double totalCount = 0.0;
    for (const auto& [tuplesID, tuplesValue] : allFlows) {
        Packet pkt = pImpl->tuplesIDToPacket(tuplesID);
        if (matchesPartialKey(pkt, key)) {
            totalCount += tuplesValue.values[0];
        }
    }

    return totalCount;
}

std::unordered_map<Packet, double, PacketHash> HyperUSSAdapter::getAllFlows() {
    auto allFlows = pImpl->sketch->AllQuery();

    std::unordered_map<Packet, double, PacketHash> result;
    for (const auto& [tuplesID, tuplesValue] : allFlows) {
        Packet pkt = pImpl->tuplesIDToPacket(tuplesID);
        result[pkt] = tuplesValue.values[0];  // Use first dimension for count
    }

    return result;
}

std::string HyperUSSAdapter::getName() const {
    return "HyperUSS";
}

void HyperUSSAdapter::clear() {
    if (pImpl->sketch != nullptr) {
        delete pImpl->sketch;
        pImpl->sketch = new OurHyper(memoryBytes, HyperUSSAdapterImpl::HASH_NUM, "HyperUSS");
    }
}

#pragma once
#include <cstdint>
#include <string>
#include <functional>

// 5-tuple packet structure for network flow identification
struct Packet {
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t proto;

    // Convert to string key for hashing
    std::string toKey() const {
        std::string key;
        key.reserve(13);
        key.append(reinterpret_cast<const char*>(&srcIP), sizeof(srcIP));
        key.append(reinterpret_cast<const char*>(&dstIP), sizeof(dstIP));
        key.append(reinterpret_cast<const char*>(&srcPort), sizeof(srcPort));
        key.append(reinterpret_cast<const char*>(&dstPort), sizeof(dstPort));
        key.append(reinterpret_cast<const char*>(&proto), sizeof(proto));
        return key;
    }

    // Get field by index (0=srcIP, 1=dstIP, 2=srcPort, 3=dstPort, 4=proto)
    uint32_t getField(int i) const {
        switch (i) {
            case 0: return srcIP;
            case 1: return dstIP;
            case 2: return srcPort;
            case 3: return dstPort;
            case 4: return proto;
            default: return 0;
        }
    }

    // Get field bit width (32, 32, 16, 16, 8)
    static int getFieldBits(int i) {
        switch (i) {
            case 0: return 32;
            case 1: return 32;
            case 2: return 16;
            case 3: return 16;
            case 4: return 8;
            default: return 0;
        }
    }

    bool operator==(const Packet& other) const {
        return srcIP == other.srcIP &&
               dstIP == other.dstIP &&
               srcPort == other.srcPort &&
               dstPort == other.dstPort &&
               proto == other.proto;
    }
};

// Custom hash for unordered_map support
struct PacketHash {
    size_t operator()(const Packet& p) const {
        // Combine all fields using XOR and bit shifts
        size_t h = std::hash<uint32_t>{}(p.srcIP);
        h ^= std::hash<uint32_t>{}(p.dstIP) << 1;
        h ^= std::hash<uint16_t>{}(p.srcPort) << 2;
        h ^= std::hash<uint16_t>{}(p.dstPort) << 3;
        h ^= std::hash<uint8_t>{}(p.proto) << 4;
        return h;
    }
};

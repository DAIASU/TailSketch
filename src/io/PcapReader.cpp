#include "PcapReader.h"
#include <arpa/inet.h>  // For ntohl(), ntohs()
#include <cstring>

// Ethernet header size
constexpr int ETHERNET_HEADER_SIZE = 14;

// IP protocol numbers
constexpr uint8_t IP_PROTO_TCP = 6;
constexpr uint8_t IP_PROTO_UDP = 17;
constexpr uint8_t IP_PROTO_ICMP = 1;

PcapReader::PcapReader()
    : handle_(nullptr), isOpen_(false), packetsRead_(0),
      packetsSkipped_(0), linkType_(0) {}

PcapReader::~PcapReader() {
    close();
}

bool PcapReader::open(const std::string& filename) {
    close();

    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_offline(filename.c_str(), errbuf);

    if (handle_ == nullptr) {
        errorMsg_ = errbuf;
        return false;
    }

    linkType_ = pcap_datalink(handle_);
    isOpen_ = true;
    packetsRead_ = 0;
    packetsSkipped_ = 0;
    return true;
}

bool PcapReader::readNext(Packet& pkt) {
    if (!isOpen_) return false;

    struct pcap_pkthdr* header;
    const u_char* data;

    while (true) {
        int ret = pcap_next_ex(handle_, &header, &data);

        if (ret == -2) {
            // EOF
            return false;
        } else if (ret == -1) {
            // Error
            errorMsg_ = pcap_geterr(handle_);
            return false;
        } else if (ret == 0) {
            // Timeout (shouldn't happen for offline)
            continue;
        }

        // Try to parse packet
        if (parsePacket(data, header->caplen, pkt)) {
            packetsRead_++;
            return true;
        }

        // Not a valid IP/TCP/UDP packet, skip
        packetsSkipped_++;
    }
}

bool PcapReader::parsePacket(const u_char* data, int len, Packet& pkt) {
    int offset = 0;

    // Handle different link types
    switch (linkType_) {
        case DLT_EN10MB:  // Ethernet
            offset = ETHERNET_HEADER_SIZE;
            break;
        case DLT_RAW:     // Raw IP
            offset = 0;
            break;
        case DLT_LINUX_SLL:  // Linux cooked capture
            offset = 16;
            break;
        default:
            offset = ETHERNET_HEADER_SIZE;
            break;
    }

    if (len < offset + 20) {  // Need at least IP header
        return false;
    }

    const u_char* ipHeader = data + offset;

    // Check IP version (should be 4)
    uint8_t version = (ipHeader[0] >> 4) & 0x0F;
    if (version != 4) {
        return false;
    }

    // Get IP header length
    uint8_t ihl = (ipHeader[0] & 0x0F) * 4;
    if (len < offset + ihl) {
        return false;
    }

    // Extract protocol
    pkt.proto = ipHeader[9];

    // Extract IPs with NETWORK TO HOST byte order conversion
    // PCAP stores data in Big Endian (Network Byte Order)
    pkt.srcIP = ntohl(*(reinterpret_cast<const uint32_t*>(ipHeader + 12)));
    pkt.dstIP = ntohl(*(reinterpret_cast<const uint32_t*>(ipHeader + 16)));

    // Get transport layer header
    const u_char* transportHeader = ipHeader + ihl;
    int transportLen = len - offset - ihl;

    if (pkt.proto == IP_PROTO_TCP && transportLen >= 4) {
        // TCP: extract ports with byte order conversion
        pkt.srcPort = ntohs(*(reinterpret_cast<const uint16_t*>(transportHeader)));
        pkt.dstPort = ntohs(*(reinterpret_cast<const uint16_t*>(transportHeader + 2)));
        return true;
    } else if (pkt.proto == IP_PROTO_UDP && transportLen >= 4) {
        // UDP: extract ports with byte order conversion
        pkt.srcPort = ntohs(*(reinterpret_cast<const uint16_t*>(transportHeader)));
        pkt.dstPort = ntohs(*(reinterpret_cast<const uint16_t*>(transportHeader + 2)));
        return true;
    } else if (pkt.proto == IP_PROTO_ICMP) {
        // ICMP: use type/code as pseudo-ports
        if (transportLen >= 2) {
            pkt.srcPort = transportHeader[0];  // ICMP type
            pkt.dstPort = transportHeader[1];  // ICMP code
            return true;
        }
    }

    // Other protocols: set ports to 0
    pkt.srcPort = 0;
    pkt.dstPort = 0;
    return true;  // Still return the packet for other IP protocols
}

void PcapReader::close() {
    if (handle_ != nullptr) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
    isOpen_ = false;
}

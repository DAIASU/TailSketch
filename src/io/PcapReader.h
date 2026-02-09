#pragma once
#include "core/Packet.h"
#include <pcap.h>
#include <string>

// PCAP file reader for extracting 5-tuples
class PcapReader {
public:
    PcapReader();
    ~PcapReader();

    // Prevent copying
    PcapReader(const PcapReader&) = delete;
    PcapReader& operator=(const PcapReader&) = delete;

    // Open a PCAP file
    bool open(const std::string& filename);

    // Read next packet, returns false on EOF or error
    bool readNext(Packet& pkt);

    // Close the file
    void close();

    // Check if file is open
    bool isOpen() const { return isOpen_; }

    // Get error message
    const std::string& getError() const { return errorMsg_; }

    // Get number of packets read
    uint64_t packetsRead() const { return packetsRead_; }

    // Get number of packets skipped (non-IP/TCP/UDP)
    uint64_t packetsSkipped() const { return packetsSkipped_; }

private:
    // Parse Ethernet/IP/TCP/UDP headers with byte order conversion
    bool parsePacket(const u_char* data, int len, Packet& pkt);

    pcap_t* handle_;
    bool isOpen_;
    std::string errorMsg_;
    uint64_t packetsRead_;
    uint64_t packetsSkipped_;
    int linkType_;
};

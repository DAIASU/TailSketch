/**
 * Multi-Sketch Comparison Program
 *
 * Compares 5 sketch algorithms on partial key queries:
 * 1. TailSketch (adaptive Huffman encoding)
 * 2. USS (Uniform Sample Sampler)
 * 3. CocoSketch (multiple hash tables with median)
 * 4. HyperUSS (multi-dimensional sketch, simplified mode)
 * 5. SandwichSketch (two-tier TopK + CoCo)
 *
 * Tests 5 patterns: SrcIP Only, DstIP Only, Src Pair, Dst Pair, IP Pair
 * Fixed beta = 1.0 for all queries
 *
 * Outputs 3 CSV files:
 * - sketch_comparison_detailed.csv: Per partial key metrics
 * - sketch_comparison_summary.csv: Per window-pattern-category metrics
 * - sketch_comparison_overall.csv: Overall metrics averaged across windows
 */

#include "AdaptiveHuffmanLearner.h"
#include "TailSketch.h"
#include "FrequentTable.h"
#include "PcapReader.h"
#include "Packet.h"

// External sketch adapters
// IMPORTANT: Include HyperUSSAdapter first to avoid TUPLES struct conflicts
#include "external_sketches/adapters/HyperUSSAdapter.h"
#include "external_sketches/adapters/USSAdapter.h"
#include "external_sketches/adapters/CocoSketchAdapter.h"
#include "external_sketches/adapters/SandwichSketchAdapter.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <array>
#include <algorithm>
#include <cmath>
#include <chrono>
#include <getopt.h>
#include <sys/stat.h>

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

struct ComparisonConfig {
    std::string pcapFile;
    std::string outputDir = "./SketchComparison/";
    int windowSize = 100000;
    int memoryKB = 256;
    int frequentTableK = 32768;
    double elephantThreshold = 0.005;
    int maxWindows = 5;  // -1 means process all windows
};

// ═══════════════════════════════════════════════════════════════════════════
// CSV Writer
// ═══════════════════════════════════════════════════════════════════════════

class CSVWriter {
public:
    CSVWriter(const std::string& filename) : filename_(filename) {
        file_.open(filename);
        if (!file_.is_open()) {
            std::cerr << "Failed to open CSV file: " << filename << "\n";
        }
    }

    ~CSVWriter() {
        if (file_.is_open()) {
            file_.close();
        }
    }

    void writeHeader(const std::vector<std::string>& headers) {
        for (size_t i = 0; i < headers.size(); i++) {
            file_ << headers[i];
            if (i < headers.size() - 1) file_ << ",";
        }
        file_ << "\n";
        file_.flush();
    }

    template<typename... Args>
    void writeRow(Args... args) {
        writeRowImpl(args...);
        file_ << "\n";
        file_.flush();
    }

private:
    std::string filename_;
    std::ofstream file_;

    template<typename T>
    void writeRowImpl(T value) {
        file_ << value;
    }

    template<typename T, typename... Args>
    void writeRowImpl(T value, Args... args) {
        file_ << value << ",";
        writeRowImpl(args...);
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Hash Functor for PartialKey
// ═══════════════════════════════════════════════════════════════════════════

struct PartialKeyHash {
    size_t operator()(const PartialKey& pk) const {
        size_t h = 0;
        if ((pk.mask & 0x01) == 0) h ^= std::hash<uint32_t>()(pk.srcIP);
        if ((pk.mask & 0x02) == 0) h ^= std::hash<uint32_t>()(pk.dstIP) << 1;
        if ((pk.mask & 0x04) == 0) h ^= std::hash<uint16_t>()(pk.srcPort) << 2;
        if ((pk.mask & 0x08) == 0) h ^= std::hash<uint16_t>()(pk.dstPort) << 3;
        if ((pk.mask & 0x10) == 0) h ^= std::hash<uint8_t>()(pk.proto) << 4;
        h ^= std::hash<uint8_t>()(pk.mask) << 5;
        return h;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

std::string partialKeyToString(const PartialKey& pk) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    if (!(pk.mask & 0x01)) ss << std::setw(8) << pk.srcIP << "-";
    else ss << "***-";
    if (!(pk.mask & 0x02)) ss << std::setw(8) << pk.dstIP << "-";
    else ss << "***-";
    if (!(pk.mask & 0x04)) ss << std::setw(4) << pk.srcPort << "-";
    else ss << "***-";
    if (!(pk.mask & 0x08)) ss << std::setw(4) << pk.dstPort << "-";
    else ss << "***-";
    if (!(pk.mask & 0x10)) ss << std::setw(2) << (int)pk.proto;
    else ss << "***";
    return ss.str();
}

PartialKey extractPartialKey(const Packet& pkt, uint8_t mask) {
    PartialKey pk;
    pk.mask = mask;
    pk.srcIP = (mask & 0x01) ? 0 : pkt.srcIP;
    pk.dstIP = (mask & 0x02) ? 0 : pkt.dstIP;
    pk.srcPort = (mask & 0x04) ? 0 : pkt.srcPort;
    pk.dstPort = (mask & 0x08) ? 0 : pkt.dstPort;
    pk.proto = (mask & 0x10) ? 0 : pkt.proto;
    return pk;
}

std::unordered_map<PartialKey, int, PartialKeyHash> buildGroundTruth(
    const std::vector<Packet>& packets,
    uint8_t mask) {
    std::unordered_map<PartialKey, int, PartialKeyHash> truth;
    for (const auto& pkt : packets) {
        truth[extractPartialKey(pkt, mask)]++;
    }
    return truth;
}

std::array<FrequentTable, 5> buildFrequentTablesFromEntireFile(
    const std::string& pcapFile, int frequentTableK) {
    std::cout << "Phase 1: Building frequent tables from entire file...\n";

    PcapReader reader;
    if (!reader.open(pcapFile)) {
        std::cerr << "Failed to open PCAP file: " << pcapFile << "\n";
        throw std::runtime_error("Failed to open PCAP file");
    }

    // Count unique values for each field across entire file
    std::array<std::unordered_map<uint32_t, uint64_t>, 5> fieldCounters;
    std::unordered_set<Packet, PacketHash> seenFlows;

    Packet pkt;
    size_t totalPackets = 0;
    while (reader.readNext(pkt)) {
        seenFlows.insert(pkt);
        fieldCounters[0][pkt.srcIP]++;
        fieldCounters[1][pkt.dstIP]++;
        fieldCounters[2][pkt.srcPort]++;
        fieldCounters[3][pkt.dstPort]++;
        fieldCounters[4][pkt.proto]++;
        totalPackets++;
        if (totalPackets % 1000000 == 0) {
            std::cout << "  Processed " << totalPackets / 1000000 << "M packets...\n";
        }
    }
    reader.close();

    std::cout << "  Total packets: " << totalPackets << "\n";
    std::cout << "  Total unique flows: " << seenFlows.size() << "\n";

    // Build frequent tables
    std::array<FrequentTable, 5> frequentTables;
    for (auto& table : frequentTables) {
        table = FrequentTable(frequentTableK);
    }
    for (int i = 0; i < 5; i++) {
        frequentTables[i].build(fieldCounters[i]);
        std::cout << "  Field " << i << ": " << frequentTables[i].size()
                  << " entries, " << frequentTables[i].getCodeLength() << " bits/code\n";
    }

    std::cout << "Phase 1 complete.\n\n";
    return frequentTables;
}

// Calculate compression metrics for TailSketch
struct CompressionMetrics {
    size_t compStor;        // Flows stored in compressed FIFO
    double ratio;           // Compression ratio
    double recPrec;         // Recovered IDs precision
    double recRec;          // Recovered IDs recall
    size_t rawBits;         // Total raw bits for window
    size_t compressedBits;  // Total compressed bits for window
};

CompressionMetrics calculateCompressionMetrics(
    const std::vector<Packet>& recoveredFlows,
    const std::unordered_map<Packet, int, PacketHash>& groundTruthFlows,
    const std::vector<Packet>& windowPackets,
    AdaptiveHuffmanLearner& learner) {

    CompressionMetrics metrics;

    // CompStor: number of unique flows in recovered set
    // This represents flows that could be stored in compressed FIFO
    metrics.compStor = recoveredFlows.size();

    // Ratio: compression ratio (raw bits / compressed bits)
    // Calculate actual compressed bits by encoding each unique flow
    constexpr size_t RAW_FLOW_ID_BITS = 104;  // 32+32+16+16+8 bits
    size_t windowRawBits = 0;
    size_t windowCompressedBits = 0;

    for (const auto& pkt : recoveredFlows) {
        windowRawBits += RAW_FLOW_ID_BITS;
        // Get actual compressed size from Huffman encoding
        std::string compressed = learner.encodeFlowID(pkt);
        windowCompressedBits += compressed.size();  // Size in bits
    }

    metrics.ratio = (windowCompressedBits > 0) ?
        static_cast<double>(windowRawBits) / windowCompressedBits : 1.0;
    metrics.rawBits = windowRawBits;
    metrics.compressedBits = windowCompressedBits;

    // RecPrec and RecRec: precision and recall of recovered IDs
    // Recovered set vs ground truth
    std::unordered_set<Packet, PacketHash> recoveredSet(recoveredFlows.begin(), recoveredFlows.end());
    std::unordered_set<Packet, PacketHash> groundTruthSet;
    for (const auto& [pkt, freq] : groundTruthFlows) {
        groundTruthSet.insert(pkt);
    }

    size_t truePositives = 0;
    for (const auto& pkt : recoveredSet) {
        if (groundTruthSet.count(pkt)) {
            truePositives++;
        }
    }

    // Precision = TP / (TP + FP) = TP / recovered
    metrics.recPrec = (recoveredSet.size() > 0) ?
        static_cast<double>(truePositives) / recoveredSet.size() : 0.0;

    // Recall = TP / (TP + FN) = TP / groundTruth
    metrics.recRec = (groundTruthSet.size() > 0) ?
        static_cast<double>(truePositives) / groundTruthSet.size() : 0.0;

    return metrics;
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Function
// ═══════════════════════════════════════════════════════════════════════════

void runComparison(const ComparisonConfig& config) {
    // Create output directory
    mkdir(config.outputDir.c_str(), 0755);

    // Open CSV writers
    CSVWriter detailedWriter(config.outputDir + "sketch_comparison_detailed.csv");
    CSVWriter summaryWriter(config.outputDir + "sketch_comparison_summary.csv");

    // Accumulator for overall metrics (averaged across windows)
    struct PatternCategoryKey {
        std::string pattern;
        std::string category;
        bool operator<(const PatternCategoryKey& other) const {
            if (pattern != other.pattern) return pattern < other.pattern;
            return category < other.category;
        }
    };

    struct AccumulatedMetrics {
        int windowCount = 0;
        double tsAAE = 0, tsARE = 0, tsCoverage = 0, tsInsertThroughput = 0, tsQueryThroughput = 0;
        double ussAAE = 0, ussARE = 0, ussCoverage = 0, ussInsertThroughput = 0, ussQueryThroughput = 0;
        double cocoAAE = 0, cocoARE = 0, cocoCoverage = 0, cocoInsertThroughput = 0, cocoQueryThroughput = 0;
        double hyperAAE = 0, hyperARE = 0, hyperCoverage = 0, hyperInsertThroughput = 0, hyperQueryThroughput = 0;
        double swAAE = 0, swARE = 0, swCoverage = 0, swInsertThroughput = 0, swQueryThroughput = 0;
        double tsCompStor = 0, tsRatio = 0, tsRawBits = 0, tsCompressedBits = 0, tsRecPrec = 0, tsRecRec = 0;
    };

    std::map<PatternCategoryKey, AccumulatedMetrics> overallMetrics;

    // Write headers
    detailedWriter.writeHeader({
        "Timewindow", "Pattern", "PartialKey", "GroundTruth",
        "TailSketch_Estimate", "TailSketch_AAE", "TailSketch_ARE",
        "USS_Estimate", "USS_AAE", "USS_ARE",
        "CocoSketch_Estimate", "CocoSketch_AAE", "CocoSketch_ARE",
        "HyperUSS_Estimate", "HyperUSS_AAE", "HyperUSS_ARE",
        "SandwichSketch_Estimate", "SandwichSketch_AAE", "SandwichSketch_ARE"
    });

    summaryWriter.writeHeader({
        "Timewindow", "Pattern", "Category", "UniqueKeys", "TotalPackets",
        "TailSketch_CompStor", "TailSketch_Ratio", "TailSketch_RawBits", "TailSketch_CompressedBits", "TailSketch_RecPrec", "TailSketch_RecRec",
        "TailSketch_AAE", "TailSketch_ARE", "TailSketch_CoverageRate", "TailSketch_InsertThroughputMpps", "TailSketch_QueryThroughputMpps",
        "USS_AAE", "USS_ARE", "USS_CoverageRate", "USS_InsertThroughputMpps", "USS_QueryThroughputMpps",
        "CocoSketch_AAE", "CocoSketch_ARE", "CocoSketch_CoverageRate", "CocoSketch_InsertThroughputMpps", "CocoSketch_QueryThroughputMpps",
        "HyperUSS_AAE", "HyperUSS_ARE", "HyperUSS_CoverageRate", "HyperUSS_InsertThroughputMpps", "HyperUSS_QueryThroughputMpps",
        "SandwichSketch_AAE", "SandwichSketch_ARE", "SandwichSketch_CoverageRate", "SandwichSketch_InsertThroughputMpps", "SandwichSketch_QueryThroughputMpps"
    });

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 1: Build frequent tables from entire file (TailSketch only)
    // ═══════════════════════════════════════════════════════════════════
    std::array<FrequentTable, 5> frequentTables =
        buildFrequentTablesFromEntireFile(config.pcapFile, config.frequentTableK);

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 2: Process windows
    // ═══════════════════════════════════════════════════════════════════

    // Pattern definitions
    struct PatternDef {
        std::string name;
        uint8_t mask;
    };

    std::vector<PatternDef> patterns = {
        {"SrcIP Only", 0x1E},
        {"DstIP Only", 0x1D},
        {"Src Pair", 0x1A},
        {"Dst Pair", 0x15},
        {"IP Pair", 0x1C}
    };

    std::cout << "Phase 2: Processing windows...\n";
    std::cout << "Patterns:\n";
    for (const auto& p : patterns) {
        std::cout << "  - " << p.name << " (mask=0x" << std::hex << (int)p.mask << std::dec << ")\n";
    }
    std::cout << "\n";

    // Open PCAP for second pass
    PcapReader reader;
    if (!reader.open(config.pcapFile)) {
        std::cerr << "Failed to open pcap file: " << config.pcapFile << "\n";
        return;
    }

    // Initialize learner with frequent tables (for TailSketch)
    AdaptiveHuffmanLearner learner;
    learner.setFrequentTables(&frequentTables);

    // State for window processing
    int windowCount = 0;
    std::vector<Packet> windowPackets;
    std::unordered_map<Packet, int, PacketHash> previousGroundTruth;
    bool isFirstWindow = true;

    Packet pkt;
    while (reader.readNext(pkt)) {
        windowPackets.push_back(pkt);

        if (windowPackets.size() >= config.windowSize) {
            windowCount++;
            std::cout << "Window " << windowCount << " (" << windowPackets.size() << " packets)...\n";

            // Check if we've reached max windows limit
            if (config.maxWindows > 0 && windowCount > config.maxWindows) {
                std::cout << "  Reached max windows limit (" << config.maxWindows << "). Stopping early.\n";
                break;
            }

            // Build ground truth for current window (5-tuple flows)
            std::unordered_map<Packet, int, PacketHash> currentGroundTruth;
            for (const auto& p : windowPackets) {
                currentGroundTruth[p]++;
            }

            // ─────────────────────────────────────────────────────────
            // Build Huffman trees for TailSketch
            // ─────────────────────────────────────────────────────────
            std::vector<Packet> treeSourceFlows;
            if (isFirstWindow) {
                std::cout << "  Building initial Huffman trees from window 1...\n";
                treeSourceFlows.reserve(currentGroundTruth.size());
                for (const auto& [p, freq] : currentGroundTruth) {
                    treeSourceFlows.push_back(p);
                }
                isFirstWindow = false;
            } else {
                std::cout << "  Building Huffman trees from previous window...\n";
                treeSourceFlows.reserve(previousGroundTruth.size());
                for (const auto& [p, freq] : previousGroundTruth) {
                    treeSourceFlows.push_back(p);
                }
            }

            learner.initFromRecoveredIDs(treeSourceFlows);
            learner.buildTrees();

            // Recovered flows for TailSketch
            std::vector<Packet> recoveredFlows;
            recoveredFlows.reserve(currentGroundTruth.size());
            for (const auto& [p, freq] : currentGroundTruth) {
                recoveredFlows.push_back(p);
            }

            // ─────────────────────────────────────────────────────────
            // Initialize all 5 sketches
            // ─────────────────────────────────────────────────────────
            size_t sketchMemory = config.memoryKB * 1024;

            TailSketch tailSketch;
            tailSketch.initialize(learner.getTrees(), sketchMemory / 5);

            USSAdapter uss;
            uss.initialize(sketchMemory);

            CocoSketchAdapter coco;
            coco.initialize(sketchMemory);

            HyperUSSAdapter hyper;
            hyper.initialize(sketchMemory);

            SandwichSketchAdapter sandwich;
            sandwich.initialize(sketchMemory);

            // ─────────────────────────────────────────────────────────
            // Insert all packets and measure insertion throughput
            // ─────────────────────────────────────────────────────────
            int totalPackets = windowPackets.size();

            // TailSketch: Use internal insertion time (excludes encoding overhead)
            tailSketch.resetTiming();
            for (const auto& p : windowPackets) {
                tailSketch.insertPacket(p, learner);
            }
            double tsInsertMs = tailSketch.getInsertionTimeNs() / 1e6;  // Convert ns to ms
            double tsInsertThroughput = (tsInsertMs > 0) ? (totalPackets / tsInsertMs) / 1000.0 : 0.0;

            auto ussInsertStart = std::chrono::high_resolution_clock::now();
            for (const auto& p : windowPackets) {
                uss.insert(p);
            }
            auto ussInsertEnd = std::chrono::high_resolution_clock::now();
            double ussInsertMs = std::chrono::duration<double, std::milli>(ussInsertEnd - ussInsertStart).count();
            double ussInsertThroughput = (ussInsertMs > 0) ? (totalPackets / ussInsertMs) / 1000.0 : 0.0;

            auto cocoInsertStart = std::chrono::high_resolution_clock::now();
            for (const auto& p : windowPackets) {
                coco.insert(p);
            }
            auto cocoInsertEnd = std::chrono::high_resolution_clock::now();
            double cocoInsertMs = std::chrono::duration<double, std::milli>(cocoInsertEnd - cocoInsertStart).count();
            double cocoInsertThroughput = (cocoInsertMs > 0) ? (totalPackets / cocoInsertMs) / 1000.0 : 0.0;

            auto hyperInsertStart = std::chrono::high_resolution_clock::now();
            for (const auto& p : windowPackets) {
                hyper.insert(p);
            }
            auto hyperInsertEnd = std::chrono::high_resolution_clock::now();
            double hyperInsertMs = std::chrono::duration<double, std::milli>(hyperInsertEnd - hyperInsertStart).count();
            double hyperInsertThroughput = (hyperInsertMs > 0) ? (totalPackets / hyperInsertMs) / 1000.0 : 0.0;

            auto swInsertStart = std::chrono::high_resolution_clock::now();
            for (const auto& p : windowPackets) {
                sandwich.insert(p);
            }
            auto swInsertEnd = std::chrono::high_resolution_clock::now();
            double swInsertMs = std::chrono::duration<double, std::milli>(swInsertEnd - swInsertStart).count();
            double swInsertThroughput = (swInsertMs > 0) ? (totalPackets / swInsertMs) / 1000.0 : 0.0;

            // Print insertion throughput summary
            std::cout << "    Insertion throughput:\n";
            double tsEncodingMs = tailSketch.getEncodingTimeNs() / 1e6;
            std::cout << "      TailSketch: " << tsInsertThroughput << " Mpps (insertion only, "
                      << tsInsertMs << "ms | encoding: " << tsEncodingMs << "ms)\n";
            std::cout << "      USS: " << ussInsertThroughput << " Mpps (" << ussInsertMs << "ms)\n";
            std::cout << "      CocoSketch: " << cocoInsertThroughput << " Mpps (" << cocoInsertMs << "ms)\n";
            std::cout << "      HyperUSS: " << hyperInsertThroughput << " Mpps (" << hyperInsertMs << "ms)\n";
            std::cout << "      SandwichSketch: " << swInsertThroughput << " Mpps (" << swInsertMs << "ms)\n";

            // Calculate TailSketch compression metrics
            CompressionMetrics tsMetrics = calculateCompressionMetrics(
                recoveredFlows, currentGroundTruth, windowPackets, learner);

            // ─────────────────────────────────────────────────────────
            // Process each pattern
            // ─────────────────────────────────────────────────────────
            for (const auto& pattern : patterns) {
                // Build ground truth for full flows
                std::unordered_map<Packet, int, PacketHash> fullFlowFreq;
                for (const auto& pkt : windowPackets) {
                    fullFlowFreq[pkt]++;
                }

                // Classify full flows as elephants or mice
                std::vector<Packet> elephantFlows, miceFlows;
                for (const auto& [pkt, freq] : fullFlowFreq) {
                    if (freq >= config.elephantThreshold * totalPackets) {
                        elephantFlows.push_back(pkt);
                    } else {
                        miceFlows.push_back(pkt);
                    }
                }

                // Build forbidden zone
                std::unordered_set<PartialKey, PartialKeyHash> forbiddenKeys;
                for (const auto& e : elephantFlows) {
                    forbiddenKeys.insert(extractPartialKey(e, pattern.mask));
                }

                // Build ground truth maps for comprehensive, mice, and elephant
                std::unordered_map<PartialKey, int, PartialKeyHash> comprehensiveGT;
                std::unordered_map<PartialKey, int, PartialKeyHash> miceGT;
                std::unordered_map<PartialKey, int, PartialKeyHash> elephantGT;

                for (const auto& [flow, freq] : fullFlowFreq) {
                    PartialKey pk = extractPartialKey(flow, pattern.mask);
                    comprehensiveGT[pk] += freq;

                    if (forbiddenKeys.count(pk)) {
                        elephantGT[pk] += freq;
                    } else {
                        miceGT[pk] += freq;
                    }
                }

                // Process 3 categories: Comprehensive, Mice, Elephant
                // Query all partial keys using cached sketch flows for efficiency
                struct CategoryData {
                    std::string name;
                    std::unordered_map<PartialKey, int, PartialKeyHash>* groundTruth;
                };

                std::vector<CategoryData> categories = {
                    {"Comprehensive", &comprehensiveGT},
                    {"Mice", &miceGT},
                    {"Elephant", &elephantGT}
                };

                // OPTIMIZATION: Cache AllQuery() results once per pattern
                // This avoids calling AllQuery() for each partial key (major bottleneck)
                std::cout << "    Caching sketch flow tables...\n";
                auto ussFlows = uss.getAllFlows();
                auto cocoFlows = coco.getAllFlows();
                auto hyperFlows = hyper.getAllFlows();
                auto swFlows = sandwich.getAllFlows();
                std::cout << "      USS: " << ussFlows.size() << " flows\n";
                std::cout << "      CocoSketch: " << cocoFlows.size() << " flows\n";
                std::cout << "      HyperUSS: " << hyperFlows.size() << " flows\n";
                std::cout << "      SandwichSketch: " << swFlows.size() << " flows\n";

                for (const auto& category : categories) {
                    if (category.groundTruth->empty()) continue;

                    std::cout << "    Category: " << category.name << " (" << category.groundTruth->size() << " partial keys)\n";

                    double tsAAESum = 0.0, tsARESum = 0.0;
                    double ussAAESum = 0.0, ussARESum = 0.0;
                    double cocoAAESum = 0.0, cocoARESum = 0.0;
                    double hyperAAESum = 0.0, hyperARESum = 0.0;
                    double swAAESum = 0.0, swARESum = 0.0;

                    int tsCoverage = 0, ussCoverage = 0, cocoCoverage = 0;
                    int hyperCoverage = 0, swCoverage = 0;
                    int totalQueries = 0;
                    int totalPacketsCategory = 0;

                    auto queryStart = std::chrono::high_resolution_clock::now();

                    // Query all partial keys in ground truth (no artificial limit)
                    for (const auto& [pk, gtFreq] : *category.groundTruth) {
                        totalQueries++;
                        totalPacketsCategory += gtFreq;

                        // TailSketch query (beta = 1.0)
                        double tsEst = tailSketch.queryPartialKey(pk, learner, totalPackets, recoveredFlows, 1.0);
                        double tsAAE = std::abs(tsEst - gtFreq);
                        double tsARE = (gtFreq > 0) ? (tsAAE / gtFreq) : 0.0;
                        tsAAESum += tsAAE;
                        tsARESum += tsARE;
                        if (tsEst > 0) tsCoverage++;

                        // External sketches: query using cached flows
                        // USS
                        double ussEst = 0.0;
                        for (const auto& [flow, count] : ussFlows) {
                            if (matchesPartialKey(flow, pk)) {
                                ussEst += count;
                            }
                        }
                        double ussAAE = std::abs(ussEst - gtFreq);
                        double ussARE = (gtFreq > 0) ? (ussAAE / gtFreq) : 0.0;
                        ussAAESum += ussAAE;
                        ussARESum += ussARE;
                        if (ussEst > 0) ussCoverage++;

                        // CocoSketch
                        double cocoEst = 0.0;
                        for (const auto& [flow, count] : cocoFlows) {
                            if (matchesPartialKey(flow, pk)) {
                                cocoEst += count;
                            }
                        }
                        double cocoAAE = std::abs(cocoEst - gtFreq);
                        double cocoARE = (gtFreq > 0) ? (cocoAAE / gtFreq) : 0.0;
                        cocoAAESum += cocoAAE;
                        cocoARESum += cocoARE;
                        if (cocoEst > 0) cocoCoverage++;

                        // HyperUSS
                        double hyperEst = 0.0;
                        for (const auto& [flow, count] : hyperFlows) {
                            if (matchesPartialKey(flow, pk)) {
                                hyperEst += count;
                            }
                        }
                        double hyperAAE = std::abs(hyperEst - gtFreq);
                        double hyperARE = (gtFreq > 0) ? (hyperAAE / gtFreq) : 0.0;
                        hyperAAESum += hyperAAE;
                        hyperARESum += hyperARE;
                        if (hyperEst > 0) hyperCoverage++;

                        // SandwichSketch
                        double swEst = 0.0;
                        for (const auto& [flow, count] : swFlows) {
                            if (matchesPartialKey(flow, pk)) {
                                swEst += count;
                            }
                        }
                        double swAAE = std::abs(swEst - gtFreq);
                        double swARE = (gtFreq > 0) ? (swAAE / gtFreq) : 0.0;
                        swAAESum += swAAE;
                        swARESum += swARE;
                        if (swEst > 0) swCoverage++;

                        // Write detailed results
                        detailedWriter.writeRow(
                            windowCount, pattern.name, partialKeyToString(pk), gtFreq,
                            tsEst, tsAAE, tsARE,
                            ussEst, ussAAE, ussARE,
                            cocoEst, cocoAAE, cocoARE,
                            hyperEst, hyperAAE, hyperARE,
                            swEst, swAAE, swARE
                        );
                    }

                    auto queryEnd = std::chrono::high_resolution_clock::now();
                    double queryMs = std::chrono::duration<double, std::milli>(queryEnd - queryStart).count();
                    double queryThroughput = (queryMs > 0) ? (totalQueries / queryMs) / 1000.0 : 0.0;

                    // Calculate averages
                    double tsAvgAAE = tsAAESum / totalQueries;
                    double tsAvgARE = tsARESum / totalQueries;
                    double tsCoverageRate = static_cast<double>(tsCoverage) / totalQueries;

                    double ussAvgAAE = ussAAESum / totalQueries;
                    double ussAvgARE = ussARESum / totalQueries;
                    double ussCoverageRate = static_cast<double>(ussCoverage) / totalQueries;

                    double cocoAvgAAE = cocoAAESum / totalQueries;
                    double cocoAvgARE = cocoARESum / totalQueries;
                    double cocoCoverageRate = static_cast<double>(cocoCoverage) / totalQueries;

                    double hyperAvgAAE = hyperAAESum / totalQueries;
                    double hyperAvgARE = hyperARESum / totalQueries;
                    double hyperCoverageRate = static_cast<double>(hyperCoverage) / totalQueries;

                    double swAvgAAE = swAAESum / totalQueries;
                    double swAvgARE = swARESum / totalQueries;
                    double swCoverageRate = static_cast<double>(swCoverage) / totalQueries;

                    // Write summary
                    summaryWriter.writeRow(
                        windowCount, pattern.name, category.name, totalQueries, totalPacketsCategory,
                        tsMetrics.compStor, tsMetrics.ratio, tsMetrics.rawBits, tsMetrics.compressedBits, tsMetrics.recPrec, tsMetrics.recRec,
                        tsAvgAAE, tsAvgARE, tsCoverageRate, tsInsertThroughput, queryThroughput,
                        ussAvgAAE, ussAvgARE, ussCoverageRate, ussInsertThroughput, queryThroughput,
                        cocoAvgAAE, cocoAvgARE, cocoCoverageRate, cocoInsertThroughput, queryThroughput,
                        hyperAvgAAE, hyperAvgARE, hyperCoverageRate, hyperInsertThroughput, queryThroughput,
                        swAvgAAE, swAvgARE, swCoverageRate, swInsertThroughput, queryThroughput
                    );

                    // Accumulate for overall averages
                    PatternCategoryKey key{pattern.name, category.name};
                    auto& acc = overallMetrics[key];
                    acc.windowCount++;
                    acc.tsAAE += tsAvgAAE; acc.tsARE += tsAvgARE; acc.tsCoverage += tsCoverageRate;
                    acc.tsInsertThroughput += tsInsertThroughput; acc.tsQueryThroughput += queryThroughput;
                    acc.ussAAE += ussAvgAAE; acc.ussARE += ussAvgARE; acc.ussCoverage += ussCoverageRate;
                    acc.ussInsertThroughput += ussInsertThroughput; acc.ussQueryThroughput += queryThroughput;
                    acc.cocoAAE += cocoAvgAAE; acc.cocoARE += cocoAvgARE; acc.cocoCoverage += cocoCoverageRate;
                    acc.cocoInsertThroughput += cocoInsertThroughput; acc.cocoQueryThroughput += queryThroughput;
                    acc.hyperAAE += hyperAvgAAE; acc.hyperARE += hyperAvgARE; acc.hyperCoverage += hyperCoverageRate;
                    acc.hyperInsertThroughput += hyperInsertThroughput; acc.hyperQueryThroughput += queryThroughput;
                    acc.swAAE += swAvgAAE; acc.swARE += swAvgARE; acc.swCoverage += swCoverageRate;
                    acc.swInsertThroughput += swInsertThroughput; acc.swQueryThroughput += queryThroughput;
                    acc.tsCompStor += tsMetrics.compStor; acc.tsRatio += tsMetrics.ratio;
                    acc.tsRawBits += tsMetrics.rawBits; acc.tsCompressedBits += tsMetrics.compressedBits;
                    acc.tsRecPrec += tsMetrics.recPrec; acc.tsRecRec += tsMetrics.recRec;
                }
            }

            // Update state for next window
            previousGroundTruth = currentGroundTruth;
            windowPackets.clear();
        }
    }

    reader.close();

    // Write overall averaged metrics across windows
    std::cout << "\nWriting overall averaged metrics across " << windowCount << " windows...\n";
    CSVWriter overallWriter(config.outputDir + "sketch_comparison_overall.csv");
    overallWriter.writeHeader({
        "Pattern", "Category",
        "TailSketch_AvgAAE", "TailSketch_AvgARE", "TailSketch_AvgCoverage", "TailSketch_AvgInsertThroughput", "TailSketch_AvgQueryThroughput",
        "TailSketch_AvgCompStor", "TailSketch_AvgRatio", "TailSketch_AvgRawBits", "TailSketch_AvgCompressedBits", "TailSketch_AvgRecPrec", "TailSketch_AvgRecRec",
        "USS_AvgAAE", "USS_AvgARE", "USS_AvgCoverage", "USS_AvgInsertThroughput", "USS_AvgQueryThroughput",
        "CocoSketch_AvgAAE", "CocoSketch_AvgARE", "CocoSketch_AvgCoverage", "CocoSketch_AvgInsertThroughput", "CocoSketch_AvgQueryThroughput",
        "HyperUSS_AvgAAE", "HyperUSS_AvgARE", "HyperUSS_AvgCoverage", "HyperUSS_AvgInsertThroughput", "HyperUSS_AvgQueryThroughput",
        "SandwichSketch_AvgAAE", "SandwichSketch_AvgARE", "SandwichSketch_AvgCoverage", "SandwichSketch_AvgInsertThroughput", "SandwichSketch_AvgQueryThroughput"
    });

    for (const auto& [key, acc] : overallMetrics) {
        if (acc.windowCount == 0) continue;
        double n = acc.windowCount;
        overallWriter.writeRow(
            key.pattern, key.category,
            acc.tsAAE/n, acc.tsARE/n, acc.tsCoverage/n, acc.tsInsertThroughput/n, acc.tsQueryThroughput/n,
            acc.tsCompStor/n, acc.tsRatio/n, acc.tsRawBits/n, acc.tsCompressedBits/n, acc.tsRecPrec/n, acc.tsRecRec/n,
            acc.ussAAE/n, acc.ussARE/n, acc.ussCoverage/n, acc.ussInsertThroughput/n, acc.ussQueryThroughput/n,
            acc.cocoAAE/n, acc.cocoARE/n, acc.cocoCoverage/n, acc.cocoInsertThroughput/n, acc.cocoQueryThroughput/n,
            acc.hyperAAE/n, acc.hyperARE/n, acc.hyperCoverage/n, acc.hyperInsertThroughput/n, acc.hyperQueryThroughput/n,
            acc.swAAE/n, acc.swARE/n, acc.swCoverage/n, acc.swInsertThroughput/n, acc.swQueryThroughput/n
        );
    }

    std::cout << "\nComparison complete! Results written to:\n";
    std::cout << "  - " << config.outputDir << "sketch_comparison_detailed.csv\n";
    std::cout << "  - " << config.outputDir << "sketch_comparison_summary.csv\n";
    std::cout << "  - " << config.outputDir << "sketch_comparison_overall.csv (averaged across " << windowCount << " windows)\n";
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Entry Point
// ═══════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    ComparisonConfig config;

    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "f:o:w:m:k:e:n:")) != -1) {
        switch (opt) {
            case 'f':
                config.pcapFile = optarg;
                break;
            case 'o':
                config.outputDir = optarg;
                break;
            case 'w':
                config.windowSize = std::stoi(optarg);
                break;
            case 'm':
                config.memoryKB = std::stoi(optarg);
                break;
            case 'k':
                config.frequentTableK = std::stoi(optarg);
                break;
            case 'e':
                config.elephantThreshold = std::stod(optarg);
                break;
            case 'n':
                config.maxWindows = std::stoi(optarg);
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " -f <pcap_file> "
                          << "[-o output_dir] [-w window_size] [-m memory_kb] "
                          << "[-k frequent_table_k] [-e elephant_threshold] [-n max_windows]\n";
                return 1;
        }
    }

    if (config.pcapFile.empty()) {
        std::cerr << "Error: PCAP file required (-f option)\n";
        std::cerr << "Usage: " << argv[0] << " -f <pcap_file> "
                  << "[-o output_dir] [-w window_size] [-m memory_kb] "
                  << "[-k frequent_table_k] [-e elephant_threshold] [-n max_windows]\n";
        return 1;
    }

    // Ensure output directory ends with slash
    if (!config.outputDir.empty() && config.outputDir.back() != '/') {
        config.outputDir += '/';
    }

    std::cout << "═══════════════════════════════════════════════════════\n";
    std::cout << "Multi-Sketch Comparison Experiment\n";
    std::cout << "═══════════════════════════════════════════════════════\n";
    std::cout << "Configuration:\n";
    std::cout << "  PCAP file: " << config.pcapFile << "\n";
    std::cout << "  Output dir: " << config.outputDir << "\n";
    std::cout << "  Window size: " << config.windowSize << " packets\n";
    std::cout << "  Max windows: " << (config.maxWindows > 0 ? std::to_string(config.maxWindows) : "unlimited") << "\n";
    std::cout << "  Memory budget: " << config.memoryKB << " KB\n";
    std::cout << "  Frequent table K: " << config.frequentTableK << "\n";
    std::cout << "  Elephant threshold: " << config.elephantThreshold << "\n";
    std::cout << "  Beta value: 1.0 (fixed)\n";
    std::cout << "═══════════════════════════════════════════════════════\n\n";

    runComparison(config);

    return 0;
}

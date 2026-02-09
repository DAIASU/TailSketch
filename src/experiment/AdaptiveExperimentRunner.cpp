#include "AdaptiveExperimentRunner.h"
#include "Logger.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <fstream>

// Raw flow ID size: 32+32+16+16+8 = 104 bits
constexpr size_t RAW_FLOW_ID_BITS = 104;

AdaptiveExperimentRunner::AdaptiveExperimentRunner(const AdaptiveConfig& config)
    : config_(config),
      windowRawBits_(0),
      windowCompressedBits_(0),
      windowInsertionTimeNs_(0),
      windowPacketCount_(0) {

    // Initialize frequent tables with capacity
    for (auto& table : frequentTables_) {
        table = FrequentTable(config_.frequentTableK);
    }

    // Initialize learner
    learner_ = std::make_unique<AdaptiveHuffmanLearner>();
    learner_->setFrequentTables(&frequentTables_);

    // Initialize frequency sketch
    frequencySketch_ = std::make_unique<TailSketch>();

    // Initialize bloom filter
    bloomFilter_ = std::make_unique<BloomFilter>(config_.bloomFilterSize);

    // Initialize FIFO storage with capacity in bits (KB * 1024 * 8)
    size_t storageBits = static_cast<size_t>(config_.storageCapacityKB) * 1024 * 8;
    storedIDs_ = std::make_unique<FIFOStorage<Packet>>(storageBits);
    storedCompressedIDs_ = std::make_unique<FIFOStorage<std::string>>(storageBits);
}

void AdaptiveExperimentRunner::run() {
    Logger::log("=== Adaptive Huffman Sketch Experiment ===");
    Logger::log("PCAP file: " + config_.pcapFile);
    Logger::log("Window size: " + std::to_string(config_.windowSize) + " packets");
    Logger::log("Storage capacity: " + std::to_string(config_.storageCapacityKB) + " KB (same for raw and compressed)");
    Logger::log("Sketch row memory: " + std::to_string(config_.sketchRowBytes) + " bytes/row");
    Logger::log("Frequent table K: " + std::to_string(config_.frequentTableK));
    Logger::log("Bloom filter size: " + std::to_string(config_.bloomFilterSize) + " bits");
    Logger::log("Elephant threshold (theta): " + std::to_string(config_.elephantThreshold));
    Logger::log("");

    // ═══════════════════════════════════════════════════════════════════
    // Phase 1: Build frequent tables from entire file
    // ═══════════════════════════════════════════════════════════════════
    Logger::log("Building frequent tables from entire file...");
    buildFrequentTables();

    for (int i = 0; i < 5; i++) {
        Logger::log("  Field " + std::to_string(i) + ": " +
                   std::to_string(frequentTables_[i].size()) + " entries, " +
                   std::to_string(frequentTables_[i].getCodeLength()) + " bits/code");
    }
    Logger::log("");

    // ═══════════════════════════════════════════════════════════════════
    // Phase 2: Build initial Huffman frequencies from first window
    // ═══════════════════════════════════════════════════════════════════
    PcapReader reader;
    if (!reader.open(config_.pcapFile)) {
        Logger::logError("Failed to open PCAP file: " + reader.getError());
        return;
    }

    Logger::log("Building initial Huffman frequencies from first window...");
    buildInitialFrequencies(reader);
    reader.close();

    // ═══════════════════════════════════════════════════════════════════
    // Phase 3: Process all windows
    // ═══════════════════════════════════════════════════════════════════
    if (!reader.open(config_.pcapFile)) {
        Logger::logError("Failed to reopen PCAP file: " + reader.getError());
        return;
    }

    Logger::log("");
    printHeader();

    int windowNum = 0;
    bool hasMorePackets = true;

    while (hasMorePackets) {
        // Process the window (reads packets internally)
        hasMorePackets = processWindow(windowNum, reader);

        // Evaluate and record results
        if (!groundTruthFreq_.empty()) {
            AdaptiveWindowResult result = evaluateWindow(windowNum);
            results_.push_back(result);
            printWindowResult(result);

            // Decode compressed IDs to get recovered IDs
            std::vector<Packet> recoveredIDs;
            for (const auto& compressed : *storedCompressedIDs_) {
                Packet recovered;
                if (learner_->decodeFlowID(compressed, recovered)) {
                    recoveredIDs.push_back(recovered);
                }
            }

            // Prepare for next window
            prepareNextWindow(recoveredIDs);
            windowNum++;
        } else {
            // No packets processed in this window, we're done
            break;
        }
    }

    reader.close();

    Logger::log("");
    printSummary();
}

// ═══════════════════════════════════════════════════════════════════════════
// Initialization
// ═══════════════════════════════════════════════════════════════════════════

void AdaptiveExperimentRunner::buildFrequentTables() {
    PcapReader reader;
    if (!reader.open(config_.pcapFile)) {
        Logger::logError("Failed to open PCAP file for frequent tables: " + reader.getError());
        return;
    }

    // Count field frequencies (deduplicated by flow ID)
    std::unordered_set<Packet, PacketHash> seenFlows;
    std::array<std::unordered_map<uint32_t, uint64_t>, 5> fieldCounters;

    Packet pkt;
    while (reader.readNext(pkt)) {
        if (seenFlows.find(pkt) != seenFlows.end()) {
            continue;  // Already seen this flow
        }
        seenFlows.insert(pkt);

        // Count each field
        fieldCounters[0][pkt.srcIP]++;
        fieldCounters[1][pkt.dstIP]++;
        fieldCounters[2][pkt.srcPort]++;
        fieldCounters[3][pkt.dstPort]++;
        fieldCounters[4][pkt.proto]++;
    }

    reader.close();

    // Build frequent tables from counters
    for (int i = 0; i < 5; i++) {
        frequentTables_[i].build(fieldCounters[i]);
    }

    Logger::log("  Total unique flows scanned: " + std::to_string(seenFlows.size()));
}

void AdaptiveExperimentRunner::buildInitialFrequencies(PcapReader& reader) {
    std::unordered_set<Packet, PacketHash> seenFlows;
    int packetCount = 0;

    Packet pkt;
    while (packetCount < config_.windowSize && reader.readNext(pkt)) {
        if (seenFlows.find(pkt) == seenFlows.end()) {
            seenFlows.insert(pkt);
            learner_->updateFrequency(pkt);
        }
        packetCount++;
    }

    Logger::log("  Processed " + std::to_string(packetCount) + " packets, " +
               std::to_string(seenFlows.size()) + " unique flows");
}

// ═══════════════════════════════════════════════════════════════════════════
// Per-Window Processing
// ═══════════════════════════════════════════════════════════════════════════

bool AdaptiveExperimentRunner::processWindow(int windowNum, PcapReader& reader) {
    // Reset per-window state
    resetWindow();

    // Build Huffman trees from current frequencies
    learner_->buildTrees();

    // Initialize frequency sketch with current trees
    frequencySketch_->initialize(learner_->getTrees(), config_.sketchRowBytes);

    // Print sketch structure for this window
    frequencySketch_->printStructure(windowNum);

    // Reset sketch timing for this window
    frequencySketch_->resetTiming();

    // Process packets
    Packet pkt;
    bool hasMorePackets = false;

    while (windowPacketCount_ < static_cast<size_t>(config_.windowSize) && reader.readNext(pkt)) {
        hasMorePackets = true;

        // Record ground truth frequency (all packets, not just unique flows)
        groundTruthFreq_[pkt]++;

        // Insert into frequency sketch (timing tracked internally)
        frequencySketch_->insertPacket(pkt, *learner_);

        // Check if this is a new flow using Bloom filter
        std::string key = pkt.toKey();
        if (bloomFilter_->contains(key)) {
            windowPacketCount_++;
            continue;  // Already seen in this window
        }
        bloomFilter_->insert(key);

        // ─────────────────────────────────────────────────────────────
        // NEW FLOW: Store both raw and compressed versions
        // ─────────────────────────────────────────────────────────────

        // Store raw ID
        storedIDs_->push(pkt, RAW_FLOW_ID_BITS);
        windowRawBits_ += RAW_FLOW_ID_BITS;

        // Encode and store compressed ID
        std::string compressed = learner_->encodeFlowID(pkt);
        size_t compressedBits = compressed.size();  // Get size before move
        storedCompressedIDs_->push(std::move(compressed), compressedBits);

        windowPacketCount_++;
    }

    // Calculate final compressed bits (data only, tree overhead added in evaluateWindow)
    windowCompressedBits_ = storedCompressedIDs_->totalBits();

    // ─────────────────────────────────────────────────────────────
    // Output ground truth flow statistics sorted by frequency
    // ─────────────────────────────────────────────────────────────
    // std::string gtOutputFile = "ground_truth_window_" + std::to_string(windowNum) + ".txt";
    // std::ofstream gtOut(gtOutputFile);
    // if (gtOut.is_open()) {
    //     // Sort flows by frequency (descending)
    //     std::vector<std::pair<Packet, uint64_t>> sortedFlows(
    //         groundTruthFreq_.begin(), groundTruthFreq_.end());
    //     std::sort(sortedFlows.begin(), sortedFlows.end(),
    //         [](const auto& a, const auto& b) { return a.second > b.second; });

    //     gtOut << "# Ground Truth Flow Statistics - Window " << windowNum << "\n";
    //     gtOut << "# Total flows: " << sortedFlows.size() << "\n";
    //     gtOut << "# Total packets: " << windowPacketCount_ << "\n";
    //     gtOut << "# Format: rank, frequency, srcIP, dstIP, srcPort, dstPort, proto\n";

    //     size_t rank = 1;
    //     for (const auto& [pkt, freq] : sortedFlows) {
    //         gtOut << rank++ << "\t" << freq << "\t"
    //               << ((pkt.srcIP >> 24) & 0xFF) << "." << ((pkt.srcIP >> 16) & 0xFF) << "."
    //               << ((pkt.srcIP >> 8) & 0xFF) << "." << (pkt.srcIP & 0xFF) << "\t"
    //               << ((pkt.dstIP >> 24) & 0xFF) << "." << ((pkt.dstIP >> 16) & 0xFF) << "."
    //               << ((pkt.dstIP >> 8) & 0xFF) << "." << (pkt.dstIP & 0xFF) << "\t"
    //               << pkt.srcPort << "\t" << pkt.dstPort << "\t"
    //               << static_cast<int>(pkt.proto) << "\n";
    //     }
    //     gtOut.close();
    // }

    // Return true if we processed packets and might have more
    return hasMorePackets && windowPacketCount_ == static_cast<size_t>(config_.windowSize);
}

AdaptiveWindowResult AdaptiveExperimentRunner::evaluateWindow(int windowNum) {
    AdaptiveWindowResult result;
    result.windowNum = windowNum;
    result.packetCount = windowPacketCount_;
    result.groundTruthFlowCount = groundTruthFreq_.size();

    // Total new flows = total raw bits / bits per raw ID
    result.totalNewFlows = windowRawBits_ / RAW_FLOW_ID_BITS;

    // Performance metrics (from sketch's internal timing)
    result.insertionTimeMs = frequencySketch_->getInsertionTimeNs() / 1e6;
    result.encodingTimeMs = frequencySketch_->getEncodingTimeNs() / 1e6;
    if (result.insertionTimeMs > 0) {
        // Throughput based on insertion time only (not encoding)
        result.throughputPps = (windowPacketCount_ * 1000.0) / result.insertionTimeMs;
    }

    // Storage counts (with same memory budget, compressed stores more)
    result.rawStoredCount = storedIDs_->size();
    result.compressedStoredCount = storedCompressedIDs_->size();

    // Bandwidth
    result.rawIDBandwidth = windowRawBits_;
    result.compressedIDBandwidth = windowCompressedBits_;
    result.treeOverheadBits = learner_->treesMemoryBits();

    if (windowCompressedBits_ > 0) {
        result.compressionRatio = static_cast<double>(windowRawBits_) / windowCompressedBits_;
    }

    // ─────────────────────────────────────────────────────────────
    // Compute precision/recall for raw storage
    // ─────────────────────────────────────────────────────────────
    std::unordered_set<Packet, PacketHash> storedSet;
    for (const auto& pkt : *storedIDs_) {
        storedSet.insert(pkt);
    }

    size_t rawTP = 0;
    for (const auto& pkt : storedSet) {
        if (groundTruthFreq_.find(pkt) != groundTruthFreq_.end()) {
            rawTP++;
        }
    }

    if (!storedSet.empty()) {
        result.rawPrecision = static_cast<double>(rawTP) / storedSet.size();
    }
    if (!groundTruthFreq_.empty()) {
        result.rawRecall = static_cast<double>(rawTP) / groundTruthFreq_.size();
    }

    // ─────────────────────────────────────────────────────────────
    // Compute precision/recall for recovered IDs
    // ─────────────────────────────────────────────────────────────
    std::unordered_set<Packet, PacketHash> recoveredSet;
    for (const auto& compressed : *storedCompressedIDs_) {
        Packet recovered;
        if (learner_->decodeFlowID(compressed, recovered)) {
            recoveredSet.insert(recovered);
        }
    }

    size_t recoveredTP = 0;
    for (const auto& pkt : recoveredSet) {
        if (groundTruthFreq_.find(pkt) != groundTruthFreq_.end()) {
            recoveredTP++;
        }
    }

    if (!recoveredSet.empty()) {
        result.recoveredPrecision = static_cast<double>(recoveredTP) / recoveredSet.size();
    }
    if (!groundTruthFreq_.empty()) {
        result.recoveredRecall = static_cast<double>(recoveredTP) / groundTruthFreq_.size();
    }

    // ─────────────────────────────────────────────────────────────
    // Calculate frequency estimation metrics (AAE/ARE)
    // ─────────────────────────────────────────────────────────────
    calculateFrequencyMetrics(recoveredSet, result);

    // Tier statistics
    const auto& stats = learner_->getStats();
    result.tier1Count = stats.tier1Count;
    result.tier2Count = stats.tier2Count;
    result.tier3Count = stats.tier3Count;

    // Per-field tier statistics
    result.tier1CountByField = stats.tier1CountByField;
    result.tier2CountByField = stats.tier2CountByField;
    result.tier3CountByField = stats.tier3CountByField;

    return result;
}

void AdaptiveExperimentRunner::calculateFrequencyMetrics(
    const std::unordered_set<Packet, PacketHash>& recoveredSet,
    AdaptiveWindowResult& result) {

    if (recoveredSet.empty()) {
        return;
    }

    double sumAEAll = 0, sumREAll = 0;
    double sumAEElephant = 0, sumREElephant = 0;
    double sumAEMouse = 0, sumREMouse = 0;
    size_t countAll = 0, countElephant = 0, countMouse = 0;

    for (const auto& pkt : recoveredSet) {
        // Get ground truth frequency
        auto gtIt = groundTruthFreq_.find(pkt);
        if (gtIt == groundTruthFreq_.end()) {
            continue;  // Not in ground truth (false positive)
        }
        uint64_t trueFreq = gtIt->second;

        // Query estimated frequency using Naive Bayes
        double estimatedFreq = frequencySketch_->queryFlowFrequency(
            pkt, *learner_, windowPacketCount_);

        // Calculate errors
        double ae = std::abs(static_cast<double>(trueFreq) - estimatedFreq);
        // double re = (trueFreq > 0) ? (ae / trueFreq) : 0.0;
        double re = ae / trueFreq;
        sumAEAll += ae;
        sumREAll += re;
        countAll++;

        // Categorize as elephant or mouse
        if (trueFreq >= static_cast<uint64_t>(config_.elephantThreshold)) {
            sumAEElephant += ae;
            sumREElephant += re;
            countElephant++;
        } else {
            sumAEMouse += ae;
            sumREMouse += re;
            countMouse++;
        }
    }

    // Calculate averages
    if (countAll > 0) {
        result.aaeAll = sumAEAll / countAll;
        result.areAll = sumREAll / countAll;
    }
    if (countElephant > 0) {
        result.aaeElephant = sumAEElephant / countElephant;
        result.areElephant = sumREElephant / countElephant;
    }
    if (countMouse > 0) {
        result.aaeMouse = sumAEMouse / countMouse;
        result.areMouse = sumREMouse / countMouse;
    }

    result.elephantCount = countElephant;
    result.mouseCount = countMouse;
}

void AdaptiveExperimentRunner::prepareNextWindow(const std::vector<Packet>& recoveredIDs) {
    // Update Huffman frequencies from recovered IDs
    learner_->initFromRecoveredIDs(recoveredIDs);
    learner_->resetStats();

    // Clear frequency sketch (will be re-initialized in next window)
    frequencySketch_->clear();
}

void AdaptiveExperimentRunner::resetWindow() {
    groundTruthFreq_.clear();
    bloomFilter_->clear();
    storedIDs_->clear();
    storedCompressedIDs_->clear();
    windowRawBits_ = 0;
    windowCompressedBits_ = 0;
    windowInsertionTimeNs_ = 0;
    windowPacketCount_ = 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Output
// ═══════════════════════════════════════════════════════════════════════════

void AdaptiveExperimentRunner::printHeader() const {
    std::cout << std::left
              << std::setw(5) << "Win"
              << std::setw(8) << "Pkts"
              << std::setw(8) << "Flows"
              << std::setw(9) << "CompStor"
              << std::setw(7) << "Ratio"
              << std::setw(10) << "Mpps"
              << std::setw(10) << "EncMs"
              << std::setw(9) << "AAE_all"
              << std::setw(9) << "ARE_all"
              << std::setw(9) << "AAE_ele"
              << std::setw(9) << "ARE_ele"
              << std::setw(9) << "AAE_mic"
              << std::setw(9) << "ARE_mic"
              << std::endl;

    std::cout << std::string(113, '-') << std::endl;
}

void AdaptiveExperimentRunner::printWindowResult(const AdaptiveWindowResult& result) const {
    double mpps = result.throughputPps / 1e6;

    std::cout << std::left << std::fixed
              << std::setw(5) << result.windowNum
              << std::setw(8) << result.packetCount
              << std::setw(8) << result.groundTruthFlowCount
              << std::setw(9) << result.compressedStoredCount
              << std::setw(7) << std::setprecision(2) << result.compressionRatio
              << std::setw(10) << std::setprecision(3) << mpps
              << std::setw(10) << std::setprecision(2) << result.encodingTimeMs
              << std::setw(9) << std::setprecision(2) << result.aaeAll
              << std::setw(9) << std::setprecision(4) << result.areAll
              << std::setw(9) << std::setprecision(2) << result.aaeElephant
              << std::setw(9) << std::setprecision(4) << result.areElephant
              << std::setw(9) << std::setprecision(2) << result.aaeMouse
              << std::setw(9) << std::setprecision(4) << result.areMouse
              << std::endl;
}

void AdaptiveExperimentRunner::printSummary() const {
    if (results_.empty()) {
        Logger::log("No results to summarize.");
        return;
    }

    Logger::log("=== Summary ===");

    // Calculate averages
    double avgCompRatio = 0;
    double avgRecPrec = 0, avgRecRec = 0;
    double avgThroughput = 0;
    double avgEncodingMs = 0, avgInsertionMs = 0;
    double avgAAEAll = 0, avgAREAll = 0;
    double avgAAEElephant = 0, avgAREElephant = 0;
    double avgAAEMouse = 0, avgAREMouse = 0;
    size_t totalTier1 = 0, totalTier2 = 0, totalTier3 = 0;
    size_t totalRawBits = 0, totalCompBits = 0;
    size_t totalPackets = 0;
    size_t totalElephants = 0, totalMice = 0;

    for (const auto& r : results_) {
        avgCompRatio += r.compressionRatio;
        avgRecPrec += r.recoveredPrecision;
        avgRecRec += r.recoveredRecall;
        avgThroughput += r.throughputPps;
        avgEncodingMs += r.encodingTimeMs;
        avgInsertionMs += r.insertionTimeMs;
        avgAAEAll += r.aaeAll;
        avgAREAll += r.areAll;
        avgAAEElephant += r.aaeElephant;
        avgAREElephant += r.areElephant;
        avgAAEMouse += r.aaeMouse;
        avgAREMouse += r.areMouse;
        totalTier1 += r.tier1Count;
        totalTier2 += r.tier2Count;
        totalTier3 += r.tier3Count;
        totalRawBits += r.rawIDBandwidth;
        totalCompBits += r.compressedIDBandwidth;
        totalPackets += r.packetCount;
        totalElephants += r.elephantCount;
        totalMice += r.mouseCount;
    }

    size_t n = results_.size();
    avgCompRatio /= n;
    avgRecPrec /= n;
    avgRecRec /= n;
    avgThroughput /= n;
    avgEncodingMs /= n;
    avgInsertionMs /= n;
    avgAAEAll /= n;
    avgAREAll /= n;
    avgAAEElephant /= n;
    avgAREElephant /= n;
    avgAAEMouse /= n;
    avgAREMouse /= n;

    std::cout << std::fixed << std::setprecision(4);
    std::cout << "Total windows: " << n << std::endl;
    std::cout << "Total packets processed: " << totalPackets << std::endl;
    std::cout << std::endl;

    std::cout << "=== ID Recovery ===" << std::endl;
    std::cout << "Average compression ratio: " << std::setprecision(2) << avgCompRatio << std::endl;
    std::cout << "Total raw bandwidth: " << (totalRawBits / 8.0 / 1024.0) << " KB" << std::endl;
    std::cout << "Total compressed bandwidth: " << (totalCompBits / 8.0 / 1024.0) << " KB" << std::endl;
    std::cout << "Overall compression ratio: " << (totalCompBits > 0 ? static_cast<double>(totalRawBits) / totalCompBits : 0) << std::endl;
    std::cout << "Average recovered precision: " << std::setprecision(4) << avgRecPrec << std::endl;
    std::cout << "Average recovered recall: " << avgRecRec << std::endl;
    std::cout << std::endl;

    std::cout << "=== Frequency Estimation ===" << std::endl;
    std::cout << "Average throughput (insertion only): " << std::setprecision(3) << (avgThroughput / 1e6) << " Mpps" << std::endl;
    std::cout << "Average encoding delay: " << std::setprecision(2) << avgEncodingMs << " ms" << std::endl;
    std::cout << "Average insertion time: " << avgInsertionMs << " ms" << std::endl;
    std::cout << "AAE (all flows): " << avgAAEAll << std::endl;
    std::cout << "ARE (all flows): " << std::setprecision(4) << avgAREAll << std::endl;
    std::cout << "AAE (elephants, theta>=" << config_.elephantThreshold << "): " << std::setprecision(2) << avgAAEElephant << std::endl;
    std::cout << "ARE (elephants): " << std::setprecision(4) << avgAREElephant << std::endl;
    std::cout << "AAE (mice): " << std::setprecision(2) << avgAAEMouse << std::endl;
    std::cout << "ARE (mice): " << std::setprecision(4) << avgAREMouse << std::endl;
    std::cout << "Total elephants: " << totalElephants << ", Total mice: " << totalMice << std::endl;
    std::cout << std::endl;

    size_t totalEncodings = totalTier1 + totalTier2 + totalTier3;
    if (totalEncodings > 0) {
        std::cout << "=== Tier Distribution ===" << std::endl;
        std::cout << "  Tier 1 (Huffman): " << totalTier1 << " ("
                  << std::setprecision(1) << (100.0 * totalTier1 / totalEncodings) << "%)" << std::endl;
        std::cout << "  Tier 2 (NYT+Freq): " << totalTier2 << " ("
                  << (100.0 * totalTier2 / totalEncodings) << "%)" << std::endl;
        std::cout << "  Tier 3 (Unknown): " << totalTier3 << " ("
                  << (100.0 * totalTier3 / totalEncodings) << "%)" << std::endl;
        std::cout << std::endl;

        // Per-field tier distribution
        std::array<size_t, 5> totalTier1ByField = {0, 0, 0, 0, 0};
        std::array<size_t, 5> totalTier2ByField = {0, 0, 0, 0, 0};
        std::array<size_t, 5> totalTier3ByField = {0, 0, 0, 0, 0};

        for (const auto& r : results_) {
            for (int i = 0; i < 5; i++) {
                totalTier1ByField[i] += r.tier1CountByField[i];
                totalTier2ByField[i] += r.tier2CountByField[i];
                totalTier3ByField[i] += r.tier3CountByField[i];
            }
        }

        const std::array<std::string, 5> fieldNames = {"srcIP", "dstIP", "srcPort", "dstPort", "proto"};

        std::cout << "Tier distribution per field:" << std::endl;
        std::cout << std::left
                  << std::setw(10) << "Field"
                  << std::setw(15) << "Tier1 (Huff)"
                  << std::setw(15) << "Tier2 (Freq)"
                  << std::setw(15) << "Tier3 (Raw)"
                  << std::setw(8) << "Total"
                  << std::endl;
        std::cout << std::string(65, '-') << std::endl;

        for (int i = 0; i < 5; i++) {
            size_t total = totalTier1ByField[i] + totalTier2ByField[i] + totalTier3ByField[i];
            if (total > 0) {
                std::cout << std::left << std::setprecision(1)
                          << std::setw(10) << fieldNames[i]
                          << std::setw(15) << (std::to_string(totalTier1ByField[i]) + " (" +
                                              std::to_string((int)(100.0 * totalTier1ByField[i] / total)) + "%)")
                          << std::setw(15) << (std::to_string(totalTier2ByField[i]) + " (" +
                                              std::to_string((int)(100.0 * totalTier2ByField[i] / total)) + "%)")
                          << std::setw(15) << (std::to_string(totalTier3ByField[i]) + " (" +
                                              std::to_string((int)(100.0 * totalTier3ByField[i] / total)) + "%)")
                          << std::setw(8) << total
                          << std::endl;
            }
        }
    }
}

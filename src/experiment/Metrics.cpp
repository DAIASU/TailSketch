#include "Metrics.h"
#include <algorithm>

double Metrics::calculateARE(const GroundTruth& gt, const CountMinSketch& sketch,
                              const KeyTransformer& keyFunc) {
    if (gt.flowCount() == 0) return 0.0;

    auto getKey = keyFunc ? keyFunc : rawKeyTransformer;

    double totalRE = 0.0;
    for (const auto& [pkt, actual] : gt.getAll()) {
        std::string key = getKey(pkt);
        uint32_t estimated = sketch.query(key);
        if (actual > 0) {
            totalRE += std::abs(static_cast<double>(estimated) - actual) / actual;
        }
    }
    return totalRE / gt.flowCount();
}

double Metrics::calculateAAE(const GroundTruth& gt, const CountMinSketch& sketch,
                              const KeyTransformer& keyFunc) {
    if (gt.flowCount() == 0) return 0.0;

    auto getKey = keyFunc ? keyFunc : rawKeyTransformer;

    double totalAE = 0.0;
    for (const auto& [pkt, actual] : gt.getAll()) {
        std::string key = getKey(pkt);
        uint32_t estimated = sketch.query(key);
        totalAE += std::abs(static_cast<double>(estimated) - actual);
    }
    return totalAE / gt.flowCount();
}

void Metrics::calculateHeavyHitterMetrics(const GroundTruth& gt,
                                           const CountMinSketch& sketch,
                                           double threshold,
                                           double& precision,
                                           double& recall,
                                           const KeyTransformer& keyFunc) {
    precision = 0.0;
    recall = 0.0;

    if (gt.flowCount() == 0) return;

    auto getKey = keyFunc ? keyFunc : rawKeyTransformer;

    uint64_t totalPackets = gt.totalPackets();
    uint64_t thresholdCount = static_cast<uint64_t>(threshold * totalPackets);

    // Find actual heavy hitters
    std::vector<Packet> actualHH;
    for (const auto& [pkt, count] : gt.getAll()) {
        if (count >= thresholdCount) {
            actualHH.push_back(pkt);
        }
    }

    if (actualHH.empty()) {
        precision = 1.0;
        recall = 1.0;
        return;
    }

    // Find detected heavy hitters (sketch estimate >= threshold)
    std::vector<Packet> detectedHH;
    for (const auto& [pkt, _] : gt.getAll()) {
        std::string key = getKey(pkt);
        uint32_t estimated = sketch.query(key);
        if (estimated >= thresholdCount) {
            detectedHH.push_back(pkt);
        }
    }

    if (detectedHH.empty()) {
        precision = 0.0;
        recall = 0.0;
        return;
    }

    // Count true positives
    int truePositives = 0;
    for (const auto& detected : detectedHH) {
        for (const auto& actual : actualHH) {
            if (detected == actual) {
                truePositives++;
                break;
            }
        }
    }

    precision = static_cast<double>(truePositives) / detectedHH.size();
    recall = static_cast<double>(truePositives) / actualHH.size();
}

double Metrics::calculateCompressionRatio(size_t uncompressedBits,
                                           size_t compressedBits) {
    if (compressedBits == 0) return 0.0;
    return static_cast<double>(uncompressedBits) / compressedBits;
}

MetricsResult Metrics::calculateAll(const GroundTruth& gt,
                                     const CountMinSketch& sketch,
                                     double heavyHitterThreshold,
                                     const KeyTransformer& keyFunc) {
    MetricsResult result;

    result.flowCount = gt.flowCount();
    result.totalPackets = gt.totalPackets();
    result.are = calculateARE(gt, sketch, keyFunc);
    result.aae = calculateAAE(gt, sketch, keyFunc);

    calculateHeavyHitterMetrics(gt, sketch, heavyHitterThreshold,
                                result.precision, result.recall, keyFunc);

    // Calculate F1 score
    if (result.precision + result.recall > 0) {
        result.f1Score = 2.0 * result.precision * result.recall /
                         (result.precision + result.recall);
    }

    return result;
}

FlowRecoveryResult Metrics::calculateFlowRecovery(
    const CompressedStorage& storage,
    const HuffmanLearner& learner,
    const GroundTruth& groundTruth) {

    FlowRecoveryResult result;
    result.totalActual = groundTruth.flowCount();

    if (storage.count() == 0 || !learner.hasBuiltTrees()) {
        return result;
    }

    // Decode all compressed IDs and collect unique recovered flows
    std::unordered_set<std::string> recoveredFlowKeys;
    std::unordered_set<std::string> correctFlowKeys;

    for (const auto& compressed : storage.getAll()) {
        Packet decoded;
        if (learner.decodePacket(compressed, decoded)) {
            std::string key = decoded.toKey();
            recoveredFlowKeys.insert(key);

            // Check if this flow exists in ground truth
            if (groundTruth.getCount(decoded) > 0) {
                correctFlowKeys.insert(key);
            }
        } else {
            result.decodeFailed++;
        }
    }

    result.totalRecovered = recoveredFlowKeys.size();
    result.correctRecovered = correctFlowKeys.size();

    // Calculate precision: correctly recovered / total recovered
    if (result.totalRecovered > 0) {
        result.precision = static_cast<double>(result.correctRecovered) / result.totalRecovered;
    }

    // Calculate recall: correctly recovered / total actual flows
    if (result.totalActual > 0) {
        result.recall = static_cast<double>(result.correctRecovered) / result.totalActual;
    }

    // Calculate F1 score
    if (result.precision + result.recall > 0) {
        result.f1Score = 2.0 * result.precision * result.recall /
                         (result.precision + result.recall);
    }

    return result;
}

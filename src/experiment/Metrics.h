#pragma once
#include "core/Packet.h"
#include "core/GroundTruth.h"
#include "core/CountMinSketch.h"
#include "core/HuffmanLearner.h"
#include "core/CompressedStorage.h"
#include <cstdint>
#include <cmath>
#include <functional>
#include <vector>
#include <unordered_set>

// Metrics calculation for sketch accuracy evaluation
struct MetricsResult {
    double are;          // Average Relative Error
    double aae;          // Average Absolute Error
    double precision;    // Precision for heavy hitter detection
    double recall;       // Recall for heavy hitter detection
    double f1Score;      // F1 score
    size_t flowCount;    // Number of unique flows
    size_t totalPackets; // Total packet count

    MetricsResult() : are(0), aae(0), precision(0), recall(0), f1Score(0),
                      flowCount(0), totalPackets(0) {}
};

// Flow ID Recovery metrics
struct FlowRecoveryResult {
    double precision;       // Correctly recovered / Total recovered
    double recall;          // Correctly recovered / Total actual flows
    double f1Score;         // F1 score
    size_t totalRecovered;  // Number of unique flows decoded
    size_t correctRecovered;// Number correctly matching ground truth
    size_t totalActual;     // Number of actual unique flows
    size_t decodeFailed;    // Number of decode failures

    FlowRecoveryResult() : precision(0), recall(0), f1Score(0),
                           totalRecovered(0), correctRecovered(0),
                           totalActual(0), decodeFailed(0) {}
};

// Key transformer function type
using KeyTransformer = std::function<std::string(const Packet&)>;

class Metrics {
public:
    // Calculate ARE with optional key transformer
    static double calculateARE(const GroundTruth& gt, const CountMinSketch& sketch,
                               const KeyTransformer& keyFunc = nullptr);

    // Calculate AAE with optional key transformer
    static double calculateAAE(const GroundTruth& gt, const CountMinSketch& sketch,
                               const KeyTransformer& keyFunc = nullptr);

    // Calculate precision and recall for heavy hitter detection
    static void calculateHeavyHitterMetrics(const GroundTruth& gt,
                                             const CountMinSketch& sketch,
                                             double threshold,
                                             double& precision,
                                             double& recall,
                                             const KeyTransformer& keyFunc = nullptr);

    // Calculate compression ratio
    static double calculateCompressionRatio(size_t uncompressedBits,
                                            size_t compressedBits);

    // Calculate all metrics at once with optional key transformer
    static MetricsResult calculateAll(const GroundTruth& gt,
                                       const CountMinSketch& sketch,
                                       double heavyHitterThreshold = 0.001,
                                       const KeyTransformer& keyFunc = nullptr);

    // Default key transformer (raw 5-tuple)
    static std::string rawKeyTransformer(const Packet& p) {
        return p.toKey();
    }

    // Calculate Flow ID Recovery metrics
    // Decodes compressed IDs and compares with ground truth
    static FlowRecoveryResult calculateFlowRecovery(
        const CompressedStorage& storage,
        const HuffmanLearner& learner,
        const GroundTruth& groundTruth);
};

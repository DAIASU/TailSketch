#include "AdaptiveExperimentRunner.h"
#include "Logger.h"
#include <iostream>
#include <getopt.h>
#include <cstdlib>

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [options] <pcap_file>\n"
              << "\n"
              << "Adaptive Huffman Sketch - Three-tier encoding with frequency estimation\n"
              << "\n"
              << "Options:\n"
              << "  -w, --window <n>     Packets per time window (default: 100000)\n"
              << "  -s, --storage <n>    FIFO storage capacity in KB (default: 128)\n"
              << "                       Same memory budget for raw and compressed storage\n"
              << "  -k, --topk <n>       Frequent table top-K entries (default: 1024)\n"
              << "  -b, --bloom <n>      Bloom filter size in bits (default: 1000000)\n"
              << "  -m, --sketch-mem <n> Sketch memory per row in bytes (default: 65536)\n"
              << "  -t, --theta <n>      Elephant threshold for frequency metrics (default: 100)\n"
              << "  -h, --help           Show this help message\n"
              << "\n"
              << "Examples:\n"
              << "  " << programName << " traffic.pcap\n"
              << "  " << programName << " -w 50000 -k 512 traffic.pcap\n"
              << "  " << programName << " -s 64 -m 32768 -t 50 traffic.pcap\n"
              << "\n"
              << "Output columns:\n"
              << "  Win       - Window number\n"
              << "  Pkts      - Packets processed in window\n"
              << "  Flows     - Ground truth unique flows in window\n"
              << "  CompStor  - Flows stored in compressed FIFO\n"
              << "  Ratio     - Compression ratio (Raw bits / Compressed bits)\n"
              << "  RecPrec   - Recovered IDs precision\n"
              << "  RecRec    - Recovered IDs recall\n"
              << "  Mpps      - Throughput (million packets per second)\n"
              << "  AAE_all   - Average Absolute Error for all flows\n"
              << "  ARE_all   - Average Relative Error for all flows\n"
              << "  AAE_ele   - AAE for elephant flows (freq >= theta)\n"
              << "  ARE_ele   - ARE for elephant flows\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    // Default configuration
    AdaptiveConfig config;
    config.windowSize = 100000;
    config.storageCapacityKB = 128;
    config.frequentTableK = 1024;
    config.bloomFilterSize = 1000000;
    config.sketchRowBytes = 65536;
    config.elephantThreshold = 100;

    // Long options
    static struct option longOptions[] = {
        {"window",      required_argument, nullptr, 'w'},
        {"storage",     required_argument, nullptr, 's'},
        {"topk",        required_argument, nullptr, 'k'},
        {"bloom",       required_argument, nullptr, 'b'},
        {"sketch-mem",  required_argument, nullptr, 'm'},
        {"theta",       required_argument, nullptr, 't'},
        {"help",        no_argument,       nullptr, 'h'},
        {nullptr,       0,                 nullptr,  0 }
    };

    // Parse command line arguments
    int opt;
    while ((opt = getopt_long(argc, argv, "w:s:k:b:m:t:h", longOptions, nullptr)) != -1) {
        switch (opt) {
            case 'w':
                config.windowSize = std::atoi(optarg);
                break;
            case 's':
                config.storageCapacityKB = std::atoi(optarg);
                break;
            case 'k':
                config.frequentTableK = std::atoi(optarg);
                break;
            case 'b':
                config.bloomFilterSize = std::atoi(optarg);
                break;
            case 'm':
                config.sketchRowBytes = std::atoi(optarg);
                break;
            case 't':
                config.elephantThreshold = std::atoi(optarg);
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    // Check for PCAP file argument
    if (optind >= argc) {
        std::cerr << "Error: No PCAP file specified.\n" << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    config.pcapFile = argv[optind];

    // Validate configuration
    if (config.windowSize <= 0) {
        std::cerr << "Error: Window size must be positive." << std::endl;
        return 1;
    }
    if (config.storageCapacityKB <= 0) {
        std::cerr << "Error: Storage capacity must be positive." << std::endl;
        return 1;
    }
    if (config.frequentTableK <= 0) {
        std::cerr << "Error: Frequent table K must be positive." << std::endl;
        return 1;
    }
    if (config.bloomFilterSize <= 0) {
        std::cerr << "Error: Bloom filter size must be positive." << std::endl;
        return 1;
    }
    if (config.sketchRowBytes <= 0) {
        std::cerr << "Error: Sketch row memory must be positive." << std::endl;
        return 1;
    }
    if (config.elephantThreshold <= 0) {
        std::cerr << "Error: Elephant threshold must be positive." << std::endl;
        return 1;
    }

    // Run the experiment
    try {
        AdaptiveExperimentRunner runner(config);
        runner.run();
    } catch (const std::exception& e) {
        Logger::logError(std::string("Exception: ") + e.what());
        return 1;
    }

    return 0;
}

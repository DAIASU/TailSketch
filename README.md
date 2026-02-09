# TailSketch Evaluation Framework

This directory contains the complete evaluation framework for the TailSketch paper, including parameter sweep experiments and statistical analysis tools.

## Executables Overview

The `CodedSketchSim` package provides two main executables:

### 1. `adaptive_main` - Single Algorithm Testing
**Purpose**: Test TailSketch (Adaptive Huffman Sketch) in isolation with custom parameters.

**Features**:
- Three-tier encoding: Frequent Table + Bloom Filter + Sketch
- Frequency estimation for all flows
- Configurable memory budget and parameters

**Usage**:
```bash
./adaptive_main [options] <pcap_file>

Options:
  -w, --window <n>     Packets per time window (default: 100000)
  -s, --storage <n>    FIFO storage capacity in KB (default: 128)
  -k, --topk <n>       Frequent table top-K entries (default: 1024)
  -b, --bloom <n>      Bloom filter size in bits (default: 1000000)
  -m, --sketch-mem <n> Sketch memory per row in bytes (default: 65536)
  -t, --theta <n>      Elephant threshold for metrics (default: 100)
```

**Example**:
```bash
./adaptive_main -w 100000 -s 128 -k 1024 caida2018.pcap
```

### 2. `sketch_comparison` - Five-Algorithm Benchmark (MAIN EVALUATION TOOL)
**Purpose**: Comprehensive comparison of 5 sketch algorithms across multiple query patterns.

**Algorithms Compared**:
1. **TailSketch**: Adaptive Huffman encoding with three-tier architecture
2. **USS**: Uniform Sample Sampler
3. **CocoSketch**: Multiple hash tables with median aggregation
4. **HyperUSS**: Multi-dimensional sketch (simplified mode)
5. **SandwichSketch**: Two-tier TopK + CoCo baseline

**Query Patterns Tested** (5 types):
- `SrcIP Only`: Aggregate by source IP
- `DstIP Only`: Aggregate by destination IP
- `Src Pair`: Source IP + Port pairs
- `Dst Pair`: Destination IP + Port pairs
- `IP Pair`: Full IP-to-IP communication pairs

**Query Categories** (3 types):
- `Comprehensive`: All flows in the window
- `Elephant`: Frequent flows (frequency ≥ threshold × window_size)
- `Mice`: Tail flows (frequency < threshold × window_size)

**Usage**:
```bash
./sketch_comparison [options] <pcap_file>

Options:
  -w, --window <n>     Packets per time window (default: 100000)
  -m, --memory <n>     Sketch memory budget in KB (default: 256)
  -k, --topk <n>       TailSketch frequent table size (default: 32768)
  -t, --threshold <f>  Elephant flow threshold (default: 0.005)
  -n, --max-wins <n>   Maximum windows to process (default: 5, -1 = all)
  -o, --output <dir>   Output directory (default: ./SketchComparison/)
```

**Example**:
```bash
./sketch_comparison -w 100000 -m 100 -t 0.005 -o results4/memory_sweep/caida2018/mem_100KB/ caida2018.pcap
```

**How It Works**:

1. **Packet Processing**: Reads PCAP file and divides traffic into time windows of N packets

2. **Insertion Phase**: For each packet, all 5 sketches insert the 5-tuple flow key simultaneously

3. **Query Phase**: After each window, for each of the 5 query patterns:
   - Extracts ground truth partial keys from full 5-tuples
   - Applies the Mask-Sweep Aggregation Algorithm to find optimal beta (mice/elephant split ratio)
   - Queries each sketch for frequency estimates of all partial keys
   - Classifies flows as Comprehensive/Elephant/Mice based on ground truth frequency

4. **Metrics Calculation**: Computes accuracy, coverage, and throughput metrics per sketch

**Output Files**:

1. **`sketch_comparison_detailed.csv`**: Per-partial-key metrics
   - One row per (Window, Pattern, PartialKey)
   - Contains ground truth and estimates from all 5 sketches
   - Columns: Timewindow, Pattern, PartialKey, GroundTruth, TailSketch_Estimate, TailSketch_AAE, TailSketch_ARE, USS_Estimate, USS_AAE, USS_ARE, ...

2. **`sketch_comparison_summary.csv`**: Per-window-pattern-category metrics
   - One row per (Window, Pattern, Category)
   - Aggregated metrics across all partial keys in that category
   - Columns: Timewindow, Pattern, Category, UniqueKeys, TotalPackets, TailSketch_AAE, TailSketch_ARE, TailSketch_AvgCoverage, TailSketch_AvgInsertThroughput, TailSketch_AvgQueryThroughput, ...

3. **`sketch_comparison_overall.csv`**: Overall metrics averaged across all windows
   - One row per (Pattern, Category)
   - Final aggregated metrics used for cross-parameter analysis
   - Columns: Pattern, Category, TailSketch_AvgAAE, TailSketch_AvgARE, TailSketch_AvgCoverage, TailSketch_AvgInsertThroughput, USS_AvgAAE, USS_AvgARE, USS_AvgCoverage, ...

**Key Metrics**:
- **AAE** (Average Absolute Error): Mean |estimate - ground_truth|
- **ARE** (Average Relative Error): Mean |estimate - ground_truth| / ground_truth
- **Coverage**: Fraction of flows successfully tracked (0.0-1.0)
- **Insert Throughput**: Millions of packets per second (Mpps) during insertion
- **Query Throughput**: Millions of queries per second (Mpps) during query phase
- **Compression Ratio**: Raw bits / Compressed bits (TailSketch only)

## Datasets

- `caida2018.pcap` (1.3GB): Primary evaluation dataset
- `caida2019.pcap` (1.7GB): Cross-validation dataset

Both are high-speed backbone traffic traces from CAIDA.

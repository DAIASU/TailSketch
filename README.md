# Adaptive Huffman Sketch

A network flow measurement framework using adaptive Huffman coding for efficient flow ID compression and frequency estimation, with advanced correlation-based partial key query capabilities.

## Overview

The Adaptive Huffman Sketch framework compresses flow identifiers (5-tuples) using a three-tier encoding scheme and estimates flow frequencies using a hybrid sketch architecture. This achieves significant memory savings while enabling accurate flow ID recovery and frequency estimation.

### Key Features

- **Three-Tier Encoding**: Adaptive Huffman + frequent table + raw encoding
- **Per-Field Compression**: Independent encoding for each of the 5 tuple fields
- **Adaptive Learning**: Huffman trees rebuilt per window from recovered IDs
- **Hybrid Frequency Sketch**: Direct counters for Tier 1, associative buffer for Tier 2/3
- **Correlation-Based Queries**: Adjusts for field correlations using beta exponents
- **Partial Key Queries**: Estimates aggregate frequency for wildcard patterns
- **Beta Grid Search**: Automated search for optimal beta values across traffic patterns
- **Comparative Analysis**: Benchmarking against SandwichSketch

## Building

### Prerequisites

- CMake 3.14+
- C++17 compatible compiler (GCC 7+, Clang 5+)
- libpcap development library

```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel

# macOS
brew install libpcap
```

### Compilation

```bash
cd CodedSketchSim
mkdir build && cd build
cmake ..
make
```

## Available Programs

This repository contains three main executables:

### 1. AdaptiveHuffmanSketch (Original Implementation)
Basic Huffman sketch with flow ID compression and frequency estimation.

```bash
./AdaptiveHuffmanSketch [options] <pcap_file>
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `-w, --window <n>` | Packets per time window | 100000 |
| `-s, --storage <n>` | FIFO storage capacity in KB | 128 |
| `-k, --topk <n>` | Frequent table top-K entries | 1024 |
| `-b, --bloom <n>` | Bloom filter size in bits | 1000000 |
| `-m, --sketch-mem <n>` | Sketch memory per row in **bytes** | 65536 |
| `-t, --theta <n>` | Elephant flow threshold | 100 |
| `-h, --help` | Show help message | - |

### 2. PartialKeyComparison (Sketch Comparison Framework)
Compares FrequencySketch vs SandwichSketch for partial key queries.

```bash
./PartialKeyComparison -f <pcap_file> [options]
```

**Options:**
- `-f <file>` - PCAP file to process (required)
- `-o <dir>` - Output directory (default: ./)
- `-w <size>` - Window size in packets (default: 100000)
- `-m <kb>` - Memory for sketch in KB (default: 256)
- `-k <k>` - Frequent table K (default: 32768)
- `-t <thresh>` - Elephant threshold in packets (default: 250)

**Outputs:**
- `comparison_summary.csv` - Per-window pattern results
- `comparison_details.txt` - Detailed breakdown per pattern and rank
- `ground_truth_window_X.txt` - Ground truth data per window

See [CORRELATION_BASED_QUERY.md](CORRELATION_BASED_QUERY.md) for correlation-based query details.

### 3. BetaGridSearch (Beta Parameter Optimization)
Automated grid search to find optimal beta values for correlation-adjusted queries.

```bash
./BetaGridSearch -f <pcap_file> [options]
```

**Options:**
- `-f <file>` - PCAP file to process (required)
- `-o <dir>` - Output directory (default: ./BetaGridSearch/)
- `-w <size>` - Window size in packets (default: 100000)
- `-m <kb>` - Memory for sketch in KB (default: 256)
- `-k <k>` - Frequent table K (default: 32768)
- `-t <thresh>` - Elephant threshold as fraction (default: 0.01)
- `-b <min>` - Beta minimum value (default: 0.0)
- `-B <max>` - Beta maximum value (default: 1.0)
- `-n <points>` - Number of beta points to test (default: 20)

**Outputs:**
- `beta_grid_topk.csv` - Top-K mice flows per pattern with beta sweep
- `beta_grid_elephant.csv` - Top elephant flow results with beta sweep
- `beta_grid_comprehensive.csv` - Comprehensive metrics across all partial keys

See [BETA_GRID_SEARCH.md](BETA_GRID_SEARCH.md) for detailed usage and analysis.

## File Structure

```
CodedSketchSim/
├── CMakeLists.txt
├── README.md
├── BETA_GRID_SEARCH.md            # Beta grid search documentation
├── CORRELATION_BASED_QUERY.md     # Correlation-based query documentation
└── src/
    ├── adaptive_main.cpp          # Original Huffman sketch implementation
    ├── comparison_main.cpp        # FrequencySketch vs SandwichSketch comparison
    ├── beta_grid_search.cpp       # Beta parameter grid search
    ├── core/
    │   ├── Packet.h               # 5-tuple struct and partial key definitions
    │   ├── AdaptiveHuffmanTree.h/cpp      # Huffman tree with NYT/UNKNOWN
    │   ├── AdaptiveHuffmanLearner.h/cpp   # Three-tier encoding/decoding
    │   ├── FrequentTable.h        # Global top-K dictionary
    │   ├── FIFOStorage.h          # Fixed-capacity FIFO storage
    │   ├── FrequencySketch.h/cpp  # Hybrid frequency estimation (correlation-based)
    │   ├── SandwichSketch.h/cpp   # SandwichSketch baseline implementation
    │   └── BloomFilter.h/cpp      # New flow detection
    ├── hash/
    │   └── hash.h/cpp             # BOBHash32 implementation
    ├── io/
    │   └── PcapReader.h/cpp       # PCAP file parsing
    └── experiment/
        ├── AdaptiveExperimentRunner.h/cpp  # Main experiment loop
        ├── Metrics.h/cpp          # AAE, ARE calculation
        └── Logger.h/cpp           # Formatted output
```

## Output Format

### Per-Window Results

```
Win  Packets  Throughput  Ratio  RecPrec RecRec  AAE_all  ARE_all  AAE_ele  ARE_ele  AAE_mic  ARE_mic
-------------------------------------------------------------------------------------------------------
0    100000   2.5M pps    2.80   0.9912  0.6912  1.2340   0.052100 0.8920   0.031200 1.4512   0.068900
```

**Columns:**
- `Win`: Window number
- `Packets`: Total packets processed
- `Throughput`: Insertion throughput (packets per second)
- `Ratio`: Compression ratio (Raw bits / Compressed bits)
- `RecPrec`: Recovery precision (|Ω₁ ∩ Ω₀| / |Ω₁|)
- `RecRec`: Recovery recall (|Ω₁ ∩ Ω₀| / |Ω₀|)
- `AAE_all/ARE_all`: Average Absolute/Relative Error for all flows
- `AAE_ele/ARE_ele`: Average Absolute/Relative Error for elephant flows (freq ≥ θ)
- `AAE_mic/ARE_mic`: Average Absolute/Relative Error for mice flows (freq < θ)

### Summary Statistics

```
Tier distribution (overall):
  Tier 1 (Huffman): 125000 (50.0%)
  Tier 2 (NYT+Freq): 50000 (20.0%)
  Tier 3 (Unknown): 75000 (30.0%)

FrequencySketch Memory Layout (64 KB per row = 320 KB total):
Field      Tier1      Tier2/3         Total
─────────────────────────────────────────────────────────
srcIP      1024 x 2B  5461 x 12B      67.6 KB (21.1%)
dstIP      2048 x 2B  5290 x 12B      67.6 KB (21.1%)
srcPort    8192 x 2B  4826 x 12B      73.9 KB (23.1%)
dstPort    8192 x 2B  4826 x 12B      73.9 KB (23.1%)
proto      256  x 2B  1    x 12B      0.5 KB  (0.2%)
                                      ──────────────────
                                      283.5 KB (88.6%)

Note: Proto field receives minimal allocation (1 bucket) due to low
entropy. Remaining memory is distributed equally among top 4 fields.
Actual memory usage may be less than theoretical 320 KB due to alignment.
```

---

# Part 1: ID Encoding & Recovery Scheme

## 1.1 Three-Tier Encoding Overview

### Frequency Map Structure

Each of the 5 Huffman learners maintains:
```
frequency_map: {
    field_value_1: freq_1,    // Learned from previous window's recovered IDs
    field_value_2: freq_2,
    ...
    NYT: 0,                   // Always 0, highest priority among freq=0
    UNKNOWN: 0                // Always 0, second highest priority among freq=0
}
```

**Special Symbol Priority Rule:** When building the Huffman tree, symbols with equal frequency are ordered as: `NYT > UNKNOWN > regular symbols`. This ensures NYT and UNKNOWN are always combined first as siblings, with NYT getting the left child (code suffix "0") and UNKNOWN getting the right child (code suffix "1").

### Frequent Table (Global Dictionary)

Built once during initialization by scanning the entire PCAP file:

```
struct FrequentTable:
    entries: map<field_value, fixed_length_code>  // Top-K frequent values
    code_length: int                               // ceil(log2(actual_size)) bits
```

**Initialization Pseudocode:**
```
function buildFrequentTables(pcap_file, K):
    seen_flows = set()
    field_counters[5] = [{}, {}, {}, {}, {}]  // One counter per field

    // Pass 1: Count field frequencies (deduplicated by flow ID)
    for each packet p in pcap_file:
        flow_id = (p.srcIP, p.dstIP, p.srcPort, p.dstPort, p.proto)
        if flow_id in seen_flows:
            continue
        seen_flows.add(flow_id)

        for i in 0..4:
            field_counters[i][p.field[i]]++

    // Pass 2: Build frequent tables with top-K entries
    frequent_tables[5]
    for i in 0..4:
        sorted_entries = sort(field_counters[i], by=frequency, descending=true)
        top_k = sorted_entries[0:K]

        // Code length based on actual size, not capacity
        actual_size = min(len(top_k), K)
        code_length = ceil(log2(actual_size))
        for idx, (field_value, _) in enumerate(top_k):
            frequent_tables[i].entries[field_value] = toBinary(idx, code_length)
        frequent_tables[i].code_length = code_length

    return frequent_tables
```

## 1.2 Three-Tier Encoding Scheme

For each field of a flow ID, encoding follows this priority:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ENCODING DECISION TREE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  field_value ──> In huffman_tree.keys? ──> YES ──> [TIER 1]             │
│                          │                         huffman_code(value)  │
│                          NO                                             │
│                          v                                              │
│                  In frequent_table? ──────> YES ──> [TIER 2]            │
│                          │                         huffman_code(NYT)    │
│                          │                         + fixed_length_index │
│                          NO                                             │
│                          v                                              │
│                                                    [TIER 3]             │
│                                                    huffman_code(UNKNOWN)│
│                                                    + raw_field_bits     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Encoding Pseudocode:**
```
function encodeField(field_idx, field_value, huffman_tree, frequent_table):
    if field_value in huffman_tree.keys:
        // Tier 1: Known symbol - use Huffman code directly
        return huffman_tree.encode(field_value)

    else if field_value in frequent_table.entries:
        // Tier 2: Globally frequent but not in current Huffman tree
        nyt_code = huffman_tree.encode(NYT)
        index_code = frequent_table.entries[field_value]  // Fixed-length
        return concat(nyt_code, index_code)

    else:
        // Tier 3: Completely unknown - escape with raw bits
        unknown_code = huffman_tree.encode(UNKNOWN)
        raw_bits = toBinary(field_value, FIELD_BITS[field_idx])
        return concat(unknown_code, raw_bits)

function encodeFlowID(flow_id, huffman_trees[5], frequent_tables[5]):
    compressed_id = ""
    for i in 0..4:
        compressed_id += encodeField(i, flow_id.field[i],
                                     huffman_trees[i], frequent_tables[i])
    return compressed_id
```

## 1.3 Three-Tier Decoding Scheme

Decoding is the reverse process. The decoder reads the bit stream and determines which tier was used based on the decoded Huffman symbol.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DECODING DECISION TREE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Read huffman_code from bitstream                                       │
│            │                                                            │
│            v                                                            │
│  symbol = huffman_tree.decode(bitstream, pos)                           │
│            │                                                            │
│            ├── symbol is regular value ──> [TIER 1]                     │
│            │                               field_value = symbol         │
│            │                                                            │
│            ├── symbol == NYT ────────────> [TIER 2]                     │
│            │                               Read next code_length bits   │
│            │                               index = toInt(bits)          │
│            │                               field_value = frequent_table │
│            │                                            .getKey(index)  │
│            │                                                            │
│            └── symbol == UNKNOWN ────────> [TIER 3]                     │
│                                            Read next FIELD_BITS[i] bits │
│                                            field_value = toInt(bits)    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Decoding Pseudocode:**
```
// Field bit widths
FIELD_BITS = [32, 32, 16, 16, 8]  // srcIP, dstIP, srcPort, dstPort, proto

function decodeField(field_idx, bitstream, pos, huffman_tree, frequent_table):
    symbol = huffman_tree.decode(bitstream, pos)  // pos is updated by reference

    if symbol == NYT:
        // Tier 2: Read fixed-length index, lookup in frequent table
        code_length = frequent_table.code_length
        index_bits = bitstream.read(pos, code_length)
        pos += code_length
        field_value = frequent_table.getKeyByIndex(toInt(index_bits))
        return field_value

    else if symbol == UNKNOWN:
        // Tier 3: Read raw field bits
        raw_bits = bitstream.read(pos, FIELD_BITS[field_idx])
        pos += FIELD_BITS[field_idx]
        field_value = toInt(raw_bits)
        return field_value

    else:
        // Tier 1: Symbol is the field value itself
        return symbol

function decodeFlowID(compressed_id, huffman_trees[5], frequent_tables[5]):
    pos = 0
    fields[5]

    for i in 0..4:
        fields[i] = decodeField(i, compressed_id, pos,
                                huffman_trees[i], frequent_tables[i])

    return FlowID(fields[0], fields[1], fields[2], fields[3], fields[4])
```

## 1.4 Huffman Tree Building with Priority Rule

```
function buildHuffmanTree(frequency_map):
    // Create priority queue with custom comparator:
    // 1. Lower frequency = higher priority (pops first, gets longer code)
    // 2. If equal frequency: NYT > UNKNOWN > regular symbols
    pq = PriorityQueue(comparator=huffmanNodeCompare)

    for (symbol, freq) in frequency_map:
        pq.push(HuffmanNode(symbol, freq))

    while pq.size() > 1:
        left = pq.pop()   // Higher priority -> left child (code "0")
        right = pq.pop()  // Lower priority -> right child (code "1")
        internal = HuffmanNode(freq=left.freq + right.freq)
        internal.left = left
        internal.right = right
        pq.push(internal)

    root = pq.pop()
    buildCodeDict(root, "")
    return HuffmanTree(root, codeDict)

function huffmanNodeCompare(a, b):
    // Returns true if a has LOWER priority than b (a should come after b)
    if a.freq != b.freq:
        return a.freq > b.freq  // Higher freq = lower priority

    // Equal frequency: NYT > UNKNOWN > regular
    // NYT has highest priority (pops first, becomes left child)
    if a.symbol == NYT: return false   // a (NYT) has higher priority
    if b.symbol == NYT: return true    // b (NYT) has higher priority

    // UNKNOWN has second highest priority
    if a.symbol == UNKNOWN: return false  // a (UNKNOWN) > regular
    if b.symbol == UNKNOWN: return true   // b (UNKNOWN) > regular

    // Regular symbols: arbitrary but deterministic
    return a.symbol > b.symbol
```

## 1.5 Key Design Points

1. **No chunking**: Encode whole field values (32-bit IP, 16-bit port, 8-bit proto)

2. **Two-pass initialization**:
   - Entire file -> global frequent tables (top-K per field)
   - First window -> initial Huffman frequencies

3. **Three-tier encoding**:
   - Tier 1: Huffman code for known symbols
   - Tier 2: NYT escape + fixed-length frequent_table index
   - Tier 3: UNKNOWN escape + raw field bits

4. **Special symbol priority**: `NYT > UNKNOWN > regular` ensures they are always siblings with same code length

5. **Adaptive learning**: Each window's Huffman tree is built from the **previous window's recovered IDs**

6. **FIFO storage**: Fixed memory capacity, auto-evicts oldest entries

---

# Part 2: Frequency Insertion & Query Scheme

## 2.1 Overview

The frequency estimation uses a **hybrid sketch architecture** that exploits the three-tier encoding structure:
- **Tier 1 symbols** (known to Huffman tree): Direct counter array with O(1) access
- **Tier 2/3 symbols** (NYT/UNKNOWN): Associative buffer with Space-Saving eviction

Flow frequency is estimated using **Naive Bayes assumption**: the joint probability of a 5-tuple is approximated as the product of marginal field probabilities.

## 2.2 Data Structures

The core data structure is the **Adaptive Huffman Sketch**, a flat memory architecture with 5 independent rows (one per field). Each row is dynamically partitioned into **Tier 1 Counters** and **Tier 2/3 Buffer**. The memory allocation is optimized based on field entropy: the proto field (low entropy, 256 values) receives minimal allocation, while the remaining memory is distributed equally among the top 4 fields.

### Physical Memory Layout

```cpp
/**
 * Bit-Packed Bucket Entry for Tier 2/3 Buffer (12 bytes)
 */
#pragma pack(push, 1)
struct PhysicalBucket {
    uint64_t code;      // Compressed code (64 bits)
    uint16_t frequency; // Frequency counter (16 bits)
    uint8_t  code_len;  // Length of valid bits (8 bits)
    uint8_t  is_valid;  // Occupancy flag (8 bits)
};
#pragma pack(pop)

/**
 * Row Layout Descriptor (Metadata)
 */
struct RowLayout {
    size_t memory_offset;              // Start offset in flat memory block
    size_t tier1_count;                // Number of Tier 1 counters (uint16_t)
    size_t tier2_count;                // Number of Tier 2/3 buckets (PhysicalBucket)
    std::vector<uint64_t> symbol_keys; // Sorted symbols for binary search
};

/**
 * Main Sketch Container (Flat Memory Architecture)
 */
struct FrequencySketch {
    std::vector<uint8_t> memory_;              // Single contiguous memory block
    std::array<RowLayout, 5> rows_;            // Metadata for 5 rows

    // Access helpers
    uint16_t* getTier1Ptr(const RowLayout& row);
    PhysicalBucket* getTier2Ptr(const RowLayout& row);
};
```

### Initialization Routine

```
Algorithm InitializeSketch(HuffmanTrees[5], TotalBytesPerRow):
    TotalBudget = TotalBytesPerRow * 5  // Total memory across all 5 rows

    // ──────────────────────────────────────────────────────────
    // PASS 1: Calculate Tier 1 requirements for all fields
    // ──────────────────────────────────────────────────────────
    TotalTier1Bytes = 0
    For i = 0 to 4:
        RegularSymbols = HuffmanTrees[i].GetRegularSymbols()  // Exclude NYT/UNKNOWN
        Rows[i].Tier1Count = Length(RegularSymbols)
        Rows[i].SymbolKeys = Sort(RegularSymbols)  // For binary search

        Tier1Bytes = Rows[i].Tier1Count * 2  // 2 bytes per uint16_t counter
        Tier1Aligned = Align8(Tier1Bytes)     // 8-byte alignment
        TotalTier1Bytes += Tier1Aligned
    EndFor

    // ──────────────────────────────────────────────────────────
    // PASS 2: Distribute remaining memory for Tier 2/3 buffers
    // ──────────────────────────────────────────────────────────
    TotalTier2Budget = TotalBudget - TotalTier1Bytes

    // Proto field (field 4): Minimal allocation (1 bucket = 12 bytes)
    ProtoTier2Bytes = 12
    RemainingForTop4 = TotalTier2Budget - ProtoTier2Bytes

    // Top 4 fields (0-3): Equal distribution of remaining memory
    BytesPerTopField = RemainingForTop4 / 4

    CurrentOffset = 0
    For i = 0 to 4:
        Rows[i].MemoryOffset = CurrentOffset
        Tier1Aligned = Align8(Rows[i].Tier1Count * 2)

        // Determine Tier 2/3 allocation
        If i == 4:  // Proto field
            Tier2Bytes = ProtoTier2Bytes
        Else:       // Top 4 fields
            Tier2Bytes = BytesPerTopField
        EndIf

        Rows[i].Tier2Count = Floor(Tier2Bytes / 12)  // 12 bytes per bucket
        ActualTier2Bytes = Rows[i].Tier2Count * 12

        CurrentOffset += (Tier1Aligned + ActualTier2Bytes)
    EndFor

    // Allocate single contiguous block
    Memory = Allocate(CurrentOffset)
    FillZero(Memory)
```

## 2.3 Insertion Algorithm

The insertion uses **Direct Addressing** for Tier 1 and **Hash-Mapped Access** for Tier 2/3. The hash-mapped approach uses modulo-based direct mapping with collision handling strategies.

```
// Collision Strategy Configuration
#define STRATEGY_VERSION 1  // 1 = Probabilistic, 2 = Decay/HeavyKeeper

Algorithm InsertPacket(Packet, Sketch, HuffmanTrees, FrequentTables):
    Fields[5] = Extract5Tuple(Packet)

    For i = 0 to 4:
        Value = Fields[i]
        Row = Sketch.Rows[i]
        Tree = HuffmanTrees[i]

        // ═════════════════════════════════════════════════════════
        // ENCODING PHASE: Symbol lookup and code generation
        // ═════════════════════════════════════════════════════════
        Index = BinarySearch(Row.SymbolKeys, Value)

        If Index != -1:  // PATH A: Tier 1 (Known Regular Symbol)
            Counters = GetTier1Ptr(Row)
        Else:            // PATH B: Tier 2/3 (NYT or UNKNOWN)
            KeyString = EncodeField(i, Value, Tree, FrequentTables[i])
            Code = StringToBinary(KeyString)  // Pre-compute uint64_t
            CodeLen = Length(KeyString)
            Buckets = GetTier2Ptr(Row)
        EndIf

        // ═════════════════════════════════════════════════════════
        // INSERTION PHASE: Actual memory write
        // ═════════════════════════════════════════════════════════
        If Index != -1:  // Tier 1: Direct counter increment
            If Counters[Index] < 0xFFFF:
                Counters[Index] += 1
        Else:            // Tier 2/3: Hash-mapped insertion
            InsertIntoBuffer(Buckets, Row.Tier2Count, Code, CodeLen)
        EndIf
    EndFor


// ─────────────────────────────────────────────────────────────
// Hash-Mapped Buffer Insertion (Direct-Mapped with Modulo)
// ─────────────────────────────────────────────────────────────
Function InsertIntoBuffer(Buckets[], Count, Code, CodeLen):
    // Direct-mapped hash index
    Idx = Code mod Count

    If NOT Buckets[Idx].IsValid:
        // Empty slot - insert new entry
        Buckets[Idx].Code = Code
        Buckets[Idx].CodeLen = CodeLen
        Buckets[Idx].Frequency = 1
        Buckets[Idx].IsValid = 1
        Return
    EndIf

    If Buckets[Idx].Code == Code AND Buckets[Idx].CodeLen == CodeLen:
        // Exact match - increment frequency
        If Buckets[Idx].Frequency < 0xFFFF:
            Buckets[Idx].Frequency += 1
        EndIf
        Return
    EndIf

    // ─────────────────────────────────────────────────────────
    // COLLISION DETECTED: Handle based on strategy
    // ─────────────────────────────────────────────────────────
    If STRATEGY_VERSION == 1:  // Probabilistic Replacement
        // Increment existing counter first
        If Buckets[Idx].Frequency < 0xFFFF:
            Buckets[Idx].Frequency += 1
        EndIf

        // Replace with probability P = 1/freq
        If Random(Buckets[Idx].Frequency) == 0:
            Buckets[Idx].Code = Code
            Buckets[Idx].CodeLen = CodeLen
            Buckets[Idx].Frequency = 1
        EndIf

    Else:  // Decay/HeavyKeeper Strategy
        // Decrement existing counter
        Buckets[Idx].Frequency -= 1

        // Replace if frequency reaches 0
        If Buckets[Idx].Frequency == 0:
            Buckets[Idx].Code = Code
            Buckets[Idx].CodeLen = CodeLen
            Buckets[Idx].Frequency = 1
        EndIf
    EndIf
```

## 2.4 Query Algorithm

Flow frequency is estimated using **Naive Bayes assumption**:

$$\hat{f} = N \times \prod_{i=1}^{5} \frac{x_i}{N}$$

Where:
- $N$: Total packets inserted
- $x_i$: Frequency count for field $i$

```
function queryFlowFrequency(flow_id, sketch, huffman_trees, frequent_tables, N):
    fields = extractFields(flow_id)

    product = 1.0
    for i in 0 to 4:
        count = queryField(i, fields[i], sketch.rows[i],
                           huffman_trees[i], frequent_tables[i])

        if count == 0:
            return 0  // Early termination

        product *= (count / N)

    return N * product


function queryField(field_idx, value, row, tree, frequent_table):
    // Tier 1: Direct lookup with binary search
    idx = BinarySearch(row.symbol_keys, value)
    if idx != -1:
        counters = getTier1Ptr(row)
        return counters[idx]

    // Tier 2/3: Hash-mapped lookup
    else:
        // Build compressed code
        if frequent_table.contains(value):
            key_string = tree.encode(NYT) + frequent_table.encode(value)
        else:
            key_string = tree.encode(UNKNOWN) + toBinary(value, FIELD_BITS[field_idx])

        code = stringToBinary(key_string)
        code_len = length(key_string)

        // Direct-mapped hash lookup
        buckets = getTier2Ptr(row)
        idx_hash = code mod row.tier2_count

        if buckets[idx_hash].is_valid AND
           buckets[idx_hash].code_len == code_len AND
           buckets[idx_hash].code == code:
            return buckets[idx_hash].frequency

        // Conservative estimate if not found
        return 1
```

## 2.5 Partial Key Query Algorithm

Partial key queries estimate the aggregate frequency of all flows matching a wildcard pattern (e.g., "SrcIP=X, * * * *"). Two query methods are implemented:

1. **Naive Bayes Query** (original): Assumes independence between fields
2. **Correlation-Based Query** (enhanced): Adjusts for field correlations using beta exponents

See [CORRELATION_BASED_QUERY.md](CORRELATION_BASED_QUERY.md) for detailed mathematical formulation and implementation.

### Partial Key Representation

```cpp
struct PartialKey {
    uint32_t srcIP, dstIP;
    uint16_t srcPort, dstPort;
    uint8_t  proto;
    uint8_t  mask;  // Bit i=1 means field i is wildcard, i=0 means exact match
                    // Bit 0=srcIP, 1=dstIP, 2=srcPort, 3=dstPort, 4=proto
};

// Example masks:
// 0x1E (11110): SrcIP exact, all others wildcard
// 0x1D (11101): DstIP exact, all others wildcard
// 0x1A (11010): SrcIP+SrcPort exact, others wildcard
// 0x15 (10101): DstIP+DstPort exact, others wildcard
// 0x1C (11100): SrcIP+DstIP exact, others wildcard
```

### Query Algorithm

#### Method 1: Naive Bayes (Independence Assumption)

```
function queryPartialKey(partial_key, sketch, huffman_trees, frequent_tables, N):
    fields = [partial_key.srcIP, partial_key.dstIP,
              partial_key.srcPort, partial_key.dstPort, partial_key.proto]

    product = 1.0
    for i in 0 to 4:
        // Check if field i is exact match (mask bit i == 0)
        if (partial_key.mask & (1 << i)) == 0:
            // Exact match: Query field frequency
            count = queryField(i, fields[i], sketch.rows[i],
                               huffman_trees[i], frequent_tables[i])

            if count == 0:
                return 0  // Early termination

            product *= (count / N)
        else:
            // Wildcard: Contributes factor of 1.0 (no constraint)
            continue

    // Estimated aggregate frequency
    return N * product
```

#### Method 2: Correlation-Based (Beta Adjustment)

```
function queryPartialKey(partial_key, sketch, huffman_trees, frequent_tables, N,
                         beta):
    fields = [partial_key.srcIP, partial_key.dstIP,
              partial_key.srcPort, partial_key.dstPort, partial_key.proto]

    product = 1.0
    for i in 0 to 4:
        if (partial_key.mask & (1 << i)) == 0:
            count = queryField(i, fields[i], sketch.rows[i],
                               huffman_trees[i], frequent_tables[i])

            if count == 0:
                return 0

            // Apply beta exponent for correlation adjustment
            product *= pow(count / N, beta)

    return N * product
```

**Beta Parameter:**
- `beta = 1.0`: Independence assumption (same as Naive Bayes)
- `beta < 1.0`: Fields are correlated, reduces over-estimation
- `beta = N_joint / (N1 * N2)`: Optimal value based on field correlations

**Example usage:**
```cpp
// Query all flows with srcIP=192.168.1.1 (other fields wildcard)
PartialKey partial_key;
partial_key.srcIP = 0xC0A80101;  // 192.168.1.1
partial_key.mask = 0x1E;  // 11110: only srcIP is exact

// Naive Bayes query
double est1 = sketch.queryPartialKey(partial_key, learner, totalPackets);

// Correlation-based query with beta
double beta = 0.75;  // From beta grid search
double est2 = sketch.queryPartialKey(partial_key, learner, totalPackets, beta);
```

### Top-K Mice Flow Selection

For pattern-based analysis, we identify the top-K partial keys that aggregate the most mice flows:

**Algorithm:**
1. **Classify full flows** as elephants (freq ≥ threshold) or mice
2. **Build forbidden zone**: Partial keys matching any elephant flow
3. **Group mice flows** by partial key (excluding forbidden zone)
4. **Sort by mice count first**, then total packets as tiebreaker
5. Take top-K

```cpp
struct MiceCandidate {
    PartialKey key;
    int miceCount;        // Number of unique mice flows matching this key
    int totalPackets;     // Total packets from those mice flows
};

// Sort by mice count (primary), then total packets (secondary)
std::sort(allCandidates.begin(), allCandidates.end(),
         [](const MiceCandidate& a, const MiceCandidate& b) {
             if (a.miceCount != b.miceCount) {
                 return a.miceCount > b.miceCount;
             }
             return a.totalPackets > b.totalPackets;
         });
```

This approach identifies partial keys that best aggregate mice flows, which is ideal for analyzing traffic patterns and finding optimal beta values.

### Accuracy Evaluation

To evaluate partial key query accuracy:

```
function evaluatePartialKeyAccuracy(partial_key, sketch, learner,
                                     ground_truth, total_packets):
    // 1. Find all flows matching the partial key pattern
    matching_flows = []
    ground_truth_total = 0
    for (flow, freq) in ground_truth:
        if matchesPartialKey(flow, partial_key):
            matching_flows.append(flow)
            ground_truth_total += freq

    // 2. Query sketch for aggregate estimate
    estimated_total = queryPartialKey(partial_key, sketch,
                                      learner.getTrees(),
                                      learner.getFrequentTables(),
                                      total_packets)

    // 3. Compute error metrics
    absolute_error = abs(estimated_total - ground_truth_total)
    relative_error = absolute_error / ground_truth_total

    return {
        "matching_flows": len(matching_flows),
        "ground_truth_total": ground_truth_total,
        "estimated_total": estimated_total,
        "AAE": absolute_error,
        "ARE": relative_error
    }
```

---

# Part 3: Metrics

## 3.1 Flow Sets Definitions

- $\Omega_0$: All unique flows in current window (Ground Truth)
- $\Omega_1$: Flows recovered from `StoredCompressedIDs` FIFO
- $\Omega_{elephant}$: Subset of $\Omega_1$ where true frequency $n_f \ge \theta$
- $\Omega_{mouse}$: Subset of $\Omega_1$ where true frequency $n_f < \theta$

## 3.2 Accuracy Metrics

For any flow set $S \in \{\Omega_1, \Omega_{elephant}, \Omega_{mouse}\}$:

$$AAE(S) = \frac{1}{|S|} \sum_{f \in S} | \hat{n}_f - n_f |$$

$$ARE(S) = \frac{1}{|S|} \sum_{f \in S} \frac{| \hat{n}_f - n_f |}{n_f}$$

Where:
- $n_f$: True frequency (from ground truth)
- $\hat{n}_f$: Estimated frequency (from sketch query)

## 3.3 Throughput

$$Throughput = \frac{N_{window}}{T_{core}}$$

Where:
- $N_{window}$: Packets processed in window
- $T_{core}$: Time spent on insertion logic only (excluding I/O)

## 3.4 Calculation Algorithm

```
function calculateMetrics(recovered_ids, ground_truth, sketch,
                          huffman_trees, frequent_tables, N, theta):

    metrics = {
        "all":      {"aae_sum": 0, "are_sum": 0, "count": 0},
        "elephant": {"aae_sum": 0, "are_sum": 0, "count": 0},
        "mouse":    {"aae_sum": 0, "are_sum": 0, "count": 0}
    }

    for flow_id in recovered_ids:
        true_freq = ground_truth.getFrequency(flow_id)
        est_freq = queryFlowFrequency(flow_id, sketch, huffman_trees,
                                      frequent_tables, N)

        abs_error = abs(est_freq - true_freq)
        rel_error = abs_error / true_freq

        // Update all
        metrics["all"]["aae_sum"] += abs_error
        metrics["all"]["are_sum"] += rel_error
        metrics["all"]["count"] += 1

        // Update elephant/mouse
        category = "elephant" if true_freq >= theta else "mouse"
        metrics[category]["aae_sum"] += abs_error
        metrics[category]["are_sum"] += rel_error
        metrics[category]["count"] += 1

    // Compute averages
    results = {}
    for cat in ["all", "elephant", "mouse"]:
        count = metrics[cat]["count"]
        if count > 0:
            results[cat + "_AAE"] = metrics[cat]["aae_sum"] / count
            results[cat + "_ARE"] = metrics[cat]["are_sum"] / count
        else:
            results[cat + "_AAE"] = 0
            results[cat + "_ARE"] = 0

    return results
```

---

# Part 4: Integrated Window Processing

## 4.1 Output Data Structure

```
struct WindowMetrics {
    // Basic Info
    int window_id;
    uint32_t total_packets;

    // Performance
    double throughput_pps;        // Packets per second
    double compression_ratio;     // Raw Bits / Compressed Bits

    // Recovery (ID Management)
    double recovery_precision;    // |Ω₁ ∩ Ω₀| / |Ω₁|
    double recovery_recall;       // |Ω₁ ∩ Ω₀| / |Ω₀|

    // Accuracy (Frequency Estimation)
    double aae_all, are_all;           // All recovered flows
    double aae_elephant, are_elephant; // Flows with freq ≥ θ
    double aae_mouse, are_mouse;       // Flows with freq < θ
};
```

## 4.2 Complete Processing Algorithm

```
function processWindow(pcap_reader, window_idx, sketch,
                       huffman_freqs, frequent_tables, config):

    # ════════════════════════════════════════════════════════════════
    # PHASE 1: Preparation
    # ════════════════════════════════════════════════════════════════
    huffman_trees[5]
    for i in 0..4:
        huffman_trees[i] = buildHuffmanTree(huffman_freqs[i])

    ground_truth.clear()
    bloom_filter.clear()
    total_insertion_ns = 0
    packet_count = 0
    bits_raw = 0
    bits_compressed = 0

    # ════════════════════════════════════════════════════════════════
    # PHASE 2: Packet Loop
    # ════════════════════════════════════════════════════════════════
    while packet_count < config.WINDOW_SIZE:
        packet = pcap_reader.next()
        if packet is null: break

        flow_id = extractFlowID(packet)
        ground_truth.add(flow_id)

        # Timed: Frequency sketch insertion
        t_start = getCurrentTimeNano()
        insertPacket(flow_id, sketch, huffman_trees, frequent_tables)
        t_end = getCurrentTimeNano()
        total_insertion_ns += (t_end - t_start)

        # Flow ID storage (for recovery evaluation)
        if not bloom_filter.contains(flow_id):
            bloom_filter.add(flow_id)
            bits_raw += 104

            comp_id = encodeFlowID(flow_id, huffman_trees, frequent_tables)
            StoredCompressedIDs.push(comp_id)
            bits_compressed += comp_id.length

        packet_count++

    # ════════════════════════════════════════════════════════════════
    # PHASE 3: Analysis & Metrics
    # ════════════════════════════════════════════════════════════════
    results = new WindowMetrics()
    results.window_id = window_idx
    results.total_packets = packet_count
    results.throughput_pps = packet_count / (total_insertion_ns / 1e9)
    results.compression_ratio = bits_raw / bits_compressed

    # Recover flow IDs (Omega_1)
    omega_1 = set()
    for cid in StoredCompressedIDs:
        fid = decodeFlowID(cid, huffman_trees, frequent_tables)
        omega_1.add(fid)

    # Recovery metrics
    intersection = intersect(omega_1, ground_truth)
    results.recovery_precision = len(intersection) / len(omega_1)
    results.recovery_recall = len(intersection) / len(ground_truth)

    # Frequency accuracy metrics
    freq_metrics = calculateMetrics(omega_1, ground_truth, sketch,
                                    huffman_trees, frequent_tables,
                                    packet_count, config.THETA)
    results.aae_all = freq_metrics["all_AAE"]
    results.are_all = freq_metrics["all_ARE"]
    results.aae_elephant = freq_metrics["elephant_AAE"]
    results.are_elephant = freq_metrics["elephant_ARE"]
    results.aae_mouse = freq_metrics["mouse_AAE"]
    results.are_mouse = freq_metrics["mouse_ARE"]

    # ════════════════════════════════════════════════════════════════
    # PHASE 4: Feedback Loop
    # ════════════════════════════════════════════════════════════════
    for i in 0..4:
        huffman_freqs[i].clear()
        huffman_freqs[i][NYT] = 0
        huffman_freqs[i][UNKNOWN] = 0

    for flow_id in omega_1:
        for i in 0..4:
            huffman_freqs[i][flow_id.field[i]]++

    return results
```

---

# Recent Enhancements

## Correlation-Based Partial Key Queries

We've implemented advanced correlation-based query methods that significantly improve accuracy for partial key queries:

### Key Improvements:

1. **Beta Parameter for Correlation Adjustment**
   - Adjusts for field dependencies in multi-field patterns
   - Formula: `beta = N_joint / (N1 × N2)`
   - Reduces over-estimation when fields are correlated

2. **Automated Beta Grid Search**
   - Tests multiple beta values (default: 20 points from 0.0 to 1.0)
   - Outputs comprehensive CSV files for analysis
   - Identifies optimal beta values per pattern

3. **Top-K Mice Flow Selection**
   - Matches comparison_main.cpp methodology
   - Sorts by unique mice count first (not just packet count)
   - Provides better pattern-based analysis

4. **Dual Sketch Comparison**
   - FrequencySketch (Huffman-based)
   - SandwichSketch (baseline)
   - Side-by-side accuracy and throughput comparison

## Output Organization

### Beta Grid Search Outputs

All outputs are grouped by partial key for easy comparison across beta values:

```csv
Window,PartialKey,Pattern,MiceFlows,TotalPackets,Beta,...
1,"SrcIP=192.168.1.1",SrcIP Only,428,428,0.0,...
1,"SrcIP=192.168.1.1",SrcIP Only,428,428,0.05,...
1,"SrcIP=192.168.1.1",SrcIP Only,428,428,0.10,...
1,"SrcIP=10.0.0.1",SrcIP Only,310,310,0.0,...
1,"SrcIP=10.0.0.1",SrcIP Only,310,310,0.05,...
```

This grouping makes it easy to:
- Compare how different beta values affect the same partial key
- Identify optimal beta per pattern
- Analyze correlation impact across traffic patterns

## Comprehensive Pattern Metrics

In addition to top-K mice flows and top elephant flows, the beta grid search computes **comprehensive metrics** by evaluating **ALL unique partial keys** for each pattern. This provides a complete picture of query accuracy across the entire partial key space.

### Mathematical Formulation

For a given pattern with mask $M$ (e.g., SrcIP Only with mask `0x1E`), let:
- $\mathcal{K}_M$ = Set of all unique partial keys observed in the window
- $f_{gt}(k)$ = Ground truth packet count for partial key $k$
- $\hat{f}(k, \beta)$ = Estimated packet count using beta value $\beta$

**Average Absolute Error (AAE):**
$$AAE(\beta) = \frac{1}{|\mathcal{K}_M|} \sum_{k \in \mathcal{K}_M} |\hat{f}(k, \beta) - f_{gt}(k)|$$

**Average Relative Error (ARE):**
$$ARE(\beta) = \frac{1}{|\mathcal{K}_M|} \sum_{k \in \mathcal{K}_M} \frac{|\hat{f}(k, \beta) - f_{gt}(k)|}{f_{gt}(k)}$$

**Query Throughput (Mpps):**
$$Throughput = \frac{N_{total}}{T_{query}} \times 10^{-6}$$

Where:
- $N_{total}$ = Total packets in window
- $T_{query}$ = Total time to query all partial keys (milliseconds)

### Algorithmic Implementation

```
Algorithm ComputeComprehensiveMetrics(pattern, betasToTest, windowPackets,
                                      freqSketch, swSketch, learner, totalPackets):

    // ═════════════════════════════════════════════════════════════════════
    // STEP 1: Build Partial Key Ground Truth
    // ═════════════════════════════════════════════════════════════════════
    partialKeyGroundTruth = {}  // Map: PartialKey -> PacketCount

    For each packet in windowPackets:
        pk = extractPartialKey(packet, pattern.mask)
        partialKeyGroundTruth[pk]++
    EndFor

    // ═════════════════════════════════════════════════════════════════════
    // STEP 2: Test Each Beta Value
    // ═════════════════════════════════════════════════════════════════════
    For each beta in betasToTest:

        // Initialize accumulators
        fs_totalAAE = 0.0
        fs_totalARE = 0.0
        sw_totalAAE = 0.0
        sw_totalARE = 0.0
        validCount = 0

        // ─────────────────────────────────────────────────────────────────
        // FrequencySketch Queries (Timed)
        // ─────────────────────────────────────────────────────────────────
        fsQueryStart = getCurrentTime()

        For each (pk, gtFreq) in partialKeyGroundTruth:
            If gtFreq == 0: continue  // Skip zero-frequency keys

            // Query FrequencySketch with beta adjustment
            fsEstimated = freqSketch.queryPartialKey(pk, learner, totalPackets, beta)

            // Compute errors
            fsAAE = |fsEstimated - gtFreq|
            fsARE = fsAAE / gtFreq

            // Accumulate
            fs_totalAAE += fsAAE
            fs_totalARE += fsARE
            validCount++
        EndFor

        fsQueryEnd = getCurrentTime()
        fsQueryTimeMs = fsQueryEnd - fsQueryStart
        fsQueryThroughputMpps = (totalPackets / fsQueryTimeMs) / 1000.0

        // ─────────────────────────────────────────────────────────────────
        // SandwichSketch Queries (Timed)
        // ─────────────────────────────────────────────────────────────────
        swQueryStart = getCurrentTime()

        For each (pk, gtFreq) in partialKeyGroundTruth:
            If gtFreq == 0: continue

            // Query SandwichSketch (exact match)
            matchingFlows = swSketch.queryPartialKey(pk)
            swEstimated = Sum(flow.count for flow in matchingFlows)

            // Compute errors
            swAAE = |swEstimated - gtFreq|
            swARE = swAAE / gtFreq

            // Accumulate
            sw_totalAAE += swAAE
            sw_totalARE += swARE
        EndFor

        swQueryEnd = getCurrentTime()
        swQueryTimeMs = swQueryEnd - swQueryStart
        swQueryThroughputMpps = (totalPackets / swQueryTimeMs) / 1000.0

        // ─────────────────────────────────────────────────────────────────
        // Compute Averages
        // ─────────────────────────────────────────────────────────────────
        result = {
            timeWindow: windowNumber,
            pattern: pattern.name,
            beta: beta,
            uniqueKeys: partialKeyGroundTruth.size(),
            fs_aae: (validCount > 0) ? (fs_totalAAE / validCount) : 0.0,
            fs_are: (validCount > 0) ? (fs_totalARE / validCount) : 0.0,
            fs_queryThroughputMpps: fsQueryThroughputMpps,
            sw_aae: (validCount > 0) ? (sw_totalAAE / validCount) : 0.0,
            sw_are: (validCount > 0) ? (sw_totalARE / validCount) : 0.0,
            sw_queryThroughputMpps: swQueryThroughputMpps
        }

        WriteToCSV(result)
    EndFor
```

### Key Characteristics

1. **Complete Coverage**: Tests every unique partial key observed in the window, not just top-K
2. **Unbiased Metrics**: Includes both frequent and infrequent partial keys
3. **Dual Sketch Comparison**: Evaluates both FrequencySketch and SandwichSketch
4. **Beta Sensitivity Analysis**: Shows how beta affects accuracy across entire key space
5. **Throughput Measurement**: Reports query performance in millions of packets per second

### Example Output

```csv
Timewindow,Pattern,Beta,UniqueKeys,FS_AAE,FS_ARE,FS_QueryThroughput,SW_AAE,SW_ARE,SW_QueryThroughput
1,SrcIP Only,0.0000,1247,45.23,0.123400,234.56,123.45,0.567800,12.34
1,SrcIP Only,0.0526,1247,43.12,0.118200,235.67,123.45,0.567800,12.34
1,SrcIP Only,0.1053,1247,41.56,0.114500,236.78,123.45,0.567800,12.34
...
1,Src Pair,0.0000,3456,67.89,0.234500,189.23,234.56,0.678900,8.76
1,Src Pair,0.0526,3456,58.34,0.201200,190.45,234.56,0.678900,8.76
1,Src Pair,0.1053,3456,52.67,0.189300,191.67,234.56,0.678900,8.76
```

### Use Cases

1. **Pattern-Level Optimization**: Find optimal beta for each pattern across all keys
2. **Robustness Testing**: Verify accuracy holds for rare/infrequent partial keys
3. **Sketch Comparison**: Compare FrequencySketch vs SandwichSketch at scale
4. **Correlation Analysis**: Understand how correlation affects overall accuracy
5. **Performance Benchmarking**: Measure query throughput across different patterns

### Interpretation

- **Low ARE with beta ≈ 1.0**: Fields are approximately independent
- **ARE decreases as beta decreases**: Fields are positively correlated
- **UniqueKeys**: Number of distinct partial key patterns observed
- **Throughput**: Higher is better; FrequencySketch typically faster than SandwichSketch

## Performance Optimizations

1. **Two-Pass Processing**
   - Pass 1: Build global frequent tables from entire PCAP
   - Pass 2: Process windows with adaptive Huffman trees

2. **Realistic Adaptation**
   - Window 1: Uses own ground truth for initial Huffman trees
   - Window 2+: Uses previous window's recovered flows
   - Simulates real-world adaptive learning

3. **Efficient Memory Layout**
   - Flat memory architecture for sketches
   - Optimized allocation based on field entropy
   - Proto field gets minimal allocation (low entropy)

## Documentation

- [BETA_GRID_SEARCH.md](BETA_GRID_SEARCH.md) - Complete beta grid search guide
- [CORRELATION_BASED_QUERY.md](CORRELATION_BASED_QUERY.md) - Mathematical formulation and implementation details

---

## License

MIT License

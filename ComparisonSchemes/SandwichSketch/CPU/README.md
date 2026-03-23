# CPU implementation
## Repository structure

- `Common/`: the hash and mmap functions
- `Struct/`: the data structures, such as heap, sketch and hash table
- `Algos/`: our and other baseline algorithms
- `Bench/`: the benchmarks about Item frequent item estimation and Set frequent item estimation
- `results/`: the files stored intermediate results
- `datasets/`: the datasets we used, CAIDA & MAWI & WEBPAGE

## Requirements

- cmake
- g++
- python3
    - pandas

## Usage

* First you need to build our code.

```sh
mkdir build results datasets
cd bulid
cmake ..
make
```
* run `./CPU [Experimental Type] [Dataset Type] [Algortihm]` to measure the algorithm's performance.

There is a table about the parameters you can choose.

| Options | Parameter |
| ---    | --- |
| Experimental Type | `SetHH`, `SetHC`, `SetHHH`, `SetHHH2`, `ItemHH`, `ItemHC`, `SetDHH`
| Dataset Type | `CAIDA`, `MAWI`, `WEBPAGE`, `NET`
| Algorithm | `CocoSketch`, `Ours`, `USSHeap`, `USS` for Set frequent item estimation, `CocoSketch`, `Ours`, `OursFull`, `USSHeap`, `USS`, `CMHash`, `CountHash`, `ASketch`, `HeavyGuardian`,`Salsa`,`SpaceSaving`,`LogLogFilter` for full set frequent item estimation

* For example, `./CPU ItemHH CAIDA Ours` will display the full set heavy hitter detection result about Our algorithm using CAIDA dataset.

* Note that `SetHH`, `SetHC`, `SetDHH` are special, running the `./CPU` command would not display the result, you need to run the corresponding parser after running the `./CPU` command

    * run `python3 HHResult.py [Memory Size(KB)]` to get a summary of set heavy hitter detection result.
    * run `python3 HCResult.py [Memory Size(KB)]` to get a summary of set heavy change detection result.
    * run `python3 DHHResult.py [Memory Size(KB)] [Node Num] [Large Node Param] [Rate] [Is disjoint]` to get a summary of distributed set heavy hitter detection result.
    * You can change `MultiAlgs` & `AllAlgs` in this parsers to change the algorithms you want. 

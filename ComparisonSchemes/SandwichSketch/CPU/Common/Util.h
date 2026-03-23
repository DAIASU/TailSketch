#ifndef UTIL_H
#define UTIL_H

#include <x86intrin.h>

// #include <sys/io.h>
#include <vector>
#include <string>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <unordered_set>
#include <unordered_map>

#include "hash.h"

#pragma pack(1)

#define MAX_TRAFFIC 6

enum HHKeyType{
    five_tuples = 1,
    srcIP_dstIP = 2,
    srcIP_srcPort = 3,
    dstIP_dstPort = 4,
    srcIP = 5,
    dstIP = 6,
};

enum HHHKeyType{
    oneD = 1,
    twoD = 2,
};

struct TIMESTAMP{
    uint8_t array[8];
};

#define TUPLES_LEN 13

struct TUPLES{
    uint8_t data[TUPLES_LEN];

    inline uint32_t srcIP() const{
        return *((uint32_t*)(data));
    }

    inline uint32_t dstIP() const{
        return *((uint32_t*)(&data[4]));
    }

    inline uint16_t srcPort() const{
        return *((uint16_t*)(&data[8]));
    }

    inline uint16_t dstPort() const{
        return *((uint16_t*)(&data[10]));
    }

    inline uint8_t proto() const{
        return *((uint8_t*)(&data[12]));
    }

    inline uint64_t srcIP_dstIP() const{
        return *((uint64_t*)(data));
    }

    inline uint64_t srcIP_srcPort() const{
        uint64_t ip = srcIP();
        uint64_t port = srcPort();
        return ((ip << 32) | port);
    }

    inline uint64_t dstIP_dstPort() const{
        uint64_t ip = dstIP();
        uint64_t port = dstPort();
        return ((ip << 32) | port);
    }
};

bool operator == (const TUPLES& a, const TUPLES& b){
    return memcmp(a.data, b.data, sizeof(TUPLES)) == 0;
}

namespace std{
    template<>
    struct hash<TUPLES>{
        size_t operator()(const TUPLES& item) const noexcept
        {
            return Hash::BOBHash32((uint8_t*)&item, sizeof(TUPLES), 0);
        }
    };
}

typedef int32_t COUNT_TYPE;

typedef std::chrono::high_resolution_clock::time_point TP;

inline TP now(){
    return std::chrono::high_resolution_clock::now();
}

inline double durationms(TP finish, TP start){
    return std::chrono::duration_cast<std::chrono::duration<double,std::ratio<1,1000000>>>(finish - start).count();
}

template<typename T>
T Median(std::vector<T> vec, uint32_t len){
    std::sort(vec.begin(), vec.end());
    return (len & 1) ? vec[len >> 1] : (vec[len >> 1] + vec[(len >> 1) - 1]) / 2.0;
}

size_t tupleLen = 13;
bool readTimeStamp = false;

TUPLES *read_data(const char *PATH, const  uint64_t length,
                     uint64_t *cnt) {
    TUPLES *items = new TUPLES[length];
    memset(items, 0, sizeof(TUPLES) * length);
    TUPLES *it = items;

    TIMESTAMP *timestamps = new TIMESTAMP[length];
    TIMESTAMP *timestamp = timestamps;

    FILE *data = fopen(PATH, "rb");
    *cnt = 0;
    while (fread(it, tupleLen, 1, data) > 0) {
        if (readTimeStamp)
            assert(fread(timestamp++, sizeof(TIMESTAMP), 1, data) > 0);
        it++;
        (*cnt)++;
        if ((*cnt) == length)
            break;
    }

    fclose(data);

    return items;
}

std::string double2string(double val, int precision) {
    std::stringstream ss;
    std::string str;
    ss << std::setprecision(precision) << val;
    ss >> str;
    return str;
}

std::vector<std::vector<TUPLES>> datasets_division(std::string PATH, uint32_t node_num, uint32_t large_node_param, bool is_disjoint, double HH_threshold, std::vector<uint32_t> &SpecialSrcIPs){
    uint64_t length;
    TUPLES* dataset = read_data(PATH.c_str(), 100000000, &length);
    std::vector<std::vector<TUPLES>> dist_datasets;
    dist_datasets.resize(node_num);
    std::vector<std::unordered_map<TUPLES, uint32_t>> realLocalTupleMap; 
    realLocalTupleMap.resize(node_num);
    std::unordered_map<TUPLES, uint32_t>  realGlobalTupleMap;
    std::unordered_map<uint32_t, uint32_t>  realGlobalSrcIPMap;
    std::unordered_map<uint32_t, std::unordered_set<TUPLES>>  SrcIPtoTuples;

    for(uint32_t i = 0; i < length; i++){
        uint32_t index;
        if(is_disjoint){
            index = hash(dataset[i]) % (node_num - 1 + large_node_param);
        }else{
            index = (hash(dataset[i]) + randomGenerator()) % (node_num - 1 + large_node_param);
        }

        if (index >= node_num - 1){
            index = node_num - 1;
        }

        dist_datasets[index].push_back(dataset[i]);
        realLocalTupleMap[index][dataset[i]]++;
        realGlobalTupleMap[dataset[i]]++;
        realGlobalSrcIPMap[dataset[i].srcIP()]++;
        if(!SrcIPtoTuples[dataset[i].srcIP()].count(dataset[i])){
            SrcIPtoTuples[dataset[i].srcIP()].insert(dataset[i]);
        }
    }

    std::unordered_map<TUPLES, bool> is_Local_HH;

    for(uint32_t i = 0; i < node_num; i++){
        uint32_t local_threshold = dist_datasets[i].size() * HH_threshold;
        for(auto iter : realLocalTupleMap[i]){
            if(iter.second > local_threshold){
                is_Local_HH[iter.first] = true;
            }
        }
    }

    uint32_t global_SrcIP_HH = 0;
    uint32_t special_SrcIP_HH = 0;
    uint32_t global_threshold = length * HH_threshold;

    for(auto iter : realGlobalSrcIPMap){
        if(iter.second > global_threshold){
            global_SrcIP_HH++;
            bool flag = false;
            for(auto tuple : SrcIPtoTuples[iter.first]){
                if(is_Local_HH[tuple]){
                    flag = true;
                    break;
                }
            }

            if(!flag){
                special_SrcIP_HH++;
                SpecialSrcIPs.push_back(iter.first);
            }
        }
    }

    std::cout << special_SrcIP_HH << "/" << global_SrcIP_HH << std::endl;

    delete dataset;

    return dist_datasets;
}


#endif

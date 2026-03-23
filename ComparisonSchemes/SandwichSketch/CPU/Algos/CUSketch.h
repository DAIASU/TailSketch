#pragma once

#include <iostream>
#include "hash.h"
#include "Abstract.h"

#define HASH_NUM 3

template<typename DATA_TYPE>
class CUSketch: public Abstract<DATA_TYPE>{
public:

    typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;

    CUSketch(uint32_t _MEMORY, std::string _name = "CUSketch") {
        this->name = _name;

        LENGTH = _MEMORY / HASH_NUM / sizeof(COUNT_TYPE);
        counters = new COUNT_TYPE*[HASH_NUM];
        for (uint32_t i = 0; i < HASH_NUM; i++)
        {
            counters[i] = new COUNT_TYPE[LENGTH];
            memset(counters[i], 0, sizeof(COUNT_TYPE) * LENGTH);
        }
    }

    ~CUSketch(){
        for (uint32_t i = 0; i < HASH_NUM; i++)
        {
            delete [] counters[i];
        }
        delete [] counters;
    }

    void Insert(const DATA_TYPE& key){
        COUNT_TYPE minValue = INT_MAX;
        for (uint32_t i = 0; i < HASH_NUM; i++)
        {
            uint32_t pos = hash(key, i) % LENGTH;
            minValue = std::min(minValue, counters[i][pos]);
        }

        COUNT_TYPE tmp = minValue + 1;
        for (uint32_t i = 0; i < HASH_NUM; i++)
        {
            uint32_t pos = hash(key, i) % LENGTH;
            counters[i][pos] = std::max(counters[i][pos], tmp);
        }
    }

    COUNT_TYPE Query(const DATA_TYPE& key){
        COUNT_TYPE res = INT_MAX;
        for (uint32_t i = 0; i < HASH_NUM; i++)
        {
            uint32_t pos = hash(key, i) % LENGTH;
            res = std::min(res, counters[i][pos]);
        }

        return res;
        
    }

    HashMap AllQuery(DATA_TYPE *dataset = NULL, int length = 0){
        HashMap ret;

        for (int i = 0; i < length; i++)
            if (ret.count(dataset[i]) == 0)
                ret[dataset[i]] = Query(dataset[i]);
        
        return ret;
    }
    
private:
    COUNT_TYPE **counters;
    uint32_t LENGTH;
};
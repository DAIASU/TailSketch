#pragma once

#include <iostream>
#include "hash.h"
#include "Abstract.h"

#define HEAVY_CELL_PER_BUCKET 8
#define LIGHT_CELL_PER_BUCKET 32
#define decay 1.08

template<typename DATA_TYPE>
class HeavyGuardian: public Abstract<DATA_TYPE>{
public:

    typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;

    HeavyGuardian(uint32_t _MEMORY, std::string _name = "HeavyGuardian") {
        this->name = _name;

        LENGTH = _MEMORY / sizeof(Bucket);
        buckets = new Bucket[LENGTH];
        memset(buckets, 0, sizeof(Bucket) * LENGTH);
    }

    ~HeavyGuardian(){
        delete [] buckets;
    }

    void Insert(const DATA_TYPE& key){
        uint32_t pos = hash(key) % LENGTH, minPos = 0;
        COUNT_TYPE minCount = INT_MAX;

        for (uint32_t i = 0; i < HEAVY_CELL_PER_BUCKET; i++)
        {
            if (buckets[pos].heavy_part[i].ID == key)
            {
                buckets[pos].heavy_part[i].count++;
                return;
            }
            if (buckets[pos].heavy_part[i].count == 0)
            {
                buckets[pos].heavy_part[i].ID = key;
                buckets[pos].heavy_part[i].count = 1;
                return;
            }
            if (buckets[pos].heavy_part[i].count < minCount)
            {
                minPos = i;
                minCount = buckets[pos].heavy_part[i].count;
            }
        }

        if(!(rand()%int(pow(decay,minCount))))
        {
            buckets[pos].heavy_part[minPos].count--;
            if (buckets[pos].heavy_part[minPos].count == 0)
            {
                buckets[pos].heavy_part[minPos].ID = key;
                buckets[pos].heavy_part[minPos].count = 1;
            }else{
                uint8_t value = std::min(buckets[pos].light_part[hash(key) % LIGHT_CELL_PER_BUCKET] + 1, 255);
                buckets[pos].light_part[hash(key) % LIGHT_CELL_PER_BUCKET] = value;
            }
            
        }
        
    }

    COUNT_TYPE Query(const DATA_TYPE& key){
        uint32_t pos = hash(key) % LENGTH;
        for (uint32_t i = 0; i < HEAVY_CELL_PER_BUCKET; i++){
            if (buckets[pos].heavy_part[i].ID == key)
            {
                return buckets[pos].heavy_part[i].count;
            }
        }

        return buckets[pos].light_part[hash(key) % LIGHT_CELL_PER_BUCKET];
    }

    HashMap AllQuery(DATA_TYPE *dataset = NULL, int length = 0){
        HashMap ret;

        for (int i = 0; i < length; i++)
            if (ret.count(dataset[i]) == 0)
                ret[dataset[i]] = Query(dataset[i]);
        
        return ret;
    }

private:
    struct HeavyCell
    {
        DATA_TYPE ID;
        COUNT_TYPE count;
    };
    
    struct Bucket
    {
        HeavyCell heavy_part[HEAVY_CELL_PER_BUCKET];
        uint8_t light_part[LIGHT_CELL_PER_BUCKET];    
    };

    Bucket *buckets;

    uint32_t LENGTH;
    
};
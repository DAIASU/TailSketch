#pragma once

#include <iostream>
#include "hash.h"
#include "Abstract.h"
#include "CMSketch.h"

#define FILTER_SIZE 32

template<typename DATA_TYPE>
class ASketch : public Abstract<DATA_TYPE>{
public:

    typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;

    ASketch(uint32_t _MEMORY, std::string _name = "ASketch") {
        this->name = _name;

        buckets = new Bucket[FILTER_SIZE];
        memset(buckets, 0, sizeof(Bucket) * FILTER_SIZE);
        sketch = new CMSketch<DATA_TYPE, COUNT_TYPE>(_MEMORY - sizeof(Bucket) * FILTER_SIZE);
    }

    ~ASketch(){
        delete [] buckets;
        delete sketch;
    }

    void Insert(const DATA_TYPE& key) {
        for (uint32_t i = 0; i < FILTER_SIZE; i++)
        {
            if(buckets[i].ID == key){
                buckets[i].new_count++;
                return;
            }
            if(buckets[i].new_count == 0){
                buckets[i].ID = key;
                buckets[i].new_count = 1;
                buckets[i].old_count = 0;
                return;
            }
        }

        sketch->Insert(key);
        COUNT_TYPE estimated_value = sketch->Query(key);
        COUNT_TYPE min_value = INT_MAX, min_index;
        for (uint32_t i = 0; i < FILTER_SIZE; i++)
        {
            if(buckets[i].new_count < min_value){
                min_index = i;
                min_value = buckets[i].new_count;
            }
        }

        if(estimated_value > min_value){
            COUNT_TYPE tmp = buckets[min_index].new_count - buckets[min_index].old_count;
            if(tmp > 0){
                sketch->Insert_with_f(buckets[min_index].ID, tmp);
            }
            buckets[min_index].ID = key;
            buckets[min_index].new_count = estimated_value;
            buckets[min_index].old_count = estimated_value;
        }

    }

    COUNT_TYPE Query(const DATA_TYPE& key){
        for (uint32_t i = 0; i < FILTER_SIZE; i++)
        {
            if(buckets[i].ID == key){
                return buckets[i].new_count;
            }
        }

        return sketch->Query(key);
    }

    HashMap AllQuery(DATA_TYPE *dataset = NULL, int length = 0){
        HashMap ret;

        for (int i = 0; i < length; i++)
            if (ret.count(dataset[i]) == 0)
                ret[dataset[i]] = Query(dataset[i]);
        
        return ret;
    }

private:
    struct Bucket
    {
        DATA_TYPE ID;
        COUNT_TYPE new_count;
        COUNT_TYPE old_count;
    };

    Bucket *buckets;
    CMSketch<DATA_TYPE, COUNT_TYPE> *sketch;
    
};
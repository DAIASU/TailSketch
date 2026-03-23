#pragma once

#include "CMSketch.h"
#include "DLeftHashingTable.h"

template<typename DATA_TYPE>
class CMHash : public Abstract<DATA_TYPE>{
public:
    typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;

    CMHash(uint32_t _MEMORY, uint32_t _threshold, std::string _name = "CMHash"){
        // std::cerr << "CMHash threshold: " << _threshold << '\n';
        
        this->name = _name;

        uint32_t LIGHT_MEMORY = _MEMORY * LIGHT_RATIO;
        uint32_t HEAVY_MEMORY = _MEMORY * HEAVY_RATIO;

        threshold = _threshold;
        sketch = new CMSketch<DATA_TYPE, COUNT_TYPE>(LIGHT_MEMORY);
        table = new DLeftHashingTable<DATA_TYPE, COUNT_TYPE>(table->Memory2Size(HEAVY_MEMORY));
    }

    ~CMHash(){
        delete sketch;
        delete table;
    }

    void Insert(const DATA_TYPE& item) {
        sketch->Insert(item);
        COUNT_TYPE est = sketch->Query(item);
        if (est > threshold)
            table->Insert(item, est);
    }

    HashMap AllQuery(DATA_TYPE *dataset = NULL, int length = 0){
        return table->AllQuery();
    }

private:
    uint32_t threshold;

    const double HEAVY_RATIO = 0.2;
    const double LIGHT_RATIO = 0.8;

    CMSketch<DATA_TYPE, COUNT_TYPE>* sketch;
    DLeftHashingTable<DATA_TYPE, COUNT_TYPE>* table;
};

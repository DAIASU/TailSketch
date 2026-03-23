#ifndef HHHBENCH_H
#define HHHBENCH_H

#include <vector>
#include <fstream>

#include "Algos.h"

#define LAYER1 33

class MultiHHHBench{
public:

    MultiHHHBench(std::string PATH, std::string name){
        dataset = read_data(PATH.c_str(), 100000000, &length);

        for(uint64_t i = 0;i < length;++i)
            mp[0][dataset[i].srcIP()] += 1;

        for(auto it = mp[0].begin(); it != mp[0].end();++it)
            for(uint32_t i = 1;i < LAYER1;++i)
                mp[i][it->first & MASK[i]] += it->second;
    }

    ~MultiHHHBench(){
        delete dataset;
    }

    void HHHMultiBench(uint32_t MEMORY, double alpha, std::string algo){
       
        Abstract<uint32_t>* sketch = newPartialSketch<uint32_t>(MEMORY, algo);

        for(uint32_t i = 0;i < length;++i){
            sketch->Insert(dataset[i].srcIP());
        }

        std::unordered_map<uint32_t, COUNT_TYPE> estMp[LAYER1];

        estMp[0] = sketch->AllQuery();

        for(auto it = estMp[0].begin(); it != estMp[0].end();++it)
            for(uint32_t i = 1;i < LAYER1;++i)
                estMp[i][it->first & MASK[i]] += it->second;

        COUNT_TYPE threshold = alpha * length;

        std::cout << "algorithm," << sketch->name << std::endl;
        CompareHHH(estMp, threshold);

        delete sketch;
    }

private:

    TUPLES* dataset;
    uint64_t length;

    std::unordered_map<uint32_t, COUNT_TYPE> mp[LAYER1];
    const uint32_t MASK[LAYER1] = {0xffffffff,0x80000000,0xc0000000,0xe0000000,0xf0000000,0xf8000000,0xfc000000,
                                   0xfe000000,0xff000000,0xff800000,0xffc00000,0xffe00000,0xfff00000,0xfff80000,
                                   0xfffc0000,0xfffe0000,0xffff0000,0xffff8000,0xffffc000,0xffffe000,0xfffff000,
                                   0xfffff800,0xfffffc00,0xfffffe00,0xffffff00,0xffffff80,0xffffffc0,0xffffffe0,
                                   0xfffffff0,0xfffffff8,0xfffffffc,0xfffffffe,0x0};

    void CompareHHH(std::unordered_map<uint32_t, COUNT_TYPE> estMp[LAYER1], COUNT_TYPE threshold){
        double realHH = 0, estHH = 0, bothHH = 0, aae = 0, are = 0;

        for(uint32_t i = 0;i < LAYER1;++i){
            for(auto it = mp[i].begin();it != mp[i].end();++it){
                bool real, est;
                double realF = it->second, estF = estMp[i][it->first];

                real = (realF > threshold);
                est = (estF > threshold);

                realHH += real;
                estHH += est;

                if(real && est){
                    bothHH += 1;
                    aae += abs(realF - estF);
                    are += abs(realF - estF) / realF;
                }
            }
        }

        std::cout << "threshold," << threshold << std::endl;

        std::cout << "realHH," << realHH << std::endl;
        std::cout << "estHH," << estHH << std::endl;
        std::cout << "bothHH," << bothHH << std::endl;

        std::cout << "recall," << bothHH / realHH << std::endl;
        std::cout << "precision," << bothHH / estHH  << std::endl;
        std::cout << "aae," << aae / bothHH << std::endl;
        std::cout << "are," << are / bothHH << std::endl;
        std::cout << std::endl;
    }
};

#endif

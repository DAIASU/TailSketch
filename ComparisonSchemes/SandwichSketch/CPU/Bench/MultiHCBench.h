#ifndef HCBENCH_H
#define HCBENCH_H

#include <vector>
#include <fstream>

#include "Algos.h"

#include "MMap.h"

class MultiHCBench{
public:

    MultiHCBench(std::string PATH, std::string name){
        fileName = name;
        std::cout << PATH << ' ' << name << '\n';

        dataset = read_data(PATH.c_str(), 100000000, &length);

        for(uint64_t i = 0;i < (length >> 1);++i){
            tuplesMp[dataset[i]] += 1;

            mp[0][dataset[i].srcIP_dstIP()] += 1;
            mp[1][dataset[i].srcIP_srcPort()] += 1;
            mp[2][dataset[i].dstIP_dstPort()] += 1;
            mp[3][dataset[i].srcIP()] += 1;
            mp[4][dataset[i].dstIP()] += 1;
        }

        for(uint64_t i = (length >> 1);i < length;++i){
            tuplesMp[dataset[i]] -= 1;

            mp[0][dataset[i].srcIP_dstIP()] -= 1;
            mp[1][dataset[i].srcIP_srcPort()] -= 1;
            mp[2][dataset[i].dstIP_dstPort()] -= 1;
            mp[3][dataset[i].srcIP()] -= 1;
            mp[4][dataset[i].dstIP()] -= 1;
        }
    }

    ~MultiHCBench(){
        delete dataset;
    }

    void HCMultiBench(uint32_t MEMORY, double alpha, std::string algo){
        Abstract<TUPLES>* sketch[2];

        sketch[0] = newPartialSketch<TUPLES>(MEMORY, algo);
        sketch[1] = newPartialSketch<TUPLES>(MEMORY, algo);

        for(uint32_t i = 0;i < (length >> 1);++i){
            sketch[0]->Insert(dataset[i]);
        }
        for(uint32_t i = (length >> 1);i < length;++i){
            sketch[1]->Insert(dataset[i]);
        }

        std::unordered_map<TUPLES, COUNT_TYPE> estTuple = sketch[0]->AllQuery(),
                                                diff = sketch[1]->AllQuery();
        for(auto it = diff.begin();it != diff.end();++it){
            estTuple[it->first] -= it->second;
        }

        std::unordered_map<uint64_t, COUNT_TYPE> estMp[5];
        for(auto it = estTuple.begin();it != estTuple.end();++it){
            estMp[0][(it->first).srcIP_dstIP()] += it->second;
            estMp[1][(it->first).srcIP_srcPort()] += it->second;
            estMp[2][(it->first).dstIP_dstPort()] += it->second;
            estMp[3][(it->first).srcIP()] += it->second;
            estMp[4][(it->first).dstIP()] += it->second;
        }

        COUNT_TYPE threshold = alpha * length;

        std::string saveFile = "../results/HC-" + fileName + "-" + sketch[0]->name + "-" + std::to_string(MEMORY) +
                "-" + std::to_string(threshold) + ".csv";

        std::ofstream outfile(saveFile);

        CompareHC(estTuple, tuplesMp, threshold, 1, outfile);

        for(uint32_t i = 0;i < 5;++i){
            CompareHC(estMp[i], mp[i], threshold, i + 2, outfile);
        }

        outfile.close();

        delete sketch[0];
        delete sketch[1];
    }

private:
    std::string fileName;

    TUPLES* dataset;
    uint64_t length;

    std::unordered_map<TUPLES, COUNT_TYPE> tuplesMp;
    std::unordered_map<uint64_t, COUNT_TYPE> mp[5];

    template<class T>
    void CompareHC(T mp, T record, COUNT_TYPE threshold, uint32_t key_type, std::ofstream& outfile){
        double realHH = 0, estHH = 0, bothHH = 0, aae = 0, are = 0;

        for(auto it = record.begin();it != record.end();++it){
            bool real, est;
            double realF = abs(it->second), estF = abs(mp[it->first]);

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

        // std::cout << "key-type," << key_type << std::endl;
        // std::cout << "threshold," << threshold << std::endl;

        // std::cout << "Recall," << bothHH / realHH << std::endl;
        // std::cout << "Precision," << bothHH / estHH << std::endl;

        // std::cout << "aae," << aae / bothHH << std::endl;
        // std::cout << "are," << are / bothHH << std::endl;
        // std::cout << std::endl;

        outfile << "key-type," << key_type << std::endl;
        outfile << "threshold," << threshold << std::endl;

        outfile << "realHH," << realHH << std::endl;
        outfile << "estHH," << estHH << std::endl;
        outfile << "bothHH," << bothHH << std::endl;

        outfile << "aae," << aae << std::endl;
        outfile << "are," << are << std::endl;
        outfile << std::endl;
    }

    template<typename DATA_TYPE>
    std::unordered_map<DATA_TYPE, COUNT_TYPE> DiffHC(
            Abstract<DATA_TYPE>* a,
            Abstract<DATA_TYPE>* b){
        std::unordered_map<DATA_TYPE, COUNT_TYPE> ret, aMp = a->AllQuery(), bMp = b->AllQuery();

        for(auto it = aMp.begin();it != aMp.end();++it){
            ret[it->first] = it->second - b->Query(it->first);
        }

        for(auto it = bMp.begin();it != bMp.end();++it){
            if(ret.find(it->first) == ret.end()){
                ret[it->first] = a->Query(it->first) - it->second;
            }
        }

        return ret;
    }
};

#endif

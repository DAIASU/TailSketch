#ifndef HHBENCH_H
#define HHBENCH_H

#include <vector>
#include <fstream>

#include "Algos.h"

#include "MMap.h"

// #define HHMultiSketch Coco_Hard_Opt5
#define HHMultiSketch CocoSketch

class MultiHHBench{
public:

    MultiHHBench(std::string PATH, std::string name){

        fileName = name;

	    dataset = read_data(PATH.c_str(), 100000000, &length);
        cycles.resize(length);

        for(uint64_t i = 0;i < length;++i){
            tuplesMp[dataset[i]] += 1;

            mp[0][dataset[i].srcIP_dstIP()] += 1;
            mp[1][dataset[i].srcIP_srcPort()] += 1;
            mp[2][dataset[i].dstIP_dstPort()] += 1;
            mp[3][dataset[i].srcIP()] += 1;
            mp[4][dataset[i].dstIP()] += 1;
        }
    }

    ~MultiHHBench(){
        delete dataset;
    }

    void HHMultiBench(uint32_t MEMORY, double alpha, std::string algo){
        Abstract<TUPLES>* sketch = newPartialSketch<TUPLES>(MEMORY, algo);
    
        TP start, finish;
        //uint32_t start, finish;
        
        start = now();
        for(uint32_t i = 0;i < length;++i){
            //start = __rdtsc();
            sketch->Insert(dataset[i]);
            //finish = __rdtsc();
            //cycles[i] = finish - start;
        }
        
        /* std::sort(cycles.begin(), cycles.end());
        std::cout << "95th: " << cycles[uint32_t(0.95 * length)] << std::endl;
        std::cout << "99th: " << cycles[uint32_t(0.99 * length)] << std::endl; */
        finish = now();
        double Thp = length / durationms(finish, start);
        // std::cout << "Thp: " << length / durationms(finish, start) << std::endl;

        std::unordered_map<TUPLES, COUNT_TYPE> estTuple = sketch->AllQuery();
        std::unordered_map<uint64_t, COUNT_TYPE> estMp[5];

        for(auto it = estTuple.begin();it != estTuple.end();++it){
            estMp[0][(it->first).srcIP_dstIP()] += it->second;
            estMp[1][(it->first).srcIP_srcPort()] += it->second;
            estMp[2][(it->first).dstIP_dstPort()] += it->second;
            estMp[3][(it->first).srcIP()] += it->second;
            estMp[4][(it->first).dstIP()] += it->second;
        }

        COUNT_TYPE threshold = alpha * length;

        std::string saveFile = "../results/HH-" + fileName + "-" + sketch->name + "-" + std::to_string(MEMORY) +
                "-" + std::to_string(threshold) + ".csv";

        std::ofstream outfile(saveFile);
        
        CompareHH(estTuple, tuplesMp, threshold, 1, Thp, outfile);

        for(uint32_t i = 0;i < 5;++i){
            CompareHH(estMp[i], mp[i], threshold, i + 2, Thp, outfile);
        }

        outfile.close();

        delete sketch;
    }

private:
    std::string fileName;
    std::vector<uint32_t> cycles;

    TUPLES *dataset;
    uint64_t length;

    std::unordered_map<TUPLES, COUNT_TYPE> tuplesMp;
    std::unordered_map<uint64_t, COUNT_TYPE> mp[5];

    template<class T>
    void CompareHH(T mp, T record, COUNT_TYPE threshold, uint32_t key_type, double Thp, std::ofstream& outfile){
        double realHH = 0, estHH = 0, bothHH = 0, aae = 0, are = 0;

        for(auto it = record.begin();it != record.end();++it){
            bool real, est;
            double realF = it->second, estF = mp[it->first];
            // std::cout << realF << "\t" << estF << "\n";

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
        // std::cout << bothHH << "\t" << realHH << "\t" << estHH << std::endl;
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
        outfile << "Thp," << Thp << std::endl;
        outfile << std::endl;
    }
};

#endif

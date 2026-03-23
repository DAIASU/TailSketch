#pragma once

#include "Algos.h"

class SingleHHBench {
public:
    typedef std::unordered_map<TUPLES, COUNT_TYPE> HashMap;

    SingleHHBench(std::string PATH, std::string name){
        fileName = name;

        std::cout << PATH << ' ' << name << '\n';

        dataset = read_data(PATH.c_str(), 10000000, &length);
        for (uint32_t i = 0; i < length; i++)
        {
            tuplesMp[dataset[i]] += 1;
        }
        
    }

    ~SingleHHBench(){
        delete dataset;
    }

    void HHBench(double alpha, std::string algo){
       
        constexpr int32_t mem_base = 0;
        constexpr int32_t mem_inc = 200000;
        constexpr int32_t mem_var = 5;
        constexpr int32_t cmp_num = 1;

        Abstract<TUPLES> *sketches[mem_var][cmp_num];

        for (int i = 0; i < mem_var; ++i) {
            sketches[i][0] = newFullSketch<TUPLES>(mem_base + (i + 1) * mem_inc, algo);
        }
        
        for (int i = 0; i < mem_var; ++i) {
            int memory = (mem_base + mem_inc * (i + 1)) / 1000;
            std::cout << "Memory size: " << memory
                    << "KB" << std::endl
                    << std::endl;
            for (int l = 0; l < length; ++l) {
                for (int j = 0; j < cmp_num; ++j) {
                    sketches[i][j]->Insert(dataset[l]);
                }
            }
            
            // ofstream out;
            // out.open("../results/Heavy_hitter_"+to_string(memory)+"KB.txt",ios::out | ios::trunc);
            for (int j = 0; j < cmp_num; ++j) {
                std::cout << sketches[i][j]->name << std::endl;
                
                CompareHH(sketches[i][j]->AllQuery(dataset, length), tuplesMp, length, alpha);
                delete sketches[i][j];
            }
            // out.close();
            std::cout << std::endl;
        }
    }

private:
    std::string fileName;

    TUPLES *dataset;
    uint64_t length;

    std::unordered_map<TUPLES, COUNT_TYPE> tuplesMp;

    void CompareHH(HashMap mp, HashMap record, uint64_t length, double alpha){
        double realHH = 0, estHH = 0, bothHH = 0, aae = 0, are = 0;
        COUNT_TYPE threshold = length * alpha;

        for(auto it = record.begin();it != record.end();++it){
            bool real, est;
            double realF = it->second, estF = mp[it->first];
            // double realF = it->second, estF = this->Query(it->first);

            // std::cout << realF << ' ' << estF << "--\n";
        
            real = (realF > threshold);
            est = (estF > threshold);

            realHH += real;
            estHH += est;

            if(real && est){
                // std::cout << realF << "," << estF << "\n";
                bothHH += 1;
                aae += abs(realF - estF);
                are += abs(realF - estF) / realF;
            }
        }
        
        aae /= bothHH;
        are /= bothHH;
        double precision = bothHH / estHH;
        double recall = bothHH / realHH;
        double f1 = (2*precision*recall) / (precision + recall);

        std::cout << "threshold," << threshold << std::endl;

        std::cout << "realHH," << realHH << std::endl;
        std::cout << "estHH," << estHH << std::endl;
        std::cout << "bothHH," << bothHH << std::endl;

        std::cout << "recall," << recall << std::endl;
        std::cout << "precision," << precision  << std::endl;
        std::cout << "aae," << aae << std::endl;
        std::cout << "are," << are << std::endl;
        std::cout << std::endl;
    }
};

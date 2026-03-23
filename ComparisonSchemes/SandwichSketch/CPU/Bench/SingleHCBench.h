#pragma once

#include "Algos.h"

class SingleHCBench {
public:
    typedef std::unordered_map<TUPLES, COUNT_TYPE> HashMap;

    SingleHCBench(std::string PATH, std::string name){
        fileName = name;

        dataset = read_data(PATH.c_str(), 10000000, &length);
        
    }

    ~SingleHCBench(){
        delete dataset;
    }

    void HCBench(double alpha, std::string algo){
        
        constexpr int32_t mem_base = 100000;
        constexpr int32_t mem_inc = 100000;
        constexpr int32_t mem_var = 5;
        constexpr int32_t cmp_num = 1;

        Abstract<TUPLES> *sketches1[mem_var][cmp_num];
        Abstract<TUPLES> *sketches2[mem_var][cmp_num];

        for (int i = 0; i < mem_var; ++i) {
            sketches1[i][0] = newFullSketch<TUPLES>(mem_base + (i + 1) * mem_inc, algo);
            sketches2[i][0] = newFullSketch<TUPLES>(mem_base + (i + 1) * mem_inc, algo);
        }

        HashMap mp,record[mem_var][cmp_num],diff;
        for (int l = 0; l < (length >> 1); ++l){
            mp[dataset[l]] += 1;
            for (int i = 0; i < mem_var; ++i) {
                for (int j = 0; j < cmp_num; ++j) {
                    sketches1[i][j]->Insert(dataset[l]);
                }
            }
        }

        for (int l = (length >> 1); l < length; ++l){
            mp[dataset[l]] -= 1;
            for (int i = 0; i < mem_var; ++i) {
                for (int j = 0; j < cmp_num; ++j) {
                    sketches2[i][j]->Insert(dataset[l]);
                }
            }
        }

        for (int i = 0; i < mem_var; ++i) {
            for (int j = 0; j < cmp_num; ++j) {
                record[i][j] = sketches1[i][j]->AllQuery(dataset, (length >> 1));
                diff = sketches2[i][j]->AllQuery(dataset + (length >> 1), length - (length >> 1));
                for(auto it = diff.begin();it != diff.end();++it){
                    record[i][j][it->first] -= it->second;
                }

            }
        }
        
        for (int i = 0; i < mem_var; ++i) {
            int memory = (mem_base + mem_inc * (i + 1)) / 1000;
            std::cout << "Memory size: " << memory
                    << "KB" << std::endl
                    << std::endl;
            // ofstream out;
            // out.open("../result/Heavy_change_in_Time_"+to_string(memory)+"KB.txt",ios::out | ios::trunc);
            for (int j = 0; j < cmp_num; ++j) {
                std::cout << (sketches1[i][j]->name) << std::endl;

                CompareHC(mp, record[i][j], length, alpha);
            }
            // out.close();
        }

        for (int i = 0; i < mem_var; ++i) {
            for (int j = 0; j < cmp_num; ++j) {
                delete sketches1[i][j];
                delete sketches2[i][j];
            }
        }
    }

private:
    std::string fileName;

    TUPLES *dataset;
    uint64_t length;

    HashMap DiffHC(HashMap map1,HashMap map2){
        HashMap ret;
        for (auto it = map1.begin();it != map1.end();++it){
            ret[it->first] = it->second - map2[it->first];
        }

        for (auto it = map2.begin();it != map2.end();++it){
            if(ret.find(it->first) == ret.end()){
                ret[it->first] = map1[it->first] - it->second;
            }
        }

        return ret;
    }

    void CompareHC(HashMap mp, HashMap record, uint64_t length, double alpha) {
        double realHH = 0, estHH = 0, bothHH = 0, aae = 0, are = 0, precision = 0, recall = 0, f1 = 0;
        COUNT_TYPE threshold = (length * alpha);

        for(auto it = mp.begin();it != mp.end();++it){
            bool real, est;
            double realF = abs(it->second), estF = abs(record[it->first]);

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

        aae /= bothHH;
        are /= bothHH;
        precision = bothHH / estHH;
        recall = bothHH / realHH;
        f1 = (2*precision*recall) / (precision + recall);

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
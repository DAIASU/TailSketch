#pragma once

#include <fstream>
#include <sstream>
#include <iomanip>

#include "Algos.h"

// #define DistributedSketch Ours

// #define node_num 10 // 10
// #define large_node_param 1 // 1

// r 0.01 0.05 0.1 0.2 0.4
// r = large_node_param / (node_num - 1 + large_node_param)
// (node_num - 1 + large_node_param) * r = large_node_param
// (1 - r) * large_node_param = (node_num - 1) * r
// large_node_param = (node_num - 1) * r / (1 - r)

class DistributedHHBench {
public:

    DistributedHHBench(std::string PATH, std::string name, int _node_num, int _large_node_param, double _r, bool _is_disjoint) {
        fileName = name;

        r = _r;
        node_num = _node_num;
        large_node_param = _large_node_param;
        is_disjoint = _is_disjoint;

        datasets = datasets_division(PATH, node_num, large_node_param, is_disjoint, 0.0001, SpecialSrcIPs);
    
        length = 0;
        for (size_t i = 0; i < datasets.size(); i++) {
            std::vector<TUPLES> &dataset = datasets[i];

            length += dataset.size();
            for (size_t j = 0; j < dataset.size(); j++) {
                tuplesMp[dataset[j]] += 1;

                mp[0][dataset[j].srcIP_dstIP()] += 1;
                mp[1][dataset[j].srcIP_srcPort()] += 1;
                mp[2][dataset[j].dstIP_dstPort()] += 1;
                mp[3][dataset[j].srcIP()] += 1;
                mp[4][dataset[j].dstIP()] += 1;
            }
        }
    }

    void Bench(uint32_t MEMORY, double alpha, std::string algo) {
        Abstract<TUPLES> *sketches[node_num];

        for (int i = 0; i < node_num; i++) {
            std::vector<TUPLES> &dataset = datasets[i];

            sketches[i] = newPartialSketch<TUPLES>(MEMORY / node_num, algo);
            for (size_t j = 0; j < dataset.size(); j++)
                sketches[i]->Insert(dataset[j]);
        }

        // std::cout << sketches[0]->name << ' ' << node_num << ' ' << large_node_param << ' ' << is_disjoint << '\n';

        std::unordered_map<TUPLES, COUNT_TYPE> estTuple;
        std::unordered_map<uint64_t, COUNT_TYPE> estMp[5];

        for (size_t i = 0; i < datasets.size(); i++) {
            std::unordered_map<TUPLES, COUNT_TYPE> nowTuple = sketches[i]->AllQuery();

            for (auto it = nowTuple.begin(); it != nowTuple.end(); ++it) {
                estTuple[it->first] += it->second;

                estMp[0][(it->first).srcIP_dstIP()] += it->second;
                estMp[1][(it->first).srcIP_srcPort()] += it->second;
                estMp[2][(it->first).dstIP_dstPort()] += it->second;
                estMp[3][(it->first).srcIP()] += it->second;
                estMp[4][(it->first).dstIP()] += it->second;
            }
        }

        COUNT_TYPE threshold = alpha * length;

        std::string saveFile = "../results/DHH-" + fileName + "-" + sketches[0]->name + "-" + std::to_string(MEMORY) +
                "-" + std::to_string(node_num) + "-" + std::to_string(large_node_param) + "-" + double2string(r, 3) +
                "-" + std::to_string(is_disjoint) + "-" + std::to_string(threshold) + ".csv";

        std::ofstream outfile(saveFile);
        
        CompareHH(estTuple, tuplesMp, threshold, 1, outfile);

        for(uint32_t i = 0;i < 5;++i){
            CompareHH(estMp[i], mp[i], threshold, i + 2, outfile);
        }

        CompareSpecialSrcIPs(estMp[3], mp[3], threshold, outfile);

        outfile.close();

        for (int i = 0; i < node_num; i++)
            delete sketches[i];
    }

private:
    double r;
    int node_num;
    int large_node_param;
    bool is_disjoint;

    std::string fileName;
    std::vector<uint32_t> SpecialSrcIPs;
    std::vector<std::vector<TUPLES>> datasets;

    uint64_t length;
    std::unordered_map<TUPLES, COUNT_TYPE> tuplesMp;
    std::unordered_map<uint64_t, COUNT_TYPE> mp[5];

    template<class T>
    void CompareHH(T mp, T record, COUNT_TYPE threshold, uint32_t key_type, std::ofstream& outfile){
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
        outfile << std::endl;
    }

    template<class T>
    void CompareSpecialSrcIPs(T estMp, T record, COUNT_TYPE threshold, std::ofstream& outfile) {
        double realHH = 0, estHH = 0, bothHH = 0, aae = 0, are = 0;

        for (uint32_t srcIP : SpecialSrcIPs) {
            bool real, est;
            double realF = record[srcIP], estF = estMp[srcIP];
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

        outfile << "SpecialSrcIPs" << std::endl;
        outfile << "threshold," << threshold << std::endl;

        outfile << "realHH," << realHH << std::endl;
        outfile << "estHH," << estHH << std::endl;
        outfile << "bothHH," << bothHH << std::endl;

        outfile << "aae," << aae << std::endl;
        outfile << "are," << are << std::endl;
        outfile << std::endl;
    }
};

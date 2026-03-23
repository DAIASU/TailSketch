#include <cassert>

#include "MultiHHBench.h"
#include "MultiHCBench.h"
#include "MultiHHHBench.h"
#include "MultiHHH2Bench.h"
#include "SingleHHBench.h"
#include "SingleHCBench.h"
#include "DistributedHHBench.h"

#include "Algos.h"

extern size_t tupleLen;
extern bool readTimeStamp;

int main(int argc,char* argv[]) {

    if (argc != 4)
    {
        std::cout << "Parameters Error!" << std::endl;
        return 0;
    }

    std::string exp_type(argv[1]);
    std::string dataset_type(argv[2]);

    std::string folder = "../datasets/";
    std::string file = "";

    if (dataset_type == "CAIDA") {
        file = "130000.dat";
        tupleLen = 13;
        readTimeStamp = true;
    }else if (dataset_type == "MAWI") {
        file = "time07.dat";
        tupleLen = 13;
        readTimeStamp = true;
    }else if (dataset_type == "WEBPAGE") {
        file = "webdocs_form00.dat";
        tupleLen = 8;
        readTimeStamp = false;
    }else if (dataset_type == "NET") {
        file = "net.dat";
        tupleLen = 4;
        readTimeStamp = false;
    }
    
    std::string algo(argv[3]);

    if(exp_type == "SetHH"){
        MultiHHBench HH(folder + file, dataset_type);

        for (int i = 1; i <= 5; i++)
            HH.HHMultiBench(i * 200000, 0.0001, algo);
    }else if(exp_type == "SetHC"){
        MultiHCBench HC(folder + file, dataset_type);

        for (int i = 1; i <= 5; i++)
            HC.HCMultiBench(i * 200000, 0.0001, algo);
    }else if(exp_type == "SetHHH"){
        std::cout << "1-D Hierarchical Heavy Hitters:" << std::endl;
        MultiHHHBench HHH(folder + file, dataset_type);

        for (uint32_t i = 1;i <= 5;++i){
            std::cout << "Memory:" << i * 200000 / 1000 << "KB" << std::endl;
            HHH.HHHMultiBench(i * 200000, 0.00005, algo);
        }
    }else if(exp_type == "SetHHH2"){
        std::cout << "2-D Hierarchical Heavy Hitters:" << std::endl;
        MultiHHH2Bench HHH2(folder + file, dataset_type);

        for (uint32_t i = 1;i <= 5;++i){
            std::cout << "Memory:" << i * 500000 / 1000 << "KB" << std::endl;
            HHH2.HHH2MultiBench(i * 500000, 0.00005, algo);
        }
    }else if(exp_type == "ItemHH"){
        std::cout << "Item Heavy Hitters:" << std::endl;
        SingleHHBench HH(folder + file, dataset_type);

        HH.HHBench(0.0001, algo);
    }else if(exp_type == "ItemHC"){
        std::cout << "Item Heavy Changes:" << std::endl;
        SingleHCBench HC(folder + file, dataset_type);
        
        HC.HCBench(0.0001, algo);
    }else if(exp_type == "SetDHH") {
        int node_num = 10;
        int large_node_param[5];
        double r[] = {0.01, 0.05, 0.1, 0.2, 0.4};
        for (int i = 0; i < 5; i++)
            large_node_param[i] = int((node_num - 1) * r[i] / (1 - r[i]) + 0.5);

        std::cout << "Distributed Set Heavy Hitters:" << std::endl;

        for (int i = 0; i < 5; i++) {
            DistributedHHBench DHH(folder + file, dataset_type, node_num, large_node_param[i], r[i], true);
            DHH.Bench(600000, 0.0001, algo);
        }
    }
    return 0;
}

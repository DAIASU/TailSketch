#pragma once

#include "Abstract.h"

template<typename DATA_TYPE>
class CocoSketch : public Abstract<DATA_TYPE>{
public:

    typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;

    CocoSketch(uint32_t _MEMORY, uint32_t _HASH_NUM = 1, std::string _name = "CocoSketch"){
        this->name = _name;

        HASH_NUM = _HASH_NUM;
        LENGTH = _MEMORY / HASH_NUM / sizeof(Counter);

        var = 0;

        counter = new Counter*[HASH_NUM];
        for(uint32_t i = 0;i < HASH_NUM;++i){
            counter[i] = new Counter[LENGTH];
            memset(counter[i], 0, sizeof(Counter) * LENGTH);
        }
    }

    ~CocoSketch(){
        for(uint32_t i = 0;i < HASH_NUM;++i)
            delete [] counter[i];
        delete [] counter;
    }

    void Insert(const DATA_TYPE& item){
        for(uint32_t i = 0;i < HASH_NUM;++i){
            uint32_t position = hash(item, i) % LENGTH;
            if (!(counter[i][position].ID == item))
            {
                var += 2*(uint64_t)(counter[i][position].count);
            }
            
            counter[i][position].count += 1;
            if(randomGenerator() % counter[i][position].count == 0){
                counter[i][position].ID = item;
            }
        }
    }

    HashMap AllQuery(DATA_TYPE *dataset = NULL, int length = 0){
        HashMap ret;
        std::vector<std::pair<COUNT_TYPE, COUNT_TYPE>> vec;
        std::unordered_map<COUNT_TYPE, COUNT_TYPE> map;
        std::vector<COUNT_TYPE> dist;

        // std::cout << "Var:" << var << "\n";

        for(uint32_t i = 0;i < HASH_NUM;++i){
            for(uint32_t j = 0;j < LENGTH;++j){
                dist.push_back(counter[i][j].count);
                if(ret.find(counter[i][j].ID) == ret.end()){
                    std::vector<COUNT_TYPE> estVec(HASH_NUM);
                    for(uint32_t k = 0;k < HASH_NUM;++k){
                        estVec[k] = counter[k][hash(counter[i][j].ID, k) % LENGTH].count;
                    }
                    ret[counter[i][j].ID] = Median(estVec, HASH_NUM);
                }
                // if(ret.find(counter[i][j].ID) == ret.end()){
                //     std::vector<COUNT_TYPE> estVec;
                //     for(uint32_t k = 0;k < HASH_NUM;++k){
                //         if (counter[k][hash(counter[i][j].ID, k) % LENGTH].ID == counter[i][j].ID)
                //         {
                //             estVec.push_back(counter[k][hash(counter[i][j].ID, k) % LENGTH].count);
                //         }
                //     }
                //     assert(estVec.size());
                //     ret[counter[i][j].ID] = Median(estVec, estVec.size());
                // }
            }
        }

        for (auto iter = dist.begin(); iter != dist.end(); iter++)
        {
            map[*iter]++;
        }

        for (auto iter = map.begin(); iter != map.end(); iter++)
        {
            vec.push_back(std::make_pair(iter->first, iter->second));
        }

        sort(vec.begin(),vec.end(),[](auto p1, auto p2){return p1.first < p2.first;});
        sort(dist.begin(), dist.end());
        std::ofstream out("basic_dist.txt");
        for (int i = 5; i < 100; i=i+5)
        {
            out << std::to_string(i) << "%:" << dist[dist.size() / 100 * i] << "\n";
        }
        out << "\n";
        for (auto iter : vec)
        {
            out << iter.first << "\t" << iter.second << "\n";
        }
        out.close();

        return ret;
    }

private:
    struct Counter{
        DATA_TYPE ID;
        COUNT_TYPE count;
    };

    uint32_t LENGTH;
    uint32_t HASH_NUM;

    uint64_t var;

    Counter** counter;
};

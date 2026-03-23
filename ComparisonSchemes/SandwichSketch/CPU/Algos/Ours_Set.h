#pragma once

#include "Abstract.h"


template<typename DATA_TYPE>
class Ours_Set :public Abstract<DATA_TYPE> {
public:

    typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;

    Ours_Set(uint32_t _MEMORY, std::string _name = "Ours"){
        this->name = _name;

        TOPK_LENGTH = _MEMORY * TOPK_RATIO / (PART1_HASH_NUM + PART2_HASH_NUM) / sizeof(Counter);
        COCO_LENGTH = _MEMORY * COCO_RATIO / sizeof(Counter);

        topk = new Counter*[PART1_HASH_NUM + PART2_HASH_NUM];
        for(uint32_t i = 0;i < PART1_HASH_NUM + PART2_HASH_NUM;++i){
            topk[i] = new Counter[TOPK_LENGTH];
            memset(topk[i], 0, sizeof(Counter) * TOPK_LENGTH);
        }

        coco = new Counter[COCO_LENGTH];
        memset(coco, 0, sizeof(Counter) * COCO_LENGTH);
    }

    ~Ours_Set(){
        for(uint32_t i = 0;i < PART1_HASH_NUM + PART2_HASH_NUM;++i)
            delete [] topk[i];
        delete [] topk;
        delete [] coco;
    }

    void Insert(const DATA_TYPE& item){
        DATA_TYPE ID = item;
        COUNT_TYPE count = 1;
        for(uint32_t i = 0; i < PART1_HASH_NUM; i++){
            uint32_t pos = hash(ID, i) % TOPK_LENGTH;
            if(topk[i][pos].ID == ID){
                topk[i][pos].count += count;
                return;
            }else if(topk[i][pos].count == 0){
                topk[i][pos].ID = ID;
                topk[i][pos].count = count;
                return;
            }else if((randomGenerator() % (topk[i][pos].count + count)) < count){
                // w.p. f1/(f1+f2)
                DATA_TYPE tmp_ID = topk[i][pos].ID;
                COUNT_TYPE tmp_count = topk[i][pos].count;
                topk[i][pos].ID = ID;
                topk[i][pos].count = count;
                ID = tmp_ID;
                count = tmp_count;
            }
        }

        for(uint32_t i = PART1_HASH_NUM; i < PART1_HASH_NUM + PART2_HASH_NUM; i++){
            uint32_t pos = hash(ID, i) % TOPK_LENGTH;
            if(topk[i][pos].ID == ID){
                topk[i][pos].count += count;
                return;
            }else if(topk[i][pos].count == 0){
                topk[i][pos].ID = ID;
                topk[i][pos].count = count;
                return;
            }else if(topk[i][pos].count < count){
                
                DATA_TYPE tmp_ID = topk[i][pos].ID;
                COUNT_TYPE tmp_count = topk[i][pos].count;
                topk[i][pos].ID = ID;
                topk[i][pos].count = count;
                ID = tmp_ID;
                count = tmp_count;
            }
        }

        uint32_t pos = hash(ID, PART1_HASH_NUM + PART2_HASH_NUM) % COCO_LENGTH;
        if(coco[pos].ID == ID){
            coco[pos].count += count;
        }else if(coco[pos].count == 0){
            coco[pos].ID = ID;
            coco[pos].count = count;
        }else{
            coco[pos].count += count;
            if((randomGenerator() % (coco[pos].count + count)) < count){
                coco[pos].ID = ID;
            }
        }
    }

    HashMap AllQuery(DATA_TYPE *dataset = NULL, int length = 0){
        HashMap ret;

        for(uint32_t i = 0;i < PART1_HASH_NUM + PART2_HASH_NUM;++i){
            for(uint32_t j = 0;j < TOPK_LENGTH;++j){
                ret[topk[i][j].ID] += topk[i][j].count;
            }
        }

        for(uint32_t i = 0;i < COCO_LENGTH;i++){
            ret[coco[i].ID] += coco[i].count;
        }

        return ret;
    }

private:
    struct Counter{
        DATA_TYPE ID;
        COUNT_TYPE count;
    };

    uint32_t PART1_HASH_NUM = 2;
    uint32_t PART2_HASH_NUM = 2;
    double TOPK_RATIO = 0.5;
    double COCO_RATIO = 1 - TOPK_RATIO;

    uint32_t TOPK_LENGTH;
    uint32_t COCO_LENGTH;

    Counter** topk;
    Counter* coco;
};

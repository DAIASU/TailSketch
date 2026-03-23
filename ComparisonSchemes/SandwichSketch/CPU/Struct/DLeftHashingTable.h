#ifndef DLeftHashingTable_H
#define DLeftHashingTable_H

#include <unordered_map>

#include "Util.h"

#define TABLE_NUM 5
#define BUCKET_HEIGHT 5

template<typename DATA_TYPE, typename COUNT_TYPE>
class DLeftHashingTable{
public:

    typedef uint8_t buckstsize_t;

    typedef std::pair<DATA_TYPE, COUNT_TYPE> KV;
    typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;

    DLeftHashingTable(uint32_t SIZE){

        inserted = 0;
        length = SIZE / TABLE_NUM / BUCKET_HEIGHT + 1;

        for (int i = 0; i < TABLE_NUM; i++) {
            bucketSize[i] = new buckstsize_t[length];
            memset(bucketSize[i], 0, sizeof(buckstsize_t) * length);

            buckets[i] = new KV*[length];
            for (int j = 0; j < length; j++)
                buckets[i][j] = new KV[BUCKET_HEIGHT];
        }
    }

    ~DLeftHashingTable(){
        for (int i = 0; i < TABLE_NUM; i++) {
            delete []bucketSize[i];
            for (int j = 0; j < length; j++)
                delete []buckets[i][j];
            delete []buckets[i];
        }
    }

    static uint32_t Size2Memory(uint32_t size){
        return (size / TABLE_NUM / BUCKET_HEIGHT + 1) *
               (sizeof(buckstsize_t) + sizeof(KV) * BUCKET_HEIGHT) * TABLE_NUM;
    }

    static uint32_t Memory2Size(uint32_t memory){
        return memory / (sizeof(buckstsize_t) + sizeof(KV) * BUCKET_HEIGHT)
                      * BUCKET_HEIGHT;
    }

    inline uint32_t size(){
        return inserted;
    }

    void Insert(const DATA_TYPE& key, const COUNT_TYPE& value) {
        buckstsize_t minSize = BUCKET_HEIGHT;
        int arr = -1;

        for (int i = 0; i < TABLE_NUM; i++) {
            uint32_t position = hash(key, i) % length;

            for (int j = 0; j < bucketSize[i][position]; j++)
                if (buckets[i][position][j].first == key) {
                    buckets[i][position][j].second = value;
                    return;
                }

            if (bucketSize[i][position] < minSize) {
                minSize = bucketSize[i][position];
                arr = i;
            }
        }

        if (arr != -1) {
            inserted += 1;
            uint32_t position = hash(key, arr) % length;
            buckets[arr][position][bucketSize[arr][position]++] = KV(key, value);
        }else {

            COUNT_TYPE minValue = 0x7fffffff;
            int arr = -1, pos, delta;

            for (int i = 0; i < TABLE_NUM; i++) {
                uint32_t position = hash(key, i) % length;

                for (int j = 0; j < bucketSize[i][position]; j++)
                    if (buckets[i][position][j].second < minValue) {
                        minValue = buckets[i][position][j].second;
                        arr = i, pos = position, delta = j;
                    }
            }

            assert(minValue < 0x7fffffff);

            if (minValue < value) {
                buckets[arr][pos][delta].first = key;
                buckets[arr][pos][delta].second = value;
            }

            // for (int i = 0; i < TABLE_NUM; i++) {
            //     buckstsize_t minSize = BUCKET_HEIGHT;
            //     for (int j = 0; j < length; j++)
            //         minSize = std::min(minSize, bucketSize[i][j]);
            //     std::cout << minSize << '\n';
            // }
            // std::cout << inserted << '\n';
            // std::cerr << "D Left Hashing Table insert error: Couldn't find a bucket.\n";
            // throw;
        }
    }

    HashMap AllQuery() {
        HashMap mp;
        for (int i = 0; i < TABLE_NUM; i++)
            for (int j = 0; j < length; j++)
                for (int k = 0; k < bucketSize[i][j]; k++)
                    mp.insert(buckets[i][j][k]);
        return mp;
    }

// protected:
    uint32_t length;
    uint32_t inserted;

    buckstsize_t *bucketSize[TABLE_NUM];
    KV **buckets[TABLE_NUM];

};

#endif

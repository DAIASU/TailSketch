#ifndef USSHeap_H
#define USSHeap_H

#include "Abstract.h"
#include "Heap.h"

template<typename DATA_TYPE>
class USSHeap : public Abstract<DATA_TYPE>{
public:

    typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;

    USSHeap(uint32_t _MEMORY, std::string _name = "USSHeap"){
        this->name = _name;

        heap = new Heap<DATA_TYPE, COUNT_TYPE>(heap->Memory2Size(_MEMORY));
    }

    ~USSHeap(){
        delete heap;
    }

    void Insert(const DATA_TYPE& item){
        if(heap->mp->Lookup(item))
            heap->Add_Data(item);
        else{
            if(heap->isFull()){
                if(randomGenerator() % (heap->getMin() + 1) == 0)
                    heap->SS_Replace(item);
                else
                    heap->Add_Min();
            }
            else
                heap->New_Data(item);
        }
    }

    HashMap AllQuery(DATA_TYPE *dataset = NULL, int length = 0){
        return heap->AllQuery();
    }

private:
    Heap<DATA_TYPE, COUNT_TYPE>* heap;
};

#endif

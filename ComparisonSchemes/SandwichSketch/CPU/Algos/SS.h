#pragma once

#include "StreamSummary.h"

template<typename DATA_TYPE>
class SS : public Abstract<DATA_TYPE> {
public:
	typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;


	SS(uint32_t MEMORY, std::string _name = "SS"){
		this->name = _name;

		summary = new StreamSummary<DATA_TYPE, COUNT_TYPE>(summary->Memory2Size(MEMORY));
	}
	~SS() { delete summary; }

	void Insert(const DATA_TYPE& item) {
		if (!summary->Add_Data(item)) {
			summary->Add_Counter(item, !summary->isFull());
		}
	}

	COUNT_TYPE Query(const DATA_TYPE item) { return summary->Query(item); }

	HashMap AllQuery(DATA_TYPE *dataset = NULL, int length = 0){
        HashMap ret;

        for (int i = 0; i < length; i++)
            if (ret.count(dataset[i]) == 0)
                ret[dataset[i]] = Query(dataset[i]);
        
        return ret;
    }

private:
	StreamSummary<DATA_TYPE, COUNT_TYPE> *summary;
};

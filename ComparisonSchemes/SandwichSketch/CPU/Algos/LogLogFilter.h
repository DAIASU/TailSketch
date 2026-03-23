#pragma once

#include <iostream>
#include "Abstract.h"
#include "CUSketch.h"
#include "LogFilter.h"

template<typename DATA_TYPE>
class LogLogFilter : public Abstract<DATA_TYPE>{
public:

	typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;

	LogLogFilter(uint32_t _MEMORY, std::string _name = "LogLogFilter") {
		this->name = _name;

		cu = new CUSketch<DATA_TYPE>(_MEMORY * CU_RATIO);
		lf = new LogFilter<DATA_TYPE, COUNT_TYPE>(_MEMORY * LF_RATIO);
	}

	~LogLogFilter() {
		delete cu;
		delete lf;
	}
    
	void Insert(const DATA_TYPE& key)
	{
		if (lf->probe(key)) {
			lf->insert(key);
		}
		else {
			cu->Insert(key);
		}
		lf->timestamp++;
	}

	COUNT_TYPE Query(const DATA_TYPE& key) {
		double ret = 0.0;
		if (lf->probe(key)) {
			ret = lf->query1(key);
		}
		else {
			ret = lf->query2() + (double)cu->Query(key);
		}			
		return (uint32_t)ret;
	}

	HashMap AllQuery(DATA_TYPE *dataset = NULL, int length = 0){
        HashMap ret;

        for (int i = 0; i < length; i++)
            if (ret.count(dataset[i]) == 0)
                ret[dataset[i]] = Query(dataset[i]);
        
        return ret;
    }
    
private:
	const double CU_RATIO = 0.75;
	const double LF_RATIO = 0.25;

	CUSketch<DATA_TYPE> *cu;
	LogFilter<DATA_TYPE, COUNT_TYPE> *lf;
};

#ifndef ABSTRACT_H
#define ABSTRACT_H

#include <unordered_map>

#include <string.h>

#include "Util.h"

template<typename DATA_TYPE>
class Abstract{
public:
    struct Counter{
        DATA_TYPE ID;
        COUNT_TYPE count;
    };

    Abstract(){}
    virtual ~Abstract(){};

    std::string name;
    typedef std::unordered_map<DATA_TYPE, COUNT_TYPE> HashMap;

    virtual void Insert(const DATA_TYPE& item) = 0;
    // virtual COUNT_TYPE Query(const DATA_TYPE& item) {
    //     return 0; // to be done.
    // }
    virtual HashMap AllQuery(DATA_TYPE *dataset = NULL, int length = 0) = 0;

};

#endif

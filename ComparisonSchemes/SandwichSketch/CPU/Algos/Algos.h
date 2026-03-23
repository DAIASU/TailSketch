#pragma once

#include "CocoSketch.h"
#include "Ours_Item.h"
#include "Ours_Set.h"
#include "Ours_ItemFull.h"
#include "CMHash.h"
#include "CountHash.h"
#include "USSHeap.h"
#include "USS.h"
#include "ASketch.h"
#include "HeavyGuardian.h"
#include "LogLogFilter.h"
#include "Salsa.h"
#include "SpaceSaving.h"

template<class T>
Abstract<T> *newFullSketch(uint32_t MEMORY, std::string name) {
    if (name == "CocoSketch")    return new CocoSketch<T>(MEMORY);
    if (name == "Ours")          return new Ours_Item<T>(MEMORY);
    if (name == "OursFull")      return new Ours_ItemFull<T>(MEMORY);
    if (name == "USSHeap")       return new USSHeap<T>(MEMORY);
    if (name == "USS")           return new USS<T>(MEMORY);
    if (name == "CMHash")        return new CMHash<T>(MEMORY, 256);
    if (name == "CountHash")     return new CountHash<T>(MEMORY, 256);
    if (name == "ASketch")       return new ASketch<T>(MEMORY);
    if (name == "HeavyGuardian") return new HeavyGuardian<T>(MEMORY);
    if (name == "Salsa")         return new SalsaCM<T>(MEMORY);
    if (name == "SpaceSaving")   return new SpaceSaving<T>(MEMORY);
    if (name == "LogLogFilter")  return new LogLogFilter<T>(MEMORY);
    abort();
}

template<class T>
Abstract<T> *newPartialSketch(uint32_t MEMORY, std::string name) {
    if (name == "CocoSketch") return new CocoSketch<T>(MEMORY);
    if (name == "Ours")       return new Ours_Set<T>(MEMORY);
    if (name == "USSHeap")    return new USSHeap<T>(MEMORY);
    if (name == "USS")        return new USS<T>(MEMORY);
    abort();
}

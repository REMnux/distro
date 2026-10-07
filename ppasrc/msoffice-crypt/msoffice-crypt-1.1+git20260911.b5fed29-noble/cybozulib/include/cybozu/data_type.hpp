#pragma once
/**
	@file
	@brief typedef of some STL data type

	@author MITSUNARI Shigeo(@herumi)
*/
#include <string>
#include <map>
#include <set>
#include <vector>
#include <cybozu/inttype.hpp>

namespace cybozu {

typedef std::vector<int> IntVec;
typedef std::vector<uint32_t> Uint32Vec;
typedef std::vector<std::string> StrVec;
typedef std::map<int, int> Int2Int;
typedef std::map<int, std::string> Int2Str;
typedef std::map<std::string, int> Str2Int;
typedef std::map<std::string, std::string> Str2Str;
typedef std::set<int> IntSet;
typedef std::set<uint32_t> Uint32Set;
typedef std::set<std::string> StrSet;

} // cybozu

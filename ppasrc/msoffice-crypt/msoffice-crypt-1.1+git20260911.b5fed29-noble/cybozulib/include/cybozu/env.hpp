#pragma once

/**
	@file
	@brief get env function

	@author MITSUNARI Shigeo(@herumi)
*/
#include <cybozu/exception.hpp>
#include <stdlib.h>

namespace cybozu {

inline bool QueryEnv(std::string& value, const std::string& key)
{
#ifdef _WIN32
	char buf[4096];
	size_t size;
	if (getenv_s(&size, buf, key.c_str()) == 0) {
		if (size > 0) {
			value.assign(buf, size - 1);
			return true;
		}
	}
	return false;
#else
	const char *p = getenv(key.c_str());
	if (p) {
		value.assign(p);
		return true;
	}
	return false;
#endif
}

/**
	get env
	@param key [in] key name
	@return value
	@note throw exception if none
*/
inline std::string GetEnv(const std::string& key)
{
	std::string value;
	if (!QueryEnv(value, key)) throw cybozu::Exception("env:GetEnv") << key;
	return value;
}

/**
	get env
	@param key [in] key name
	@param defaultValue [in] default value
	@return value
	@note return defaultValue if none
*/
inline std::string GetEnv(const std::string& key, const std::string& defaultValue)
{
	std::string value;
	if (!QueryEnv(value, key)) return defaultValue;
	return value;
}

} // cybozu

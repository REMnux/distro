#pragma once
/**
	@file
	@brief format string
	@author MITSUNARI Shigeo(@herumi)
*/
#include <string>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <cybozu/exception.hpp>

#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 4 && __GNUC_MINOR__ >= 4)
#define CYBOZU_FORMAT_DISABLE_WARNING
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif

namespace cybozu {

inline void vformat(std::string& str, const char *format, va_list args)
{
#ifdef _MSC_VER
	_locale_t curLoc = _get_current_locale();
	int size = _vscprintf_l(format, curLoc, args);
	if (size < 0 || size >= INT_MAX) throw cybozu::Exception("vformat:_vscprintf_l");

	str.resize(size + 1);

	int ret = _vsprintf_s_l(&str[0], size + 1, format, curLoc, args);
	if (ret < 0) throw cybozu::Exception("vformat:_vsprintf_s_l");
	str.resize(size);
#else
#if 1
	char *p;
	int ret = vasprintf(&p, format, args);
	if (ret < 0) throw cybozu::Exception("vformat:vasnprintf");
	try {
		str.assign(p, ret);
		free(p);
	} catch (...) {
		free(p);
		throw std::bad_alloc();
	}
#else
	// slow
	va_list keep;
	va_copy(keep, args);
	int len = vsnprintf(0, 0, format, args); // len excludes the null byte
	if (len < 0) throw cybozu::Exception("vformat:vasnprintf err1");
	str.resize(len + 1);
	len = vsnprintf(&str[0], str.size(), format, keep); // len incluedes the null byte
	if (len < 0) throw cybozu::Exception("vformat:vasnprintf err2");
	str.resize(len);
#endif
#endif
}

#ifdef _MSC_VER
	#define CYBOZU_FORMAT_PRINTF _Printf_format_string_
#else
	#define CYBOZU_FORMAT_PRINTF
#endif

#ifdef __GNUC__
__attribute__((format(printf, 2, 3)))
#endif
inline void format(std::string& str, CYBOZU_FORMAT_PRINTF const char *format, ...)
{
	va_list args;
	va_start(args, format);
	cybozu::vformat(str, format, args);
	va_end(args);
}

#ifdef __GNUC__
__attribute__((format(printf, 1, 2)))
#endif
inline std::string format(CYBOZU_FORMAT_PRINTF const char *format, ...)
{
	std::string str;
	va_list args;
	va_start(args, format);
	cybozu::vformat(str, format, args);
	va_end(args);
	return str;
}

} // cybozu

#ifdef CYBOZU_FORMAT_DISABLE_WARNING
#pragma GCC diagnostic push
#endif

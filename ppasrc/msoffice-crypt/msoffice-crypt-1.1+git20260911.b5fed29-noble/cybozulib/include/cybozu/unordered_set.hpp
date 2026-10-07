#pragma once

#include <cybozu/inttype.hpp>

#ifdef CYBOZU_USE_BOOST
	#include <boost/unordered_set.hpp>
#elif (CYBOZU_CPP_VERSION >= CYBOZU_CPP_VERSION_CPP11) || defined(__APPLE__)
	#include <unordered_set>
#elif (CYBOZU_CPP_VERSION == CYBOZU_CPP_VERSION_TR1)
	#include <list>
	#include <tr1/unordered_set>
#endif


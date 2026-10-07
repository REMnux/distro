#include <stdio.h>
#include <cybozu/env.hpp>
#include <cybozu/test.hpp>

CYBOZU_TEST_AUTO(env)
{
	std::string val;
	CYBOZU_TEST_ASSERT(!cybozu::QueryEnv(val, "aw3vraw3vasv"));
#ifdef _WIN32
	const char *key = "USERPROFILE";
	const char *assumeVal = "C:\\Users";
#elif defined(__APPLE__)
	const char *key = "HOME";
	const char *assumeVal = "/Users";
#else
	const char *key = "HOME";
	const char *assumeVal = "/home";
#endif
	val = cybozu::GetEnv(key);
	CYBOZU_TEST_EQUAL(val.substr(0, strlen(assumeVal)), assumeVal);
	CYBOZU_TEST_EQUAL(cybozu::GetEnv("asvrifansevjase", "default"), "default");
}

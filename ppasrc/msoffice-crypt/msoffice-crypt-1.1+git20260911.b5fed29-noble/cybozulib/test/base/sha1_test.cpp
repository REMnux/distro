#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cybozu/sha1.hpp>
#include <cybozu/test.hpp>

struct Tbl {
	const char *ret;
	const char *msg;
} tbl[] = {
	{ "a9993e364706816aba3e25717850c26c9cd0d89d", "abc" },
	{ "84983e441c3bd26ebaae4aa1f95129e5e54670f1", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
	{ "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a" },
	{ "afc53a4ea20856f98e08dc6f3a5c9833137768ed", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
	{ "bab574e1a8088c10993968e2dd1994e3f24853ac", "sha1_test.cppMicrosoft(R)IncrementalLinkerVersion9.00.30729.01Copyright(C)MicrosoftCorporation.Allrightsreserved./debug/out:sha1_test.exe/LIBPATH:c:/p/boost/libsha1_test.obj" },
	{ "da39a3ee5e6b4b0d3255bfef95601890afd80709", "" },
};

CYBOZU_TEST_AUTO(sha1)
{
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		cybozu::Sha1 sha1;
		const char *msg = tbl[i].msg;
		sha1.digest(msg, strlen(msg));
		const std::string h = sha1.toString();
		CYBOZU_TEST_EQUAL(h, tbl[i].ret);
	}
}

CYBOZU_TEST_AUTO(update)
{
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		cybozu::Sha1 sha1;
		const char *msg = tbl[i].msg;
		size_t len = strlen(msg);
		if (len == 0) continue;
		sha1.update(msg, 1);
		sha1.digest(msg + 1, len - 1);
		const std::string h = sha1.toString();
		CYBOZU_TEST_EQUAL(h, tbl[i].ret);
	}
}

CYBOZU_TEST_AUTO(update2)
{
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		for (int step = 1; step < 80; step++) {
			const char *const msg = tbl[i].msg;
			const int len = (int)strlen(msg);
			int j = 0;
			cybozu::Sha1 sha1;
			while (j + step <= len) {
				sha1.update(msg + j, step);
				j += step;
			}
			sha1.digest(msg + j, len - j);
			const std::string h = sha1.toString();
			CYBOZU_TEST_EQUAL(h, tbl[i].ret);
		}
	}
}

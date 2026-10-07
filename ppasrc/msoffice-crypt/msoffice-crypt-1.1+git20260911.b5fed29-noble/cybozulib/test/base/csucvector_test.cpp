#include <cybozu/test.hpp>
#include <cybozu/sucvector.hpp>
#include <cybozu/csucvector.hpp>
#include <cybozu/xorshift.hpp>
#include <sstream>

cybozu::SucVector g_sv;
cybozu::CSucVector g_cv;
const size_t bitLen = 100000;

struct Init {
	Init()
	{
		cybozu::BitVector bv;
		bv.resize(bitLen);
		cybozu::XorShift rg;
		for (size_t i = 0; i < 100; i++) {
			bv.set(rg() % bitLen);
		}
		g_sv.init(bv.getBlock(), bitLen);
		g_cv.init(bv.getBlock(), bitLen);
	}
};

CYBOZU_TEST_SETUP_FIXTURE(Init);

void testGet(const cybozu::SucVector& sv, const cybozu::CSucVector& cv)
{
	for (size_t i = 0; i < bitLen; i++) {
		bool a = sv.get(i);
		bool b = cv.get(i);
		CYBOZU_TEST_EQUAL(a, b);
	}
}

void testRank(const cybozu::SucVector& sv, const cybozu::CSucVector& cv)
{
	for (size_t i = 0; i < bitLen; i++) {
		uint64_t a = sv.rank1(i);
		uint64_t b = cv.rank1(i);
		CYBOZU_TEST_EQUAL(a, b);
	}
}

CYBOZU_TEST_AUTO(get)
{
	testGet(g_sv, g_cv);
}

CYBOZU_TEST_AUTO(rank)
{
	testRank(g_sv, g_cv);
}

CYBOZU_TEST_AUTO(loadsave)
{
	std::stringstream ss;
	g_cv.save(ss);
	cybozu::CSucVector cv;
	cv.load(ss);
	testGet(g_sv, cv);
	testRank(g_sv, cv);
}
#include <cybozu/test.hpp>
#include <cybozu/wavelet_matrix.hpp>
#include <algorithm>
#include <cybozu/xorshift.hpp>
#include <cybozu/benchmark.hpp>

template<class T>
size_t selectC(const T *a, size_t N, uint32_t val, size_t n)
{
	n++;
	for (size_t i = 0; i < N; i++) {
		if (a[i] == val) n--;
		if (n == 0) return i;
	}
	return cybozu::NotFound;
}

template<class T>
size_t rankC(const T *a, size_t N, uint32_t val)
{
	return std::count(a, a + N, val);
}

template<class T>
size_t rankLtC(const T *a, size_t N, uint32_t val)
{
	size_t ret = 0;
	for (size_t i = 0; i < N; i++) {
		if (a[i] < val) ret++;
	}
	return ret;
}

CYBOZU_TEST_AUTO(mini)
{
	std::vector<uint32_t> v;
	const uint32_t vTbl[] = { 4, 7, 6, 5, 3, 2, 1, 0, 1, 4, 1, 7 };
	const size_t vn = CYBOZU_NUM_OF_ARRAY(vTbl);
	for (size_t i = 0; i < vn; i++) {
		v.push_back(vTbl[i]);
	}
	cybozu::WaveletMatrix wm;
	wm.init(v, 3);
	for (size_t i = 0; i < vn; i++) {
		CYBOZU_TEST_EQUAL(wm.get(i), vTbl[i]);
	}

	for (uint32_t val = 0; val <= 7; val++) {
		for (size_t pos = 0; pos < vn; pos++) {
			size_t a = wm.rank(val, pos);
			size_t b = rankC(vTbl, pos, val);
			CYBOZU_TEST_EQUAL(a, b);
			a = wm.rankLt(val, pos);
			b = rankLtC(vTbl, pos, val);
			CYBOZU_TEST_EQUAL(a, b);
		}
	}
	for (int r = 0; r < 3; r++) {
		for (int val = 0; val < 8; val++) {
			size_t a = wm.select(val, r);
			size_t b = selectC(vTbl, vn, val, r);
			CYBOZU_TEST_EQUAL(a, b);
		}
	}
}

void testSub(const cybozu::WaveletMatrix& wm, const std::vector<uint32_t>& v, uint32_t maxVal, size_t valBitLen)
{
	const size_t vn = v.size();
	for (size_t i = 0; i < vn; i++) {
		CYBOZU_TEST_EQUAL(wm.get(i), v[i]);
		uint32_t val;
		uint64_t p1 = wm.get(&val, i);
		uint64_t p2 = wm.rank(v[i], i);
		CYBOZU_TEST_EQUAL(val, v[i]);
		CYBOZU_TEST_EQUAL(p1, p2);
	}
	for (uint32_t val = 0; val < maxVal; val++) {
		for (size_t pos = 0; pos < vn; pos++) {
			size_t a = wm.rank(val, pos);
			size_t b = std::count(v.begin(), v.begin() + pos, val);
			CYBOZU_TEST_EQUAL(a, b);
		}
		CYBOZU_TEST_EQUAL(wm.rank(val, vn), (uint64_t)std::count(v.begin(), v.end(), val));
	}
	for (size_t r = 0; r < valBitLen; r++) {
		for (uint32_t val = 0; val < maxVal; val++) {
			size_t a = wm.select(val, r);
			size_t b = selectC(&v[0], vn, val, r);
			CYBOZU_TEST_EQUAL(a, b);
		}
	}
}

CYBOZU_TEST_AUTO(large_load_save)
{
	cybozu::XorShift rg;
	std::vector<uint32_t> v;
	const size_t vn = 5000;
	const size_t valBitLen = 8;
	const uint32_t maxVal = 1 << valBitLen;
	v.resize(vn);
	for (size_t i = 0; i < vn; i++) {
		v[i] = rg() % maxVal;
	}
	cybozu::WaveletMatrix wm;
	wm.init(v, valBitLen);
	testSub(wm, v, maxVal, valBitLen);
	std::string data;
	{
		std::ostringstream os;
		wm.save(os);
		data = os.str();
	}
	{
		std::istringstream is(data);
		cybozu::WaveletMatrix wm2;
		wm2.load(is);
		testSub(wm2, v, maxVal, valBitLen);
	}
#ifndef NDEUBG
	size_t x = 0;
	cybozu::CpuClock clk;
	for (uint32_t val = 0; val < maxVal; val++) {
		clk.begin();
		for (size_t pos = 0; pos < vn; pos++) {
			x += wm.rank(val, pos);
		}
		clk.end();
	}
	printf("wm.rank   %08x %5.2fKclk\n", (int)x, clk.getClock() / double(clk.getCount() * vn) * 1e-3);
	x = 0;
	const int N = 3;
	for (int i = 0; i < N; i++) {
		for (size_t r = 0; r < valBitLen; r++) {
			clk.begin();
			for (uint32_t val = 0; val < maxVal; val++) {
				x += wm.select(val, r);
			}
			clk.end();
		}
	}
	printf("wm.select %08x %5.2fKclk\n", (int)x, clk.getClock() / double(clk.getCount() * maxVal) * 1e-3);
#endif
}

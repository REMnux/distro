#include <cybozu/test.hpp>
#include <cybozu/sucvector.hpp>
#include <cybozu/xorshift.hpp>
#include <cybozu/benchmark.hpp>
#include <sstream>
#include <time.h>

uint64_t select64n(uint64_t v, uint64_t n)
{
	size_t count = 0;
	for (int i = 0; i < 64; i++) {
		if (v & (uint64_t(1) << i))
			count++;
		if (count == n)
			return i;
	}
	return 64;
}

uint64_t rank(const cybozu::SucVector& v, bool b, size_t n)
{
	uint64_t ret = 0;
	for (size_t i = 0; i < n; i++) {
		if (v.get(i) == b) {
			ret++;
		}
	}
	return ret;
}

uint64_t select(const cybozu::SucVector& v, bool b, size_t n)
{
	n++;
	for (size_t i = 0; i < v.size(); i++) {
		if (v.get(i) == b) n--;
		if (n == 0) return i;
	}
	return cybozu::NotFound;
}

/*
	compare speed
	from https://code.google.com/p/shellinford/source/browse/trunk/src/shellinford_bit_vector.cc
*/
inline uint64_t select64C(uint64_t x, uint64_t i)
{
	uint64_t x1 = ((x  & 0xaaaaaaaaaaaaaaaaULL) >>  1) + (x  & 0x5555555555555555ULL);
	uint64_t x2 = ((x1 & 0xccccccccccccccccULL) >>  2) + (x1 & 0x3333333333333333ULL);
	uint64_t x3 = ((x2 & 0xf0f0f0f0f0f0f0f0ULL) >>  4) + (x2 & 0x0f0f0f0f0f0f0f0fULL);
	uint64_t x4 = ((x3 & 0xff00ff00ff00ff00ULL) >>  8) + (x3 & 0x00ff00ff00ff00ffULL);
	uint64_t x5 = ((x4 & 0xffff0000ffff0000ULL) >> 16) + (x4 & 0x0000ffff0000ffffULL);
//	i++;
	uint64_t pos = 0;
	uint64_t v5 = x5 & 0xffffffffULL;
	if (i > v5) { i -= v5; pos += 32; }
	uint64_t v4 = (x4 >> pos) & 0x0000ffffULL;
	if (i > v4) { i -= v4; pos += 16; }
	uint64_t v3 = (x3 >> pos) & 0x000000ffULL;
	if (i > v3) { i -= v3; pos +=  8; }
	uint64_t v2 = (x2 >> pos) & 0x0000000fULL;
	if (i > v2) { i -= v2; pos +=  4; }
	uint64_t v1 = (x1 >> pos) & 0x00000003ULL;
	if (i > v1) { i -= v1; pos +=  2; }
	uint64_t v0 = (x  >> pos) & 0x00000001ULL;
	if (i > v0) { i -= v0; pos +=  1; }
	return pos;
}

CYBOZU_TEST_AUTO(testall)
{
	cybozu::XorShift rg;
	const size_t N = 30;
	std::vector<uint64_t> v;
	v.resize(N);
	for (size_t i = 0; i < N; i++) {
		v[i] = rg.get64();
	}
	cybozu::SucVector sv;
	sv.init(&v[0], v.size() * 64);
	for (size_t i = 0; i < sv.size(); i++) {
		CYBOZU_TEST_EQUAL(sv.rank(true, i), rank(sv, true, i));
		CYBOZU_TEST_EQUAL(sv.rank(false, i), rank(sv, false, i));
		CYBOZU_TEST_EQUAL(sv.select(true, i), select(sv, true, i));
		CYBOZU_TEST_EQUAL(sv.select(false, i), select(sv, false, i));
	}
}

CYBOZU_TEST_AUTO(test0)
{
	cybozu::SucVector sv;
	uint64_t blk = 722;
	sv.init(&blk, 64); // 0100101101
	CYBOZU_TEST_EQUAL(sv.rank(1, 6), 2u);
	CYBOZU_TEST_EQUAL(sv.select(0, 4), 8u);
}

CYBOZU_TEST_AUTO(select)
{
	const uint64_t v[] = {
		0xdca345ea1b5116e6ULL,
		0x951049aad88d00b0ULL,
		0x1ec7825e8db24146ULL,
		0x9af814432ac00f2cULL,
		0xffffffffffffffffULL,
		0x242342afecbfe4aaULL,
		0xffffffffffffffffULL,
		0xf324987abcef3242ULL
	};
	const size_t bitLen = sizeof(v) * 8;
	cybozu::SucVector sv;
	sv.init(v, bitLen);
	for (int s = 0; s < 2; s++) {
		const bool b = s == 0;
		const uint64_t max = sv.rank(b, bitLen);
		for (size_t r = 0; r < max; r++) {
			CYBOZU_TEST_EQUAL(sv.select(b, r), select(sv, b, r));
			CYBOZU_TEST_EQUAL(sv.rank(b, sv.select(b, r) + 1), r + 1);
		}
	}
}

CYBOZU_TEST_AUTO(relation)
{
	const uint64_t v = 0x242342afecbfe4aaULL;
	const size_t max = cybozu::popcnt<uint64_t>(v);
	for (size_t r = 0; r < max; r++) {
		CYBOZU_TEST_EQUAL(cybozu::sucvector_util::rank64(v, cybozu::sucvector_util::select64(v, r) + 1), r);
		CYBOZU_TEST_EQUAL(cybozu::sucvector_util::rank64(v, cybozu::sucvector_util::select64(v, r + 1) + 1), r + 1);
	}
}

CYBOZU_TEST_AUTO(rank)
{
	cybozu::SucVector sv;
	uint64_t blk = 6;
	sv.init(&blk, 64); // 0b0110
	const struct {
		bool val;
		uint32_t rank0;
		uint32_t rank1;
	} tbl [] = {
		{ 0, 1, 0 },
		{ 1, 1, 1 },
		{ 1, 1, 2 },
		{ 0, 2, 2 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		CYBOZU_TEST_EQUAL(sv.rank0(i + 1), tbl[i].rank0);
		CYBOZU_TEST_EQUAL(sv.rank1(i + 1), tbl[i].rank1);
		CYBOZU_TEST_EQUAL(sv.get(i), tbl[i].val);
	}
}

bool get(const uint64_t *blk, size_t pos)
{
	size_t q = pos / 64;
	size_t r = pos & 63;
	return ((blk[q] >> r) & 1) != 0;
}

uint32_t count(const uint64_t *blk, size_t pos)
{
	uint32_t ret = 0;
	for (size_t i = 0; i < pos; i++) {
		if (get(blk, i)) ret++;
	}
	return ret;
}

void testSub(const cybozu::SucVector& sv, const uint64_t *tbl, size_t tblNum)
{
	for (size_t i = 0; i < tblNum * 64; i++) {
		CYBOZU_TEST_EQUAL(sv.get(i), get(tbl, i));
		CYBOZU_TEST_EQUAL(sv.rank1(i), count(tbl, i));
	}
	CYBOZU_TEST_EQUAL(sv.rank0(tblNum * 64), sv.size(0));
	CYBOZU_TEST_EQUAL(sv.rank1(tblNum * 64), sv.size(1));
}

CYBOZU_TEST_AUTO(get_load_save)
{
	uint64_t tbl[] = {
		0x1234567812345678ULL, 0xffffffffffffffffULL, 0x1020304050607080ULL,
		0x3172039874192874ULL, 0x0000000000000000ULL, 0xfeabcbfeacbefaaeULL,
		0xfefefefefefefeefULL, 0x1864192836419823ULL, 0xaaaaaaaaaaaaaaaaULL,
	};
	const size_t tblNum = CYBOZU_NUM_OF_ARRAY(tbl);
	cybozu::SucVector sv;
	sv.init(tbl, tblNum * 64);

	testSub(sv, tbl, tblNum);
	std::string data;
	{
		std::ostringstream os;
		sv.save(os);
		data = os.str();
	}
	{
		std::istringstream is(data);
		cybozu::SucVector sv2;
		sv2.load(is);
		testSub(sv2, tbl, tblNum);
	}
}

CYBOZU_TEST_AUTO(select8)
{
	const uint32_t s = 13;
	for (uint32_t v = 0; v < (1 << s); v++) {
		for (uint32_t x = 0; x < s; x++) {
			uint64_t a = cybozu::sucvector_util::select64(v, x);
//			uint64_t a = select64n(v, x);
			uint64_t b = select64C(v, x);
			if (a < 64) {
				CYBOZU_TEST_EQUAL(a, b);
			}
		}
	}
}

CYBOZU_TEST_AUTO(select64)
{
	uint64_t tbl[] = {
		0xf0f0f0f0f0f030eeULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL,
		0x0000000000000001ULL,
		0x9190751837459273ULL,
		0xffffffffffffffffULL,
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		uint64_t v = tbl[i];
		for (size_t x = 0; x < 64; x++) {
//			uint64_t a = select64C(v, x);
			uint64_t a = cybozu::sucvector_util::select64(v, x);
			uint64_t b = select64n(v, x);
			if (a < 64) {
				CYBOZU_TEST_EQUAL(a, b);
			}
		}
	}
}

#ifdef NDEBUG

template<class R, class P1, class P2>
struct BenchSelect {
	cybozu::XorShift rg_;
	uint64_t ret_;
	R (*f_)(P1, P2);
	BenchSelect(const char *msg, R (*f)(P1, P2))
		: ret_(0)
		, f_(f)
	{
		printf("%s", msg);
		CYBOZU_BENCH("", run);
		printf(" %x\n", (int)ret_);
	}
	void run()
	{
		uint64_t v = rg_.get64();
		int x = rg_.get32() % 64;
		ret_ += f_(v, x);
	}
};

template<class T, class F>
void bench(const T& sv, const F& f, size_t N)
{
	const uint64_t M = sv.size();
	cybozu::XorShift rg;
	uint64_t ret = 0;
	clock_t begin = clock();
	for (size_t i = 0; i < N; i++) {
		uint64_t x = rg() & (M - 1);
		ret += (sv.*f)((x & 1) != 0, x);
	}
	double t = (clock() - begin) / double(CLOCKS_PER_SEC) / N * 1e9;
	printf("ret=%x, %.2fnsec\n", (int)ret, t);
}

template<class Suc>
void benchAll(size_t bitN)
{
	cybozu::XorShift rg;
	const size_t N = size_t(1) << bitN;
	std::vector<uint64_t> v(N / 64);
	for (size_t i = 0, n = v.size(); i < n; i++) {
		v[i] = rg.get64();
	}
	Suc sv;
	sv.init(&v[0], N);
	puts("bench");
	puts("rank");
	bench(sv, &Suc::rank, 10000000);
	puts("select");
	bench(sv, &Suc::select, 1000000);
}

CYBOZU_TEST_AUTO(select64Bench)
{
	BenchSelect<uint64_t, uint64_t, uint64_t>("select64C  ", select64C);
	BenchSelect<uint32_t, uint64_t, size_t>  ("cy:select64", cybozu::sucvector_util::select64);
	BenchSelect<uint64_t, uint64_t, uint64_t>("select64n  ", select64n);

	puts("SucVectorLt4G");
	benchAll<cybozu::SucVectorLt4G>(31);
	puts("SucVector");
	benchAll<cybozu::SucVector>(31);
}
#endif


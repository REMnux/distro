#include <cybozu/wavelet_matrix.hpp>
#include <cybozu/xorshift.hpp>
#include <algorithm>
#include <cybozu/benchmark.hpp>
#include <stdlib.h>

struct Naive {
private:
	Naive(const Naive&);
	void operator=(const Naive&);
public:
	const std::vector<uint8_t>& v_;
	explicit Naive(const std::vector<uint8_t>& v)
		: v_(v)
	{
	}
	size_t get(size_t pos) const
	{
		return v_[pos];
	}
	size_t rank(uint32_t val, size_t pos) const
	{
		return std::count(v_.begin(), v_.begin() + pos, val);
	}
	size_t rankLt(uint32_t val, size_t pos) const
	{
		size_t ret = 0;
		for (size_t i = 0, n = pos; i < n; i++) {
			if (v_[i] < val) ret++;
		}
		return ret;
	}
	size_t select(uint32_t val, size_t n) const
	{
		const size_t N = v_.size();
		n++;
		for (size_t i = 0; i < N; i++) {
			if (v_[i] == val) n--;
			if (n == 0) return i;
		}
		return cybozu::NotFound;
	}
};

void add(size_t& ret, size_t x)
{
	ret += x;
}

template<class T, class RG>
void bench_get(const T& wm, RG& rg, size_t N)
{
	size_t ret = 0;
	printf("get   ");
	CYBOZU_BENCH("", add, ret, wm.get(rg() & (N - 1)));
	printf(" ret=%u\n", (int)ret);
}

template<class T, class RG>
void bench_rank(const T& wm, RG& rg, size_t N)
{
	size_t ret = 0;
	printf("rank  ");
	CYBOZU_BENCH("", add, ret, wm.rank(uint8_t(rg()), rg() & (N - 1)));
	printf(" ret=%u\n", (int)ret);
}

template<class T, class RG>
void bench_rankLt(const T& wm, RG& rg, size_t N)
{
	size_t ret = 0;
	printf("rank  ");
	CYBOZU_BENCH("", add, ret, wm.rankLt(uint8_t(rg()), rg() & (N - 1)));
	printf(" ret=%u\n", (int)ret);
}

template<class T, class RG>
void oneSelect(size_t& ret, const T& wm, RG& rg, const std::vector<int>& maxTbl)
{
	uint8_t c = uint8_t(rg());
	size_t pos = rg() % maxTbl[c];
	ret += wm.select(c, pos);
}

template<class T, class Vec8, class RG>
void bench_select(const T& wm, const Vec8& v, RG& rg)
{
	size_t ret = 0;
	std::vector<int> maxTbl;
	maxTbl.resize(256);
	for (int i = 0; i < 256; i++) {
		maxTbl[i] = (int)wm.size(i) + 1;
	}
	printf("select");
	CYBOZU_BENCH("", oneSelect, ret, wm, rg, maxTbl);
	printf(" ret=%u\n", (int)ret);
	Naive nv(v);
/*
	over pos=67108805, i=1024, v=58
over pos=67108841, i=1026, v=35
*/
	const struct {
		uint8_t v;
		uint64_t pos;
	} tbl[] = {
		{ 58, 1024 },
		{ 35, 1026 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		uint8_t c = tbl[i].v;
		uint64_t pos = tbl[i].pos;
		uint64_t a = nv.select(c, pos);
		uint64_t b = wm.select(c, pos);
		if (a != b) {
			printf("ERR c=%d, pos=%d, a=%d, b=%d\n", (int)c, (int)pos, (int)a, (int)b);
			exit(1);
		}
	}
	puts("select ok");
}

template<class Vec8>
void bench(const cybozu::WaveletMatrix& wm, const Vec8& v, size_t N)
{
	cybozu::XorShift rg;
	puts("wm");
	bench_get(wm, rg, N);
	bench_rank(wm, rg, N);
	bench_rankLt(wm, rg, N);
	bench_select(wm, v, rg);
#if 0
	bench_get(nv, "nv", 1000000, N);
	bench_rank(nv, "nv", 10, N);
	bench_rank_lt(nv, "nv", 10, N);
	bench_select(nv, "nv", 10);
#endif
}

void run(size_t bitLen)
{
	cybozu::XorShift rg;
	cybozu::WaveletMatrix wm;
	const size_t N = size_t(1) << bitLen;
	printf("%09llx\n", (long long)N);
	puts("init");
	std::vector<uint8_t> v;
	v.resize(N);
	for (size_t i = 0; i < N; i++) {
		v[i] = uint8_t(rg());
	}
#if 0
	printf("v\n");
	for (size_t i = 0; i < N; i++) {
		printf("%d ", v[i]);
	}
	printf("\n");
#endif
	wm.init(v, 8);
	puts("start");
	bench(wm, v, N);
}

int main(int argc, char *argv[])
	try
{
	size_t bitLen = 26;
	argc--, argv++;
	while (argc > 0) {
		if (argc > 1 && strcmp(*argv, "-b") == 0) {
			argc--, argv++;
			bitLen = atoi(*argv);
		} else
		{
			printf("usage wm_bench_smpl.exe [-b bitLen]\n");
			return 1;
		}
		argc--, argv++;
	}
	run(bitLen);
} catch (std::exception& e) {
	printf("err %s\n", e.what());
}

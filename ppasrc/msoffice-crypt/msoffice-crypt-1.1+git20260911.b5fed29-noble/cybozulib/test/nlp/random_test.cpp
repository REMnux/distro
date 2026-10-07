#include <stdio.h>
#include <cybozu/test.hpp>
#include <cybozu/nlp/random.hpp>
#include <cybozu/random_generator.hpp>
#include <math.h>
#include <time.h>

CYBOZU_TEST_AUTO(random)
{
	double sum = 0;
	double sqsum = 0;
	const int n = 1000000;

	cybozu::nlp::NormalRandomGenerator g;
	for (int i = 0; i < n; i++) {
		double v = g.get();
		sum += v;
		sqsum += v * v;
	}
	double m = sum / n;
	double s = sqsum / n - m * m;
	printf("m=%f, s=%f\n", m, s);
	CYBOZU_TEST_ASSERT(fabs(m) < 2e-3);
	CYBOZU_TEST_ASSERT(fabs(s - 1) < 2e-3);
}

template<class RG>
struct Benchmark {
	RG rg;
	Benchmark()
	{
		const int N = 1000000;
		uint32_t a = 0;
		clock_t begin = clock();
		for (int i = 0; i < N; i++) {
			a += rg();
		}
		clock_t end = clock();
		double time = (end - begin) / double(CLOCKS_PER_SEC) / N * 1e6;
		printf("%x %.3fusec\n", a, time);
	}
};

CYBOZU_TEST_AUTO(bench)
{
	Benchmark<cybozu::nlp::UniformRandomGenerator>();
	Benchmark<cybozu::RandomGenerator>();
}

CYBOZU_TEST_AUTO(urando_bench)
{
	cybozu::RandomGenerator rg;
	const int N = 1000000;
	clock_t begin = clock();
	char buf[20];
	for (int i = 0; i < N; i++) {
		rg.read(buf, sizeof(buf));
	}
	clock_t end = clock();
	double time = (end - begin) / double(CLOCKS_PER_SEC) / N * 1e6;
	printf("%.3fusec\n", time);
}

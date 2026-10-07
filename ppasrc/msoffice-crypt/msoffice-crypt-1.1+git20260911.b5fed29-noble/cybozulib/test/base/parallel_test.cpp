#include <stdio.h>
#include <cybozu/parallel.hpp>
#include <cybozu/test.hpp>
#include <cybozu/time.hpp>
#include <math.h>

struct X {
	int x;
	int processedNum;
	X()
		: x(0)
		, processedNum(0)
	{
	}
	bool operator()(int idx, int /*threadIdx*/)
	{
		double ret = 0;
		const int N = 1000;
		for (int i = 0; i < N; i++) {
			ret += sin(double(i) / N) * idx;
		}
		cybozu::AtomicAdd(&processedNum, 1);
		cybozu::AtomicAdd(&x, (int)ret);
		return true;
	}
};

void test(int n, int threadNum)
{
	X x;
	cybozu::parallel_for(x, n, threadNum);
	CYBOZU_TEST_EQUAL(x.processedNum, n);
}

CYBOZU_TEST_AUTO(parallel)
	try
{
	for (int threadNum = 1; threadNum < 8; threadNum++) {
		printf("threadNum=%d\n", threadNum);
		double begin = cybozu::GetCurrentTimeSec();
		for (int n = 1; n < 100; n += 10) {
			test(n, threadNum);
		}
		printf("time %f\n", cybozu::GetCurrentTimeSec() - begin);
	}
} catch (std::exception& e) {
	printf("err %s\n", e.what());
}

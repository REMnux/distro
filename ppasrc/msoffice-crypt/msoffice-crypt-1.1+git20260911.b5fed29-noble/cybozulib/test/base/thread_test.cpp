#include <stdio.h>
#include <cybozu/thread.hpp>
#include <cybozu/mutex.hpp>
#include <cybozu/test.hpp>
#include <cybozu/atomic.hpp>

const int N = 1000000;
int s_count = 0;

class ThreadTest : public cybozu::ThreadBase {
	cybozu::Mutex& mutex_;
	int num_;
public:
	ThreadTest(cybozu::Mutex& mutex, int num)
		: mutex_(mutex)
		, num_(num)
	{
		printf("make %d\n", num_);
	}

	void threadEntry()
	{
		printf("start %d\n", num_);
		for (int i = 0; i < N; i++) {
			cybozu::AutoLock al(mutex_);
			s_count++;
		}
		printf("end %d\n", num_);
	}
};

CYBOZU_TEST_AUTO(cpuNum)
{
	int num = cybozu::GetProcessorNum();
	CYBOZU_TEST_ASSERT(num > 0);
	printf("cpu num=%d\n", num);
}

CYBOZU_TEST_AUTO(autoLock)
{
	cybozu::Mutex mutex_;
	ThreadTest t1(mutex_, 1);
	ThreadTest t2(mutex_, 2);
	if (!t1.beginThread()) puts("err thread 1");
	if (!t2.beginThread()) puts("err thread 2");
	cybozu::Sleep(1000);
	/*
		verity number of increment
	*/
	puts("start main");
	for (int i = 0; i < N; i++) {
		cybozu::AutoLock al(mutex_);
		s_count++;
	}
	puts("end main");

	if (!t1.joinThread()) puts("err join 1");
	if (!t2.joinThread()) puts("err join 2");
	cybozu::mfence();
	CYBOZU_TEST_EQUAL(s_count, N * 3);
}


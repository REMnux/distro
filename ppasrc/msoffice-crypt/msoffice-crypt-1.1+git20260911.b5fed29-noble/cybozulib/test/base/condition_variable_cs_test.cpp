#ifdef _WIN32
	#undef _WIN32_WINNT
	#define _WIN32_WINNT 0x600
#endif
#include <stdio.h>
#include <cybozu/thread.hpp>
#include <cybozu/condition_variable_cs.hpp>
#include <cybozu/test.hpp>

class Thread : public cybozu::ThreadBase {
	cybozu::CriticalSection& cs_;
	cybozu::ConditionVariableCs& cv_;
	bool done_;
public:
	Thread(cybozu::CriticalSection& cs, cybozu::ConditionVariableCs& cv)
		: cs_(cs)
		, cv_(cv)
		, done_(false)
	{
	}

	void threadEntry()
	{
		cs_.lock();
		cv_.wait(cs_);
		cs_.unlock();
		done_ = true;
	}
	bool done() const { return done_; }
};

CYBOZU_TEST_AUTO(notifyOne)
{
	cybozu::CriticalSection cs;
	cybozu::ConditionVariableCs cv;

	Thread t1(cs, cv);
	Thread t2(cs, cv);
	Thread t3(cs, cv);

	t1.beginThread();
	t2.beginThread();
	t3.beginThread();
	cybozu::Sleep(100);

	CYBOZU_TEST_EQUAL(t1.done() + t2.done() + t3.done(), 0);

	cv.notifyOne();
	cybozu::Sleep(100);
	CYBOZU_TEST_EQUAL(t1.done() + t2.done() + t3.done(), 1);

	cv.notifyOne();
	cybozu::Sleep(100);
	CYBOZU_TEST_EQUAL(t1.done() + t2.done() + t3.done(), 2);

	cv.notifyOne();
	cybozu::Sleep(100);
	CYBOZU_TEST_EQUAL(t1.done() + t2.done() + t3.done(), 3);

	t1.joinThread();
	t2.joinThread();
	t3.joinThread();
}

CYBOZU_TEST_AUTO(broadcast)
{
	cybozu::CriticalSection cs;
	cybozu::ConditionVariableCs cv;

	Thread t1(cs, cv);
	Thread t2(cs, cv);
	Thread t3(cs, cv);

	t1.beginThread();
	t2.beginThread();
	t3.beginThread();
	cybozu::Sleep(100);

	CYBOZU_TEST_EQUAL(t1.done() + t2.done() + t3.done(), 0);

	cv.notifyOne();
	cybozu::Sleep(100);
	CYBOZU_TEST_EQUAL(t1.done() + t2.done() + t3.done(), 1);

	cv.notifyAll();
	cybozu::Sleep(100);
	CYBOZU_TEST_EQUAL(t1.done() + t2.done() + t3.done(), 3);

	t1.joinThread();
	t2.joinThread();
	t3.joinThread();
}

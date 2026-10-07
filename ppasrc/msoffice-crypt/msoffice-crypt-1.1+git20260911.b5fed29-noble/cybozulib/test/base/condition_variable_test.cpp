#include <stdio.h>
#include <cybozu/thread.hpp>
#include <cybozu/condition_variable.hpp>
#include <cybozu/test.hpp>

class Thread : public cybozu::ThreadBase {
	cybozu::Mutex& mutex_;
	cybozu::ConditionVariable& cv_;
	bool done_;
public:
	Thread(cybozu::Mutex& mutex, cybozu::ConditionVariable& cv)
		: mutex_(mutex)
		, cv_(cv)
		, done_(false)
	{
	}

	void threadEntry()
	{
		mutex_.lock();
		cv_.wait(mutex_);
		mutex_.unlock();
		done_ = true;
	}
	bool done() const { return done_; }
};

CYBOZU_TEST_AUTO(notifyOne)
{
	cybozu::Mutex mutex;
	cybozu::ConditionVariable cv;

	Thread t1(mutex, cv);
	Thread t2(mutex, cv);
	Thread t3(mutex, cv);

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
	cybozu::Mutex mutex;
	cybozu::ConditionVariable cv;

	Thread t1(mutex, cv);
	Thread t2(mutex, cv);
	Thread t3(mutex, cv);

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

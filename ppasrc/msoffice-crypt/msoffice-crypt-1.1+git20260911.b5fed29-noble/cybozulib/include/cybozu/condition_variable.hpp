#pragma once
/**
	@file
	@brief conditional variable

	@author MITSUNARI Shigeo(@herumi)
	@note http://www.cs.wustl.edu/~schmidt/win32-cv-1.html
*/
#include <cybozu/mutex.hpp>

namespace cybozu {

class ConditionVariable {
public:
	ConditionVariable()
	{
#ifdef _WIN32
		waiterNum_ = 0;
		wasBroadcast_ = false;
		sema_ = CreateSemaphore(NULL, 0, 0x7fffffff, NULL);
		InitializeCriticalSection(&waiterNumLock_);
		waiterDone_ = CreateEvent(NULL, FALSE, FALSE, NULL);
#else
		pthread_cond_init(&cv_, NULL);
#endif
	}
	~ConditionVariable()
	{
#ifdef _WIN32
		CloseHandle(waiterDone_);
		DeleteCriticalSection(&waiterNumLock_);
		CloseHandle(sema_);
#else
		pthread_cond_destroy(&cv_);
#endif
	}
	void wait(cybozu::Mutex& mutex)
	{
#ifdef _WIN32
		EnterCriticalSection(&waiterNumLock_);
		waiterNum_++;
		LeaveCriticalSection(&waiterNumLock_);

		SignalObjectAndWait(mutex.hdl_, sema_, INFINITE, FALSE);
		EnterCriticalSection(&waiterNumLock_);

		waiterNum_--;
		int last_waiter = wasBroadcast_ && waiterNum_ == 0;

		LeaveCriticalSection (&waiterNumLock_);
		if (last_waiter) {
			SignalObjectAndWait(waiterDone_, mutex.hdl_, INFINITE, FALSE);
		} else {
			WaitForSingleObject(mutex.hdl_, INFINITE);
		}
#else
		pthread_cond_wait(&cv_, &mutex.hdl_);
#endif
	}
	void notifyOne()
	{
#ifdef _WIN32
		EnterCriticalSection(&waiterNumLock_);
		bool have_waiters = waiterNum_ > 0;
		LeaveCriticalSection (&waiterNumLock_);

		if (have_waiters) {
			ReleaseSemaphore (sema_, 1, 0);
		}
#else
		pthread_cond_signal(&cv_);
#endif
	}
	void notifyAll()
	{
#ifdef _WIN32
		EnterCriticalSection(&waiterNumLock_);
		bool have_waiters = false;

		if (waiterNum_ > 0) {
			wasBroadcast_ = true;
			have_waiters = true;
		}

		if (have_waiters) {
			ReleaseSemaphore (sema_, waiterNum_, 0);

			LeaveCriticalSection(&waiterNumLock_);

			WaitForSingleObject(waiterDone_, INFINITE);
			wasBroadcast_ = false;
		} else {
			LeaveCriticalSection(&waiterNumLock_);
		}
#else
		pthread_cond_broadcast(&cv_);
#endif
	}
private:
	ConditionVariable(const ConditionVariable&);
	ConditionVariable& operator=(const ConditionVariable&);
#ifdef _WIN32
	int waiterNum_;
	CRITICAL_SECTION waiterNumLock_;
	HANDLE sema_;
	HANDLE waiterDone_;
	bool wasBroadcast_;
#else
	pthread_cond_t cv_;
#endif
};

} // cybozu

#pragma once
/**
	@file
	@brief condition variable cs(for Windows Vista or later)

	@author MITSUNARI Shigeo(@herumi)
	@note wrapper for condition variable for Windows Vista or lator
	cybozu::CriticalSection is same as cybozu::Mutex on Linux
*/
#include <cybozu/critical_section.hpp>

#if defined(_WIN32) && (_WIN32_WINNT < 0x0600)
	#error "not support Windows Xp or before"
#endif

namespace cybozu {

namespace thread {
#ifdef _WIN32
	typedef CONDITION_VARIABLE CvCsHandle;
#else
	typedef pthread_cond_t CvCsHandle;
#endif
} // thread

class ConditionVariableCs {
public:
	ConditionVariableCs()
	{
#ifdef _WIN32
		InitializeConditionVariable(&hdl_);
#else
		pthread_cond_init(&hdl_, NULL);
#endif
	}
	~ConditionVariableCs()
	{
#ifdef _WIN32
		// none
#else
		pthread_cond_destroy(&hdl_);
#endif
	}
	void wait(cybozu::CriticalSection& cs)
	{
#ifdef _WIN32
		SleepConditionVariableCS(&hdl_, &cs.hdl_, INFINITE);
#else
		pthread_cond_wait(&hdl_, &cs.hdl_);
#endif
	}
	void notifyOne()
	{
#ifdef _WIN32
		WakeConditionVariable(&hdl_);
#else
		pthread_cond_signal(&hdl_);
#endif
	}
	void notifyAll()
	{
#ifdef _WIN32
		WakeAllConditionVariable(&hdl_);
#else
		pthread_cond_broadcast(&hdl_);
#endif
	}
private:
	ConditionVariableCs(const ConditionVariableCs&);
	ConditionVariableCs& operator=(const ConditionVariableCs&);
	thread::CvCsHandle hdl_;
};

} // cybozu

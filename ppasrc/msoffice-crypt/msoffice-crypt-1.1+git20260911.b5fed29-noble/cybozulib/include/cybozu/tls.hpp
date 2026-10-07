#pragma once
/**
	@file
	@brief thread local strage

	@author MITSUNARI Shigeo(@herumi)
	@author MITSUNARI Shigeo
*/
#ifdef _MSC_VER
	#ifndef WIN32_LEAN_AND_MEAN
		#define WIN32_LEAN_AND_MEAN
	#endif
	#include <windows.h>
	#define CYBOZU_TLS __declspec(thread)
#else
	#include <pthread.h>
	#include <limits.h>
	#define CYBOZU_TLS __thread
#endif

namespace cybozu {

namespace tls {

#ifdef _WIN32

typedef DWORD TlsIndex;
const TlsIndex invalidTlsIndex = 0xFFFFFFFF;

inline TlsIndex Init()
{
	return ::TlsAlloc();
}

inline void *GetValue(TlsIndex idx)
{
	return ::TlsGetValue(idx);
}

inline bool SetValue(TlsIndex idx, void *val)
{
	return ::TlsSetValue(idx, val) != 0;
}

inline bool Term(TlsIndex idx)
{
	return ::TlsFree(idx) != 0;
}

#else

typedef pthread_key_t TlsIndex;
const TlsIndex invalidTlsIndex = PTHREAD_KEYS_MAX + 1;

inline TlsIndex Init()
{
	pthread_key_t idx;
	if (!::pthread_key_create(&idx, 0)) {
		return idx;
	}
	return invalidTlsIndex;
}

inline void *GetValue(TlsIndex idx)
{
	return ::pthread_getspecific(idx);
}

inline bool SetValue(TlsIndex idx, void *val)
{
	return ::pthread_setspecific(idx, val) == 0;
}

inline bool Term(TlsIndex idx)
{
	return ::pthread_key_delete(idx) == 0;
}

#endif

} // cybozu::tls

/**
	Tls class
	make Tls instance before creating thread
*/
class Tls {
	tls::TlsIndex idx_;
	bool isValid() const
	{
		return idx_ != tls::invalidTlsIndex;
	}
public:
	Tls()
		: idx_(tls::Init())
	{
	}
	bool set(void *p)
	{
		return isValid() && tls::SetValue(idx_, p);
	}
	void *get() const
	{
		return isValid() ? tls::GetValue(idx_) : 0;
	}
	~Tls()
	{
		if (isValid()) {
			set(0);
			tls::Term(idx_);
		}
	}
};

} // cybozu

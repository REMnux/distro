#include <stdio.h>
#include <cybozu/thread.hpp>
#include <cybozu/tls.hpp>
#include <cybozu/test.hpp>

static CYBOZU_TLS int s_x;

class Test : public cybozu::ThreadBase {
	int a_;
	cybozu::Tls *tls_;
public:
	Test()
		: a_(0)
		, tls_(0)
	{
	}
	void set(int a, cybozu::Tls& tls)
	{
		a_ = a;
		tls_ = &tls;
	}
	void threadEntry()
	{
		printf("start %d\n", a_);
		s_x = a_;
		tls_->set(&a_);
		cybozu::Sleep(500);
		printf("tls=%d, s_x=%d, %p\n", *static_cast<const int*>(tls_->get()), s_x, &s_x);
		CYBOZU_TEST_EQUAL(a_, s_x);
		CYBOZU_TEST_EQUAL(a_, *static_cast<const int*>(tls_->get()));
	}
};

CYBOZU_TEST_AUTO(tls)
{
	cybozu::Tls tls;
	{
		const int n = 10;
		Test t[n];
		for (int i = 0; i < n; i++) {
			t[i].set(i, tls);
		}
		for (int i = 0; i < n; i++) {
			t[i].beginThread();
		}
		for (int i = 0; i < n; i++) {
			t[i].joinThread();
		}
	}
}

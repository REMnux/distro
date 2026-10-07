#include <cybozu/atomic.hpp>
#include <cybozu/test.hpp>

CYBOZU_TEST_AUTO(atomic_not_in_thread)
{
	int a, b, c;
	int64_t ia, ib;

	a = 2, b = 5;
	cybozu::AtomicAdd(&a, b);
	CYBOZU_TEST_EQUAL(a, 7);

#if (CYBOZU_OS_BIT == 64)
	ia = 4, ib = 9;
	cybozu::AtomicAdd(&ia, ib);
	CYBOZU_TEST_EQUAL(ia, 13);
#endif

	a = 4;
	c = cybozu::AtomicCompareExchange(&a, 9, 4);
	CYBOZU_TEST_EQUAL(c, 4);
	CYBOZU_TEST_EQUAL(a, 9);

	a = 4;
	c = cybozu::AtomicCompareExchange(&a, 9, 5);
	CYBOZU_TEST_EQUAL(c, 4);
	CYBOZU_TEST_EQUAL(a, 4);

	ia = 10;
	ib = cybozu::AtomicCompareExchange<int64_t>(&ia, 0x123456789012LL, 10);
	CYBOZU_TEST_EQUAL(ib, 10);
	CYBOZU_TEST_EQUAL(ia, 0x123456789012LL);

	ia = 10;
	ib = cybozu::AtomicCompareExchange<int64_t>(&ia, 0x123456789012LL, 11);
	CYBOZU_TEST_EQUAL(ib, 10);
	CYBOZU_TEST_EQUAL(ia, 10);

	a = 3;
	b = cybozu::AtomicExchange(&a, 4);
	CYBOZU_TEST_EQUAL(b, 3);
	CYBOZU_TEST_EQUAL(a, 4);

	size_t ua, ub;
	ua = 5;
	ub = cybozu::AtomicExchange<size_t>(&ua, 4);
	CYBOZU_TEST_EQUAL(ua, 4ULL);
	CYBOZU_TEST_EQUAL(ub, 5ULL);
}

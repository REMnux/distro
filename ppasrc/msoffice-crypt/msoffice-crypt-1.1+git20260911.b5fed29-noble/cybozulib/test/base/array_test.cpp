/*
	debug for AlignedAlloc with doClear = false
*/
#include <cybozu/array.hpp>
#include <cybozu/test.hpp>

int a_count = 0;
int b_count = 0;

struct A {
	int n;
	A()
		: n(a_count)
	{
		a_count++;
	}
	~A()
	{
		a_count--;
	}
};

struct B {
	std::string x;
	B()
	{
		if (b_count == 3) throw std::bad_exception();
		b_count++;
		x = "dummy";
	}
	~B()
	{
		b_count--;
	}
};

CYBOZU_TEST_AUTO(scoped_array)
{
	{
		cybozu::ScopedArray<A> a(10);
		CYBOZU_TEST_EQUAL(a_count, 10);
		for (int i = 0; i < 10; i++) {
			CYBOZU_TEST_EQUAL(a[i].n, i);
			CYBOZU_TEST_EQUAL(a.data()[i].n, i);
		}
	}
	CYBOZU_TEST_EQUAL(a_count, 0);
}

bool isAligned(const void *p, size_t alignSize)
{
	return (uintptr_t(p) & (alignSize - 1)) == 0;
}

CYBOZU_TEST_AUTO(aligned_array)
{
	cybozu::AlignedArray<int> a(10);
	CYBOZU_TEST_EQUAL(a.size(), 10);
	CYBOZU_TEST_ASSERT(isAligned(&a[0], 16));
	for (int i = 0; i < 10; i++) {
		CYBOZU_TEST_EQUAL(a[i], 0);
		CYBOZU_TEST_EQUAL(a.data()[i], 0);
	}
}

CYBOZU_TEST_AUTO(aligned_array_char)
{
	cybozu::AlignedArray<char> a(51);
	CYBOZU_TEST_ASSERT(isAligned(&a[0], 16));
	for (size_t i = 0; i < a.size(); i++) {
		CYBOZU_TEST_EQUAL(a[i], 0);
	}
}

CYBOZU_TEST_AUTO(resize)
{
	cybozu::AlignedArray<char> a(10);
	CYBOZU_TEST_EQUAL(a.size(), 10);
	CYBOZU_TEST_ASSERT(isAligned(&a[0], 16));
	for (size_t i = 0; i < 10; i++) {
		a[i] = (char)i;
	}
	a.resize(20);
	CYBOZU_TEST_EQUAL(a.size(), 20);
	CYBOZU_TEST_ASSERT(isAligned(&a[0], 16));
	for (size_t i = 0; i < 10; i++) {
		CYBOZU_TEST_EQUAL(a[i], (char)i);
	}
	for (size_t i = 10; i < 20; i++) {
		CYBOZU_TEST_EQUAL(a[i], (char)0);
	}
	const char *p = &a[0];
	a.resize(4);
	CYBOZU_TEST_EQUAL(a.size(), 4);
	CYBOZU_TEST_EQUAL(&a[0], p);
	for (size_t i = 0; i < 4; i++) {
		CYBOZU_TEST_EQUAL(a[i], (char)i);
	}
	CYBOZU_TEST_ASSERT(!a.empty());
	a.resize(0);
	CYBOZU_TEST_EQUAL(a.size(), 0);
	CYBOZU_TEST_ASSERT(a.empty());
	a.resize(20);
	CYBOZU_TEST_EQUAL(a.size(), 20);
	CYBOZU_TEST_EQUAL(&a[0], p); // same pointer until resize(20)
	a.resize(21);
	CYBOZU_TEST_EQUAL(a.size(), 21);
	CYBOZU_TEST_ASSERT(&a[0] != p); // different pointer
}

CYBOZU_TEST_AUTO(AlignedArray_copy)
{
	cybozu::AlignedArray<int> x, z, y;
	x.resize(10);
	for (size_t i = 0; i < x.size(); i++) x[i] = (int)i;
	y.resize(5);

	y = x;
	z = x;
	cybozu::AlignedArray<int> w(x);
	CYBOZU_TEST_EQUAL_ARRAY(x.data(), y.data(), x.size());
	CYBOZU_TEST_EQUAL_ARRAY(x.data(), z.data(), x.size());
	CYBOZU_TEST_EQUAL_ARRAY(x.data(), w.data(), x.size());

	w.resize(25);
	for (size_t i = 0; i < w.size(); i++) w[i] = (int)i + 123;
	w = x;
	CYBOZU_TEST_EQUAL_ARRAY(x.data(), w.data(), x.size());
}

#if (CYBOZU_CPP_VERSION == CYBOZU_CPP_VERSION_CPP11)
CYBOZU_TEST_AUTO(AlignedArray_move)
{
	cybozu::AlignedArray<long> x, y;
	x.resize(10);
	y.resize(5);
	const long* px = x.data();
	const long* py = y.data();
	CYBOZU_TEST_EQUAL(x.size(), 10);
	CYBOZU_TEST_EQUAL(y.size(), 5);
	for (size_t i = 0; i < x.size(); i++) {
		x[i] = (long)i;
	}
	for (size_t i = 0; i < y.size(); i++) {
		y[i] = (long)i + 10;
	}
	for (size_t i = 0; i < x.size(); i++) {
		CYBOZU_TEST_EQUAL(x[i], (long)i);
	}
	for (size_t i = 0; i < y.size(); i++) {
		CYBOZU_TEST_EQUAL(y[i], 10 + (long)i);
	}
	cybozu::AlignedArray<long> z(std::move(x));
	const long* pz = &z[0];
	CYBOZU_TEST_EQUAL(pz, px);
	CYBOZU_TEST_EQUAL(x.data(), (long*)0);
	CYBOZU_TEST_EQUAL(z.data(), px);
	CYBOZU_TEST_EQUAL(z.size(), 10);
	for (size_t i = 0; i < 10; i++) {
		CYBOZU_TEST_EQUAL(z[i], (long)i);
	}
	CYBOZU_TEST_EQUAL(x.size(), 0);

	z = std::move(y);
	CYBOZU_TEST_EQUAL(py, &z[0]);
	CYBOZU_TEST_EQUAL(py, z.data());
	CYBOZU_TEST_EQUAL(y.size(), 0);
	CYBOZU_TEST_EQUAL(z.size(), 5);
	for (size_t i = 0; i < 5; i++) {
		CYBOZU_TEST_EQUAL(z[i], 10 + (long)i);
	}
}
#endif

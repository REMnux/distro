#include <stdio.h>
#include <cybozu/test.hpp>
#include <cybozu/stream.hpp>
#include <cybozu/serializer.hpp>
#include <cybozu/nlp/sparse.hpp>
#include <map>

template<class IntVec1, class IntVec2>
void test_push_back()
{
	IntVec1 v1;
	IntVec2 v2;

	const struct {
		unsigned int pos;
		int val;
	} tbl[] = {
		{ 2, 4 }, { 5, 2 }, { 100, 4 }, { 101, 3}, { 999, 4 }, { 1000, 1 }, { 1896, 3 },
		{ 2793, 511 }, { 4000, 100 }, { 100000, 999 }, { 116384, 33 },
		{ 2397152, 123459 }, { 278435456, 9 }, { 378435456, 9 }, { 1378435456, 9 },
		{ 2378435456U, 1234 },
		{ 3378435456U, 1234 },
		{ 4294967295U, 56789 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		v1.push_back(tbl[i].pos, tbl[i].val);
		v2.push_back(tbl[i].pos, tbl[i].val);
	}
	CYBOZU_TEST_EQUAL(v1.size(), CYBOZU_NUM_OF_ARRAY(tbl));
	CYBOZU_TEST_EQUAL(v2.size(), CYBOZU_NUM_OF_ARRAY(tbl));
	int j = 0;
	for (typename IntVec1::const_iterator i = v1.begin(), ie = v1.end(); i != ie; ++i) {
		CYBOZU_TEST_EQUAL(i->pos(), tbl[j].pos);
		CYBOZU_TEST_EQUAL(i->val(), tbl[j].val);
		j++;
	}
	j = 0;
	for (typename IntVec2::const_iterator i = v2.begin(), ie = v2.end(); i != ie; ++i) {
		CYBOZU_TEST_EQUAL(i->pos(), tbl[j].pos);
		CYBOZU_TEST_EQUAL(i->val(), tbl[j].val);
		j++;
	}
	{
		std::stringstream ss;
		cybozu::save(ss, v1);
		IntVec1 out1;
		cybozu::load(out1, ss);
		CYBOZU_TEST_ASSERT(v1 == out1);
	}
}

template<class IntVec>
void test_empty()
{
	IntVec v;
	CYBOZU_TEST_EQUAL((int)v.size(), 0);
	CYBOZU_TEST_ASSERT(v.empty());
	for (typename IntVec::const_iterator i = v.begin(); i != v.end(); ++i) {
		printf("%d\n", i->val());
	}
	v.push_back(3, 1);
	CYBOZU_TEST_EQUAL((int)v.size(), 1);
	CYBOZU_TEST_ASSERT(!v.empty());
	for (typename IntVec::const_iterator i = v.begin(); i != v.end(); ++i) {
		CYBOZU_TEST_EQUAL(i->pos(), (size_t)3);
		CYBOZU_TEST_EQUAL(i->val(), 1);
	}
	v.push_back(4, 2);
	CYBOZU_TEST_EQUAL((int)v.size(), 2);
	int j = 0;
	for (typename IntVec::const_iterator i = v.begin(); i != v.end(); ++i) {
		CYBOZU_TEST_EQUAL(i->pos(), size_t(j + 3));
		CYBOZU_TEST_EQUAL(i->val(), j + 1);
		j++;
	}
	v.clear();
	CYBOZU_TEST_EQUAL((int)v.size(), 0);
	CYBOZU_TEST_ASSERT(v.empty());
	IntVec v1, v2;
	for (int i = 0; i < 3; i++) {
		v1.push_back(i, i);
		v2.push_back(i, i);
	}
	CYBOZU_TEST_ASSERT(v1 == v2);
	v2.push_back(10, 10);
	CYBOZU_TEST_ASSERT(v1 != v2);
}

CYBOZU_TEST_AUTO(push_back1)
{
	typedef cybozu::nlp::SparseVector<int> IntVec1;
	typedef cybozu::nlp::SparseVector<int> IntVec2;

	test_push_back<IntVec1, IntVec2>();
	test_empty<IntVec1>();
}

CYBOZU_TEST_AUTO(push_back2)
{
	typedef cybozu::nlp::SparseVector<int, cybozu::nlp::option::CompressedPositionTbl> IntVec1;
	typedef cybozu::nlp::SparseVector<int, cybozu::nlp::option::CompressedPositionTbl> IntVec2;

	test_push_back<IntVec1, IntVec2>();
	test_empty<IntVec1>();
}

template<class DoubleVec, class IntVec>
void test_intersect()
{
	DoubleVec dv;
	IntVec iv;

	const struct {
		unsigned int pos;
		double val;
	} dTbl[] = {
		{ 5, 3.14 }, { 10, 2 }, { 12, 1.4 }, { 100, 2.3 }, { 1000, 4 },
	};

	const struct {
		unsigned int pos;
		int val;
	} iTbl[] = {
		{ 2, 4 }, { 5, 2 }, { 100, 4 }, { 101, 3}, { 999, 4 }, { 1000, 1 }, { 2000, 3 },
	};

	const struct {
		unsigned int pos;
		double d;
		int i;
	} interTbl[] = {
		 { 5, 3.14, 2 }, { 100, 2.3, 4 }, { 1000, 4, 1 }
	};

	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(dTbl); i++) {
		dv.push_back(dTbl[i].pos, dTbl[i].val);
	}
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(iTbl); i++) {
		iv.push_back(iTbl[i].pos, iTbl[i].val);
	}

	int j = 0;
	for (typename DoubleVec::const_iterator i = dv.begin(), ie = dv.end(); i != ie; ++i) {
		CYBOZU_TEST_EQUAL(i->pos(), dTbl[j].pos);
		CYBOZU_TEST_EQUAL(i->val(), dTbl[j].val);
		j++;
	}

	j = 0;
	for (typename IntVec::const_iterator i = iv.begin(), ie = iv.end(); i != ie; ++i) {
		CYBOZU_TEST_EQUAL(i->pos(), iTbl[j].pos);
		CYBOZU_TEST_EQUAL(i->val(), iTbl[j].val);
		j++;
	}

	int sum = 0;
	for (typename IntVec::const_iterator i = iv.begin(), ie = iv.end(); i != ie; ++i) {
		sum += i->val() * i->val();
	}
	CYBOZU_TEST_EQUAL(sum, 71);

	typedef cybozu::nlp::Intersection<DoubleVec, IntVec> InterSection;
	InterSection inter(dv, iv);

	j = 0;
	for (typename InterSection::const_iterator i = inter.begin(), ie = inter.end(); i != ie; ++i) {
		CYBOZU_TEST_EQUAL(i->pos(), interTbl[j].pos);
		CYBOZU_TEST_EQUAL(i->val1(), interTbl[j].d);
		CYBOZU_TEST_EQUAL(i->val2(), interTbl[j].i);
		j++;
	}
}

CYBOZU_TEST_AUTO(intersect1)
{
	typedef cybozu::nlp::SparseVector<double> DoubleVec;
	typedef cybozu::nlp::SparseVector<int> IntVec;
	test_intersect<DoubleVec, IntVec>();
}

CYBOZU_TEST_AUTO(intersect2)
{
	typedef cybozu::nlp::SparseVector<double, cybozu::nlp::option::CompressedPositionTbl> DoubleVec;
	typedef cybozu::nlp::SparseVector<int, cybozu::nlp::option::CompressedPositionTbl> IntVec;
	test_intersect<DoubleVec, IntVec>();
}

CYBOZU_TEST_AUTO(unionTest)
{
	typedef cybozu::nlp::SparseVector<int> IntVec;
	typedef cybozu::nlp::Union<IntVec, IntVec> Uni;
	struct V {
		struct {
			size_t pos;
			int v1;
			int v2;
		} a[10];
		size_t n;
	};
	const struct Elem {
		V x;
		V y;
		V z;
	} tbl[] = {
		{
			{ {}, 0 },
			{ { { 0, 1, 0 }, { 2, 4, 0 }, { 3, 5, 0 } }, 3 },
			{ { { 0, 0, 1 }, { 2, 0, 4 }, { 3, 0, 5 } }, 3 },
		},
		{
			{ { { 0, 1, 0 }, { 2, 4, 0 }, { 3, 5, 0 } }, 3 },
			{ {}, 0 },
			{ { { 0, 1, 0 }, { 2, 4, 0 }, { 3, 5, 0 } }, 3 },
		},
		{
			{ {              { 1, 2, 0 }, { 2, 5, 0 },              { 9, 4, 0 } }, 3 },
			{ { { 0, 1, 0 },              { 2, 4, 0 }, { 3, 5, 0 }              }, 3 },
			{ { { 0, 0, 1 }, { 1, 2, 0 }, { 2, 5, 4 }, { 3, 0, 5 }, { 9, 4, 0 } }, 5 },
		},
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		const Elem& e = tbl[i];
		IntVec x, y;
		for (size_t j = 0; j < e.x.n; j++) {
			x.push_back(e.x.a[j].pos, e.x.a[j].v1);
		}
		for (size_t j = 0; j < e.y.n; j++) {
			y.push_back(e.y.a[j].pos, e.y.a[j].v1);
		}
		Uni uni(x, y);
		size_t n = 0;
		for (Uni::const_iterator j = uni.begin(), je = uni.end(); j != je; ++j) {
			CYBOZU_TEST_EQUAL(j->val1(), e.z.a[n].v1);
			CYBOZU_TEST_EQUAL(j->val2(), e.z.a[n].v2);
			CYBOZU_TEST_EQUAL(j->pos(), e.z.a[n].pos);
			n++;
		}
		CYBOZU_TEST_EQUAL(n, e.z.n);
	}
}

CYBOZU_TEST_AUTO(map)
{
	const struct {
		size_t pos;
		int val;
	} tbl[] = {
		{ 1, 100 }, { 200, 5 }, { 3, 123 }, { 9, 1 },
	};
	typedef std::map<size_t, int> Map;
	Map m;
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		m[tbl[i].pos] = tbl[i].val;
	}
	typedef cybozu::nlp::SparseVector<int> IntVec;
	IntVec v;
	v.set(m);
	CYBOZU_TEST_EQUAL(m.size(), v.size());
	Map::const_iterator mi = m.begin(), mie = m.end();
	IntVec::const_iterator vi = v.begin();
	for (; mi != mie; ++mi, ++vi) {
		CYBOZU_TEST_EQUAL(mi->first, vi->pos());
		CYBOZU_TEST_EQUAL(mi->second, vi->val());
	}
}

CYBOZU_TEST_AUTO(innerProduct)
{
	const struct {
		size_t pos;
		int val;
	} Ltbl[] = {
		{ 1, 100 }, { 10, 5 }, { 20, 2 }, { 30, 4 },
	};

	const struct {
		size_t pos;
		double val;
	} Rtbl[] = {
		{ 2, 1.5 }, { 10, 0.1 }, { 11, 3 }, { 30, 2 }, { 40, 1 },
	};

	{
		cybozu::nlp::SparseVector<int> lhs;
		cybozu::nlp::SparseVector<double, cybozu::nlp::option::CompressedPositionTbl> rhs;
		for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(Ltbl); i++) {
			lhs.push_back(Ltbl[i].pos, Ltbl[i].val);
		}
		for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(Rtbl); i++) {
			rhs.push_back(Rtbl[i].pos, Rtbl[i].val);
		}
		{
			int a;
			cybozu::nlp::InnerProduct(&a, lhs, lhs);
			CYBOZU_TEST_EQUAL(a, 10000 + 25 + 4 + 16);
		}
		{
			double b;
			cybozu::nlp::InnerProduct(&b, rhs, rhs);
			CYBOZU_TEST_EQUAL(b, 2.25 + 0.01 + 9 + 4 + 1);
		}
		{
			double c;
			cybozu::nlp::InnerProduct(&c, lhs, rhs);
			CYBOZU_TEST_EQUAL(c, 8.5);
		}
		{
			double d;
			cybozu::nlp::InnerProduct(&d, rhs, lhs);
			CYBOZU_TEST_EQUAL(d, 8.5);
		}
	}

	{
		typedef cybozu::nlp::SparseVector<int> Lhs;
		typedef cybozu::nlp::SparseVector<double, cybozu::nlp::option::CompressedPositionTbl> Rhs;
		Lhs lhs;
		Rhs rhs;

		for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(Ltbl); i++) {
			lhs.push_back(Ltbl[i].pos, Ltbl[i].val);
		}
		for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(Rtbl); i++) {
			rhs.push_back(Rtbl[i].pos, Rtbl[i].val);
		}
		{
			int a;
			cybozu::nlp::InnerProduct(&a, lhs, lhs);
			CYBOZU_TEST_EQUAL(a, 10000 + 25 + 4 + 16);
		}
		{
			double b;
			cybozu::nlp::InnerProduct(&b, rhs, rhs);
			CYBOZU_TEST_EQUAL(b, 2.25 + 0.01 + 9 + 4 + 1);
		}
		{
			double c;
			cybozu::nlp::InnerProduct(&c, lhs, rhs);
			CYBOZU_TEST_EQUAL(c, 8.5);
		}
		{
			double d;
			cybozu::nlp::InnerProduct(&d, rhs, lhs);
			CYBOZU_TEST_EQUAL(d, 8.5);
		}
	}
}

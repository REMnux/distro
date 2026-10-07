#include <stdio.h>
#include <cybozu/serializer.hpp>
#include <cybozu/test.hpp>
#include <cybozu/xorshift.hpp>
#include <map>
#include <set>
#include <list>
#include <vector>
#include <cybozu/unordered_map.hpp>

typedef std::vector<int> IntVec;
typedef std::vector<std::string> StrVec;
typedef std::vector<StrVec> StrVecVec;

template<class T>
void SaveAndLoad(T& y, const T& x)
{
	y = T();
	std::stringstream ss;
	cybozu::save(ss, x);
	cybozu::load(y, ss);
}

template<class T>
void SaveAndLoadVec(T& y, const T& x)
{
	y = T();
	std::stringstream ss;
	cybozu::savePodVec(ss, x);
	cybozu::loadPodVec(y, ss);
}

template<class T>
void testInteger()
{
	cybozu::XorShift rg;
	for (int i = 0; i < 100; i++) {
		T x = T(rg.get64()), y;
		SaveAndLoad(y, x);
		CYBOZU_TEST_EQUAL(x, y);
	}
}

template<class T>
void testFloat()
{
	cybozu::XorShift rg;
	for (int i = 0; i < 100; i++) {
		long long r = rg.get64();
		long long q = rg.get64();
		int sign = rg() & 1 ? 1 : -1;
		T x = q ? (T)(r / T(q) * sign) : 0, y;
		SaveAndLoad(y, x);
		CYBOZU_TEST_EQUAL(x, y);
	}
}

CYBOZU_TEST_AUTO(integer)
{
	testInteger<char>();
	testInteger<short>();
	testInteger<int>();
	testInteger<long long>();
	testInteger<unsigned char>();
	testInteger<unsigned short>();
	testInteger<unsigned int>();
	testInteger<unsigned long long>();
}

const uint32_t limitInt32tbl[] = {
	0, 1, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 150, 191, 192, 255,
	256, 257, 65535,
	65536, 16777215,
	16777216, 2147483647, uint32_t(2147483648u), uint32_t(4294967295u),
};

const uint64_t limitInt64tbl[] = {
	0, 1, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 150, 191, 192, 255,
	256, 257, 65535,
	65536, 16777215,
	16777216, 2147483647, 2147483648u, 4294967295u,
	uint64_t(4294967296ULL),
	uint64_t((1ULL << 40) - 1),
	uint64_t(1ULL << 40),
	uint64_t((1ULL << 48) - 1),
	uint64_t(1ULL << 48),
	uint64_t(1ULL << 56),
	uint64_t((1ULL << 56) - 1),
	uint64_t(1ULL << 63),
	uint64_t(18446744073709551615ULL),
};

template<class T, class S, size_t N>
void testLimitInt(const S (&tbl)[N])
{
	for (size_t i = 0; i < N; i++) {
		{
			T x = T(tbl[i]), y;
			SaveAndLoad(y, x);
			CYBOZU_TEST_EQUAL(x, y);
		}
		{
			T x = T(~tbl[i] + 1), y;
			SaveAndLoad(y, x);
			CYBOZU_TEST_EQUAL(x, y);
		}
	}
}

void dump(const std::string& str)
{
	for (size_t i = 0; i < str.size(); i++) {
		printf("%02x ", (uint8_t)str[i]);
	}
	printf("\n");
}

CYBOZU_TEST_AUTO(limit)
{
	testLimitInt<int>(limitInt32tbl);
	testLimitInt<uint32_t>(limitInt32tbl);
	testLimitInt<int64_t>(limitInt64tbl);
	testLimitInt<uint64_t>(limitInt64tbl);
}

CYBOZU_TEST_AUTO(bool)
{
	for (int i = 0; i < 2; i++) {
		bool x = i == 0, y;
		SaveAndLoad(y, x);
		CYBOZU_TEST_EQUAL(y, x);
	}
}

CYBOZU_TEST_AUTO(float)
{
	testFloat<float>();
	testFloat<double>();
}

CYBOZU_TEST_AUTO(string)
{
	const char *tbl[] = {
		"",
		"abc",
		"abc\n\r,xxx",
		"abc\n\r\\,xxx",
		"XX99\x01\x02\x33\xff",
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string x = tbl[i], y;
		SaveAndLoad(y, x);
		CYBOZU_TEST_EQUAL(x, y);
	}
	const char *tbl2[] = {
		"",
		"abc this is a pen",
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl2); i++) {
		const char *msg = tbl2[i];
		std::stringstream ss;
		cybozu::save(ss, msg);
		std::string y;
		cybozu::load(y, ss);
		CYBOZU_TEST_EQUAL(y, msg);
	}
}

template<typename V, typename T>
void Set(V& x, const T* in, size_t n)
{
	x.clear();
	for (size_t i = 0; i < n; i++) {
		x.push_back(in[i]);
	}
}

template<class T>
void verify(const T& x, const T& y)
{
	const size_t n = x.size();
	CYBOZU_TEST_EQUAL(n, y.size());
	if (x.size() == y.size()) {
		for (typename T::const_iterator i = x.begin(), ie = x.end(), j = y.begin(); i != ie; ++i, ++j) {
			CYBOZU_TEST_EQUAL(*i, *j);
		}
	}
}

template<class T>
void verifyPair(const T& x, const T& y)
{
	const size_t n = x.size();
	CYBOZU_TEST_EQUAL(n, y.size());
	if (x.size() == y.size()) {
		for (typename T::const_iterator i = x.begin(), ie = x.end(), j = y.begin(); i != ie; ++i, ++j) {
			CYBOZU_TEST_EQUAL(i->first, j->first);
			CYBOZU_TEST_EQUAL(i->second, j->second);
		}
	}
}

CYBOZU_TEST_AUTO(IntVec)
{
	const struct {
		size_t n;
		int v[5];
	} tbl[] = {
		{ 0, { 0 } },
		{ 1, { 1234567 } },
		{ 4, { 0, 12, 243, -344 } },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		IntVec x, y, z;
		Set(x, tbl[i].v, tbl[i].n);
		SaveAndLoad(y, x);
		verify(x, y);
		SaveAndLoadVec(z, x);
		verify(x, z);
	}
}

CYBOZU_TEST_AUTO(StrVec)
{
	const struct {
		size_t n;
		const char *v[5];
	} tbl[] = {
		{ 0, { "" } },
		{ 1, { "1234567" } },
		{ 5, { "0", "12", "243", "-344", "abc" } },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		StrVec x, y, z;
		Set(x, tbl[i].v, tbl[i].n);
		SaveAndLoad(y, x);
		verify(x, y);
	}
}

CYBOZU_TEST_AUTO(StrVecVec)
{
	const struct {
		size_t n;
		const char *v[5];
	} tbl[] = {
		{ 0, { "" } },
		{ 1, { "1234567" } },
		{ 5, { "abc", "def", "asdf", "234", "521" } },
	};
	StrVecVec x, y;

	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		StrVec v;
		Set(v, tbl[i].v, tbl[i].n);
		x.push_back(v);
	}

	SaveAndLoad(y, x);
	const size_t xn = x.size();
	CYBOZU_TEST_EQUAL(xn, y.size());
	if (xn == y.size()) {
		for (size_t i = 0; i < xn; i++) {
			verify(x[i], y[i]);
		}
	}
}

CYBOZU_TEST_AUTO(str2double)
{
	std::map<std::string, double> x, y;
	x["asdfasd"] = 1.2;
	x["this"] = 3.141592;
	x["is"] = 1.2;
	x["a"] = -120;
	x["pen"] = 0;
	SaveAndLoad(y, x);
	verifyPair(x, y);
}

template<class S, class T>
void CopyMap(S& s, const T& t)
{
	for (typename T::const_iterator i = t.begin(), ie = t.end(); i != ie; ++i) {
		s[i->first] = i->second;
	}
}

CYBOZU_TEST_AUTO(strHashDouble)
{
	CYBOZU_NAMESPACE_STD::unordered_map<std::string, int> x, y;
	x["asdfasd"] = 12;
	x["this"] = 3141592;
	x["is"] = 999;
	x["a"] = -120;
	x["pen"] = 0;

	SaveAndLoad(y, x);
	// unordered_map does not keep order
	std::map<std::string, int> xx, yy;
	CopyMap(xx, x);
	CopyMap(yy, y);
	verifyPair(xx, yy);
}

CYBOZU_TEST_AUTO(list)
{
	std::list<std::string> x, y;
	x.push_back("asdfasd");
	x.push_back("absdf");
	x.push_back("hit");
	x.push_back("hello");

	SaveAndLoad(y, x);
	verify(x, y);
}

CYBOZU_TEST_AUTO(set)
{
	std::set<std::string> x, y;
	x.insert("asdfasd");
	x.insert("absdf");
	x.insert("hit");
	x.insert("hello");

	SaveAndLoad(y, x);
	verify(x, y);
}

CYBOZU_TEST_AUTO(mapMap)
{
	typedef std::map<std::string, double> Str2Double;
	typedef std::map<std::string, Str2Double> Map;
	Map x, y;

	Str2Double a, b, c;
	a["sdf"] = 10.2;
	a["this"] = -123.42;
	b["std"] = 0;
	b["map"] = 9998.1234;
	b["this this"] = 122.22;
	c["do\r\t\n"] = 9.33099;
	c[",,,"] = 333;

	x["123"] = a;
	x["##$$"] = b;
	x["4232\""] = c;

	SaveAndLoad(y, x);
	const size_t n = x.size();
	CYBOZU_TEST_EQUAL(n, y.size());
	for (Map::const_iterator i = x.begin(), ie = x.end(), j = y.begin(); i != ie; ++i, ++j) {
		CYBOZU_TEST_EQUAL(i->first, j->first);
		verifyPair(i->second, j->second);
	}
}

CYBOZU_TEST_AUTO(hashHash)
{
	typedef CYBOZU_NAMESPACE_STD::unordered_map<std::string, double> Str2Double;
	typedef CYBOZU_NAMESPACE_STD::unordered_map<std::string, Str2Double> Map;
	Map x, y;

	Str2Double a, b, c;
	a["sdf"] = 10.2;
	a["this"] = -123.42;
	b["std"] = 0;
	b["map"] = 9998.1234;
	b["this this"] = 122.22;
	c["do\r\t\n"] = 9.33099;
	c[",,,"] = 333;

	x["123"] = a;
	x["##$$"] = b;
	x["4232\""] = c;

	SaveAndLoad(y, x);
	typedef std::map<std::string, Str2Double> Map2;
	Map2 xx, yy;
	CopyMap(xx, x);
	CopyMap(yy, y);
	CYBOZU_TEST_EQUAL(x.size(), y.size());
	if (x.size() == y.size()) {
		for (Map2::const_iterator i = xx.begin(), ie = xx.end(), j = yy.begin(); i != ie; ++i, ++j) {
			CYBOZU_TEST_EQUAL(i->first, j->first);
			std::map<std::string, double> xxx, yyy;
			CopyMap(xxx, i->second);
			CopyMap(yyy, j->second);
			verifyPair(xxx, yyy);
		}
	}
//	compressTest(x, y, true);
//	compressTest(x, y, false);
}

template<class Stream>
void CustomStreamTest()
{
	typedef std::map<std::string, int> Str2Int;
	Str2Int a, b;
	a["sdf"] = 10;
	a["this"] = -123;
	a["dore"] = 2;
	Stream s;
	cybozu::save(s, a);
	cybozu::load(b, s);
	CYBOZU_TEST_EQUAL(a.size(), b.size());
	Str2Int::const_iterator ia = a.begin(), ib = b.begin();
	while (ia != a.end()) {
		CYBOZU_TEST_ASSERT(ib != b.end());
		CYBOZU_TEST_EQUAL(ia->first, ib->first);
		CYBOZU_TEST_EQUAL(ia->second, ib->second);
		++ia, ++ib;
	}
	CYBOZU_TEST_ASSERT(ib == b.end());
}

struct Stream1 {
	std::string buf;
	size_t readSome(void *p, size_t n)
	{
		if (n > buf.size()) n = buf.size();
		memcpy(p, buf.data(), n);
		buf = buf.substr(n);
		return n;
	}
	void write(const void *p, size_t n)
	{
		buf.append((const char *)p, n);
	}
};

struct Stream2 {
	std::string buf;
};

namespace cybozu {

template<>
size_t readSome<Stream2>(void *p, size_t n, Stream2& s)
{
	std::string& buf = s.buf;
	if (n > buf.size()) n = buf.size();
	memcpy(p, buf.data(), n);
	buf = buf.substr(n);
	return n;
}
template<>
void write<Stream2>(Stream2& s, const void *p, size_t n)
{
	s.buf.append((const char*)p, n);
}

} // cybozu

CYBOZU_TEST_AUTO(customStream)
{
	CustomStreamTest<Stream1>();
	CustomStreamTest<Stream2>();
}

#if 0
#include <cybozu/stream_ext.hpp>
template<class X, class Y>
void compressTest(X& x, Y& y, bool useCompression)
{
	std::string out;
	{
		cybozu::RefStringOutputStream os(out);
		cybozu::CompressOutputStream<cybozu::RefStringOutputStream> enc(os, useCompression);

		cybozu::serialize(enc, x);
		// enc.flush(); call in destructor of enc
	}

	cybozu::MemoryInputStream is(out);
	cybozu::DecompressInputStream<cybozu::MemoryInputStream> dec(is, useCompression);
	cybozu::deserialize(dec, y);

	CYBOZU_TEST_ASSERT(x == y);
}

#endif

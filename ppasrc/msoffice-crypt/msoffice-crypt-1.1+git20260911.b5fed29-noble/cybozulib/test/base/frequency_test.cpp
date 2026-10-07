#include <cybozu/test.hpp>
#include <cybozu/frequency.hpp>
#include <sstream>

template<class Element>
struct Tbl {
	Element c;
	size_t n;
};

template<class Freq, class T, size_t N>
void verify(const Freq& freq, const T (&tbl)[N])
{
	CYBOZU_TEST_EQUAL(freq.size(), N);
	for (size_t i = 0; i < N; i++) {
		CYBOZU_TEST_EQUAL(freq.getFrequency(tbl[i].c), tbl[i].n);
		CYBOZU_TEST_EQUAL(freq.getIndex(tbl[i].c), i);
		CYBOZU_TEST_EQUAL(freq.getElement(i), tbl[i].c);
	}
}

CYBOZU_TEST_AUTO(char)
{
	std::string a = "abcaaab\x80\x80\xff\xff\xff";
	typedef cybozu::freq_local::FrequencyVec<char> Freq;
	std::stringstream ss;
	Freq freq;
	{
		Freq freqTmp(a.begin(), a.end());
		freqTmp.save(ss);
	}
	freq.load(ss);
	const Tbl<char> tbl[] = {
		{ 'a', 4 },
		{ '\xff', 3 },
		{ '\x80', 2 },
		{ 'b', 2 },
		{ 'c', 1 },
	};
	verify(freq, tbl);
	Freq freq2;
	for (size_t i = 0; i < a.size(); i++) {
		freq2.append(a[i]);
	}
	freq2.ready();
	verify(freq2, tbl);
}

CYBOZU_TEST_AUTO(int)
{
	const int inTbl[] = {
		3, 5, 2, 3, 5, 2, 9, 5, 2, 2, 0,
	};
	typedef cybozu::Frequency<int> Freq;
	std::stringstream ss;
	Freq freq;
	{
		Freq freqTmp(inTbl, inTbl + CYBOZU_NUM_OF_ARRAY(inTbl));
		freqTmp.save(ss);
	}
	freq.load(ss);
	const Tbl<int> tbl[] = {
		{ 2, 4 },
		{ 5, 3 },
		{ 3, 2 },
		{ 9, 1 },
		{ 0, 1 },
	};
	verify(freq, tbl);
	Freq freq2;
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(inTbl); i++) {
		freq2.append(inTbl[i]);
	}
	freq2.ready();
	verify(freq2, tbl);
}

CYBOZU_TEST_AUTO(string)
{
	const std::string inTbl[] = {
		"abc", "123", "a", "abc", "abc", "x", "123", "x",
	};
	typedef cybozu::Frequency<std::string> Freq;
	std::stringstream ss;
	Freq freq;
	{
		Freq freqTmp(inTbl, inTbl + CYBOZU_NUM_OF_ARRAY(inTbl));
		freqTmp.save(ss);
	}
	freq.load(ss);
	const Tbl<std::string> tbl[] = {
		{ "abc", 3 },
		{ "x", 2 },
		{ "123", 2 },
		{ "a", 1 },
	};
	verify(freq, tbl);
	Freq freq2;
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(inTbl); i++) {
		freq2.append(inTbl[i]);
	}
	freq2.ready();
	verify(freq2, tbl);
}

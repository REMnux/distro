#pragma once
/**
	@file
	@brief frequency of elements in a sequence
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <assert.h>
#include <vector>
#include <algorithm>
#include <functional>
#include <iostream>
#include <cybozu/exception.hpp>
#include <cybozu/unordered_map.hpp>
#include <cybozu/serializer.hpp>

namespace cybozu {

namespace freq_local {

template<class Element, class Int = size_t>
class FrequencyVec {
	static const size_t N = size_t(1) << (sizeof(Element) * 8);
	size_t size_;
	Int freqTbl_[N];
	uint8_t char2idx_[N];
	uint8_t idx2char_[N];
	struct Greater {
		const Int *p_;
		explicit Greater(const Int *p) : p_(p) {}
		bool operator()(uint8_t lhs, uint8_t rhs) const
		{
			Int a = p_[lhs];
			Int b = p_[rhs];
			if (a > b) return true;
			if (a < b) return false;
			return a > b;
		}
	};
public:
	typedef Element value_type;
	typedef Int size_type;

	FrequencyVec() { clear(); }
	template<class Iter>
	FrequencyVec(Iter begin, Iter end)
	{
		clear();
		init(begin, end);
	}
	void clear()
	{
		size_ = 0;
		memset(freqTbl_, 0, sizeof(freqTbl_));
	}
	template<class Iter>
	void init(Iter begin, Iter end)
	{
		while (begin != end) {
			append(*begin);
			++begin;
		}
		ready();
	}
	void append(const Element e)
	{
		freqTbl_[uint8_t(e)]++;
	}
	void ready()
	{
		for (size_t i = 0; i < N; i++) idx2char_[i] = uint8_t(i);
		Greater greater(freqTbl_);
		std::sort(idx2char_, idx2char_ + N, greater);
		size_ = 0;
		for (size_t i = 0; i < N; i++) {
			uint8_t c = idx2char_[i];
			char2idx_[c] = (uint8_t)i;
			if (freqTbl_[c]) size_++;
		}
	}
	/*
		element -> freq
	*/
	Int getFrequency(Element e) const { return freqTbl_[uint8_t(e)]; }
	/*
		element -> idx
	*/
	Int getIndex(Element e) const { return char2idx_[uint8_t(e)]; }
	/*
		idx -> element
	*/
	Element getElement(size_t idx) const
	{
//		if (idx >= N) throw cybozu::Exception("Frequency:getElement:bad idx") << idx;
		assert(idx < N);
		return Element(idx2char_[idx]);
	}
	size_t size() const { return size_; }
	template<class InputStream>
	void load(InputStream& is)
	{
		cybozu::load(size_, is);
		cybozu::loadRange(freqTbl_, N, is);
		cybozu::loadRange(char2idx_, N, is);
		cybozu::loadRange(idx2char_, N, is);
	}
	void save(std::ostream& os) const
	{
		cybozu::save(os, size_);
		cybozu::saveRange(os, freqTbl_, N);
		cybozu::saveRange(os, char2idx_, N);
		cybozu::saveRange(os, idx2char_, N);
	}
	void put() const
	{
		for (size_t i = 0; i < size_; i++) {
			uint8_t c = idx2char_[i];
			printf("%d %d %d\n", (int)i, c, freqTbl_[c]);
		}
	}
};

} // cybozu::freq_local

/*
	count Element
	Element : type of element
	Int : type of counter
*/
template<class Element, class Int = size_t>
class Frequency {
	struct FreqIdx {
		Int freq;
		mutable Int idx;
		template<class InputStream>
		void load(InputStream& is)
		{
			cybozu::load(freq, is);
			cybozu::load(idx, is);
		}
		template<class OutputStream>
		void save(OutputStream& os) const
		{
			cybozu::save(os, freq);
			cybozu::save(os, idx);
		}
	};
	typedef CYBOZU_NAMESPACE_STD::unordered_map<Element, FreqIdx> Map;
	typedef Element value_type;
	typedef Int size_type;
	typedef std::vector<typename Map::const_iterator> Idx2Ref;
	static inline bool greater(typename Map::const_iterator i, typename Map::const_iterator j)
	{
		const Int a = i->second.freq;
		const Int b = j->second.freq;
		if (a > b) return true;
		if (a < b) return false;
		return i->first > j->first;
	}
	Map m_;
	Idx2Ref idx2ref_;
	void initIdx2Ref()
	{
		idx2ref_.resize(m_.size());
		size_t pos = 0;
		for (typename Map::const_iterator i = m_.begin(), ie = m_.end(); i != ie; ++i) {
			idx2ref_[pos++] = i;
		}
		std::sort(idx2ref_.begin(), idx2ref_.end(), greater);
	}
public:
	Frequency(){ clear(); }
	template<class Iter>
	Frequency(Iter begin, Iter end)
	{
		clear();
		init(begin, end);
	}
	void clear()
	{
		m_.clear();
		idx2ref_.clear();
	}
	template<class Iter>
	void init(Iter begin, Iter end)
	{
		while (begin != end) {
			append(*begin);
			++begin;
		}
		ready();
	}
	void append(const Element& e)
	{
		m_[e].freq++;
	}
	void ready()
	{
		initIdx2Ref();
		for (size_t i = 0, ie = idx2ref_.size(); i < ie; i++) {
			idx2ref_[i]->second.idx = (Int)i;
		}
	}
	/*
		element -> freq
	*/
	Int getFrequency(const Element& e) const
	{
		typename Map::const_iterator i = m_.find(e);
		return (i != m_.end()) ? i->second.freq : 0;
	}
	/*
		element -> idx
	*/
	Int getIndex(const Element& e) const
	{
		typename Map::const_iterator i = m_.find(e);
		if (i == m_.end()) throw cybozu::Exception("Frequency:getIndex:not found") << e;
		return i->second.idx;
	}
	/*
		idx -> element
	*/
	const Element& getElement(size_t idx) const
	{
		if (idx >= idx2ref_.size()) throw cybozu::Exception("Frequency:getElement:bad idx") << idx;
		return idx2ref_[idx]->first;
	}
	size_t size() const { return idx2ref_.size(); }
	template<class InputStream>
	void load(InputStream& is)
	{
		cybozu::load(m_, is);
		initIdx2Ref();
	}
	template<class OutputStream>
	void save(OutputStream& os) const
	{
		cybozu::save(os, m_);
	}
	void put() const
	{
		for (size_t i = 0, n = idx2ref_.size(); i < n; i++) {
			typename Map::const_iterator j = idx2ref_[i];
			std::cout << i << ' ' << j->first << ' ' << j->second.freq << std::endl;
		}
	}
};

template<class Int>
struct Frequency<uint8_t, Int> : freq_local::FrequencyVec<uint8_t, Int> {
	Frequency() {}
	template<class Iterator>
	Frequency(Iterator begin, Iterator end) : freq_local::FrequencyVec<uint8_t, Int>(begin, end) {}
};
template<class Int>
struct Frequency<char, Int> : freq_local::FrequencyVec<char, Int> {
	Frequency() {}
	template<class Iterator>
	Frequency(Iterator begin, Iterator end) : freq_local::FrequencyVec<char, Int>(begin, end) {}
};

} // cybozu

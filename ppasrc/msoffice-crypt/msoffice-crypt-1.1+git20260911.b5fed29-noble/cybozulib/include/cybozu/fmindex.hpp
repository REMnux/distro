#pragma once
/**
	@file
	@brief FM-index
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <map>
#include <vector>
#include <fstream>
#include <stdio.h>
#ifdef CYBOZU_FMINDEX_USE_CSUCVECTOR
	#include <cybozu/csucvector.hpp>
#endif
#include <cybozu/wavelet_matrix.hpp>
#include <cybozu/bitvector.hpp>
#include <cybozu/frequency.hpp>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4389)
#pragma warning(disable:4018)
#endif
#include "sais.hxx"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4127) // constant condition
#endif

namespace cybozu {
/*
	T : type of alphabet
	isRawData : deal with input data as is
	T must be uint8_t or uint16_t if isRawData
*/
template<class T, bool isRawData = false>
class FMindexT {
public:
	static const size_t maxCharNum = size_t(1) << (sizeof(T) * 8);
	typedef std::vector<uint32_t> Vec32;
	typedef std::vector<T> Vec;
#ifdef CYBOZU_FMINDEX_USE_CSUCVECTOR
	typedef cybozu::CSucVector SucVector;
#else
	typedef cybozu::SucVectorT<uint32_t, false> SucVector;
#endif
	typedef cybozu::WaveletMatrixT<false, SucVector> WaveletMatrix;
	Vec32 cf;
	WaveletMatrix wm;
	Vec32 alignedSa;
	SucVector alignedPos;
	cybozu::Frequency<T, uint32_t> freq;
	int skip_;
	size_t charNum_;

	/*
		setup freq, cf by [begin, end)
	*/
	template<class Iter>
	void initCf(Vec& v, Iter begin, Iter end)
	{
		const size_t size = std::distance(begin, end);
		if (size >= (uint64_t(1) << 32) - 1) {
			throw cybozu::Exception("FMindexT:initCf:too large dataSize") << size;
		}
		v.resize(size + 1); // add NUL at the end of data
		if (isRawData) {
			assert(sizeof(T) <= 16);
			charNum_ = size_t(1) << (sizeof(T) * 8);
			std::vector<uint32_t> charNumTbl(charNum_);
			charNumTbl[0] = 1;
			for (size_t i = 0; i < size; i++) {
				T c = *begin++;
				if (c <= 0) throw cybozu::Exception("FMindext:initCf:zero alphabet") << c;
				v[i] = c;
				charNumTbl[c]++;
			}
			cf.resize(charNum_);
			uint32_t sum = 0;
			for (size_t i = 0; i < charNum_; i++) {
				cf[i] = sum;
				sum += charNumTbl[i];
			}
		} else {
			freq.init(begin, end);
			charNum_ = freq.size() + 1; // +1 means last zero
			if (charNum_ > maxCharNum) throw cybozu::Exception("FMindexT:initCf:too many alphabet");
			for (size_t i = 0; i < size; i++) {
				v[i] = static_cast<T>(freq.getIndex(*begin++) + 1);
			}
			cf.resize(charNum_);
			cf[0] = 0;
			uint32_t sum = 1;
			for (size_t i = 1; i < charNum_; i++) {
				cf[i] = sum;
				sum += freq.getFrequency(freq.getElement(i - 1));
			}
		}
	}
	void initBwt(Vec& bwt, const Vec& s, const Vec32& sa) const
	{
		const size_t size = sa.size();
		bwt.resize(size);
		for (size_t i = 0; i < size; i++) {
			if (sa[i] > 0) {
				bwt[i] = s[sa[i] - 1];
			} else {
				bwt[i] = s[size - 1];
			}
		}
	}
	size_t getBitLen(size_t x) const
	{
		if (x == 0) return 1;
		size_t ret = 0;
		while (x > 0) {
			x >>= 1;
			ret++;
		}
		return ret;
	}
public:
	FMindexT()
		: skip_(8)
		, charNum_(0)
	{
	}

	/*
		[begin, end)
		replace '\0' in [begin, end) with space
		append '\0' at the end of [begin, end)
	*/
	template<class Iter>
	void init(Iter begin, Iter end, int skip = 8)
	{
		if (skip <= 0) {
			throw cybozu::Exception("FMindexT:buildFMindex:skip is positive") << skip;
		}
		skip_ = skip;
		Vec v;
		initCf(v, begin, end);
		const size_t dataSize = v.size();

		Vec32 sa;
		sa.resize(dataSize);
		if (saisxx(&v[0], &sa[0], (int)dataSize, (int)charNum_) == -1) {
			throw cybozu::Exception("FMindexT:init:saisxx");
		}
		Vec bwt;
		initBwt(bwt, v, sa);
		wm.init(bwt, getBitLen(charNum_));

#if 1
		cybozu::BitVector bv;
		bv.resize(dataSize);
		for (size_t i = 0; i < dataSize; i++) {
			if ((sa[i] % skip) == 0) {
				bv.set(i);
				alignedSa.push_back(sa[i]);
			}
		}
		alignedPos.init(bv.getBlock(), bv.size());
#else
		alignedPos.resize(dataSize);
		for (size_t i = 0; i < dataSize; i++) {
			if ((sa[i] % skip) == 0) {
				alignedPos.set(i);
				alignedSa.push_back(sa[i]);
			}
		}
		alignedPos.ready();
#endif
	}

	/*
		get range of bwt for key
	*/
	template<class Int, class Key>
	bool getRange(Int* pbegin, Int* pend, const Key& _key) const
	{
		if (_key.empty()) return false;
		const size_t keySize = _key.size();
		const typename Key::value_type *key;
		Key cvtKey;
		if (isRawData) {
			key = &_key[0];
		} else {
			cvtKey.resize(keySize);
			for (size_t i = 0; i < keySize; i++) {
				if (freq.getFrequency(_key[i]) == 0) return false;
				cvtKey[i] = typename Key::value_type(freq.getIndex(_key[i]) + 1);
			}
			key = &cvtKey[0];
		}
		size_t i = keySize - 1;
		size_t begin = 0;
		size_t end = wm.size();
		while (begin < end) {
			const T c = key[i];
			const uint32_t cfc = cf[c];
			begin = cfc + wm.rank(c, begin);
			end = cfc + wm.rank(c, end);
			if (i == 0) break;
			i--;
		}

		if (begin < end) {
			*pbegin = Int(begin);
			*pend = Int(end);
			return true;
		}
		return false;
	}
	template<class Int>
	bool getRange(Int* pbegin, Int* pend, const char *key) const
	{
		return getRange(pbegin, pend, std::string(key));
	}
	size_t convertPosition(size_t bwtPos) const
	{
		size_t t = 0;
		while (!alignedPos.get(bwtPos)) {
			T c;
			bwtPos = wm.get(&c, bwtPos);
			bwtPos += cf[c];
			t++;
		}
		return t + alignedSa[alignedPos.rank1(bwtPos)];
	}
	/*
		get previous string at pos
		@note assume T is vector or std::string
	*/
	template<class Str>
	void getPrevString(Str& str, size_t bwtPos, size_t len) const
	{
		str.resize(len);
		T c;
		while (len > 0) {
			bwtPos = wm.get(&c, bwtPos);
			bwtPos += cf[c];
			if (c == 0) {
				str.erase(str.begin(), str.begin() + len);
				return;
			}
			len--;
			str[len] = isRawData ? c : freq.getElement(c - 1);
		}
	}

	template<class OutputStream>
	void save(OutputStream& os) const
	{
		cybozu::save(os, skip_);
		cybozu::savePodVec(os, cf);
		wm.save(os);
		cybozu::savePodVec(os, alignedSa);
		alignedPos.save(os);
		if (!isRawData) freq.save(os);
	}
	template<class InputStream>
	void load(InputStream& is)
	{
		cybozu::load(skip_, is);
		cybozu::loadPodVec(cf, is);
		wm.load(is);
		cybozu::loadPodVec(alignedSa, is);
		alignedPos.load(is);
		if (isRawData) {
			charNum_ = size_t(1) << (sizeof(T) * 8);
		} else {
			freq.load(is);
			charNum_ = freq.size();
		}
	}
};

typedef FMindexT<uint8_t> FMindex;

} // cybozu

#ifdef _MSC_VER
#pragma warning(pop)
#endif

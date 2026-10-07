#pragma once
/**
	@file
	@brief Wavelet Matrix
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <cybozu/sucvector.hpp>
#include <stdio.h>
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4127)
#endif

//#define CYBOZU_WAVELET_MATRIX_DIRECT_CONSTRUCT

#ifndef CYBOZU_WAVELET_MATRIX_DIRECT_CONSTRUCT
	#include <cybozu/bitvector.hpp>
#endif

namespace cybozu {
/*
	current version supports only max 32GiB
*/
template<bool withSelect = true, class SucVector = cybozu::SucVectorT<uint32_t, false> >
class WaveletMatrixT {
	typedef uint32_t size_type;
	bool getPos(uint64_t v, size_t pos) const
	{
		return (v & (uint64_t(1) << pos)) != 0;
	}
	template<class V>
	size_t countZero(const V& in, size_t bitPos) const
	{
		size_t ret = 0;
		const size_t mask = size_t(1) << bitPos;
		for (size_t i =0, n = in.size(); i < n; i++) {
			if (!(in[i] & mask)) ret++;
		}
		return ret;
	}
	void initFromTbl(std::vector<size_type>& tbl, size_t pos, size_t from, size_t i) const
	{
		if (i == valBitLen_) {
			tbl[pos] = (size_type)from;
		} else {
			initFromTbl(tbl, pos, svv[i].rank(false, from), i + 1);
			initFromTbl(tbl, pos + (size_t(1) << (valBitLen_ - 1 - i)), svv[i].rank(true, from) + offTbl[i], i + 1);
		}
	}
	void initFromLtTbl(std::vector<size_type>& tbl, size_t pos, size_t from, size_t ret, size_t i) const
	{
		if (i == valBitLen_) {
			tbl[pos] = (size_type)ret;
		} else {
			size_t end = svv[i].rank1(from);
			initFromLtTbl(tbl, pos, from - end, ret, i + 1);
			initFromLtTbl(tbl, pos + (size_t(1) << (valBitLen_ - 1 - i)), offTbl[i] + end, ret + from - end, i + 1);
		}
	}
	typedef std::vector<SucVector> SucVecVec;
	uint64_t maxVal_;
	size_t valBitLen_;
	size_t size_;
	SucVecVec svv;
	std::vector<size_type> offTbl;
	std::vector<size_type> fromTbl;
	std::vector<size_type> fromLtTbl;
	typedef std::vector<uint32_t> Uint32Vec;
	static const uint64_t posUnit = 256;
	std::vector<Uint32Vec> selTbl_;

	// call after initialized
	template<class Vec>
	void initSelTbl(std::vector<Uint32Vec>& tblVec, const Vec& vec) const
	{
		if (!withSelect) return;
		tblVec.resize(maxVal_);

		Uint32Vec iTbl(maxVal_);
		Uint32Vec numTbl(maxVal_);
		for (uint64_t v = 0; v < maxVal_; v++) {
			const size_t size = sucvector_util::getBlockNum(this->size(v), posUnit);
			tblVec[v].resize(size);
			iTbl[v] = 1;
		}
		for (uint32_t pos = 0, n = (uint32_t)vec.size(); pos < n; pos++) {
			uint64_t v = vec[pos];
			uint32_t i = iTbl[v];
			numTbl[v]++;
			if (numTbl[v] >= i * posUnit) {
				if (i < tblVec[v].size()) {
					tblVec[v][i] = pos + 1;
					iTbl[v]++;
				}
			}
		}
	}
public:
	WaveletMatrixT()
		: maxVal_(1)
		, valBitLen_(0)
		, size_(0)
	{
	}
	/*
		data format(endian is depend on CPU:eg. little endian for x86/x64)
		valBitLen     : 8
		maxVal        : 8
		size          : 8
		svv
		offTblSize    : 8
		offTbl
		fromTblSize   : 8
		fromTbl
		fromLtTblSize : 8
		fromLtTbl
	*/
	template<class OutputStream>
	void save(OutputStream& os) const
	{
		cybozu::save(os, maxVal_);
		cybozu::save(os, valBitLen_);
		cybozu::save(os, size_);
		assert(valBitLen_ == svv.size());
		for (size_t i = 0; i < valBitLen_; i++) {
			svv[i].save(os);
		}
		cybozu::savePodVec(os, offTbl);
		cybozu::savePodVec(os, fromTbl);
		cybozu::savePodVec(os, fromLtTbl);

		if (withSelect) {
			for (uint64_t v = 0; v < maxVal_; v++) {
				cybozu::savePodVec(os, selTbl_[v]);
			}
		}
	}
	template<class InputStream>
	void load(InputStream& is)
	{
		cybozu::load(maxVal_, is);
		cybozu::load(valBitLen_, is);
		cybozu::load(size_, is);
		svv.resize(valBitLen_);
		for (size_t i = 0; i < valBitLen_; i++) {
			svv[i].load(is);
		}
		cybozu::loadPodVec(offTbl, is);
		cybozu::loadPodVec(fromTbl, is);
		cybozu::loadPodVec(fromLtTbl, is);

		if (withSelect) {
			selTbl_.resize(maxVal_);
			for (uint64_t v = 0; v < maxVal_; v++) {
				cybozu::loadPodVec(selTbl_[v], is);
			}
		}
	}
	uint64_t size() const { return size_; }
	uint64_t size(uint64_t val) const
	{
		assert(val < maxVal_);
		return rank(val, size_);
	}
	template<class Vec>
	void init(const Vec& vec, size_t valBitLen)
	{
		if (vec.size() > (uint64_t(1) << 32)) throw cybozu::Exception("WaveletMatrix:init:too large") << vec.size();
		if (valBitLen > 16) throw cybozu::Exception("WaveletMatrix:init:too large valBitLen") << valBitLen;
		valBitLen_ = valBitLen;
		maxVal_ = uint64_t(1) << valBitLen_;
		size_ = vec.size();
		svv.resize(valBitLen_);

		// count zero bit
		offTbl.resize(valBitLen_);
		for (size_t i = 0, n = offTbl.size(); i < n; i++) {
			offTbl[i] = (size_type)countZero(vec, valBitLen - 1 - i);
		}

		// construct svv
		Vec cur = vec, next;
		next.resize(size_);
		for (size_t i = 0; i < valBitLen; i++) {
#ifdef CYBOZU_WAVELET_MATRIX_DIRECT_CONSTRUCT
			SucVector& sv = svv[i];
#else
			cybozu::BitVector sv;
#endif
			sv.resize(size_);
			size_t zeroPos = 0;
			size_t onePos = offTbl[i];
			for (size_t j = 0; j < size_; j++) {
				bool b = getPos(cur[j], valBitLen - 1 - i);
				if (b) {
					sv.set(j);
				}
				if (i == valBitLen - 1) continue;
				if (b) {
					next[onePos++] = cur[j];
				} else {
					next[zeroPos++] = cur[j];
				}
			};
#ifdef CYBOZU_WAVELET_MATRIX_DIRECT_CONSTRUCT
			sv.ready();
#else
			svv[i].init(sv.getBlock(), sv.size());
#endif
			next.swap(cur);
		}

		// construct fromTbl
		fromTbl.resize(maxVal_);
		initFromTbl(fromTbl, 0, 0, 0);

		fromLtTbl.resize(maxVal_);
		initFromLtTbl(fromLtTbl, 0, 0, 0, 0);

		initSelTbl(selTbl_, vec);
	}
	uint64_t get(uint64_t pos) const
	{
		assert(pos < size_);
		uint64_t ret = 0;
		size_t i = 0;
		for (;;) {
			bool b = svv[i].get(pos);
			ret = (ret << 1) | uint32_t(b);
			if (i == valBitLen_ - 1) return ret;
#if 0
			pos = svv[i].rank(b, pos);
			if (b) pos += offTbl[i];
#else
			if (b) {
				pos = offTbl[i] + svv[i].rank1(pos);
			} else {
				pos -= svv[i].rank1(pos);
			}
#endif
			i++;
		}
	}
	/*
		get number of val in [0, pos)
		@note shotcut idea to reduce computing 'from' by @echizen_tm
		see http://ja.scribd.com/doc/102636443/Wavelet-Matrix
	*/
	uint64_t rank(uint64_t val, uint64_t pos) const
	{
		assert(val < maxVal_);
		if (pos > size_) pos = size_;
		for (size_t i = 0; i < valBitLen_; i++) {
			bool b = (val & (uint64_t(1) << (valBitLen_ - 1 - i))) != 0;
			if (b) {
				pos = offTbl[i] + svv[i].rank1(pos);
			} else {
				pos -= svv[i].rank1(pos);
			}
		}
		return pos - fromTbl[val];
	}
	/*
		get value and rank
		val = get(pos);
		return rank(val, pos);
	*/
	template<class T>
	uint64_t get(T* pval, uint64_t pos) const
	{
		if (pos > size_) pos = size_;
		uint64_t ret = 0;
		for (size_t i = 0; i < valBitLen_; i++) {
			bool b = svv[i].get(pos);
			ret = (ret << 1) | uint32_t(b);
			if (b) {
				pos = offTbl[i] + svv[i].rank1(pos);
			} else {
				pos -= svv[i].rank1(pos);
			}
		}
		*pval = (T)ret;
		return pos - fromTbl[ret];
	}
	/*
		get number of less than val in [0, pos)
	*/
	uint64_t rankLt(uint64_t val, uint64_t pos) const
	{
		assert(val < maxVal_);
		if (pos > size_) pos = size_;
		uint64_t ret = 0;
		for (size_t i = 0; i < valBitLen_; i++) {
			bool b = getPos(val, valBitLen_ - 1 - i);
			uint64_t end = svv[i].rank1(pos);
			if (b) {
				ret += pos - end;
				pos = offTbl[i] + end;
			} else {
				pos -= end;
			}
		}
		return ret - fromLtTbl[val];
	}
	uint64_t select(uint64_t val, uint64_t rank) const
	{
		if (!withSelect) throw cybozu::Exception("WaveletMatrix:select:not support");
		assert(val < maxVal_);
		const Uint32Vec& tbl = selTbl_[val];
		if (rank / posUnit >= tbl.size()) return cybozu::NotFound;
		const size_t pos = size_t(rank / posUnit);
//		size_t L = 0;
//		size_t R = size_;
		size_t L = tbl[pos];
		size_t R = pos >= tbl.size() - 1 ? size_ : tbl[pos + 1];
//printf("val=%d, rank=%d, L=%d, R=%d, size=%d\n", (int)val, (int)rank, (int)L, (int)R, (int)size_);
		rank++;
		while (L < R) {
			size_t M = (L + R) / 2;
			if (this->rank(val, M) < rank) {
				L = M + 1;
			} else {
				R = M;
			}
		}
		if (L > 0) L--;
		for (;;) {
			if (this->rank(val, L) == rank) {
				return L - 1;
			}
			L++;
			if (L > size_) return cybozu::NotFound;
		}
	}
};

typedef WaveletMatrixT<> WaveletMatrix;

} // cybozu

#ifdef _MSC_VER
#pragma warning(pop)
#endif

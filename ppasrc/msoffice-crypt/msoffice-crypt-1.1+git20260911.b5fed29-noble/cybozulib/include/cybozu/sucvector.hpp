#pragma once
/**
	@file
	@brief succinct vector
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause

	@note use -msse4.2 option for popcnt
*/
#include <assert.h>
#include <vector>
#include <cybozu/exception.hpp>
#include <cybozu/bit_operation.hpp>
#include <cybozu/select8.hpp>
#include <cybozu/serializer.hpp>
#include <iosfwd>

#ifdef _MSC_VER
	#pragma warning(push)
	#pragma warning(disable : 4127)
#endif

namespace cybozu {

const uint64_t NotFound = ~uint64_t(0);

namespace sucvector_util {

inline uint32_t rank64(uint64_t v, size_t i)
{
    return cybozu::popcnt<uint64_t>(v & cybozu::makeBitMask64(i));
}

template<class T>
T getBlockNum(T x, T block)
{
	return (x + block - 1) / block;
}

inline uint32_t select64(uint64_t v, size_t r)
{
	assert(r <= 64);
	if (r > popcnt(v)) return 64;
	uint32_t pos = 0;
	uint32_t c = popcnt(uint32_t(v));
	if (r > c) {
		r -= c;
		pos = 32;
		v >>= 32;
	}
	c = popcnt<uint32_t>(uint16_t(v));
	if (r > c) {
		r -= c;
		pos += 16;
		v >>= 16;
	}
	c = popcnt<uint32_t>(uint8_t(v));
	if (r > c) {
		r -= c;
		pos += 8;
		v >>= 8;
	}
	if (r == 8 && uint8_t(v) == 0xff) return pos + 7;
	assert(r <= 8);
	c = cybozu::select8_util::select8(uint8_t(v), r);
	return pos + c;
}

} // cybozu::sucvector_util

/*
	extra memory
	(32 + 8 * 4) / 256 = 1/4 bit per bit for rank
*/
template<class type, bool withSelect = true>
class SucVectorT {
	typedef type size_type;
	static const bool support1TiB = sizeof(size_type) == 8;
	static const int maxBitLen = support1TiB ? 32 + 8 : 32; // don't increase this value
	static const uint64_t maxBitSize = uint64_t(1) << maxBitLen;
	struct Block {
		uint64_t org[4];
		union {
			uint64_t a64;
			struct {
				uint32_t a;
				uint8_t b[4]; // b[0] is used for (b[0] << 32) | a
			} ab;
		};
		void clear()
		{
			memset(this, 0, sizeof(Block));
		}
	};
	uint64_t bitSize_;
	uint64_t numTbl_[2];
	bool freezed_;
	std::vector<Block> blk_;
	typedef std::vector<uint32_t> Uint32Vec;
	static const uint64_t posUnit = 1024;
	Uint32Vec selTbl_[2];

	template<int b>
	uint64_t rank_a(size_t i) const
	{
		assert(i < blk_.size());
		uint64_t ret;
		if (support1TiB) {
			ret  = blk_[i].a64 & makeBitMask64(maxBitLen);
		} else {
			ret = blk_[i].ab.a;
		}
		if (!b) ret = i * uint64_t(256) - ret;
		return ret;
	}
	template<bool b>
	size_t get_b(size_t L, size_t i) const
	{
		assert(L < blk_.size());
		assert(0 < i && i < 4);
		size_t r = blk_[L].ab.b[i];
		if (!b) r = 64 * i - r;
		return r;
	}
	// call after blk_, numTbl_ are initialized
	void initSelTbl()
	{
		if (!withSelect) return;
		initSelTblSub<false>(selTbl_[0]);
		initSelTblSub<true>(selTbl_[1]);
	}
	template<bool b>
	void initSelTblSub(Uint32Vec& tbl)
	{
		const int tablePos = b ? 1 : 0;
		assert(numTbl_[tablePos] / posUnit < 0x7fffffff - 1);
		const size_t size = size_t(sucvector_util::getBlockNum(numTbl_[tablePos], posUnit));
		tbl.resize(size);
		uint32_t pos = 0;
		for (size_t i = 0; i < size; i++) {
			uint64_t r = i * posUnit;
			while (rank_a<b>(pos) < r) {
				pos++;
				if (pos == blk_.size()) break;
			}
			tbl[i] = pos;
		}
	}
	void initBlock(const uint64_t *buf, size_t blkNum)
	{
		uint64_t num1 = 0;
		size_t pos = 0;
		for (size_t i = 0, n = blk_.size(); i < n; i++) {
			Block& blk = blk_[i];
			if (support1TiB) {
				blk.a64 = num1 % maxBitSize;
			} else {
				if (num1 > 0xffffffff) throw cybozu::Exception("SucVectorT:too large num1") << num1;
				blk.ab.a = (uint32_t)num1;
			}
			uint32_t subNum1 = 0;
			for (size_t j = 0; j < 4; j++) {
				uint64_t v;
				if (buf) {
					v = pos < blkNum ? buf[pos++] : 0;
					blk.org[j] = v;
				} else {
					v = blk.org[j];
				}
				uint32_t c = cybozu::popcnt(v);
				num1 += c;
				if (j > 0) {
					blk.ab.b[j] = (uint8_t)subNum1;
				}
				subNum1 += c;
			}
		}
		numTbl_[0] = blkNum * 64 - num1;
		numTbl_[1] = num1;
		initSelTbl();
		freezed_ = true;
	}
public:
	/*
		data format(endian is depend on CPU:eg. little endian for x86/x64)
		bitSize  : 8
		numTbl_[0]  : 8
		numTbl_[1]  : 8
		blkSize  : 8
		blk data : blkSize * sizeof(Block)
	*/
	template<class OutputStream>
	void save(OutputStream& os) const
	{
		cybozu::save(os, bitSize_);
		cybozu::save(os, numTbl_[0]);
		cybozu::save(os, numTbl_[1]);
		cybozu::savePodVec(os, blk_);
		if (withSelect) {
			cybozu::savePodVec(os, selTbl_[0]);
			cybozu::savePodVec(os, selTbl_[1]);
		}
	}
	template<class InputStream>
	void load(InputStream& is)
	{
		cybozu::load(bitSize_, is);
		cybozu::load(numTbl_[0], is);
		cybozu::load(numTbl_[1], is);
		cybozu::loadPodVec(blk_, is);
		if (withSelect) {
			cybozu::loadPodVec(selTbl_[0], is);
			cybozu::loadPodVec(selTbl_[1], is);
		} else {
			initSelTbl();
		}
	}
	SucVectorT() : bitSize_(0), freezed_(false) { numTbl_[0] = numTbl_[1] = 0; }
	SucVectorT(const uint64_t *buf, uint64_t bitSize)
	{
		init(buf, bitSize);
	}
	/*
		initialize SucVector
		@param buf [in] bit pattern buffer
		@param bitSize [in] bitSize ; buf size = (bitSize + 63) / 64
	*/
	void init(const uint64_t *buf, uint64_t bitSize)
	{
		const size_t blkNum = resize(bitSize, false);
		initBlock(buf, blkNum);
	}
	/*
		initialize SucVector after calling set without BitVector
		1. resize(bitSize)
		2. construct bit vector with set(pos)
		3. ready()
	*/
	size_t resize(size_t bitSize, bool doClear = true)
	{
		if (bitSize > maxBitSize) throw cybozu::Exception("SucVectorT:resize:too large bitSize") << bitSize;
		assert((bitSize + 63) / 64 <= ~size_t(0));
		bitSize_ = bitSize;
		const size_t blkNum = size_t((bitSize + 63) / 64);
		const size_t tblNum = (blkNum + 3) / 4; // tblNum <= 2^32
		blk_.resize(tblNum);
		if (doClear) {
			for (size_t i = 0; i < tblNum; i++) {
				blk_[i].clear();
			}
		}
		freezed_ = false;
		return blkNum;
	}
	void set(size_t idx)
	{
		if (freezed_) throw cybozu::Exception("SucVector:set:freezed");
		if (idx >= bitSize_) throw cybozu::Exception("SucVector:set:bad idx") << idx;
		const size_t q = idx / 256;
		const size_t r = idx % 256;

		uint64_t& b = blk_[q].org[r / 64];
		b |= uint64_t(1) << (r % 64);
	}
	void ready()
	{
		initBlock(0, blk_.size() * 4);
	}
	uint64_t rank1(uint64_t pos) const
	{
		if (pos >= bitSize_) return numTbl_[1];
		assert(pos / 256 <= ~size_t(0));
		size_t q = size_t(pos / 256);
		size_t r = size_t((pos / 64) & 3);
		assert(q < blk_.size());
		const Block& blk = blk_[q];
		uint64_t ret;
		if (support1TiB) {
			ret = blk.a64 % maxBitSize;
		} else {
			ret = blk.ab.a;
		}
		if (r > 0) {
			ret += blk.ab.b[r]; // faster on sandy-bridge
//			ret += uint8_t(blk.a64 >> (32 + r * 8));
		}
		ret += cybozu::popcnt<uint64_t>(blk.org[r] & cybozu::makeBitMask64(pos & 63));
		return ret;
	}
	uint64_t size() const { return bitSize_; }
	uint64_t size(bool b) const { return numTbl_[b ? 1 : 0]; }
	uint64_t rank0(uint64_t pos) const
	{
		return pos - rank1(pos);
	}
	uint64_t rank(bool b, uint64_t pos) const
	{
		if (b) return rank1(pos);
		return rank0(pos);
	}
	bool get(uint64_t pos) const
	{
		if (pos >= bitSize_) throw cybozu::Exception("SucVector:get") << pos << bitSize_;
		size_t q = size_t(pos / 256);
		size_t r = size_t((pos / 64) & 3);
		assert(q < blk_.size());
		const Block& blk = blk_[q];
		return (blk.org[r] & (1ULL << (pos & 63))) != 0;
	}
	uint64_t select0(uint64_t rank) const { return selectSub<false>(rank); }
	uint64_t select1(uint64_t rank) const { return selectSub<true>(rank); }
	uint64_t select(bool b, uint64_t rank) const
	{
		if (b) return select1(rank);
		return select0(rank);
	}

	/*
		0123456789
		0100101101
		 ^  ^ ^^
		 0  1 23
		select(v, r) = min { i - 1 | rank(v, i) = r + 1 }
		select(3) = 7
	*/
	template<bool b>
	uint64_t selectSub(uint64_t rank) const
	{
		if (!withSelect) throw cybozu::Exception("SucVector:selectSub is not supported");
		const int tablePos = b ? 1 : 0;
		if (rank >= numTbl_[tablePos]) return NotFound;
		const Uint32Vec& tbl = selTbl_[tablePos];
		assert(rank / posUnit < tbl.size());
		const size_t pos = size_t(rank / posUnit);
		size_t L = tbl[pos];
		size_t R = pos >= tbl.size() - 1 ? blk_.size() : tbl[pos + 1];
		rank++;
		while (L < R) {
			size_t M = (L + R) / 2; // (R - L) / 2 + L;
			if (rank_a<b>(M) < rank) {
				L = M + 1;
			} else {
				R = M;
			}
		}
		if (L > 0) L--;
		rank -= rank_a<b>(L);

		size_t i = 0;
		while (i < 3) {
			size_t r = get_b<b>(L, i + 1);
			if (r >= rank) {
				break;
			}
			i++;
		}
		if (i > 0) {
			size_t r = get_b<b>(L, i);
			rank -= r;
		}
		uint64_t v = blk_[L].org[i];
		if (!b) v = ~v;
		assert(rank <= 64);
		uint64_t ret = cybozu::sucvector_util::select64(v, size_t(rank));
		ret += L * 256 + i * 64;
		return ret;
	}
};

typedef cybozu::SucVectorT<uint32_t> SucVectorLt4G;
typedef cybozu::SucVectorT<uint64_t> SucVector;

} // cybozu

#ifdef _WIN32
	#pragma warning(pop)
#endif

#pragma once
/**
	@file
	@brief compressed succinct vector
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
	@note use -msse4.2 option for popcnt
*/
#include <cybozu/sucvector.hpp>
#include <cybozu/bitvector.hpp>
#include <cybozu/serializer.hpp>
#include <vector>
#include <iosfwd>
#include <map>

#ifdef _MSC_VER
	#pragma warning(push)
	#pragma warning(disable : 4351) // init buf in cstr
#endif

//#define USE_CLK
#ifdef USE_CLK
#include <cybozu/benchmark.hpp>
#endif

namespace cybozu {

namespace csucvector_util {

static const size_t tblBitLen = 8;
static const size_t maxTblSize = size_t(1) << tblBitLen;
static const uint64_t all1 = uint64_t(-1);

inline uint64_t getMask(size_t pos)
{
	assert(pos < 64);
	return (uint64_t(1) << pos) - 1;
}

struct Encoding {
	uint64_t v;
	uint32_t len;
	uint32_t rk;
	Encoding(uint64_t v = 0, uint32_t len = 0)
		: v(v)
		, len(len)
		, rk(len <= 64 ? cybozu::popcnt<uint64_t>(v) : v == 0 ? 0 : len) { }
	bool operator<(const Encoding& rhs) const
	{
		if (len > rhs.len) return true;
		if (len < rhs.len) return false;
		return v > rhs.v;
	}
};

struct InputStream {
	const uint64_t *block_;
	size_t bitSize_;
	size_t blockSize_;
	size_t cur_;
	InputStream(const uint64_t *block, size_t bitSize)
		: block_(block), bitSize_(bitSize), blockSize_((bitSize + 63) / 64), cur_(0)
	{
	}
	uint64_t peek(size_t offset = 0) const
	{
		const size_t q = (cur_ + offset) / 64;
		const size_t r = (cur_ + offset) & 63;
		if (q >= blockSize_) return 0;
		if (r == 0) return block_[q];
		uint64_t L = block_[q];
		uint64_t H = q < blockSize_ - 1 ? block_[q + 1] : 0;
		return ((L >> r) & getMask(64 - r)) | (H << (64 - r));
	}
	void consume(size_t size)
	{
		if (!empty()) cur_ += size;
	}
	bool empty() const { return cur_ >= bitSize_; }
};

struct Bigram {
	struct Pair {
		uint32_t prev;
		uint32_t cur;
		Pair(uint32_t prev = 0, uint32_t cur = 0) : prev(prev), cur(cur) {}
	};
	typedef std::multimap<uint32_t, Pair, std::greater<uint32_t> > PairMap;
	const std::vector<Encoding>& encTbl_;
	uint32_t tblNum;
	std::vector<std::vector<uint32_t> > tbl;
	size_t prev;
	explicit Bigram(const std::vector<Encoding>& encTbl)
		: encTbl_(encTbl)
		, tblNum((uint32_t)encTbl.size())
		, tbl()
		, prev(tblNum) // first special value
	{
		tbl.resize(tblNum);
		for (uint32_t i = 0; i < tblNum; i++) {
			tbl[i].resize(tblNum);
		}
	}
//	~Bigram(){ put(); }
	void append(uint32_t v)
	{
		if (v >= tblNum) throw cybozu::Exception("CSucVector:Bigram:bad v") << v;
		if (prev == tblNum) {
			prev = v;
			return;
		}
		tbl[prev][v]++;
		prev = v;
	}
	void getPairMap(PairMap& m) const
	{
		for (uint32_t i = 0; i < tblNum; i++) {
			for (uint32_t j = 0; j < tblNum; j++) {
				m.insert(PairMap::value_type(tbl[i][j], Pair(i, j)));
			}
		}
	}
	bool isAll1(uint64_t x, size_t len) const
	{
		if (len >= 64) {
			return x == all1;
		}
		const uint64_t mask = getMask(len);
		return (x & mask) == (all1 & mask);
	}
	bool concatPair(uint64_t& v, uint32_t& len, const Pair& pair) const
	{
		const uint64_t L = encTbl_[pair.prev].v;
		const uint32_t Ln = encTbl_[pair.prev].len;
		const uint64_t H = encTbl_[pair.cur].v;
		const uint32_t Hn = encTbl_[pair.cur].len;
		if (L == 0 && H == 0) {
			v = 0;
			len = Ln + Hn;
			return true;
		}
		if (isAll1(L, Ln) && isAll1(H, Hn)) {
			len = Ln + Hn;
			v = len >= 64 ? all1 : getMask(len);
			return true;
		}
		if (Ln + Hn <= 64) {
			v = (H << Ln) | L;
			len = Ln + Hn;
			return true;
		}
		return false;
	}
	bool getTopEncoding(uint64_t& v, uint32_t& len) const
	{
		PairMap m;
		getPairMap(m);
		return concatPair(v, len, m.begin()->second);
	}
	void put() const
	{
		PairMap m;
		getPairMap(m);
		int n = 0;
		for (PairMap::const_iterator i = m.begin(), ie = m.end(); i != ie; ++i) {
			if (i->first > 0) {
				printf("%u (%u, %u) ", i->first, i->second.prev, i->second.cur);
				uint64_t v;
				uint32_t len;
				if (concatPair(v, len, i->second)) {
					printf(" { 0x%llx, %u }\n", (long long)v, len);
				} else {
					printf("over prev=%u cur=%u\n", i->second.prev, i->second.cur);
				}
				n++;
				if (n == 10) break;
			}
		}
	}
private:
	Bigram(const Bigram&);
	void operator=(const Bigram&);
};

} // cybozu::csucvector_util

struct CSucVector {
#ifdef USE_CLK
	mutable cybozu::CpuClock clkGet;
	mutable cybozu::CpuClock clkRank;
	void putClkSub(const char *msg, const cybozu::CpuClock& clk) const
	{
		if (clk.getCount() == 0) return;
		printf("%s:%6.2f %d\n", msg, clk.getClock() / double(clk.getCount()), clk.getCount());
	}
	void putClk() const
	{
		putClkSub("get   ", clkGet);
		putClkSub("rank  ", clkRank);
		puts("");
	}
#endif

	struct Block {
		uint32_t orgPos;
		uint32_t vecPos;
		uint32_t rk;
		Block(uint32_t orgPos = 0, uint32_t vecPos = 0, uint32_t rk = 0) : orgPos(orgPos), vecPos(vecPos), rk(rk) {}
	};
	static const uint32_t skip = 1024;
	typedef std::vector<Block> BlockVec;
	typedef std::vector<csucvector_util::Encoding> EncodingTbl;
	typedef std::vector<uint32_t> Vec32;
	typedef std::vector<uint8_t> Vec8;
	EncodingTbl encTbl;
	uint32_t bitSize_;
	Vec8 vec;
	BlockVec blkVec;
	uint32_t rk_;
	Vec32 freqTbl;

	struct OutputStream {
		Vec32& freqTbl; // output
		Vec8& vec; // output
		uint32_t& rk; // output
		csucvector_util::Bigram bi; // output
		const EncodingTbl& encTbl; // in
		OutputStream(Vec32& freqTbl, Vec8& vec, uint32_t& rk, const uint64_t *buf, uint32_t bitSize, const EncodingTbl& encTbl)
			: freqTbl(freqTbl)
			, vec(vec)
			, rk(rk)
			, bi(encTbl)
			, encTbl(encTbl)
		{
			csucvector_util::InputStream is(buf, bitSize);
			freqTbl.clear();
			freqTbl.resize(encTbl.size());
			vec.clear();
			rk = 0;
			for (;;) {
				uint32_t s = append(is);
				is.consume(s);
				if (is.empty()) break;
			}
			printf("bitSize=%u\n",bitSize);
		}
		uint32_t append(const csucvector_util::InputStream& is)
		{
			uint64_t v = is.peek();
			for (size_t i = 0; i < encTbl.size(); i++) {
				const uint32_t len = encTbl[i].len;
				bool found = false;
				if (len >= 64) {
					const size_t q = len / 64;
					const size_t r = len % 64;
					const uint64_t target = encTbl[i].v;
					if (v == target) {
						found = true;
						for (size_t j = 1; j < q; j++) {
							if (is.peek(j * 64) != target) {
								found = false;
								break;
							}
						}
						if (found && r > 0) {
							const uint64_t mask = csucvector_util::getMask(r);
							if ((is.peek(q * 64) & mask) != (target & mask)) {
								found = false;
							}
						}
					}
				} else {
					const uint64_t mask = csucvector_util::getMask(len);
					found = (v & mask) == encTbl[i].v;
				}
				if (found) {
					bi.append((uint8_t)i);
					freqTbl[i]++;
					rk += encTbl[i].rk;
					vec.push_back(uint8_t(i));
					return len;
				}
			}
			printf("NOT HERE!!! in debug mode\n");
			for (size_t i = 0; i < 4; i++) {
				printf("of=%d %llx\n", (int)i, (long long)is.peek(i * 64));
			}
			exit(1);
		}
	};
	void initTable()
	{
		static const struct {
			uint64_t v;
			uint32_t len;
		} tbl[] = {
#if 1
{ 0x0, 16384 },
{ 0xffffffffffffffff, 8192 },
{ 0x0, 8192 },
{ 0xffffffffffffffff, 4096 },
{ 0x0, 4096 },
{ 0xffffffffffffffff, 2048 },
{ 0x0, 2048 },
{ 0xffffffffffffffff, 1024 },
{ 0x0, 1024 },
{ 0xffffffffffffffff, 512 },
{ 0x0, 512 },
{ 0x0, 384 },
{ 0xffffffffffffffff, 256 },
{ 0x0, 256 },
{ 0x0, 224 },
{ 0xffffffffffffffff, 192 },
{ 0xffffffffffffffff, 128 },
{ 0x0, 128 },
{ 0x0, 96 },
{ 0x0, 85 },
{ 0xffffffffffffffff, 64 },
{ 0x0, 64 },
{ 0x1fffffffffffff, 53 },
{ 0x0, 53 },
{ 0x3fffffffffff, 46 },
{ 0x0, 46 },
{ 0x7fffffffff, 39 },
{ 0x4000000, 35 },
{ 0x2000000, 35 },
{ 0x1000000, 35 },
{ 0x800000, 35 },
{ 0x400000, 35 },
{ 0x200000, 35 },
{ 0xffffffff, 32 },
{ 0x0, 32 },
{ 0xfffffff, 28 },
{ 0x8000000, 28 },
{ 0x7ffffff, 28 },
{ 0x4000000, 28 },
{ 0x0, 28 },
{ 0x1fffff, 21 },
{ 0x1fff7f, 21 },
{ 0x1dffff, 21 },
{ 0x1bffff, 21 },
{ 0x180000, 21 },
{ 0x17ffff, 21 },
{ 0x100000, 21 },
{ 0xfffff, 21 },
{ 0x80000, 21 },
{ 0x40000, 21 },
{ 0x20000, 21 },
{ 0x10000, 21 },
{ 0x8000, 21 },
{ 0x4000, 21 },
{ 0x81, 21 },
{ 0x0, 21 },
{ 0x3fff, 14 },
{ 0x3ffe, 14 },
{ 0x3f7f, 14 },
{ 0x3eff, 14 },
{ 0x3dff, 14 },
{ 0x3c00, 14 },
{ 0x3bff, 14 },
{ 0x3800, 14 },
{ 0x37ff, 14 },
{ 0x3000, 14 },
{ 0x2fff, 14 },
{ 0x2800, 14 },
{ 0x2400, 14 },
{ 0x2200, 14 },
{ 0x2100, 14 },
{ 0x2080, 14 },
{ 0x2040, 14 },
{ 0x2020, 14 },
{ 0x2010, 14 },
{ 0x2008, 14 },
{ 0x2004, 14 },
{ 0x2002, 14 },
{ 0x2001, 14 },
{ 0x2000, 14 },
{ 0x1fff, 14 },
{ 0x1800, 14 },
{ 0x1400, 14 },
{ 0x1200, 14 },
{ 0x1100, 14 },
{ 0x1080, 14 },
{ 0x1020, 14 },
{ 0x1010, 14 },
{ 0x1008, 14 },
{ 0x1004, 14 },
{ 0x1002, 14 },
{ 0x1001, 14 },
{ 0x1000, 14 },
{ 0xfff, 14 },
{ 0xc00, 14 },
{ 0xa00, 14 },
{ 0x900, 14 },
{ 0x880, 14 },
{ 0x808, 14 },
{ 0x804, 14 },
{ 0x802, 14 },
{ 0x801, 14 },
{ 0x800, 14 },
{ 0x7ff, 14 },
{ 0x600, 14 },
{ 0x500, 14 },
{ 0x480, 14 },
{ 0x401, 14 },
{ 0x400, 14 },
{ 0x300, 14 },
{ 0x280, 14 },
{ 0x208, 14 },
{ 0x202, 14 },
{ 0x201, 14 },
{ 0x200, 14 },
{ 0x180, 14 },
{ 0x102, 14 },
{ 0x101, 14 },
{ 0x100, 14 },
{ 0x80, 14 },
{ 0x40, 14 },
{ 0x20, 14 },
{ 0x10, 14 },
{ 0x8, 14 },
{ 0x4, 14 },
{ 0x2, 14 },
{ 0x1, 14 },
{ 0x0, 14 },
#else
			{ 0, 64 * 32 },
			{ uint64_t(-1), 64 * 16 },
			{ uint64_t(-1), 256 },
			{ 0, 256 },
			{ 0, 32 },
			{ 0xffffffff, 32 },
#endif
		};
		encTbl.clear();
		for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
			encTbl.push_back(csucvector_util::Encoding(tbl[i].v, tbl[i].len));
		}
		for (int i = 0; i < 128; i++) {
			encTbl.push_back(csucvector_util::Encoding(i, 7));
		}
		std::sort(encTbl.begin(), encTbl.end());
		if (encTbl.size() > csucvector_util::maxTblSize) {
			throw cybozu::Exception("CSucVector:initTable:bad size") << encTbl.size();
		}
	}

	CSucVector() { clear(); }
	~CSucVector()
	{
//		put();
#ifdef USE_CLK
		putClk();
#endif
	}
	CSucVector(const uint64_t *buf, uint64_t bitSize)
	{
		clear();
		init(buf, bitSize);
	}
	void clear()
	{
		bitSize_ = 0;
		rk_ = 0;
	}
	void init(const uint64_t *buf, uint64_t bitSize)
	{
		if (bitSize >= (uint64_t(1) << 32)) throw cybozu::Exception("CSucVector:init:big bitSize") << bitSize;
		bitSize_ = (uint32_t)bitSize;
		initTable();
		for (;;) {
			OutputStream os(freqTbl, vec, rk_, buf, bitSize_, encTbl);
//	os.bi.put();
			if (encTbl.size() == csucvector_util::maxTblSize) break;
			uint64_t v;
			uint32_t len;
			if (!os.bi.getTopEncoding(v, len)) {
				printf("ERR getTopEncoding\n");
				os.bi.put();
				putEncTbl();
				exit(1);
			}
			printf("append v=%llx, len=%u tblSize=%u\n", (long long)v, len, (uint32_t)encTbl.size());
			encTbl.push_back(csucvector_util::Encoding(v, len));
			std::sort(encTbl.begin(), encTbl.end());
		}
//		putEncTbl();
		initBlockVec();
	}
	void initBlockVec()
	{
		blkVec.reserve(bitSize_ / skip + 16);
		uint32_t orgPos = 0;
		uint32_t rk = 0;
		uint32_t samplingPos = 0;
		for (size_t vecPos = 0, n = vec.size(); vecPos < n; vecPos++) {
			uint8_t v = vec[vecPos];
			uint32_t next = orgPos + encTbl[v].len;

			while (samplingPos < next) {
				blkVec.push_back(Block(orgPos, (uint32_t)vecPos, rk));
				samplingPos += skip;
			}
			orgPos = next;
			rk += encTbl[v].rk;
		}
	}
	void putEncTbl() const
	{
		for (size_t i = 0; i < encTbl.size(); i++) {
			printf("%2d : { 0x%llx, %u },\n", (int)i, (long long)encTbl[i].v, encTbl[i].len);
		}
	}
	void putSub() const
	{
		const uint32_t inSize = bitSize_ / 8;
		if (inSize == 0) return;
		const uint32_t compSize = (uint32_t)vec.size();
		const uint32_t idxSize = (uint32_t)(blkVec.size() * sizeof(blkVec[0]));
		const double cr = compSize * 100.0 / inSize;
		const double ir = idxSize * 100.0 / inSize;
		printf("in   Size= %9d, rank=%u\n", inSize, rk_);
		printf("comp Size= %9u\n", compSize);
		printf("idx  Size= %9u(blkVec.size=%7u)\n", idxSize, (uint32_t)blkVec.size());
		printf("totalSize= %9u\n", compSize + idxSize);
		printf("rate=%5.2f%%(%5.2f%% + %5.2f%%)\n", cr + ir, cr, ir);
	}
	void put() const
	{
		putSub();
		if (freqTbl.empty()) return;
		const uint32_t compSize = (uint32_t)vec.size();
		for (size_t i = 0; i < freqTbl.size(); i++) {
			printf("freqTbl[%2d] = %8d(%5.2f%%, %5.2f%%)\n", (int)i, freqTbl[i], freqTbl[i] * 100.0 / compSize, freqTbl[i] * encTbl[i].len * 100.0 / bitSize_);
		}
	}
	bool get(size_t pos) const
	{
		if (pos >= bitSize_) throw cybozu::Exception("CSucVector:get:bad pos") << pos;
#ifdef USE_CLK
clkGet.begin();
#endif
		const uint32_t cur = blkVec[pos / skip].orgPos;
		uint32_t vecPos = blkVec[pos / skip].vecPos;
		pos -= cur;
		uint8_t v;
		for (;;) {
			v = vec[vecPos++];
			uint32_t len = encTbl[v].len;
			if (len > pos) break;
			pos -= len;
		}
		const bool b = (pos >= 64) ? encTbl[v].v != 0 : (encTbl[v].v & (size_t(1) << pos)) != 0;
#ifdef USE_CLK
clkGet.end();
#endif
		return b;
	}
	size_t rank1(size_t pos) const
	{
		if (pos >= bitSize_) return rk_;
#ifdef USE_CLK
clkRank.begin();
#endif
		const uint32_t cur = blkVec[pos / skip].orgPos;
		uint32_t vecPos = blkVec[pos / skip].vecPos;
		size_t rk = blkVec[pos / skip].rk;
		pos -= cur;
		uint8_t v;
		for (;;) {
			v = vec[vecPos++];
			size_t len = encTbl[v].len;
			if (len > pos) break;
			pos -= len;
			rk += encTbl[v].rk;
		}
		size_t adj = 0;
		if (pos >= 64) {
			if (encTbl[v].v != 0) adj = pos;
		} else {
			uint64_t x = encTbl[v].v & csucvector_util::getMask(pos);
			adj = cybozu::popcnt<uint64_t>(x);
		}
		rk += adj;
#ifdef USE_CLK
clkRank.end();
#endif
		return rk;
	}
	size_t rank0(size_t pos) const
	{
		return pos - rank1(pos);
	}
	size_t rank(bool b, size_t pos) const
	{
		if (b) return rank1(pos);
		return rank0(pos);
	}
	template<class OutputStream>
	void save(OutputStream& os) const
	{
		cybozu::save(os, bitSize_);
		cybozu::savePodVec(os, vec);
		cybozu::savePodVec(os, blkVec);
		cybozu::save(os, rk_);
		cybozu::savePodVec(os, encTbl);
	}
	template<class InputStream>
	void load(InputStream& is)
	{
		cybozu::load(bitSize_, is);
		cybozu::loadPodVec(vec, is);
		cybozu::loadPodVec(blkVec, is);
		cybozu::load(rk_, is);
		cybozu::loadPodVec(encTbl, is);
	}
};

} // cybozu

#ifdef _WIN32
	#pragma warning(pop)
#endif

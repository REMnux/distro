#pragma once
/**
	@file
	@brief SHA1 class

	@author MITSUNARI Shigeo(@herumi)
	@note this is naive implementation so is not fast.
*/

#include <cybozu/inttype.hpp>
#include <cybozu/endian.hpp>
#include <string>
#include <algorithm>
#include <memory.h>
#include <assert.h>

namespace cybozu {

class Sha1 {
private:
	uint64_t totalSize_;
	size_t roundBufSize_;
	char roundBuf_[64];
	uint32_t H_[5];
	uint32_t K_[80];
	uint32_t digest_[5];
	bool done_;

	uint32_t S(uint32_t x, int s) const
	{
#ifdef _MSC_VER
		return _rotl(x, s);
#else
		return (x << s) | (x >> (32 - s));
#endif
	}

	uint32_t f0(uint32_t b, uint32_t c, uint32_t d) const { return (b & c) | (~b & d); }
	uint32_t f1(uint32_t b, uint32_t c, uint32_t d) const { return b ^ c ^ d; }
	uint32_t f2(uint32_t b, uint32_t c, uint32_t d) const { return (b & c) | (b & d) | (c & d); }
	uint32_t f(int t, uint32_t b, uint32_t c, uint32_t d) const
	{
		if (t < 20) {
			return f0(b, c, d);
		} else
		if (t < 40) {
			return f1(b, c, d);
		} else
		if (t < 60) {
			return f2(b, c, d);
		} else {
			return f1(b, c, d);
		}
	}

	void reset()
	{
		static const uint32_t tbl[] = {
			0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
		};
		for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
			for (int j = 0; j < 20; j++) {
				K_[i * 20 + j] = tbl[i];
			}
		}
		totalSize_ = 0;
		roundBufSize_ = 0;
		H_[0] = 0x67452301;
		H_[1] = 0xefcdab89;
		H_[2] = 0x98badcfe;
		H_[3] = 0x10325476;
		H_[4] = 0xc3d2e1f0;
		done_ = false;
	}
	/**
		@param buf [in] buffer(64byte)
	*/
	void round(const char *buf)
	{
		uint32_t W[80];
		for (int i = 0; i < 16; i++) {
			W[i] = cybozu::Get32bitAsBE(&buf[i * 4]);
		}
		for (int i = 16 ; i < 80; i++) {
			W[i] = S(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
		}
		uint32_t a = H_[0];
		uint32_t b = H_[1];
		uint32_t c = H_[2];
		uint32_t d = H_[3];
		uint32_t e = H_[4];
		for (int i = 0; i < 80; i++) {
			uint32_t tmp = S(a, 5) + f(i, b, c, d) + e + W[i] + K_[i];
			e = d;
			d = c;
			c = S(b, 30);
			b = a;
			a = tmp;
		}
		H_[0] += a;
		H_[1] += b;
		H_[2] += c;
		H_[3] += d;
		H_[4] += e;
		totalSize_ += 64;
	}
	/*
		final phase
		@note bufSize < 64
	*/
	void term(const char *buf, size_t bufSize)
	{
		assert(bufSize < 64);
		const uint64_t totalSize = totalSize_ + bufSize;

		uint8_t last[64];
		memcpy(last, buf, bufSize);
		memset(&last[bufSize], 0, 64 - bufSize);
		last[bufSize] = uint8_t(0x80); /* top bit = 1 */
		if (bufSize >= 56) {
			round(cybozu::cast<const char*>(last));
			memset(last, 0, sizeof(last)); // clear stack
		}
		cybozu::Set32bitAsBE(&last[56], uint32_t(totalSize >> 29));
		cybozu::Set32bitAsBE(&last[60], uint32_t(totalSize * 8));
		round(cybozu::cast<const char*>(last));

		for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(H_); i++) {
			cybozu::Set32bitAsBE(&digest_[i], H_[i]);
		}
		done_ = true;
	}
public:
	Sha1()
	{
		reset();
	}
	void update(const char *buf, size_t bufSize)
	{
		if (bufSize == 0) return;
		assert(!done_);
		if (roundBufSize_ > 0) {
			size_t size = std::min(64 - roundBufSize_, bufSize);
			memcpy(roundBuf_ + roundBufSize_, buf, size);
			roundBufSize_ += size;
			buf += size;
			bufSize -= size;
		}
		if (roundBufSize_ == 64) {
			round(roundBuf_);
			roundBufSize_ = 0;
		}
		while (bufSize >= 64) {
			assert(roundBufSize_ == 0);
			round(buf);
			buf += 64;
			bufSize -= 64;
		}
		if (bufSize > 0) {
			assert(bufSize < 64);
			assert(roundBufSize_ == 0);
			memcpy(roundBuf_, buf, bufSize);
			roundBufSize_ = bufSize;
		}
		assert(roundBufSize_ < 64);
	}
	void update(const std::string& buf)
	{
		update(buf.c_str(), buf.size());
	}
	std::string digest(const char *buf, size_t bufSize)
	{
		assert(!done_);
		update(buf, bufSize);
		term(roundBuf_, roundBufSize_);
		std::string ret =  get();
		reset();
		return ret;
	}
	std::string digest(const std::string& str = "")
	{
		return digest(str.c_str(), str.size());
	}
	/**
		convert to printable string
	*/
	std::string toString() const
	{
		std::string str;
		char buf[32];
		for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(digest_); i++) {
			uint32_t v = cybozu::Get32bitAsBE(&digest_[i]);
			CYBOZU_SNPRINTF(buf, sizeof(buf), "%08x", v);
			str += buf;
		}
		return str;
	}
	void get(char out[20]) const
	{
		memcpy(out, digest_, sizeof(digest_));
	}
	std::string get() const
	{
		return std::string(cybozu::cast<const char*>(&digest_[0]), sizeof(digest_));
	}
};

} // cybozu


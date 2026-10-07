#pragma once
/**
	@file
	@brief siphash
	Copyright (c) 2013  Marek Majkowski <marek@popcount.org>
	modified by MITSUNARI Shigeo
*/

#include <cybozu/endian.hpp>

namespace cybozu {

namespace siphash_local {

inline uint64_t rotate(uint64_t x, uint64_t b)
{
	return (x << b) | (x >> (64 - b));
}

inline void halfRound(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d, int s, int t)
{
	a += b; c += d;
	b = rotate(b, s) ^ a;
	d = rotate(d, t) ^ c;
	a = rotate(a, 32);
}

inline void doubleRound(uint64_t &v0, uint64_t &v1, uint64_t &v2, uint64_t &v3)
{
	halfRound(v0, v1, v2, v3, 13, 16);
	halfRound(v2, v1, v0, v3, 17, 21);
	halfRound(v0, v1, v2, v3, 13, 16);
	halfRound(v2, v1, v0, v3, 17, 21);
}

} // cybozu::siphash_local

uint64_t siphash24(const void *src, size_t srcSize, uint64_t k0 = uint64_t(0x0706050403020100ULL), uint64_t k1 = uint64_t(0x0f0e0d0c0b0a0908ULL))
{
	uint64_t v0 = k0 ^ uint64_t(0x736f6d6570736575ULL);
	uint64_t v1 = k1 ^ uint64_t(0x646f72616e646f6dULL);
	uint64_t v2 = k0 ^ uint64_t(0x6c7967656e657261ULL);
	uint64_t v3 = k1 ^ uint64_t(0x7465646279746573ULL);

	const uint8_t *in = (const uint8_t*)src;
	uint64_t b = (uint64_t)srcSize << 56;

	while (srcSize >= 8) {
		uint64_t mi = cybozu::Get64bitAsLE(in);
		in += 8; srcSize -= 8;
		v3 ^= mi;
		siphash_local::doubleRound(v0, v1, v2, v3);
		v0 ^= mi;
	}

	switch (srcSize) {
	case 7: b |= uint64_t(in[6]) << 48; // fallthrough
	case 6: b |= uint64_t(in[5]) << 40; // fallthrough
	case 5: b |= uint64_t(in[4]) << 32; // fallthrough
	case 4: b |= uint64_t(in[3]) << 24; // fallthrough
	case 3: b |= uint64_t(in[2]) << 16; // fallthrough
	case 2: b |= uint64_t(in[1]) << 8; // fallthrough
	case 1: b |= in[0]; // fallthrough
	}

	v3 ^= b;
	siphash_local::doubleRound(v0, v1, v2, v3);
	v0 ^= b; v2 ^= 0xff;
	siphash_local::doubleRound(v0, v1, v2, v3);
	siphash_local::doubleRound(v0, v1, v2, v3);
	return (v0 ^ v1) ^ (v2 ^ v3);
}

} // cybozu

/*
 <MIT License>
 Copyright (c) 2013  Marek Majkowski <marek@popcount.org>
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 </MIT License>

 Original location:
    https://github.com/majek/csiphash/

 Solution inspired by code from:
    Samuel Neves (supercop/crypto_auth/siphash24/little)
    djb (supercop/crypto_auth/siphash24/little2)
    Jean-Philippe Aumasson (https://131002.net/siphash/siphash24.c)
*/

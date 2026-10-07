#pragma once
/**
	@file
	@brief wrapper of __m128
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <cybozu/inttype.hpp>
#include <stdio.h>
#include <assert.h>
#ifdef _WIN32
	#include <intrin.h>
#else
	#ifdef __linux__
		#include <x86intrin.h>
	#else
		#include <emmintrin.h>
	#endif
#endif

#ifndef MIE_PACK // for shufps
	#define MIE_PACK(x, y, z, w) ((x) * 64 + (y) * 16 + (z) * 4 + (w))
#endif

namespace cybozu {

struct V128 {
	__m128i x_;
	V128()
	{
	}
	V128(const uint32_t *p)
		: x_(_mm_load_si128((const __m128i*)p))
	{
	}
	V128(__m128i x)
		: x_(x)
	{
	}
	V128(__m128 x)
		: x_(_mm_castps_si128(x))
	{
	}
	__m128 to_ps() const { return _mm_castsi128_ps(x_); }
	// m = [x3:x2:x1:x0]
	V128(uint32_t x3, uint32_t x2, uint32_t x1, uint32_t x0)
		: x_(_mm_set_epi32(x3, x2, x1, x0))
	{
	}
	explicit V128(uint32_t x)
		: x_(_mm_cvtsi32_si128(x))
	{
	}
#if defined(_M_X64) || defined(__x86_64__)
	explicit V128(uint64_t x)
		: x_(_mm_cvtsi64_si128(x))
	{
	}
#endif
	V128(const V128& rhs)
		: x_(rhs.x_)
	{
	}
	void clear()
	{
		*this = _mm_setzero_si128();
	}
	void set(uint32_t x)
	{
		x_ = _mm_set1_epi32(x);
	}
	// m = [x3:x2:x1:x0]
	void set(uint32_t x3, uint32_t x2, uint32_t x1, uint32_t x0)
	{
		x_ = _mm_set_epi32(x3, x2, x1, x0);
	}
	// aligned
	void store(uint32_t *p) const
	{
		_mm_store_si128((__m128i*)p, x_);
	}
	// unaligned
	void store_u(uint32_t *p) const
	{
		_mm_storeu_si128((__m128i*)p, x_);
	}
	// aligned
	void load(const uint32_t *p)
	{
		x_ = _mm_load_si128((const __m128i*)p);
	}
	// unaligned
	void load_u(const uint32_t *p)
	{
		x_ = _mm_loadu_si128((const __m128i*)p);
	}
	/*
		*this >>= n
	*/
	template<int n>
	void shrBit();
	/*
		*this <<= n
	*/
	template<int n>
	void shlBit();
	void put(const char *msg = 0) const
	{
		uint32_t v[4];
		store_u(v);
		if (msg) printf("%s", msg);
		printf("%08x:%08x:%08x:%08x", v[3], v[2], v[1], v[0]);
		if (msg) putchar('\n');
	}
};

inline uint32_t movd(const V128& a)
{
	return _mm_cvtsi128_si32(a.x_);
}

inline V128 Zero()
{
	return _mm_setzero_si128();
}

template<int n>
inline V128 psrldq(const V128& a)
{
	return _mm_srli_si128(a.x_, n);
}

template<int n>
inline V128 pslldq(const V128& a)
{
	return _mm_slli_si128(a.x_, n);
}

template<int n>
inline V128 psrlq(const V128& a)
{
	return _mm_srli_epi64(a.x_, n);
}

inline V128 psrlq(const V128& a, const V128& n)
{
	return _mm_srl_epi64(a.x_, n.x_);
}

template<int n>
inline V128 psllq(const V128& a)
{
	return _mm_slli_epi64(a.x_, n);
}

inline V128 psllq(const V128& a, const V128& n)
{
	return _mm_sll_epi64(a.x_, n.x_);
}

template<int n>
inline V128 palignr(const V128& a, const V128& b)
{
	return _mm_alignr_epi8(a.x_, b.x_, n);
}

inline V128 punpckhdq(const V128& a, const V128& b)
{
	return _mm_unpackhi_epi32(a.x_, b.x_);
}

inline V128 punpckhqdq(const V128& a, const V128& b)
{
	return _mm_unpackhi_epi64(a.x_, b.x_);
}

inline V128 punpckldq(const V128& a, const V128& b)
{
	return _mm_unpacklo_epi32(a.x_, b.x_);
}

inline V128 punpcklqdq(const V128& a, const V128& b)
{
	return _mm_unpacklo_epi64(a.x_, b.x_);
}

inline V128 unpcklps(const V128& a, const V128& b)
{
	return _mm_unpacklo_ps(a.to_ps(), b.to_ps());
}

inline V128 unpckhps(const V128& a, const V128& b)
{
	return _mm_unpackhi_ps(a.to_ps(), b.to_ps());
}

inline V128 paddd(const V128& a, const V128& b)
{
	return _mm_add_epi32(a.x_, b.x_);
}
inline V128 psubd(const V128& a, const V128& b)
{
	return _mm_sub_epi32(a.x_, b.x_);
}

inline V128 pandn(const V128& a, const V128& b)
{
	return _mm_andnot_si128(a.x_, b.x_);
}

inline V128 por(const V128& a, const V128& b)
{
	return _mm_or_si128(a.x_, b.x_);
}

inline V128 pand(const V128& a, const V128& b)
{
	return _mm_and_si128(a.x_, b.x_);
}

inline V128 pxor(const V128& a, const V128& b)
{
	return _mm_xor_si128(a.x_, b.x_);
}

inline V128 pmaxsd(const V128& a, const V128& b)
{
	return _mm_max_epi32(a.x_, b.x_);
}

inline V128 pminsd(const V128& a, const V128& b)
{
	return _mm_min_epi32(a.x_, b.x_);
}

inline V128 pmaxud(const V128& a, const V128& b)
{
	return _mm_max_epu32(a.x_, b.x_);
}

inline V128 pminud(const V128& a, const V128& b)
{
	return _mm_min_epu32(a.x_, b.x_);
}

inline V128 pcmpeqd(const V128& a, const V128& b)
{
	return _mm_cmpeq_epi32(a.x_, b.x_);
}

inline V128 pcmpgtd(const V128& a, const V128& b)
{
	return _mm_cmpgt_epi32(a.x_, b.x_);
}

inline uint32_t pmovmskb(const V128& a)
{
	return _mm_movemask_epi8(a.x_);
}
inline V128 pshufb(const V128& a, const V128& b)
{
	return _mm_shuffle_epi8(a.x_, b.x_);
}

template<int n>
inline V128 pshufd(const V128& a)
{
	return _mm_shuffle_epi32(a.x_, n);
}

template<int idx>
inline uint32_t pextrd(const V128& a)
{
	return _mm_extract_epi32(a.x_, idx);
}

template<int idx>
inline V128 pinsrd(const V128& a, uint32_t v)
{
	return _mm_castsi128_ps(_mm_insert_epi32(a.x_, v, idx));
}

template<int idx>
inline V128 pinsrb(const V128& a, uint8_t v)
{
	return _mm_castsi128_ps(_mm_insert_epi8(a.x_, v, idx));
}

inline int ptest_zf(const V128& a, const V128& b)
{
	return _mm_testz_si128(a.x_, b.x_);
}

inline int ptest_cf(const V128& a, const V128& b)
{
	return _mm_testc_si128(a.x_, b.x_);
}

inline V128 psadbw(const V128& a, const V128& b)
{
	return _mm_sad_epu8(a.x_, b.x_);
}

inline void swap128(uint32_t *p, uint32_t *q)
{
	V128 t(p);
	V128(q).store(p);
	t.store(q);
}

inline void copy128(uint32_t *dest, const uint32_t *src)
{
	V128(src).store(dest);
}

template<int n>
inline void V128::shrBit()
{
	assert(n < 64);
	*this = psrlq<n>(*this) | psllq<64 - n>(psrldq<8>(*this));
#if 0
	if (n == 64) {
		*this = psrldq<8>(*this);
	} else if (n > 64) {
		*this = psrlq<n - 64>(psrldq<8>(*this));
	}
#endif
}

template<int n>
inline void V128::shlBit()
{
	assert(n < 64);
	*this = psllq<n>(*this) | psrlq<64 - n>(pslldq<8>(*this));
#if 0
	if (n == 64) {
		*this = pslldq<8>(*this);
	} else if (n > 64) {
		*this = psllq<n - 64>(pslldq<8>(*this));
	}
#endif
}

/*
	byte rotr [x2:x1:x0]
*/
template<int n>
inline void rotrByte(V128& x0, V128& x1, V128& x2)
{
	V128 t(x0);
	x0 = palignr<n>(x1, x0);
	x1 = palignr<n>(x2, x1);
	x2 = palignr<n>(t, x2);
}

/*
	byte rotl [x2:x1:x0]
*/
template<int n>
inline void rotlByte(V128& x0, V128& x1, V128& x2)
{
	V128 t(x2);
	x2 = palignr<16 - n>(x2, x1);
	x1 = palignr<16 - n>(x1, x0);
	x0 = palignr<16 - n>(x0, t);
}

#if defined(_M_X64) || defined(__x86_64__)
inline uint64_t movq(const V128& a)
{
	return _mm_cvtsi128_si64(a.x_);
}
#endif

} // cybozu

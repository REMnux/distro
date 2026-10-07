#pragma once
/**
	@file
	@brief PCG
	@see http://www.pcg-random.org/

	@author MITSUNARI Shigeo(@herumi)
	@author MITSUNARI Shigeo
*/
#include <cybozu/inttype.hpp>
#include <stdlib.h> // for _rotr

namespace cybozu {

class Pcg32 {
public:
	uint64_t state;
	uint32_t rotr(uint32_t x, uint32_t r) const
	{
#if defined(__GNUC__) && (CYBOZU_HOST == CYBOZU_HOST_INTEL)
		__asm__ volatile("rorl %%cl, %0" : "=r"(x) : "0"(x), "c"(r));
		return x;
#elif defined(_MSC_VER)
		return _rotr(x, r);
#else
		return (x >> r) | (x << ((-r) & 31));
#endif
	}
public:
	explicit Pcg32(uint64_t state = uint64_t(0x185706b82c2e03f8ULL))
		: state(state)
	{
	}
	uint32_t get32()
	{
		uint64_t old = state;
		state = old * 6364136223846793005ULL + 0x6d;
		uint32_t x = uint32_t(((old >> 18u) ^ old) >> 27u);
		uint32_t r = uint32_t(old >> 59u);
		return rotr(x, r);
	}
	uint32_t operator()() { return get32(); }
	uint64_t get64()
	{
		uint32_t a = get32();
		uint32_t b = get32();
		return (uint64_t(a) << 32) | b;
	}
	template<class T>
	void read(T *x, size_t n)
	{
		const size_t size = sizeof(T) * n;
		uint8_t *p8 = static_cast<uint8_t*>(x);
		for (size_t i = 0; i < size; i++) {
			p8[i] = static_cast<uint8_t>(get32());
		}
	}
	void read(uint32_t *x, size_t n)
	{
		for (size_t i = 0; i < n; i++) {
			x[i] = get32();
		}
	}
	void read(uint64_t *x, size_t n)
	{
		for (size_t i = 0; i < n; i++) {
			x[i] = get64();
		}
	}
};

} // cybozu

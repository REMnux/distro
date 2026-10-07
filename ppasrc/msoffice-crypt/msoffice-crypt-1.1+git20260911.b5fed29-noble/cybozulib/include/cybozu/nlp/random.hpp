#pragma once
/**
	@file
	@brief normal random generator

	@author MITSUNARI Shigeo(@herumi)
	@author MITSUNARI Shigeo
*/
#include <cybozu/xorshift.hpp>

namespace cybozu { namespace nlp {

/*
	use xor shift
*/
class UniformRandomGenerator {
	double a_;
	double b_;
	cybozu::XorShift rg;
public:
	/* generate uniform random value in [a, b) */
	explicit UniformRandomGenerator(double a = 0, double b = 1, int seed = 0)
		: a_(a)
		, b_(b)
		, rg(seed)
	{
	}
	void init(int seed = 0)
	{
		rg.init(seed);
	}
	/* [0, 2^32) random number */
	uint32_t operator()() { return rg.get32(); }
	uint32_t get32() { return rg.get32(); }
	uint64_t get64() { return rg.get64(); }
	/* [a, b) random number */
	double getDouble()
	{
		uint32_t x = get32() >> 5;
		uint32_t y = get32() >> 6;
		double z = (x * double(1U << 26) + y) * (1.0 / double(1LL << 53));
		return (b_ - a_) * z + a_;
	}
};

/*
	normal random generator
*/
class NormalRandomGenerator {
	UniformRandomGenerator gen_;
	double u_;
	double s_;
public:
	explicit NormalRandomGenerator(double u = 0, double s = 1, int seed = 0)
		: gen_(seed)
		, u_(u)
		, s_(s)
	{
	}
	void init(int seed = 0)
	{
		gen_.init(seed);
	}
	double get()
	{
		double sum = -6;
		for (int i = 0; i < 12; i++) {
			sum += gen_.getDouble();
		}
		return sum * s_ + u_;
	}
};

} } // cybozu::nlp

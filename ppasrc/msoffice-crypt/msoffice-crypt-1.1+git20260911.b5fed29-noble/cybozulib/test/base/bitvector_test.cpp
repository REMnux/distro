#include <cybozu/test.hpp>
#include <cybozu/bitvector.hpp>
#include <cybozu/xorshift.hpp>

CYBOZU_TEST_AUTO(set)
{
	cybozu::BitVector cv;
	std::vector<bool> sv;
	cybozu::XorShift rg;
	const size_t size = 100;
	cv.resize(size);
	sv.resize(size);
	for (int j = 0; j < 2; j++) {
		for (size_t i = 0; i < size; i++) {
			bool b = (rg.get32() & 1) != 0;
			cv.set(i, b);
			sv[i] = b;
		}
		for (size_t i = 0; i < size; i++) {
			CYBOZU_TEST_EQUAL(cv.get(i), sv[i]);
		}
	}
}

CYBOZU_TEST_AUTO(resize)
{
	uint16_t x[] = { 0x1234, 0x5678, 0x9abc };
	cybozu::BitVectorT<uint16_t> v;
	v.append(x, 48);
	CYBOZU_TEST_EQUAL(v.size(), 48);
	CYBOZU_TEST_EQUAL(v.getBlock()[2], x[2]);
	uint16_t val = x[2];
	for (size_t i = 47; i >= 33; i--) {
		v.resize(i);
		CYBOZU_TEST_EQUAL(v.size(), i);
		CYBOZU_TEST_EQUAL(v.getBlock()[2], val & cybozu::GetMaskBit<uint16_t>(i - 32));
	}
}

struct StdVec : std::vector<bool> {
	template<class T>
	void append(const T*src, size_t bitLen)
	{
		for (size_t i = 0; i < bitLen; i++) {
			bool b = cybozu::GetBlockBit(src, i);
			push_back(b);
		}
	}
	void append(size_t src, size_t bitLen)
	{
		for (size_t i = 0; i < bitLen; i++) {
			bool b = (src & (size_t(1) << i)) != 0;
			push_back(b);
		}
	}
};

template<class T>
void verifyVec(const T& v1, const StdVec& v2)
{
	CYBOZU_TEST_EQUAL(v1.size(), v2.size());
	int sum = 0;
	for (size_t i = 0; i < v1.size(); i++) {
		sum += v1.get(i) ^ v2[i];
	}
	CYBOZU_TEST_EQUAL(sum, 0);
}

CYBOZU_TEST_AUTO(shiftLeftBit)
{
	const struct {
		uint32_t x[4];
		size_t bitLen;
		size_t shift;
		uint32_t z0;
		uint32_t z[5];
	} tbl[] = {
		{ { 1, 0, 0, 0 }, 1, 1, 0xfffffff, { 3, 0, 0, 0 } },
		{ { 0x12345678, 0, 0, 0 }, 16, 16, 0xabcd1234, { 0x56781234, 0, 0, 0 } },
		{ { 0x12345678, 0, 0, 0 }, 16, 17, 0xabcd1234, { 0xacf11234, 0x0, 0, 0 } },
		{ { 0x12345678, 0, 0, 0 }, 16, 18, 0xabcd1234, { 0x59e11234, 0x1, 0, 0 } },
		{ { 0x12345678, 0, 0, 0 }, 32, 31, 0xabcd1234, { 0x2bcd1234, 0x91a2b3c, 0, 0 } },
		{ { 0x12345678, 0x9abcdef0, 0x11112222, 0xffccaaee }, 128, 19, 0x983a4ba, { 0xb3c3a4ba, 0xf78091a2, 0x1114d5e6, 0x57708889, 0x7fe65 } },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		const size_t bitLen = tbl[i].bitLen;
		const size_t shift = tbl[i].shift;
		uint32_t z[5];
		z[0] = tbl[i].z0;
		cybozu::bitvector_local::shiftLeftBit(z, tbl[i].x, bitLen, shift);
		const size_t n = cybozu::RoundupBit<uint32_t>(bitLen + shift);
		CYBOZU_TEST_EQUAL_ARRAY(z, tbl[i].z, n);
	}
}

CYBOZU_TEST_AUTO(shiftRightBit)
{
	const struct {
		uint32_t x[5];
		size_t bitLen;
		size_t shift;
		uint32_t z[4];
	} tbl[] = {
		{ { 0x12345678, 0, 0, 0 }, 1, 1, { 0, 0, 0, 0 } },
		{ { 0x12345678, 0, 0, 0 }, 1, 3, { 1, 0, 0, 0 } },
		{ { 0x12345678, 0xaaaabbbb, 0, 0 }, 10, 31, { 0x376, 0, 0, 0 } },
		{ { 0x12345678, 0, 0, 0 }, 1, 1, { 0, 0, 0, 0 } },
		{ { 0x12345678, 0, 0, 0 }, 13, 5, { 0x2b3, 0, 0, 0 } },
		{ { 0x12345678, 0xaaaabbbb, 0xffeebbcc, 0xfeba9874, 1 }, 128, 1, { 0x891a2b3c, 0x55555ddd, 0x7ff75de6, 0xff5d4c3a } },
		{ { 0x12345678, 0xaaaabbbb, 0xffeebbcc, 0xfeba9874, 0 }, 128, 1, { 0x891a2b3c, 0x55555ddd, 0x7ff75de6, 0x7f5d4c3a } },
		{ { 0x12345678, 0xaaaabbbb, 0xffeebbcc, 0xfeba9874, 0 }, 128, 18, { 0xaeeec48d, 0xaef32aaa, 0xa61d3ffb, 0x3fae } },
		{ { 0x12345678, 0xaaaabbbb, 0xffeebbcc, 0xfeba9874, 0 }, 96, 18, { 0xaeeec48d, 0xaef32aaa, 0xa61d3ffb, 0 } },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		uint32_t z[4];
		cybozu::bitvector_local::shiftRightBit(z, tbl[i].x, tbl[i].bitLen, tbl[i].shift);
		const size_t n = cybozu::RoundupBit<uint32_t>(tbl[i].bitLen);
		CYBOZU_TEST_EQUAL_ARRAY(z, tbl[i].z, n);
	}
}

CYBOZU_TEST_AUTO(append)
{
	const uint16_t src1[] = { 0x3210, 0x7654, 0xba98 };
	const uint16_t src2[] = { 0xabcd, 0xfebd, 0xffff };
	typedef cybozu::BitVectorT<uint16_t> Vec;
	{
		Vec v1;
		StdVec v2;
		v1.append(src1, 2);
		v2.append(src1, 2);
		v1.append(src2, 16);
		v2.append(src2, 16);
		verifyVec(v1, v2);
		Vec v3, v4;
		v3.append(src1, 2);
		v4.append(src2, 16);
		v3.append(v4);
		CYBOZU_TEST_ASSERT(v1 == v3);
	}
	for (size_t i = 0; i < 48; i++) {
		for (size_t j = 0; j < 48; j++) {
			Vec v1;
			StdVec v2;
			v1.append(src1, i);
			v2.append(src1, i);
			v1.append(src2, j);
			v2.append(src2, j);
			verifyVec(v1, v2);
			Vec v3, v4;
			v3.append(src1, i);
			v4.append(src2, j);
			v3.append(v4);
			CYBOZU_TEST_ASSERT(v1 == v3);
		}
	}
	for (size_t i = 0; i < 16; i++) {
		for (size_t j = 0; j < 16; j++) {
			Vec v1;
			StdVec v2;
			v1.append(src1[0], i);
			v2.append(src1[0], i);
			v1.append(src2[0], j);
			v2.append(src2[0], j);
			verifyVec(v1, v2);
		}
	}
}

CYBOZU_TEST_AUTO(extract)
{
	const uint16_t src1[] = { 0x3210, 0x7654, 0xba98, 0xabcd, 0x98db };
	typedef cybozu::BitVectorT<uint16_t> Vec;
	Vec v;
	v.append(src1, sizeof(src1) * 8);
	for (size_t pos = 0; pos <= 33; pos++) {
		int sum = 0;
		for (size_t bitLen = 0; bitLen <= 33; bitLen++) {
			uint16_t dst[3];
			v.extract(dst, pos, bitLen);
			for (size_t i = 0; i < bitLen; i++) {
				sum += v.get(pos + i) ^ cybozu::GetBlockBit(dst, i);
			}
		}
		CYBOZU_TEST_EQUAL(sum, 0);
		sum = 0;
		for (size_t bitLen = 0; bitLen <= 33; bitLen++) {
			Vec v2;
			v.extract(v2, pos, bitLen);
			for (size_t i = 0; i < bitLen; i++) {
				sum += v.get(pos + i) ^ v2.get(i);
			}
		}
		CYBOZU_TEST_EQUAL(sum, 0);
		sum = 0;
		for (size_t bitLen = 0; bitLen <= 16; bitLen++) {
			uint16_t r = v.extract(pos, bitLen);
			for (size_t i = 0; i < bitLen; i++) {
				sum += v.get(pos + i) ^ cybozu::GetBlockBit(&r, i);
			}
		}
		CYBOZU_TEST_EQUAL(sum, 0);
	}
}

#include <cybozu/test.hpp>
#include <cybozu/bit_operation.hpp>

CYBOZU_TEST_AUTO(bsf)
{
	const struct {
		uint32_t x;
		int val;
	} tbl[] = {
		{ 1, 0 },
		{ 2, 1 },
		{ 3, 0 },
		{ 4, 2 },
		{ 0xffffffff, 0 },
		{ 0x80000000, 31 },
		{ 0x80000010, 4 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		CYBOZU_TEST_EQUAL(cybozu::bsf(tbl[i].x), tbl[i].val);
	}
}

CYBOZU_TEST_AUTO(bsr)
{
	const struct {
		uint32_t x;
		int val;
	} tbl[] = {
		{ 1, 0 },
		{ 2, 1 },
		{ 3, 1 },
		{ 4, 2 },
		{ 0xfff, 11 },
		{ 0xfffff, 19 },
		{ 0xffffffff, 31 },
		{ 0x80000000, 31 },
		{ 0x80000010, 31 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		CYBOZU_TEST_EQUAL(cybozu::bsr(tbl[i].x), tbl[i].val);
	}
}

CYBOZU_TEST_AUTO(bsf64)
{
	const struct {
		uint64_t x;
		int val;
	} tbl[] = {
		{ 1, 0 },
		{ 2, 1 },
		{ 3, 0 },
		{ 4, 2 },
		{ 0xffffffff, 0 },
		{ 0x80000000, 31 },
		{ 0x100000000ULL, 32 },
		{ 0xffffffffffffffffULL, 0 },
		{ 0x8000000000000000ULL, 63 },
		{ 0x8000000000000010ULL, 4 },
		{ 0x8000001000000000ULL, 36 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		CYBOZU_TEST_EQUAL(cybozu::bsf(tbl[i].x), tbl[i].val);
	}
}

CYBOZU_TEST_AUTO(bsr64)
{
	const struct {
		uint64_t x;
		int val;
	} tbl[] = {
		{ 1, 0 },
		{ 2, 1 },
		{ 3, 1 },
		{ 4, 2 },
		{ 0xfff, 11 },
		{ 0xfffff, 19 },
		{ 0xffffffff, 31 },
		{ 0x80000000, 31 },
		{ 0x100000000ULL, 32 },
		{ 0x1100000000ULL, 36 },
		{ 0xffffffffffffffffULL, 63 },
		{ 0x8000000000000000ULL, 63 },
		{ 0x8000001000000000ULL, 63 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		CYBOZU_TEST_EQUAL(cybozu::bsr(tbl[i].x), tbl[i].val);
	}
}

CYBOZU_TEST_AUTO(popcnt)
{
	const struct {
		uint32_t x;
		uint32_t val;
	} tbl[] = {
		{ 0, 0 },
		{ 1, 1 },
		{ 2, 1 },
		{ 3, 2 },
		{ 4, 1 },
		{ 5, 2 },
		{ 0xfff, 12 },
		{ 0xf0000000, 4 },
		{ 0xffffffff, 32 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		CYBOZU_TEST_EQUAL(cybozu::popcnt(tbl[i].x), tbl[i].val);
	}
}

CYBOZU_TEST_AUTO(popcnt64)
{
	const struct {
		uint64_t x;
		uint32_t val;
	} tbl[] = {
		{ 0, 0 },
		{ 1, 1 },
		{ 2, 1 },
		{ 3, 2 },
		{ 4, 1 },
		{ 5, 2 },
		{ 0xfff, 12 },
		{ 0xffffffff, 32 },
		{ 0xfffffffffull, 36 },
		{ 0xf000000000000000ull, 4 },
		{ 0xffffffffffffffffull, 64 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		CYBOZU_TEST_EQUAL(cybozu::popcnt(tbl[i].x), tbl[i].val);
	}
}

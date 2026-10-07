#include <stdio.h>
#include <sstream>
#include <iostream>
#include <cybozu/itoa.hpp>
#include <cybozu/test.hpp>

CYBOZU_TEST_AUTO(test_int)
{
	const struct {
		const char *str;
		int x;
	} tbl[] = {
		{ "0", 0 },
		{ "1", 1 },
		{ "12", 12 },
		{ "123", 123 },
		{ "1223424", 1223424 },
		{ "214748364", 214748364 },
		{ "314748364", 314748364 },
		{ "2147483639", 2147483639 },
		{ "2147483640", 2147483640 },
		{ "2147483641", 2147483641 },
		{ "2147483642", 2147483642 },
		{ "2147483643", 2147483643 },
		{ "2147483644", 2147483644 },
		{ "2147483645", 2147483645 },
		{ "2147483646", 2147483646 },
		{ "2147483647", 2147483647 },
		{ "-1", -1 },
		{ "-12", -12 },
		{ "-123", -123 },
		{ "-1223424", -1223424 },
		{ "-214748364", -214748364 },
		{ "-314748364", -314748364 },
		{ "-2147483645", -2147483645 },
		{ "-2147483646", -2147483646 },
		{ "-2147483647", -2147483647 },
		{ "-2147483648", -2147483647 - 1 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string s;
		cybozu::itoa(s, tbl[i].x);
		CYBOZU_TEST_EQUAL(s, tbl[i].str);
	}
}

CYBOZU_TEST_AUTO(test_short)
{
	const struct {
		const char *str;
		short x;
	} tbl[] = {
		{ "0", 0 },
		{ "1", 1 },
		{ "12", 12 },
		{ "123", 123 },
		{ "32765", 32765 },
		{ "32766", 32766 },
		{ "32767", 32767 },
		{ "-1", -1 },
		{ "-12", -12 },
		{ "-123", -123 },
		{ "-32766", -32766 },
		{ "-32767", -32767 },
		{ "-32768", -32768 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string s;
		cybozu::itoa(s, tbl[i].x);
		CYBOZU_TEST_EQUAL(s, tbl[i].str);
	}
}

CYBOZU_TEST_AUTO(test_unsigned_short)
{
	const struct {
		const char *str;
		unsigned short x;
	} tbl[] = {
		{ "0", 0 },
		{ "1", 1 },
		{ "12", 12 },
		{ "123", 123 },
		{ "12234", 12234 },
		{ "32767", 32767 },
		{ "32768", 32768 },
		{ "65534", 65534 },
		{ "65535", 65535 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string s;
		cybozu::itoa(s, tbl[i].x);
		CYBOZU_TEST_EQUAL(s, tbl[i].str);
	}
}

CYBOZU_TEST_AUTO(test_uint)
{
	const struct {
		const char *str;
		unsigned int x;
	} tbl[] = {
		{ "0", 0 },
		{ "1", 1 },
		{ "12", 12 },
		{ "123", 123 },
		{ "1223424", 1223424 },
		{ "214748364", 214748364 },
		{ "314748364", 314748364 },
		{ "2147483639", 2147483639 },
		{ "2147483640", 2147483640 },
		{ "2147483641", 2147483641 },
		{ "2147483642", 2147483642 },
		{ "2147483643", 2147483643 },
		{ "2147483644", 2147483644 },
		{ "2147483645", 2147483645 },
		{ "2147483646", 2147483646 },
		{ "2147483647", 2147483647 },
		{ "2147483648", 2147483648U },
		{ "2147483649", 2147483649U },
		{ "2147483650", 2147483650U },
		{ "2147483651", 2147483651U },
		{ "2147483652", 2147483652U },
		{ "2147483653", 2147483653U },
		{ "2147483654", 2147483654U },
		{ "2147483655", 2147483655U },
		{ "4294967286", 4294967286U },
		{ "4294967287", 4294967287U },
		{ "4294967288", 4294967288U },
		{ "4294967289", 4294967289U },
		{ "4294967290", 4294967290U },
		{ "4294967291", 4294967291U },
		{ "4294967292", 4294967292U },
		{ "4294967293", 4294967293U },
		{ "4294967294", 4294967294U },
		{ "4294967295", 4294967295U },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string s;
		cybozu::itoa(s, tbl[i].x);
		CYBOZU_TEST_EQUAL(s, tbl[i].str);
	}
}

CYBOZU_TEST_AUTO(test_int64)
{
	const struct {
		const char *str;
		int64_t x;
	} tbl[] = {
		{ "0", 0 },
		{ "1", 1 },
		{ "12", 12 },
		{ "123", 123 },
		{ "1223424", 1223424 },
		{ "214748364", 214748364 },
		{ "314748364", 314748364 },
		{ "2147483639", 2147483639 },
		{ "2147483640", 2147483640 },
		{ "2147483641", 2147483641 },
		{ "2147483642", 2147483642 },
		{ "2147483643", 2147483643 },
		{ "2147483644", 2147483644 },
		{ "2147483645", 2147483645 },
		{ "2147483646", 2147483646 },
		{ "2147483647", 2147483647 },
		{ "9223372036854775794", 9223372036854775794LL },
		{ "9223372036854775795", 9223372036854775795LL },
		{ "9223372036854775796", 9223372036854775796LL },
		{ "9223372036854775797", 9223372036854775797LL },
		{ "9223372036854775798", 9223372036854775798LL },
		{ "9223372036854775799", 9223372036854775799LL },
		{ "9223372036854775800", 9223372036854775800LL },
		{ "9223372036854775801", 9223372036854775801LL },
		{ "9223372036854775802", 9223372036854775802LL },
		{ "9223372036854775803", 9223372036854775803LL },
		{ "9223372036854775804", 9223372036854775804LL },
		{ "9223372036854775805", 9223372036854775805LL },
		{ "9223372036854775806", 9223372036854775806LL },
		{ "9223372036854775807", 9223372036854775807LL },
		{ "-1", -1 },
		{ "-12", -12 },
		{ "-123", -123 },
		{ "-1223424", -1223424 },
		{ "-214748364", -214748364 },
		{ "-314748364", -314748364 },
		{ "-2147483645", -2147483645 },
		{ "-2147483646", -2147483646 },
		{ "-2147483647", -2147483647 },
		{ "-2147483648", -2147483647 - 1 },
		{ "-9223372036854775795", -9223372036854775795LL },
		{ "-9223372036854775796", -9223372036854775796LL },
		{ "-9223372036854775797", -9223372036854775797LL },
		{ "-9223372036854775798", -9223372036854775798LL },
		{ "-9223372036854775799", -9223372036854775799LL },
		{ "-9223372036854775800", -9223372036854775800LL },
		{ "-9223372036854775801", -9223372036854775801LL },
		{ "-9223372036854775802", -9223372036854775802LL },
		{ "-9223372036854775803", -9223372036854775803LL },
		{ "-9223372036854775804", -9223372036854775804LL },
		{ "-9223372036854775805", -9223372036854775805LL },
		{ "-9223372036854775806", -9223372036854775806LL },
		{ "-9223372036854775807", -9223372036854775807LL },
		{ "-9223372036854775808", -9223372036854775807LL - 1 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string s;
		cybozu::itoa(s, tbl[i].x);
		CYBOZU_TEST_EQUAL(s, tbl[i].str);
	}
}

CYBOZU_TEST_AUTO(test_uint64)
{
	const struct {
		const char *str;
		uint64_t x;
	} tbl[] = {
		{ "0", 0 },
		{ "1", 1 },
		{ "12", 12 },
		{ "123", 123 },
		{ "123456789", 123456789 },
		{ "1000000000", 1000000000 },
		{ "2147483647", 2147483647 },
		{ "2147483648", 2147483648ULL },
		{ "2147483649", 2147483649ULL },
		{ "4294967295", 4294967295ULL },
		{ "4294967296", 4294967296ULL },
		{ "4294967297", 4294967297ULL },
		{ "9223372036854775807", 9223372036854775807ULL },
		{ "9223372036854775808", 9223372036854775808ULL },
		{ "9223372036854775809", 9223372036854775809ULL },
		{ "18446744073709551615", 18446744073709551615ULL },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string s;
		cybozu::itoa(s, tbl[i].x);
		CYBOZU_TEST_EQUAL(s, tbl[i].str);
	}
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		char buf[21];
		for (size_t bufSize = 0; bufSize < sizeof(buf); bufSize++) {
			memset(buf, 0, sizeof(buf));
			size_t n = cybozu::itoa_local::uintToDec(buf, bufSize, tbl[i].x);
			const char *expectedStr = tbl[i].str;
			size_t expectedLen = strlen(expectedStr);
			if (bufSize < expectedLen) {
				CYBOZU_TEST_EQUAL(n, 0);
			} else {
				CYBOZU_TEST_EQUAL(n, expectedLen);
				CYBOZU_TEST_EQUAL_ARRAY(expectedStr, buf + bufSize - n, n);
			}
		}
	}
}

CYBOZU_TEST_AUTO(zeroPadding)
{
	const struct {
		const char *str;
		int val;
	} intTbl[] = {
		{ "0000", 0 },
		{ "0001", 1 },
		{ "0012", 12 },
		{ "0123", 123 },
		{ "1234", 1234 },
		{ "12345", 12345 },
		{ "0000", -0 },
		{ "-001", -1 },
		{ "-012", -12 },
		{ "-123", -123 },
		{ "-1234", -1234 },
		{ "-12345", -12345 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(intTbl); i++) {
		CYBOZU_TEST_EQUAL(cybozu::itoaWithZero(intTbl[i].val, 4), intTbl[i].str);
	}
}

CYBOZU_TEST_AUTO(itohexchar)
{
	const struct {
		const char *strL;
		const char *strH;
		unsigned char val;
	} tbl[] = {
		{ "00", "00", 0 },
		{ "01", "01", 1 },
		{ "02", "02", 2 },
		{ "03", "03", 3 },
		{ "04", "04", 4 },
		{ "05", "05", 5 },
		{ "06", "06", 6 },
		{ "07", "07", 7 },
		{ "08", "08", 8 },
		{ "09", "09", 9 },
		{ "0a", "0A", 10 },
		{ "0b", "0B", 11 },
		{ "0c", "0C", 12 },
		{ "0d", "0D", 13 },
		{ "0e", "0E", 14 },
		{ "0f", "0F", 15 },
		{ "31", "31", 49 },
		{ "32", "32", 50 },
		{ "33", "33", 51 },
		{ "34", "34", 52 },
		{ "35", "35", 53 },
		{ "36", "36", 54 },
		{ "37", "37", 55 },
		{ "38", "38", 56 },
		{ "39", "39", 57 },
		{ "3a", "3A", 58 },
		{ "3b", "3B", 59 },
		{ "3c", "3C", 60 },
		{ "3d", "3D", 61 },
		{ "3e", "3E", 62 },
		{ "3f", "3F", 63 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		CYBOZU_TEST_EQUAL(cybozu::itohex(tbl[i].val), tbl[i].strH);
		CYBOZU_TEST_EQUAL(cybozu::itohex(tbl[i].val, false), tbl[i].strL);
	}
}

CYBOZU_TEST_AUTO(uintToHex)
{
	const struct {
		const char *str;
		uint64_t val;
	} tbl[] = {
		{ "0", 0 },
		{ "1", 1 },
		{ "2", 2 },
		{ "3", 3 },
		{ "4", 4 },
		{ "5", 5 },
		{ "6", 6 },
		{ "7", 7 },
		{ "8", 8 },
		{ "9", 9 },
		{ "a", 10 },
		{ "b", 11 },
		{ "c", 12 },
		{ "d", 13 },
		{ "e", 14 },
		{ "f", 15 },
		{ "31", 49 },
		{ "32", 50 },
		{ "33", 51 },
		{ "34", 52 },
		{ "35", 53 },
		{ "36", 54 },
		{ "37", 55 },
		{ "38", 56 },
		{ "39", 57 },
		{ "3a", 58 },
		{ "3b", 59 },
		{ "3c", 60 },
		{ "3d", 61 },
		{ "3e", 62 },
		{ "3f", 63 },
		{ "123", 0x123 },
		{ "1234567890abcdef", 0x1234567890abcdefull },
		{ "ffffffffffffffff", 0xffffffffffffffffull },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		const char *expectedStr = tbl[i].str;
		size_t expectedSize = strlen(expectedStr);
		char buf[32];
		size_t n = cybozu::itoa_local::uintToHex(buf, sizeof(buf), tbl[i].val, false);
		CYBOZU_TEST_EQUAL(n, expectedSize);
		CYBOZU_TEST_EQUAL_ARRAY(expectedStr, buf + sizeof(buf) - n, n);
	}
}

CYBOZU_TEST_AUTO(uintToBin)
{
	const struct {
		const char *str;
		uint64_t val;
	} tbl[] = {
		{ "0", 0 },
		{ "1", 1 },
		{ "10", 2 },
		{ "11", 3 },
		{ "100", 4 },
		{ "101", 5 },
		{ "110", 6 },
		{ "111", 7 },
		{ "1000", 8 },
		{ "1001", 9 },
		{ "1010", 10 },
		{ "1011", 11 },
		{ "1100", 12 },
		{ "1101", 13 },
		{ "1110", 14 },
		{ "1111", 15 },
		{ "10000", 16 },
		{ "10001", 17 },
		{ "10010", 18 },
		{ "10011", 19 },
		{ "11111111111111111111111111111111", 0xffffffff },
		{ "10001101000101011001111000100100000001001000110100010101100111", 0x2345678901234567ull },
		{ "1111111111111111111111111111111111111111111111111111111111111111", 0xffffffffffffffffull },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		const char *expectedStr = tbl[i].str;
		size_t expectedSize = strlen(expectedStr);
		char buf[64];
		size_t n = cybozu::itoa_local::uintToBin(buf, sizeof(buf), tbl[i].val);
		CYBOZU_TEST_EQUAL(n, expectedSize);
		CYBOZU_TEST_EQUAL_ARRAY(expectedStr, buf + sizeof(buf) - n, n);
	}
}

CYBOZU_TEST_AUTO(itohex)
{
	CYBOZU_TEST_EQUAL(cybozu::itohex((unsigned short)0), "0000");
	CYBOZU_TEST_EQUAL(cybozu::itohex((unsigned int)0), "00000000");
	CYBOZU_TEST_EQUAL(cybozu::itohex((uint64_t)0), "0000000000000000");

	CYBOZU_TEST_EQUAL(cybozu::itohex((unsigned short)0x12cd), "12CD");
	CYBOZU_TEST_EQUAL(cybozu::itohex((unsigned int)0x1234adef), "1234ADEF");
	CYBOZU_TEST_EQUAL(cybozu::itohex((uint64_t)0xaaaabbbbffffeeeeULL), "AAAABBBBFFFFEEEE");

	CYBOZU_TEST_EQUAL(cybozu::itohex((unsigned short)0x12cd, false), "12cd");
	CYBOZU_TEST_EQUAL(cybozu::itohex((unsigned int)0x1234adef, false), "1234adef");
	CYBOZU_TEST_EQUAL(cybozu::itohex((uint64_t)0xaaaabbbbffffeeeeULL, false), "aaaabbbbffffeeee");
}

CYBOZU_TEST_AUTO(getBinLength)
{
	const struct {
		uint64_t v;
		size_t len;
	} tbl[] = {
		{ 0, 1 },
		{ 1, 1 },
		{ 2, 2 },
		{ 3, 2 },
		{ 4, 3 },
		{ 0xffff, 16 },
		{ 0xffffffff, 32 },
		{ uint64_t(1) << 32, 33 },
		{ uint64_t(0xffffffffffffffffull), 64 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		CYBOZU_TEST_EQUAL(cybozu::getBinLength(tbl[i].v), tbl[i].len);
	}
}

CYBOZU_TEST_AUTO(itobin)
{
	char buf[80];
	const struct {
		const char *out;
		size_t len;
		uint64_t v;
	} tbl[] = {
		{ "0", 1, 0 },
		{ "000", 3, 0 },
		{ "1", 1, 1 },
		{ "10", 2, 6 },
		{ "1100", 4, 12 },
		{ "1111", 4, 15 },
		{ "10000000", 8, 128, },
		{ "11111111111111111111", 20, (1 << 20) - 1},
		{ "1111111111111111111111111111111111111111111111111111111111111111", 64, uint64_t(-1) },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		memset(buf, 'x', sizeof(buf));
		cybozu::itobin(buf, tbl[i].len, tbl[i].v);
		CYBOZU_TEST_EQUAL(memcmp(buf, tbl[i].out, tbl[i].len), 0);
		CYBOZU_TEST_EQUAL(buf[tbl[i].len], 'x'); // check buffer overrun
	}
}

CYBOZU_TEST_AUTO(itobin2)
{
	CYBOZU_TEST_EQUAL(cybozu::itobin((unsigned char)0), "00000000");
	CYBOZU_TEST_EQUAL(cybozu::itobin((unsigned short)0), "0000000000000000");
	CYBOZU_TEST_EQUAL(cybozu::itobin((unsigned int)0), "00000000000000000000000000000000");
	CYBOZU_TEST_EQUAL(cybozu::itobin((uint64_t)0), "0000000000000000000000000000000000000000000000000000000000000000");

	CYBOZU_TEST_EQUAL(cybozu::itobin((unsigned char)0x12), "00010010");
	CYBOZU_TEST_EQUAL(cybozu::itobin((unsigned int)0x1234adef), "00010010001101001010110111101111");
	CYBOZU_TEST_EQUAL(cybozu::itobin((uint64_t)0xaaaabbbbffffeeeeULL), "1010101010101010101110111011101111111111111111111110111011101110");

	CYBOZU_TEST_EQUAL(cybozu::itobin((unsigned char)0x12, false), "10010");
	CYBOZU_TEST_EQUAL(cybozu::itobin((unsigned int)0x1234adef, false), "10010001101001010110111101111");
	CYBOZU_TEST_EQUAL(cybozu::itobin((uint64_t)0xaaaabbbbffffeeeeULL, false), "1010101010101010101110111011101111111111111111111110111011101110");
}

std::string cvt(uint64_t x)
{
	std::ostringstream os;
	os << std::hex << x;
	return os.str();
}

CYBOZU_TEST_AUTO(itohexWithoutZero)
{
	for (uint64_t i = 0; i < 35; i++) {
		std::string a = cvt(i);
		std::string b = cvt(i);
		CYBOZU_TEST_EQUAL(a, b);
	}
	const uint64_t tbl[] = {
		0, 1, 15, 16, 255, 256, 257,
		0xffff, 0x10000, 0xffffffff, 0x12345678,
		uint64_t(0x100000000ull),
		uint64_t(0x123456789abcdefull),
		uint64_t(0xffffffffffffffffull),
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string a = cvt(tbl[i]);
		std::string b = cybozu::itohex(tbl[i], false, false);
		CYBOZU_TEST_EQUAL(a, b);
	}
}

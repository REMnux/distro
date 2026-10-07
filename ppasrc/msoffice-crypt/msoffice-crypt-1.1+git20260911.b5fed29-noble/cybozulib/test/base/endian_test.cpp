#include <stdio.h>
#include <memory.h>
#include <cybozu/endian.hpp>
#include <cybozu/test.hpp>

#ifdef _WIN32
	#pragma warning(disable : 4309) /* trivial cast */
#endif

CYBOZU_TEST_AUTO(endian_test)
{
	uint8_t buf[] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff };
	{
		uint64_t x;
		x = cybozu::Get64bitAsLE(buf);
		CYBOZU_TEST_EQUAL(x, uint64_t(0xffdebc9a78563412LL));

		x = cybozu::Get64bitAsBE(buf);
		CYBOZU_TEST_EQUAL(x, uint64_t(0x123456789abcdeffLL));
	}
	{
		uint32_t x;
		x = cybozu::Get32bitAsLE(buf);
		CYBOZU_TEST_EQUAL(x, 0x78563412U);

		x = cybozu::Get32bitAsBE(buf);
		CYBOZU_TEST_EQUAL(x, 0x12345678U);
	}
	char buf2[8];
	cybozu::Set32bitAsLE(buf2, 0x78563412);
	CYBOZU_TEST_ASSERT(memcmp(buf2, buf, 4) == 0);

	cybozu::Set32bitAsBE(buf2, 0x12345678);
	CYBOZU_TEST_ASSERT(memcmp(buf2, buf, 4) == 0);

	cybozu::Set64bitAsLE(buf2, uint64_t(0xffdebc9a78563412LL));
	CYBOZU_TEST_ASSERT(memcmp(buf2, buf, 8) == 0);

	cybozu::Set64bitAsBE(buf2, uint64_t(0x123456789abcdeffLL));
	CYBOZU_TEST_ASSERT(memcmp(buf2, buf, 8) == 0);

	{
		unsigned short x;
		x = cybozu::Get16bitAsLE(buf);
		CYBOZU_TEST_EQUAL(x, 0x3412);
		x = cybozu::Get16bitAsBE(buf);
		CYBOZU_TEST_EQUAL(x, 0x1234);
	}
	{
		char buf3[2];
		cybozu::Set16bitAsLE(buf3, 0x3456);
		CYBOZU_TEST_ASSERT(memcmp(buf3, "\x56\x34", 2) == 0);
		cybozu::Set16bitAsBE(buf3, 0x3456);
		CYBOZU_TEST_ASSERT(memcmp(buf3, "\x34\x56", 2) == 0);
	}
}

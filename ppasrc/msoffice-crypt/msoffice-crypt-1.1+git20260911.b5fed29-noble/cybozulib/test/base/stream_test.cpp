#include <cybozu/test.hpp>
#include <cybozu/stream.hpp>
#include <sstream>

CYBOZU_TEST_AUTO(sstream)
{
	const std::string str = "123";
	{
		std::ostringstream os;
		cybozu::OutputStreamTag<std::ostringstream>::write(os, str.c_str(), str.size());
		CYBOZU_TEST_EQUAL(os.str(), str);
	}
	{
		char buf[64] = {};
		std::istringstream is(str);
		size_t readSize = cybozu::readSome(buf, sizeof(buf), is);
		CYBOZU_TEST_EQUAL(str.size(), readSize);
		CYBOZU_TEST_ASSERT(memcmp(buf, str.c_str(), str.size()) == 0);
	}
	{
		char buf[64] = {};
		std::istringstream is(str);
		cybozu::read(buf, str.size(), is);
		CYBOZU_TEST_ASSERT(memcmp(buf, str.c_str(), str.size()) == 0);
	}
	{
		std::istringstream is("123");
		char c;
		CYBOZU_TEST_ASSERT(cybozu::readChar(&c, is));
		CYBOZU_TEST_EQUAL(c, '1');
		CYBOZU_TEST_ASSERT(cybozu::readChar(&c, is));
		CYBOZU_TEST_EQUAL(c, '2');
		CYBOZU_TEST_ASSERT(cybozu::readChar(&c, is));
		CYBOZU_TEST_EQUAL(c, '3');
		CYBOZU_TEST_ASSERT(!cybozu::readChar(&c, is));
	}
}

CYBOZU_TEST_AUTO(memory)
{
	const std::string str = "123";
	{
		char buf[64] = {};
		cybozu::MemoryOutputStream os(buf, sizeof(buf));
		cybozu::OutputStreamTag<cybozu::MemoryOutputStream>::write(os, str.c_str(), str.size());
		CYBOZU_TEST_EQUAL(str.size(), os.getPos());
		CYBOZU_TEST_ASSERT(memcmp(buf, str.c_str(), str.size()) == 0);
	}
	{
		cybozu::MemoryInputStream is(str.c_str(), str.size());
		char buf[64] = {};
		size_t readSize = cybozu::readSome(buf, sizeof(buf), is);
		CYBOZU_TEST_EQUAL(str.size(), readSize);
		CYBOZU_TEST_EQUAL(is.getPos(), readSize);
		CYBOZU_TEST_ASSERT(memcmp(buf, str.c_str(), str.size()) == 0);
	}
	{
		cybozu::MemoryInputStream is(str.c_str(), str.size());
		char buf[64] = {};
		cybozu::read(buf, str.size(), is);
		CYBOZU_TEST_EQUAL(str.size(), is.getPos());
		CYBOZU_TEST_ASSERT(memcmp(buf, str.c_str(), str.size()) == 0);
	}
	{
		cybozu::MemoryInputStream is(str.c_str(), str.size());
		char c = 0;
		CYBOZU_TEST_ASSERT(cybozu::readChar(&c, is));
		CYBOZU_TEST_EQUAL(c, '1');
		CYBOZU_TEST_ASSERT(cybozu::readChar(&c, is));
		CYBOZU_TEST_EQUAL(c, '2');
		CYBOZU_TEST_ASSERT(cybozu::readChar(&c, is));
		CYBOZU_TEST_EQUAL(c, '3');
		CYBOZU_TEST_ASSERT(!cybozu::readChar(&c, is));
	}
}

CYBOZU_TEST_AUTO(string)
{
	const std::string str = "123";
	{
		std::string s;
		cybozu::StringOutputStream os(s);
		cybozu::OutputStreamTag<cybozu::StringOutputStream>::write(os, str.c_str(), str.size());
		CYBOZU_TEST_EQUAL(str, s);
	}
	{
		cybozu::StringInputStream is(str);
		char buf[64] = {};
		size_t readSize = cybozu::readSome(buf, sizeof(buf), is);
		CYBOZU_TEST_EQUAL(str.size(), readSize);
		CYBOZU_TEST_EQUAL(is.getPos(), readSize);
		CYBOZU_TEST_ASSERT(memcmp(buf, str.c_str(), str.size()) == 0);
	}
	{
		cybozu::StringInputStream is(str);
		char buf[64] = {};
		cybozu::read(buf, str.size(), is);
		CYBOZU_TEST_EQUAL(str.size(), is.getPos());
		CYBOZU_TEST_ASSERT(memcmp(buf, str.c_str(), str.size()) == 0);
	}
}

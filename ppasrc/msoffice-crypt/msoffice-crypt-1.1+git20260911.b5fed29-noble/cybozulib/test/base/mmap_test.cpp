#include <cybozu/test.hpp>
#include <cybozu/mmap.hpp>
#include <cybozu/file.hpp>
#include <string>

CYBOZU_TEST_AUTO(mmap)
{
	std::string path = cybozu::GetExePath();
	size_t pos = path.find("cybozulib");
	CYBOZU_TEST_ASSERT(pos != std::string::npos);
	path = path.substr(0, pos + 9) + "/include/cybozu/mmap.hpp";
	cybozu::Mmap mmap(path);
	const std::string str(mmap.get(), (size_t)mmap.size());
	CYBOZU_TEST_EQUAL(str.find("#pragma once"), 0U);
}

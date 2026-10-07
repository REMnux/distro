#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <cybozu/test.hpp>
#include <cybozu/csv.hpp>
#include <cybozu/file.hpp>

#ifdef _MSC_VER
	#pragma warning(disable : 4510)
	#pragma warning(disable : 4512)
	#pragma warning(disable : 4610)
#endif

CYBOZU_TEST_AUTO(separator)
{
	CYBOZU_TEST_ASSERT(cybozu::csv_local::isValidSeparator(','));
	CYBOZU_TEST_ASSERT(cybozu::csv_local::isValidSeparator('\t'));
	CYBOZU_TEST_ASSERT(cybozu::csv_local::isValidSeparator(';'));
	CYBOZU_TEST_ASSERT(cybozu::csv_local::isValidSeparator(' '));
	CYBOZU_TEST_ASSERT(!cybozu::csv_local::isValidSeparator('\\'));
	CYBOZU_TEST_ASSERT(!cybozu::csv_local::isValidSeparator('"'));
}

CYBOZU_TEST_AUTO(output1)
{
	std::string str;
	cybozu::StringOutputStream os(str);
	cybozu::CsvWriterT<cybozu::StringOutputStream> csv(os);
	std::vector<std::string> vec;
	vec.push_back("123");
	vec.push_back("");
	vec.push_back("a\r\nb\nc");
	vec.push_back("xx\"yy");
	vec.push_back("1123\"\"d");
	csv.write(vec.begin(), vec.end());
	CYBOZU_TEST_EQUAL(str, "\"123\",\"\",\"a\r\nb\nc\",\"xx\"\"yy\",\"1123\"\"\"\"d\"\r\n");
}

CYBOZU_TEST_AUTO(output2)
{
	std::string str;
	cybozu::StringOutputStream os(str);
	cybozu::CsvWriterT<cybozu::StringOutputStream> csv(os, '\t');
	std::vector<std::string> vec;
	vec.push_back("\x8A\xBF\x8E\x9A");
	vec.push_back("\x95\xCF\x8A\xB7");
	csv.write(vec.begin(), vec.end());
	CYBOZU_TEST_EQUAL(str, "\"\x8A\xBF\x8E\x9A\"\t\"\x95\xCF\x8A\xB7\"\r\n");
}

CYBOZU_TEST_AUTO(input)
{
	const struct {
		const char *in;
		size_t n;
		const char out[4][16];
	} tbl[] = {

		// Top -> End
		{ "", 0, { "" } },

		// ignore \x0d
		{ "\x0d\x0d\x0d", 0, { "" } },

		// Top -> Top
		{ ",,,", 3, { "", "", "" } },

		// Top -> SearchSep -> End
		{ "a", 1, { "a" } },

		// Top -> SearchSep -> SearchSep -> End
		{ "abc", 1, { "abc" } },

		// Top -> SearchSep -> Top
		{ "abc,def\r\nxyz", 2, { "abc", "def" } },

		{ "abc,def", 2, { "abc", "def" } },
		{ "abc,def,ghi", 3, { "abc", "def", "ghi" } },
		{ "abc\"xyz,def", 2, { "abc\"xyz", "def" } },

		// Top -> InQuote -> NeedSepOrQuote -> End
		{ "\"abcxyz\"", 1, { "abcxyz" } },

		// Top -> InQuote -> NeedSepOrQuote -> Top

		{ "\"abc,xyz\",def", 2, { "abc,xyz", "def" } },

		// Top -> InQuote -> NeedSepOrQuote -> InQuote

		{ "\"abc\"\"\"\"xyz\"", 1, { "abc\"\"xyz" } },
		{ "\"abc,def\r\nxyz\",qqq" , 2, { "abc,def\nxyz", "qqq" } },

		{ "\"abc\"\"xyz\",xyz", 2, { "abc\"xyz", "xyz" } },
		{ "\"abc\",\"\",\"xyz\"", 3, { "abc", "", "xyz" } },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		cybozu::MemoryInputStream is(tbl[i].in, strlen(tbl[i].in));
		cybozu::CsvReaderT<cybozu::MemoryInputStream> csv(is);

		std::vector<std::string> vec;
		csv.read(vec);
		const size_t n = tbl[i].n;
		CYBOZU_TEST_EQUAL(vec.size(), n);
		for (size_t j = 0; j < std::min(n, vec.size()); j++) {
			CYBOZU_TEST_EQUAL(vec[j], tbl[i].out[j]);
		}
	}
}

CYBOZU_TEST_AUTO(input2)
{
	const char *inStr = "\"\xE6\xBC\xA2\xE5\xAD\x97\"\t\"\xE5\xA4\x89\xE6\x8F\x9B\"\r\n";
	cybozu::MemoryInputStream is(inStr, strlen(inStr));
	cybozu::CsvReaderT<cybozu::MemoryInputStream> csv(is, '\t');
	std::vector<std::string> vec;

	csv.read(vec);

	CYBOZU_TEST_EQUAL(vec.size(), 2U);
	CYBOZU_TEST_EQUAL(vec[0], "\xE6\xBC\xA2\xE5\xAD\x97");
	CYBOZU_TEST_EQUAL(vec[1], "\xE5\xA4\x89\xE6\x8F\x9B");
}

CYBOZU_TEST_AUTO(input_err)
{
	const struct {
		const std::string in;
		const char *msg;
	} tbl[] = {
		{ "\"abc", "quote is necessary" },
		{ "\"abc\"a", "bad character after quote" },
		{ "12345678901234567890", "too large size" },
		{ "123,45,67,8,9,0,1,234,56,7890", "too large size" },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		cybozu::StringInputStream is(tbl[i].in);

		cybozu::CsvReaderT<cybozu::StringInputStream, 20> csv(is);
		std::vector<std::string> vec;
		CYBOZU_TEST_EXCEPTION_MESSAGE(csv.read(vec), cybozu::Exception, tbl[i].msg);
	}
}

CYBOZU_TEST_AUTO(file)
{
	const struct {
		const char in[10][20];
		size_t n;
		const char out[10][20];
	} tbl[] = {
		{ { "abc", "def", "xyz" }, 3, { "abc", "def", "xyz" } },
		{ { "abc,xyz", "", "x\"y\"z" }, 3, { "abc,xyz", "", "x\"y\"z" } },
		{ { "abc,xyz\r\n123", "\t", ",,,\"\n" }, 3, { "abc,xyz\n123", "\t", ",,,\"\n" } },
	};
	{
		cybozu::CsvWriter csv(cybozu::GetExePath() + "csv_file_test.csv", '\t');
		for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
			std::vector<std::string> vec;
			for (size_t j = 0; j < tbl[i].n; j++) {
				vec.push_back(tbl[i].in[j]);
			}
			csv.write(vec.begin(), vec.end());
		}
	}
	{
		cybozu::CsvReader csv(cybozu::GetExePath() + "csv_file_test.csv", '\t');
		for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
			std::vector<std::string> vec;
			bool ret = csv.read(vec);
			CYBOZU_TEST_ASSERT(ret);
			CYBOZU_TEST_EQUAL(vec.size(), tbl[i].n);
			for (size_t j = 0; j < std::min(vec.size(), tbl[i].n); j++) {
				CYBOZU_TEST_EQUAL(vec[j], tbl[i].out[j]);
			}
		}
		std::vector<std::string> vec;
		bool ret = csv.read(vec);
		CYBOZU_TEST_ASSERT(vec.empty());
		CYBOZU_TEST_ASSERT(!ret);
	}
}

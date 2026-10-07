#include <stdio.h>
#include <vector>
#include <sstream>
#include <cybozu/test.hpp>
#include <cybozu/string.hpp>
#include <cybozu/string_operation.hpp>

#ifdef _MSC_VER
	#pragma warning(disable : 4309)
#endif

CYBOZU_TEST_AUTO(ascii_space)
{
	for (int i = 0; i < 256; i++) {
		if (i == ' ' || i == '\t') {
			CYBOZU_TEST_ASSERT(cybozu::IsSpace((char)i));
		} else {
			CYBOZU_TEST_ASSERT(!cybozu::IsSpace((char)i));
		}
	}
}

CYBOZU_TEST_AUTO(skipSpace)
{
	const struct {
		const char *in;
		const char *out;
	} tbl[] = {
		{ "abc", "abc" },
		{ "  abc", "abc" },
		{ "      ", "" },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		const char *begin = tbl[i].in;
		const char *end = begin + strlen(begin);
		const char *p = cybozu::SkipSpace(begin, end);
		CYBOZU_TEST_EQUAL(p, tbl[i].out);
		std::string str(begin, end);
		CYBOZU_TEST_EQUAL(cybozu::SkipSpace(str.begin(), str.end()) - str.begin(), p - begin);
	}
}

bool is_space_normal(cybozu::Char c)
{
	static const cybozu::Char spaceTbl[] = {
		0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x20,
		0x85,
		0xa0,
		0x1680,
		0x180e,
		0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
		0x2028,
		0x2029,
		0x202f,
		0x205f,
		0x3000,
		0xfeff, // zero width no-break space
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(spaceTbl); i++) {
		if (c == spaceTbl[i]) return true;
	}
	return false;
}

CYBOZU_TEST_AUTO(unicode_space)
{
	for (cybozu::Char c = 0; c <= 0x10ffff; c++) {
		if (cybozu::IsSpace(c) != is_space_normal(c)) {
			printf("c=%x\n", c);
			CYBOZU_TEST_FAIL("bad space");
		}
	}
	CYBOZU_TEST_ASSERT(1);
}

CYBOZU_TEST_AUTO(trim)
{
	const struct {
		const char *in;
		const char *out;
	} tbl[] = {
		{ "", "" },
		{ " \t", "" },
		{ "   abc xyz\t\t\t", "abc xyz" },
		{ "abc ddd	", "abc ddd" },
		{ "\t\t\txxx", "xxx" },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		{
			std::string in(tbl[i].in);
			std::string out = cybozu::TrimCopy(in);
			CYBOZU_TEST_EQUAL(out, tbl[i].out);
		}
		{
			cybozu::String in(tbl[i].in);
			cybozu::String out = cybozu::TrimCopy(in);
			CYBOZU_TEST_EQUAL(out, tbl[i].out);
		}
		{
			std::string in(tbl[i].in);
			cybozu::Trim(in);
			CYBOZU_TEST_EQUAL(in, tbl[i].out);
		}
		{
			cybozu::String in(tbl[i].in);
			cybozu::Trim(in);
			CYBOZU_TEST_EQUAL(in, tbl[i].out);
		}
	}
	cybozu::String str("\x20\x20""doremi\x20\xe3\x80\x80\x20\xe3\x80\x80");
	cybozu::Trim(str);
	CYBOZU_TEST_EQUAL(str, "doremi");
}

CYBOZU_TEST_AUTO(casecmp)
{
	const struct {
		const char *lhs;
		size_t lhsSize;
		const char *rhs;
		size_t rhsSize;
		int ret;
	} tbl[] = {
		{ "", 0, "", 0, 0 },
		{ "abc", 3, "abc", 3, 0 },
		{ "abcd", 4, "abc", 3, 1 },
		{ "abc", 3, "abcd", 4, -1 },
		{ "abc\0xyz", 7, "abc", 3, 1 },
		{ "abc\0xyz", 3, "abcd", 4, -1 },
		{ "AAA", 3, "aaa", 3, 0 },
		{ "012345678ABCDEFGHIJKLMNOPQRSTUVWXYZaVN#)(WV#N(WRUW#VRW", 55
		 ,"012345678abcdefghijklmnopqrstuvwxyzaVN#)(WV#N(WRUW#VRW", 55, 0 },
		{ "AAAbbB", 3, "aaabbb", 3, 0 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		{
			std::string lhs(tbl[i].lhs, tbl[i].lhs + tbl[i].lhsSize);
			std::string rhs(tbl[i].rhs, tbl[i].rhs + tbl[i].rhsSize);
			int ret = cybozu::CaseCompare(lhs, rhs);
			ret = (ret > 0) ? 1 : (ret < 0) ? -1 : 0;
			CYBOZU_TEST_EQUAL(ret, tbl[i].ret);
		}
		{
			cybozu::String lhs(tbl[i].lhs, tbl[i].lhs + tbl[i].lhsSize);
			cybozu::String rhs(tbl[i].rhs, tbl[i].rhs + tbl[i].rhsSize);
			int ret = cybozu::CaseCompare(lhs, rhs);
			ret = (ret > 0) ? 1 : (ret < 0) ? -1 : 0;
			CYBOZU_TEST_EQUAL(ret, tbl[i].ret);
		}
	}
}

CYBOZU_TEST_AUTO(caseEqualStart)
{
	CYBOZU_TEST_ASSERT(cybozu::CaseEqualStartWith(std::string("abcdef"), "abC"));
	CYBOZU_TEST_ASSERT(cybozu::CaseEqualStartWith(std::string("ABC"), "aBc"));
	CYBOZU_TEST_ASSERT(!cybozu::CaseEqualStartWith(std::string("AB"), "abc"));

	CYBOZU_TEST_ASSERT(cybozu::CaseEqualStartWith(cybozu::String("abcdef"), "abC"));
	CYBOZU_TEST_ASSERT(cybozu::CaseEqualStartWith(cybozu::String("ABC"), "aBc"));
	CYBOZU_TEST_ASSERT(!cybozu::CaseEqualStartWith(cybozu::String("AB"), "abc"));
}

CYBOZU_TEST_AUTO(caseEqaul)
{
	const struct {
		const char *lhs;
		const char *rhs;
		bool ret;
	} tbl[] = {
		{ "abcdef", "abC", false },
		{ "ABC", "aBc", true },
		{ "AB", "abc", false },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		{
			std::string lhs(tbl[i].lhs);
			std::string rhs(tbl[i].rhs);
			CYBOZU_TEST_EQUAL(cybozu::CaseEqual(lhs, rhs), tbl[i].ret);
		}
		{
			cybozu::String lhs(tbl[i].lhs);
			cybozu::String rhs(tbl[i].rhs);
			CYBOZU_TEST_EQUAL(cybozu::CaseEqual(lhs, rhs), tbl[i].ret);
		}
	}
}

CYBOZU_TEST_AUTO(tolower)
{
	const struct {
		const char *str;
		const char *up;
		const char *low;
	} tbl[] = {
		{ "", "", "" },
		{ "ab23dc5\0def", "AB23DC5\0DEF", "ab23dc5\0def" },
		{ "#$%%#$(%')#($&", "#$%%#$(%')#($&", "#$%%#$(%')#($&" },
		{ "AbCdEfGHijklmnOPQRSTUvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz" },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		{
			std::string str(tbl[i].str);
			cybozu::ToUpper(str);
			CYBOZU_TEST_EQUAL(str, tbl[i].up);
			str = tbl[i].str;
			cybozu::ToLower(str);
			CYBOZU_TEST_EQUAL(str, tbl[i].low);
		}
		{
			cybozu::String str(tbl[i].str);
			cybozu::ToUpper(str);
			CYBOZU_TEST_EQUAL(str, tbl[i].up);
			str = tbl[i].str;
			cybozu::ToLower(str);
			CYBOZU_TEST_EQUAL(str, tbl[i].low);
		}
		{
			std::string up;
			cybozu::ToUpper(up, std::string(tbl[i].str));
			CYBOZU_TEST_EQUAL(up, tbl[i].up);
			std::string low;
			cybozu::ToLower(low, std::string(tbl[i].str));
			CYBOZU_TEST_EQUAL(low, tbl[i].low);
		}
		{
			cybozu::String up;
			cybozu::ToUpper(up, std::string(tbl[i].str));
			CYBOZU_TEST_EQUAL(up, tbl[i].up);
			cybozu::String low;
			cybozu::ToLower(low, std::string(tbl[i].str));
			CYBOZU_TEST_EQUAL(low, tbl[i].low);
		}
		const std::string pre = "aBc";
		{
			std::string up = pre;
			cybozu::ToUpper(up, std::string(tbl[i].str), cybozu::string::DoAppend);
			CYBOZU_TEST_EQUAL(up, pre + tbl[i].up);
			std::string low = pre;
			cybozu::ToLower(low, std::string(tbl[i].str), cybozu::string::DoAppend);
			CYBOZU_TEST_EQUAL(low, pre + tbl[i].low);
		}
		{
			cybozu::String up = pre;
			cybozu::ToUpper(up, std::string(tbl[i].str), cybozu::string::DoAppend);
			CYBOZU_TEST_EQUAL(up, pre + tbl[i].up);
			cybozu::String low = pre;
			cybozu::ToLower(low, std::string(tbl[i].str), cybozu::string::DoAppend);
			CYBOZU_TEST_EQUAL(low, pre + tbl[i].low);
		}
	}
}

CYBOZU_TEST_AUTO(CaseFind)
{
	const struct {
		const char *in;
		const char *target;
		int pos;
	} tbl [] = {
		{ "", "", 0 },
		{ "abc", "", 0 },
		{ "", "a", -1 },
		{ "", "abc", -1 },
		{ "abc", "abcd", -1 },
		{ "abcdef", "def", 3 },
		{ "abcDEF", "def", 3 },
		{ "abcDef", "dEF", 3 },
		{ "abcDef", "dEFg", -1 },
		{ "abcDef", "dEFg", -1 },
		{ "abcAB%%cde$$%sdf", "ab%%CDE$$%S", 3 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string in(tbl[i].in);
		const char *p = cybozu::CaseFind(in.c_str(), in.c_str() + in.size(), tbl[i].target);
		int pos = tbl[i].pos;
		if (pos == -1) {
			CYBOZU_TEST_EQUAL_POINTER(p, 0);
		} else {
			CYBOZU_TEST_EQUAL_POINTER(p, in.c_str() + pos);
		}
	}
}

CYBOZU_TEST_AUTO(split)
{
	typedef std::vector<std::string> StrVec;
	const struct {
		const char *in;
		char splitChar;
		size_t maxNum;
		const char *out[5];
		size_t splitNum;
	} tbl [] = {
		{ "abc,def", ',', 3, { "abc", "def" }, 2 },
		{ "abc,def,ghi,jkl", ',', 3, { "abc", "def", "ghi,jkl" }, 3 },
		{ "abc,def,ghi,jkl", ',', 5, { "abc", "def", "ghi", "jkl" }, 4},
		{ "abc,def,ghi,jkl", ',', 2, { "abc", "def,ghi,jkl" }, 2},
		{ "abc,def,ghi,jkl", ',', 1, { "abc,def,ghi,jkl" }, 1},

		{ "abc=def", '=', 2, { "abc", "def" }, 2 },
		{ ",", ',', 5, { "", "" }, 2 },
		{ "xyz", ',', 5, { "xyz" }, 1 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		StrVec out;
		size_t splitNum = cybozu::Split(out, std::string(tbl[i].in), tbl[i].splitChar, tbl[i].maxNum);
		std::vector<std::string> r = cybozu::Split(std::string(tbl[i].in), tbl[i].splitChar, tbl[i].maxNum);
		CYBOZU_TEST_ASSERT(r == out);
		CYBOZU_TEST_EQUAL(splitNum, tbl[i].splitNum);
		if (splitNum == tbl[i].splitNum) {
			for (size_t j = 0; j < splitNum; j++) {
				CYBOZU_TEST_EQUAL(out[j], tbl[i].out[j]);
			}
		}
	}
}

CYBOZU_TEST_AUTO(Strip)
{
	const struct {
		const char *in;
		const char *out;
	} tbl[] = {
		{ "", "" },
		{ "abc", "abc" },
		{ "abc\n", "abc" },
		{ "abc\ndef\n\r\n\r", "abc\ndef" },
		{ "\r\n\r\n", "" },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string s1(tbl[i].in);
		cybozu::Strip(s1);
		CYBOZU_TEST_EQUAL(s1, tbl[i].out);
		cybozu::String s2(tbl[i].in);
		cybozu::Strip(s2);
		CYBOZU_TEST_EQUAL(s2, tbl[i].out);
	}
}
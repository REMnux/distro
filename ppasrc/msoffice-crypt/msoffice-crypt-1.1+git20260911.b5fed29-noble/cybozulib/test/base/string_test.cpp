// don't delete bom(EF BB BF) for visual stduio
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <assert.h>
#include <vector>
#include <iterator>
#include <stdexcept>
#include <cybozu/string.hpp>
#include <cybozu/test.hpp>

using namespace cybozu;

#ifdef _MSC_VER
	#pragma warning(disable : 4309)
	#pragma warning(disable : 4310)
#endif

///////// iterator

#ifdef _MSC_VER
	#define STR(x) L ## x
#else
	#define STR(x) x
#endif

CYBOZU_TEST_AUTO(string_iterator_test)
{
	// String s(STR("これはUTF-8 1"));
	String s("\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1");
	String t;
	std::copy(s.begin(), s.end(), std::back_inserter(t));
	CYBOZU_TEST_EQUAL(s, t);
}

CYBOZU_TEST_AUTO(string_reverse_iterator_test)
{
	/* String s("これはUTF-8 1"); */
	String s("\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1");
	String t;
	std::copy(s.rbegin(), s.rend(), std::back_inserter(t));
	/* String checked("1 8-FTUはれこ"); */
	String checked("1 8-FTU" "\xe3\x81\xaf\xe3\x82\x8c\xe3\x81\x93");
	CYBOZU_TEST_EQUAL(t, checked);
}

CYBOZU_TEST_AUTO(string_iterater_test_push_back)
{
	/* String s("これはUTF-8 1"); */
	String s("\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1");
	Char t = '2';
	s.push_back(t);
	/* String checked("これはUTF-8 12"); */
	String checked("\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 12");
	CYBOZU_TEST_EQUAL(s, checked);
}

///////// utility

// copy [off, off + count) to [dest, dest + count)
CYBOZU_TEST_AUTO(string_util_test_copy)
{
	/* String s("あいueお"), t; */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x8A"), t;
	Char dest[100];
	s.copy(dest, 3, 1);
	dest[3] = '\0'; /* copy method does not terminate */
	t = dest;
	/* "いue" */
	CYBOZU_TEST_EQUAL(t, "\xe3\x81\x84\x75\x65");
}

// exchange contents with rhs
CYBOZU_TEST_AUTO(string_util_test_swap)
{
	/* String s("あいueお"), t("abcうえf"); */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x8A");
	String t("\x61\x62\x63\xe3\x81\x86\xe3\x81\x88\x66");
	s.swap(t);
	/* CYBOZU_TEST_EQUAL(t, "あいueお"); */
	CYBOZU_TEST_EQUAL(t, "\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x8A");
	/* CYBOZU_TEST_EQUAL(s, "abcうえf"); */
	CYBOZU_TEST_EQUAL(s, "\x61\x62\x63\xe3\x81\x86\xe3\x81\x88\x66");
}

// return [off, off + count) as new string
CYBOZU_TEST_AUTO(string_util_test_substr)
{
	/* String s("あいueお"); */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x8A");
	String t = s.substr(1, 3);
	/* CYBOZU_TEST_EQUAL(t, "いue"); */
	CYBOZU_TEST_EQUAL(t, "\xe3\x81\x84\x75\x65");
}
/////////// compare //////////
//// String
// compare [0, _Mysize) with rhs
CYBOZU_TEST_AUTO(string_util_test_compare_cybozu_str)
{
	/* String s("ういのおくやま"); */
	String s("\xE3\x81\x86\xE3\x81\x84\xE3\x81\xAE\xE3\x81\x8A\xE3\x81\x8F\xE3\x82\x84\xE3\x81\xBE");
	/* String t("ういのおくやま"); */
	String t("\xE3\x81\x86\xE3\x81\x84\xE3\x81\xAE\xE3\x81\x8A\xE3\x81\x8F\xE3\x82\x84\xE3\x81\xBE");
	/* String t("うゐのおくやま"); */
	String u("\xE3\x81\x86\xE3\x82\x90\xE3\x81\xAE\xE3\x81\x8A\xE3\x81\x8F\xE3\x82\x84\xE3\x81\xBE");

	CYBOZU_TEST_ASSERT(s.compare(t) == 0);
	CYBOZU_TEST_ASSERT(s.compare(u) != 0);
}

// compare [off, off + n) with rhs
CYBOZU_TEST_AUTO(string_util_test_compare_cybozu_substring)
{
	/* String s("ういのおくやま"); */
	String s("\xE3\x81\x86\xE3\x81\x84\xE3\x81\xAE\xE3\x81\x8A\xE3\x81\x8F\xE3\x82\x84\xE3\x81\xBE");
	/* String t("おくやま"); */
	String t("\xE3\x81\x8A\xE3\x81\x8F\xE3\x82\x84\xE3\x81\xBE");

	CYBOZU_TEST_EQUAL(s.compare(3, 4, t), 0);
}

// compare [off, off + n) with rhs [rhsOff, rhsOff + count)
CYBOZU_TEST_AUTO(string_util_test_compare_cybozu_substring_substring)
{
	/* String s("あいu いue おく"); */
	String s("\xe3\x81\x82\xe3\x81\x84u"
			 " "
			 "\xe3\x81\x84\x75\x65"
			 " "
			 "\xE3\x81\x8A\xE3\x81\x8F");
	/* "あいueお" "いue" "abc" */
	String t("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x8A" "\xe3\x81\x84\x75\x65" "abc");
	printf("size=%d, %d\n", (int)s.size(), (int)t.size());
	CYBOZU_TEST_EQUAL(s.compare(4, 3, t, 5, 3), 0);
}

//// Char *
// compare [0, _Mysize) with [str, <null>)
CYBOZU_TEST_AUTO(string_util_test_compare_cybozu_char_array_zero)
{
	String s("doragon");
	Char t[] = {'d','o','r','a','g','o','n', 0};
	CYBOZU_TEST_EQUAL(s.compare(t), 0);
}

CYBOZU_TEST_AUTO(string_util_test_compare_offset_cybozu_char_array_zero)
{
	String s("doragon quest");
	Char t[] = {'d','o','r','a','g','o','n', 0};
	CYBOZU_TEST_EQUAL(s.compare(0, 7, t), 0);
}

CYBOZU_TEST_AUTO(string_util_test_compare_offset_cybozu_char_array_zero_offset)
{
	String s("doragon quest");
	Char t[] = {'q','u','e','s','t', ' ', '5', 0};
	CYBOZU_TEST_EQUAL(s.compare(8, 5, t, 5), 0);
}

CYBOZU_TEST_AUTO(string_util_test_toUtf8string)
{
	std::string s("doragon");
	String t("doragon");
	t.toUtf8();
	CYBOZU_TEST_EQUAL(t.toUtf8(), s);

	s.erase();
	t.erase();
	/* s = "あいうえお"; */
	s = "\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";
	/* t = "あいうえお"; */
	t = "\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";
	CYBOZU_TEST_EQUAL(t.toUtf8(), s);

	/* "どabcれ" "(丈に点)" 最後の文字はサロゲートペアになる文字 */
	const Char cs[] = { 0x00003069, 0x00000061, 0x00000062, 0x00000063, 0x0000308c, 0x0002000b, 0 };
	String ss(cs);
	CYBOZU_TEST_EQUAL(ss, "\xe3\x81\xa9" "abc" "\xe3\x82\x8c" "\xf0\xa0\x80\x8b");
}

CYBOZU_TEST_AUTO(string_constructor_char_array_test)
{
	const Char str[] = { 'a', 'b', 'c', 'd', 'e', 0 };
	String a(str, 5);
	std::stringstream ss;
	ss << a;
	CYBOZU_TEST_EQUAL(ss.str(), "abcde");
}

CYBOZU_TEST_AUTO(string_constructor_substring_test)
{
	const Char str[] = { 'a', 'b', 'c', 'd', 'e', 0 };
	String a(str, 5);
	String b(a, 1, 2);
	std::stringstream ss;
	ss << b;
	CYBOZU_TEST_EQUAL(ss.str(), "bc");
}

CYBOZU_TEST_AUTO(string_constructor_zeroterminated_test)
{
	const Char str[] = { 'a', 'b', 'c', 'd', 'e', 0 };
	String a(str);
	std::stringstream ss;
	ss << a;
	CYBOZU_TEST_EQUAL(ss.str(), "abcde");
}

CYBOZU_TEST_AUTO(string_constructor_from_count_times_c)
{
	String a(10, 'a');
	std::stringstream ss;
	ss << a;
	CYBOZU_TEST_EQUAL(ss.str(), "aaaaaaaaaa");
}

CYBOZU_TEST_AUTO(string_constructor_surrogate_pair_test)
{
	/* "どabcれ" "(丈に点)" 最後の文字はサロゲートペアになる文字 */
	String a("\xe3\x81\xa9" "abc" "\xe3\x82\x8c" "\xf0\xa0\x80\x8b");
	const Char s[] = { 0x00003069, 0x00000061, 0x00000062, 0x00000063, 0x0000308c, 0x0002000b, 0 };
	std::stringstream ss;
	ss << a;
	CYBOZU_TEST_ASSERT(a == s);
	CYBOZU_TEST_EQUAL(ss.str(), "\xe3\x81\xa9" "abc" "\xe3\x82\x8c" "\xf0\xa0\x80\x8b");
}

// test iterator
CYBOZU_TEST_AUTO(string_constructor_iterator_test)
{
	/* std::string a("What is 寿限無寿限無?"); */
	std::string a("What is " "\xE5\xAF\xBF\xE9\x99\x90\xE7\x84\xA1" "?");
	String s(a.begin() + 5, a.end());
	std::string b("is " "\xE5\xAF\xBF\xE9\x99\x90\xE7\x84\xA1" "?");
	/* CYBOZU_TEST_EQUAL(s, "is 寿限無寿限無?"); */
	CYBOZU_TEST_EQUAL(s, b);
}

CYBOZU_TEST_AUTO(string_constructor_comp_test)
{
	const Char s[] = { 0x8868, 0 };
	/* String a("表"); */
	String a("\xE8\xA1\xA8");
	String b(s, 1);
	CYBOZU_TEST_EQUAL(a, b);
}

// pointer
CYBOZU_TEST_AUTO(string_constructor_pointer_test)
{
	/* const char a[] = "What is 寿限無寿限無?"; */
	const char a[] = "What is " "\xE5\xAF\xBF\xE9\x99\x90\xE7\x84\xA1" "?";
	String s(a, a + CYBOZU_NUM_OF_ARRAY(a) - 1);
	String x("What is " "\xE5\xAF\xBF\xE9\x99\x90\xE7\x84\xA1" "?");
	/* CYBOZU_TEST_EQUAL(s, "What is 寿限無寿限無?"); */
	CYBOZU_TEST_EQUAL(s, x);

	String t(a + 3, a + 6);
	CYBOZU_TEST_EQUAL(t, "t i");
}

// stringstream(char)
CYBOZU_TEST_AUTO(string_constructor_stringstream_test)
{
	std::basic_stringstream<char> ss;
	ss << "\xe3\x81\xa9" "abc" "\xe3\x82\x8c" "\xf0\xa0\x80\x8b";
	String a(std::istreambuf_iterator<char>(ss.rdbuf()), std::istreambuf_iterator<char>());

	CYBOZU_TEST_EQUAL(a, "\xe3\x81\xa9" "abc" "\xe3\x82\x8c" "\xf0\xa0\x80\x8b");
}

// stringstream(Char)
CYBOZU_TEST_AUTO(string_constructor_stringstream_Char_test)
{
	std::basic_stringstream<Char> ss;
	const Char s[] = { 0x00003069, 0x00000061, 0x00000062, 0x00000063, 0x0000308c, 0x0002000b, 0 };

	ss << s;
	String a(std::istreambuf_iterator<Char>(ss.rdbuf()), std::istreambuf_iterator<Char>());
	CYBOZU_TEST_EQUAL(a, "\xe3\x81\xa9" "abc" "\xe3\x82\x8c" "\xf0\xa0\x80\x8b");
}

//from Char16
CYBOZU_TEST_AUTO(string_constructor_char16_test)
{
	const Char16 str[] = { 'a', 'b', 'c', 'd', 'e', 0 };
	String16 a(str);
	String s(a);
	CYBOZU_TEST_EQUAL(s, "abcde");
}

///////// index

CYBOZU_TEST_AUTO(string_index_test_at)
{
	/* String s("これはUTF-8 1"); */
	String s("\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1");
	Char t = s.at(3);
	Char c = 'U';
	CYBOZU_TEST_ASSERT(t == c);
}

CYBOZU_TEST_AUTO(string_index_test_at_exception)
{
	try {
		/* String s("これはUTF-8 1"); */
		String s("\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1");
		s.at(200);
		CYBOZU_TEST_FAIL("NEVER REACHED!");
	} catch (std::out_of_range&) {
		std::cout << "std::out_of_range thrown!" << std::endl;
	} catch (...) {
		CYBOZU_TEST_FAIL("NEVER REACHED!");
	}
}

CYBOZU_TEST_AUTO(string_index_test_index)
{
	/* String s("これはUTF-8 1"); */
	String s("\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1");
	Char t = s[6];
	Char c = '-';
	CYBOZU_TEST_ASSERT(t == c);
}

//cybozu::String
CYBOZU_TEST_AUTO(string_append_op_test_string)
{
	/* const char cs2[] = "です"; */
	const char cs2[] = "\xE3\x81\xA7\xE3\x81\x99";
	/* String s = "これはUTF-8"; */
	String s = "\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8";
	s += cs2;
	String checked = "\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8" "\xE3\x81\xA7\xE3\x81\x99";
	/* CYBOZU_TEST_EQUAL(s, "これはUTF-8です"); */
	CYBOZU_TEST_EQUAL(s, checked);
}

//Char [] Null Terminated
CYBOZU_TEST_AUTO(string_append_op_test_char_array)
{
	/* "こUTF-8 3"; */
	const Char c[] = { 0x00003053, 0x00000055, 0x00000054, 0x00000046, 0x0000002d, 0x00000038, ' ', '3', 0 };
	/* String s = "あああ"; */
	String s = "\xE3\x81\x82\xE3\x81\x82\xE3\x81\x82";
	s += c;
	String checked = "\xE3\x81\x82\xE3\x81\x82\xE3\x81\x82" "\xe3\x81\x93" "UTF-8 3";
	/* CYBOZU_TEST_EQUAL(s, "あああこUTF-8 3"); */
	CYBOZU_TEST_EQUAL(s, checked);
}

//Char
CYBOZU_TEST_AUTO(string_append_op_test_char)
{
	/* "こUTF-8 3"; */
	const Char c = '3';
	/* String s = "あああ"; */
	String s = "\xE3\x81\x82\xE3\x81\x82\xE3\x81\x82";
	s += c;
	/* CYBOZU_TEST_EQUAL(s, "あああ3"); */
	String checked = "\xE3\x81\x82\xE3\x81\x82\xE3\x81\x82\x33";
	CYBOZU_TEST_EQUAL(s, checked);
}

//cybozu::String
CYBOZU_TEST_AUTO(string_append_test_string)
{
	/* String s = "あああ"; */
	String s = "\xE3\x81\x82\xE3\x81\x82\xE3\x81\x82";
	String t;
	t.append(s);
	/* CYBOZU_TEST_EQUAL(t, "あああ"); */
	CYBOZU_TEST_EQUAL(t, "\xE3\x81\x82\xE3\x81\x82\xE3\x81\x82");
}

//cybozu::String
CYBOZU_TEST_AUTO(string_append_test_sub_string)
{
	/* String s = "あIう"; */
	String s = "\xE3\x81\x82\x49\xE3\x81\x86";
	String t;
	t.append(s, 1, 1);
	CYBOZU_TEST_EQUAL(t, "I");
}

//Char[]
CYBOZU_TEST_AUTO(string_append_test_char_array_off_z)
{
	/* "こUTF-8 3" */
	const Char c[] = { 0x00003053, 0x00000055, 0x00000054, 0x00000046, 0x0000002d, 0x00000038, ' ', '3', 0 };
	String t;
	t.append(c,2);
	/* CYBOZU_TEST_EQUAL(t, "こU"); */
	const String checked = "\xE3\x81\x93\x55";
	CYBOZU_TEST_EQUAL(t, checked);
}

//Zero terminated Char array
CYBOZU_TEST_AUTO(string_append_test_zero_terminated_char_array)
{
	/* "こUTF-8 3" */
	const Char c[] = { 0x00003053, 0x00000055, 0x00000054, 0x00000046, 0x0000002d, 0x00000038, ' ', '3', 0 };
	String t;
	t.append(c);
	String checked = "\xe3\x81\x93" "UTF-8 3";
	/* CYBOZU_TEST_EQUAL(t, "こUTF-8 3"); */
	CYBOZU_TEST_EQUAL(t, checked);
}

//count * Char
CYBOZU_TEST_AUTO(string_append_test_multiple_char)
{
	/* String t = "あいうえお"; */
	String t = "\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";
	Char x = 'w';
	t.append(10, x);
	String checked = "\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A" "wwwwwwwwww";
	CYBOZU_TEST_EQUAL(t, checked);
}

// test iterator
CYBOZU_TEST_AUTO(string_append_test_iterator)
{
	/* std::string a("What is 寿限無寿限無?"); */
	std::string a("What is " "\xE5\xAF\xBF\xE9\x99\x90\xE7\x84\xA1" "?");
	String t;
	t.append(a.begin() + 5, a.end());
	std::string b("is " "\xE5\xAF\xBF\xE9\x99\x90\xE7\x84\xA1" "?");
	/* CYBOZU_TEST_EQUAL(t, "is 寿限無寿限無?"); */
	CYBOZU_TEST_EQUAL(t, b);
}

// append [str, str + count)
CYBOZU_TEST_AUTO(string_append_char_array)
{
	const char cs[] = "abcdefg";
	String t;
	t.append(cs, 3);
	CYBOZU_TEST_EQUAL(t, "abc");
}

// append [str, str + count)
CYBOZU_TEST_AUTO(string_append_char_array_null)
{
	/* const char cs[] = "あいうえお"; */
	const char cs[] = "\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";
	String t;
	t.append(cs);
	const String checked = "\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";
	/* CYBOZU_TEST_EQUAL(t,"あいうえお"); */
	CYBOZU_TEST_EQUAL(t, checked);
}

// append str
CYBOZU_TEST_AUTO(string_append_std_string)
{
	/* const std::string x = "サイボウズ"; */
	const std::string x("\xE3\x82\xB5\xE3\x82\xA4\xE3\x83\x9C\xE3\x82\xA6\xE3\x82\xBA");
	String t;
	t.append(x);
	/* CYBOZU_TEST_EQUAL(t,"サイボウズ"); */
	String checked = "\xE3\x82\xB5\xE3\x82\xA4\xE3\x83\x9C\xE3\x82\xA6\xE3\x82\xBA";
	CYBOZU_TEST_EQUAL(t, checked);
}

CYBOZU_TEST_AUTO(string_assignment_test_char_array)
{
	/* const char cs[] = "これはUTF-8 1"; */
	const char cs[] = "\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1";
	String s;
	s = cs;
	String checked = "\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1";
	/* CYBOZU_TEST_EQUAL(s, "これはUTF-8 1"); */
	CYBOZU_TEST_EQUAL(s, checked);
}

CYBOZU_TEST_AUTO(string_assignment_test_std_string)
{
	/* const std::string ss = "これは 2"; */
	const std::string ss = "\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" " 2";
	String s;
	s = ss;
	String checked = "\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" " 2";
	/* CYBOZU_TEST_EQUAL(s, "これは 2"); */
	CYBOZU_TEST_EQUAL(s, checked);
}

CYBOZU_TEST_AUTO(string_assignment_test_uchar_32)
{
	/* "こUTF-8 3" */
	const Char c[] = { 0x00003053, 0x00000055, 0x00000054, 0x00000046, 0x0000002d, 0x00000038, ' ', '3', 0 };
	String s;
	s = c;
	/* CYBOZU_TEST_EQUAL(s, "こUTF-8 3"); */
	String checked = "\xe3\x81\x93" "UTF-8 3";
	CYBOZU_TEST_EQUAL(s, checked);
}

//cybozu::String
CYBOZU_TEST_AUTO(string_assignment_cybozu_string)
{
	String s, ss;
	/* s = "これはUTF-8 1"; */
	s = "\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1";
	ss = s;
	CYBOZU_TEST_EQUAL(s, ss);
}

//Char
CYBOZU_TEST_AUTO(string_assignment_Char)
{
	const Char c = 'a';
	String s;
	s = c;
	CYBOZU_TEST_EQUAL(s, "a");
}

////////////////////////////////////
//cybozu::String
CYBOZU_TEST_AUTO(string_assignment_cybozu_string_assign)
{
	String s, ss;
	/* s = "これはUTF-8 1"; */
	s = "\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1";
	ss.assign(s);
	CYBOZU_TEST_EQUAL(ss, s);
}
// assign rhs [off, off + count)
CYBOZU_TEST_AUTO(string_assignment_cybozu_substring_assign)
{
	String s, ss;
	/* s = "これはUTF-8 2"; */
	s = "\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 2";
	ss.assign(s,3,4);
	CYBOZU_TEST_EQUAL(ss, "UTF-");
}

// assign [str, str + count)
CYBOZU_TEST_AUTO(string_assignment_cybozu_char_array_assign)
{
	String ss;
	Char c[] = {'a','b','c','d','e','f',0};
	ss.assign(c,3);
	CYBOZU_TEST_EQUAL(ss, "abc");
}

// assign [str, <null>)
CYBOZU_TEST_AUTO(string_assignment_cybozu_char_array_zero_terminated)
{
	String ss;
	Char c[] = {'a','b','c','d','e','f',0};
	ss.assign(c);
	CYBOZU_TEST_EQUAL(ss,  "abcdef");
}

// assign count * c
CYBOZU_TEST_AUTO(string_assignment_cybozu_multiple_char)
{
	String ss;
	Char c = 'X';
	ss.assign(10, c);
	CYBOZU_TEST_EQUAL(ss, "XXXXXXXXXX");
}

//Iterator
CYBOZU_TEST_AUTO(string_assignment_cybozu_iterator)
{
	String ss;
	/* std::string a("What is 寿限無寿限無?"); */
	std::string a("What is " "\xE5\xAF\xBF\xE9\x99\x90\xE7\x84\xA1" "?");
	ss.assign(a.begin()+3, a.end());
	std::string b("t is " "\xE5\xAF\xBF\xE9\x99\x90\xE7\x84\xA1" "?");
	CYBOZU_TEST_EQUAL(ss, b);
}

// assign [str, str + count)
CYBOZU_TEST_AUTO(string_assignment_cybozu_std_char_array)
{
	String ss;
	char c[] = "ABCDEFG";
	ss.assign(c, 5);
	CYBOZU_TEST_EQUAL(ss, "ABCDE");
}

// assign [str, <null>)
CYBOZU_TEST_AUTO(string_assignment_cybozu_std_char_array_assign)
{
	String ss;
	/* char c[] = "あいうえおー"; */
	char c[] = "\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A\xE3\x83\xBC";
	ss.assign(c);
	std::string checked = "\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A\xE3\x83\xBC";
	CYBOZU_TEST_EQUAL(ss, checked);
}

// assign str
CYBOZU_TEST_AUTO(string_assignment_cybozu_std_string_assign)
{
	String ss;
	/* std::string a("サイボウズ"); */
	std::string a("\xE3\x82\xB5\xE3\x82\xA4\xE3\x83\x9C\xE3\x82\xA6\xE3\x82\xBA");
	ss.assign(a);
	String checked = "\xE3\x82\xB5\xE3\x82\xA4\xE3\x83\x9C\xE3\x82\xA6\xE3\x82\xBA";
	/* CYBOZU_TEST_EQUAL(ss, "サイボウズ"); */
	CYBOZU_TEST_EQUAL(ss, checked);

}

///////// direct_access

// return pointer to null-terminated nonmutable arrya
CYBOZU_TEST_AUTO(string_utility_test_c_str)
{
	String s("abcdefg");
	const Char cs[] = {'a', 'b', 'c',  'd', 'e', 'f', 'g', 0};
	for (int i = 0; i<8 ; i++) {
		CYBOZU_TEST_ASSERT(s.c_str()[i] == cs[i]);
	}
}

// return pointer to nonmutable array
CYBOZU_TEST_AUTO(string_utility_test_data)
{
	String s("abcdefg");
	const Char cs[] = {'a', 'b', 'c',  'd', 'e', 'f', 'g', 0};
	for (int i = 0; i<7 ; i++) {
		CYBOZU_TEST_ASSERT(s.c_str()[i] == cs[i]);
	}
}

///////// erase
// insert rhs at off
CYBOZU_TEST_AUTO(string_erase_test_cybozu_string)
{
	/* String s("いろはにほへと"); */
	String s("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	s.erase(2, 3);
	/* CYBOZU_TEST_EQUAL(s, "いろへと"); */
	String checked("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xB8\xE3\x81\xA8");
	CYBOZU_TEST_EQUAL(s,  checked);

	/* String t("かきくけこ"); */
	String t("\xE3\x81\x8B\xE3\x81\x8D\xE3\x81\x8F\xE3\x81\x91\xE3\x81\x93");
	t.erase();
	CYBOZU_TEST_EQUAL(t, "");
}

// erase element at here
CYBOZU_TEST_AUTO(string_erase_test_iterator)
{
	/* String s("いろはにほへと"); */
	String s("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	s.erase(s.begin() + 3);
	/* CYBOZU_TEST_EQUAL(s, "いろはほへと"); */
	String checked("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	CYBOZU_TEST_EQUAL(s, checked);
}

// erase substring [begin, end)
CYBOZU_TEST_AUTO(string_erase_test_iterator_substr)
{
	/* String s("いろはにほへと"); */
	String s("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	s.erase(s.begin()+3, s.end()-1);
	/* CYBOZU_TEST_EQUAL(s, "いろはと"); */
	String checked("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xA8");
	CYBOZU_TEST_EQUAL(s, checked);
}

//erase all
CYBOZU_TEST_AUTO(string_erase_test_all)
{
	/* String s("わかよたれそ"); */
	String s("\xE3\x82\x8F\xE3\x81\x8B\xE3\x82\x88\xE3\x81\x9F\xE3\x82\x8C\xE3\x81\x9D");
	s.clear();
	CYBOZU_TEST_EQUAL(s, "");
}

///////// find

// look for rhs beginnng at or after off
CYBOZU_TEST_AUTO(string_size_test_find_cybozu_string)
{
	/* String s("あいueい"); */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x84");
	/* const String t("い"); */
	const String t("\xe3\x81\x84");

	CYBOZU_TEST_EQUAL(s.find(t), 1);
	CYBOZU_TEST_EQUAL(s.find(t, 2), 4);
}

// look for [str, str + count) beginnng at or after off
CYBOZU_TEST_AUTO(string_size_test_find_cybozu_char_array)
{
	/* String s("あいueい"); */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x84");
	const Char t[] = {'u','e'};
	CYBOZU_TEST_EQUAL(s.find(t, 0, 2), 2);
	CYBOZU_TEST_EQUAL(s.find(t, 3, 1), size_t(-1));
}

// look for [str, <null>) beginnng at or after off
CYBOZU_TEST_AUTO(string_size_test_find_cybozu_char_array_zero)
{
	/* String s("あいueい"); */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x84");
	const Char t[] = {'u','e', 0};
	CYBOZU_TEST_EQUAL(s.find(t, 0), 2);
	CYBOZU_TEST_EQUAL(s.find(t, 3), size_t(-1));
}

// look for c at or after off
CYBOZU_TEST_AUTO(string_size_test_find_cybozu_char)
{
	/* String s("あいueい"); */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x84");
	CYBOZU_TEST_EQUAL(s.find('u', 0), 2);
	CYBOZU_TEST_EQUAL(s.find('u', 3), size_t(-1));
}

// look for rhs beginning before off
CYBOZU_TEST_AUTO(string_size_test_rfind_cybozu_string)
{
	/* String s("あいueい"); */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x84");
	CYBOZU_TEST_EQUAL(s.rfind("\xe3\x81\x84"), 4);
	CYBOZU_TEST_EQUAL(s.rfind("\xe3\x81\x84", 3), 1);
}

// look for [str, str + count) beginning before off
CYBOZU_TEST_AUTO(string_size_test_rfind_cybozu_char_array)
{
	/* String s("あいueい"); */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x84");
	Char cs[] = {'u', 'e'};
	CYBOZU_TEST_EQUAL(s.rfind(cs,4,2), 2);
}

CYBOZU_TEST_AUTO(string_size_test_rfind_cybozu_char_array_zero)
// look for [str, <null>) beginning before off
{
	/* String s("あいueい"); */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x84");
	Char cs[] = {'u', 'e', 0};
	CYBOZU_TEST_EQUAL(s.rfind(cs,4), 2);
	CYBOZU_TEST_EQUAL(s.rfind(cs,0), size_t(-1));
}

CYBOZU_TEST_AUTO(string_size_test_rfind_cybozu_char)
// look for [str, <null>) beginning before off
{
	/* String s("あいueい"); */
	String s("\xe3\x81\x82\xe3\x81\x84\x75\x65\xe3\x81\x84");
	Char c = 'u';
	CYBOZU_TEST_EQUAL(s.rfind(c), 2);
	CYBOZU_TEST_EQUAL(s.rfind(c,1), size_t(-1));
}

CYBOZU_TEST_AUTO(string_size_test_find_first_of_cybozu_string)
// look for one of rhs at or after off
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	/* String c("わをん"); */
	String c("\xE3\x82\x8F\xE3\x82\x92\xE3\x82\x93");
	CYBOZU_TEST_EQUAL(s.find_first_of(c), 7);
	CYBOZU_TEST_EQUAL(s.find_first_of(c,8), 10);
}


// look for one of [str, str + count) at or after off
CYBOZU_TEST_AUTO(string_size_test_find_first_of_cybozu_char_array)
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	Char c[] = {'c', 'd', 'e'};
	CYBOZU_TEST_EQUAL(s.find_first_of(c, 0, 2), size_t(-1));
	CYBOZU_TEST_EQUAL(s.find_first_of(c, 0, 3), 3);
}

// look for c at or after off
CYBOZU_TEST_AUTO(string_size_test_find_first_of_cybozu_char)
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	Char c = 'e';
	CYBOZU_TEST_EQUAL(s.find_first_of(c), 3);
	CYBOZU_TEST_EQUAL(s.find_first_of(c, 6), size_t(-1));
}

// look for one of rhs before off
CYBOZU_TEST_AUTO(string_size_test_find_last_of_cybozu_string)
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	/* String cs("わをん"); */
	String cs("\xE3\x82\x8F\xE3\x82\x92\xE3\x82\x93");
	CYBOZU_TEST_EQUAL( s.find_last_of(cs), 10);
	CYBOZU_TEST_EQUAL( s.find_last_of(cs, 4), size_t(-1));
}

// look for one of [str, str + count) before off
CYBOZU_TEST_AUTO(string_size_test_find_last_of_cybozu_char_array)
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	Char c[] = {'c', 'd', 'e'};
	CYBOZU_TEST_EQUAL( s.find_last_of(c, 20, 3), 3);
	CYBOZU_TEST_EQUAL( s.find_last_of(c, 20, 2), size_t(-1));
}

// look for one of [str, <null>) before off
CYBOZU_TEST_AUTO(string_size_test_find_last_of_cybozu_char_array_zero)
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	Char c[] = {'c', 'd', 'e', 0};
	CYBOZU_TEST_EQUAL( s.find_last_of(c, 20), 3);
	CYBOZU_TEST_EQUAL( s.find_last_of(c, 2), size_t(-1));
}

// look for none of rhs at or after off
CYBOZU_TEST_AUTO(string_size_test_find_first_not_of_cybozu_string)
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	/* String t("えいもeimoんせすん"); */
	String t("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	/* String u("えん"); */
	String u ("\xE3\x81\x88\xE3\x82\x93");
	CYBOZU_TEST_EQUAL( s.find_first_not_of(t), size_t(-1));
	CYBOZU_TEST_EQUAL( s.find_first_not_of(u, 3), 3);
	CYBOZU_TEST_EQUAL( s.find_first_not_of(u), 1);
}

// look for none of [str, str + count) at or after off
CYBOZU_TEST_AUTO(string_size_test_find_first_not_of_cybozu_char_array)
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	Char t[] = {'e','i','m','o'};
	CYBOZU_TEST_EQUAL( s.find_first_not_of(t, 0, 4), 0);
	CYBOZU_TEST_EQUAL( s.find_first_not_of(t, 3, 2), 5);
}

// look for one of [str, <null>) at or after off
CYBOZU_TEST_AUTO(string_size_test_find_first_not_of_cybozu_char_array_zero)
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	Char t[] = {'e','i','m','o', 0};
	CYBOZU_TEST_EQUAL( s.find_first_not_of(t, 0), 0);
	CYBOZU_TEST_EQUAL( s.find_first_not_of(t, 3), 7);
}

// look for non c at or after off
CYBOZU_TEST_AUTO(string_size_test_find_first_not_of_cybozu_char)
{
	String s("mmmmmOPmmmmmQ");
	Char t = 'm';
	CYBOZU_TEST_EQUAL( s.find_first_not_of(t, 0), 5);
	CYBOZU_TEST_EQUAL( s.find_first_not_of(t, 8), 12);
}

// look for none of rhs before off
CYBOZU_TEST_AUTO(string_size_test_find_last_not_of_cybozu_string)
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	String t("eimo");
	CYBOZU_TEST_EQUAL( s.find_last_not_of(t), 10);
	CYBOZU_TEST_EQUAL( s.find_last_not_of(t, 4), 2);
}

// look for none of [str, str + count) before off
CYBOZU_TEST_AUTO(string_size_test_find_last_not_of_cybozu_char_array)
{
	/* String s("えいもeimoんせすん"); */
	String s("\xE3\x81\x88\xE3\x81\x84\xE3\x82\x82" "eimo" "\xE3\x82\x93\xE3\x81\x9B\xE3\x81\x99\xE3\x82\x93");
	Char t[] = {'e','i','m','o'};
	CYBOZU_TEST_EQUAL( s.find_last_not_of(t, 4, 2), 2);
	CYBOZU_TEST_EQUAL( s.find_last_not_of(t, 100, 4), 10);
}

// look for none of [str, <null>) before off
CYBOZU_TEST_AUTO(string_size_test_find_last_not_of_cybozu_char_array_zero)
{
	String s("eimo");
	Char t[] = {'e','i','m','o', 0};
	CYBOZU_TEST_EQUAL( s.find_last_not_of(t, 4), size_t(-1));
	Char u[] = {'a','b','c','d','e',0};
	CYBOZU_TEST_EQUAL( s.find_last_not_of(u, 4), 3);
}

// look for non c before off
CYBOZU_TEST_AUTO(string_size_test_find_last_not_of_cybozu_char)
{
	String s("mmmmmOPmmmmmQ");
	Char t = 'm';
	CYBOZU_TEST_EQUAL( s.find_last_not_of(t, 100), 12);
	CYBOZU_TEST_EQUAL( s.find_last_not_of(t, 8), 6);
}

// insert rhs at off
CYBOZU_TEST_AUTO(string_insert_test_cybozu_string)
{
	/* String s("いろはにほへと"); */
	String s("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	const String t("abc");
	s.insert(3, t);
	/* CYBOZU_TEST_EQUAL(s, "いろはabcにほへと"); */
	String checked("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF" "abc" "\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	CYBOZU_TEST_EQUAL(s, checked);
}

// insert rhs [off, off + count) at off
CYBOZU_TEST_AUTO(string_insert_test_cybozu_substring)
{
	/* String s("いろはにほへと"); */
	String s("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	const String t("abc");
	s.insert(3, t, 1, 1);
	/* CYBOZU_TEST_EQUAL(s, "いろはbにほへと"); */
	String checked("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF" "b" "\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	CYBOZU_TEST_EQUAL(s, checked);
}

// insert [str, str + count) at off
CYBOZU_TEST_AUTO(string_insert_test_cybozu_char_array)
{
	/* String s("ちりぬるを"); */
	String s("\xE3\x81\xA1\xE3\x82\x8A\xE3\x81\xAC\xE3\x82\x8B\xE3\x82\x92");
	const Char c[]={'v', 'w', 'x', 'y', 'z', 0};
	s.insert(4, c, 3);
	/* CYBOZU_TEST_EQUAL(s, "ちりぬるvwxを"); */
	String checked("\xE3\x81\xA1\xE3\x82\x8A\xE3\x81\xAC\xE3\x82\x8B" "vwx" "\xE3\x82\x92");
	CYBOZU_TEST_EQUAL(s, checked);
}

// insert [str, <null>) at off
CYBOZU_TEST_AUTO(string_insert_test_cybozu_char_array_zero)
{
	/* String s("ちりぬるを"); */
	String s("\xE3\x81\xA1\xE3\x82\x8A\xE3\x81\xAC\xE3\x82\x8B\xE3\x82\x92");
	const Char c[]={'v', 'w', 'x', 'y', 'z', 0};
	s.insert(4, c);
	/* CYBOZU_TEST_EQUAL(s, "ちりぬるvwxyzを"); */
	String checked("\xE3\x81\xA1\xE3\x82\x8A\xE3\x81\xAC\xE3\x82\x8B" "vwxyz" "\xE3\x82\x92");
	CYBOZU_TEST_EQUAL(s, checked);
}

// insert count * c at off
CYBOZU_TEST_AUTO(string_insert_test_cybozu_multi_char)
{
	/* String s("ちりぬるを"); */
	String s("\xE3\x81\xA1\xE3\x82\x8A\xE3\x81\xAC\xE3\x82\x8B\xE3\x82\x92");
	const Char c ='X';
	s.insert(2, 4, c);
	/* CYBOZU_TEST_EQUAL(s, "ちりXXXXぬるを"); */
	String checked("\xE3\x81\xA1\xE3\x82\x8A" "XXXX"
				   "\xE3\x81\xAC\xE3\x82\x8B\xE3\x82\x92");
	CYBOZU_TEST_EQUAL(s, checked);
}

// insert c at here
CYBOZU_TEST_AUTO(string_insert_test_cybozu_iterator_char)
{
	/* String s("ちりぬるを"); */
	String s("\xE3\x81\xA1\xE3\x82\x8A\xE3\x81\xAC\xE3\x82\x8B\xE3\x82\x92");
	const Char c ='X';
	s.insert(s.begin()+1, c);
	/* CYBOZU_TEST_EQUAL(s, "ちXりぬるを"); */
	String checked("\xE3\x81\xA1" "X"
				   "\xE3\x82\x8A\xE3\x81\xAC\xE3\x82\x8B\xE3\x82\x92");
	CYBOZU_TEST_EQUAL(s, checked);

}

// insert count * Char at here
CYBOZU_TEST_AUTO(string_insert_test_cybozu_iterator_multi_chars)
{
	/* String s("ちりぬるを"); */
	String s("\xE3\x81\xA1\xE3\x82\x8A\xE3\x81\xAC\xE3\x82\x8B\xE3\x82\x92");
	const Char c ='Y';
	s.insert(s.begin(), 5, c);
	/* CYBOZU_TEST_EQUAL(s, "YYYYYちりぬるを"); */
	String checked("YYYYY" "\xE3\x81\xA1\xE3\x82\x8A\xE3\x81\xAC\xE3\x82\x8B\xE3\x82\x92");
	CYBOZU_TEST_EQUAL(s, checked);
}

// insert [begin, end) at here
CYBOZU_TEST_AUTO(string_insert_test_cybozu_iterator_iterator)
{
	/* String s("あいうえお"); */
	String s("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	String t("abcdef");
	s.insert(s.begin()+2, t.begin()+1, t.begin()+3);

	/* CYBOZU_TEST_EQUAL(s, "あいbcうえお"); */
	String checked("\xE3\x81\x82\xE3\x81\x84" "bc" "\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	CYBOZU_TEST_EQUAL(s, checked);
}
// NOT EQUAL CASE
CYBOZU_TEST_AUTO(string_util_test_not_equal_cc)
{
	String t1("doragon");
	String t2("doragun");
	CYBOZU_TEST_ASSERT(t1 != t2);
}

CYBOZU_TEST_AUTO(string_util_test_not_equal_cs)
{
	String t1("doragon");
	std::string t2("doragun");
	CYBOZU_TEST_ASSERT(t1 != t2);
}

CYBOZU_TEST_AUTO(string_util_test_not_equal_cs2)
{
	String t1("doragon");
	const char t2[]="doragun";
	CYBOZU_TEST_ASSERT(t1 != t2);
}

CYBOZU_TEST_AUTO(string_util_test_not_equal_sc)
{
	std::string t1("doragon");
	String t2("doragun");
	CYBOZU_TEST_ASSERT(t1 != t2);
}

CYBOZU_TEST_AUTO(string_util_test_not_equal_sc2)
{
	const char t1[] ="doragon";
	String t2("doragun");
	CYBOZU_TEST_ASSERT(t1 != t2);
}


// < CASE
CYBOZU_TEST_AUTO(string_util_test_less_than_cc)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえを */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");

	CYBOZU_TEST_ASSERT(t1 < t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_cs)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえを */
	std::string t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");

	CYBOZU_TEST_ASSERT(t1 < t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_cs2)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえを */
	const char t2[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92";

	CYBOZU_TEST_ASSERT(t1 < t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_sc)
{
	/* あいうえお */
	std::string t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえを */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");

	CYBOZU_TEST_ASSERT(t1 < t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_sc2)
{
	/* あいうえお */
	const char t1[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";
	/* あいうえを */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");

	CYBOZU_TEST_ASSERT(t1 < t2);
}

// <= CASE
CYBOZU_TEST_AUTO(string_util_test_less_than_or_equal_cc)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえを */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");

	CYBOZU_TEST_ASSERT(t1 <= t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_or_equal_cs)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえを */
	std::string t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");

	CYBOZU_TEST_ASSERT(t1 <= t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_or_equal_cs2)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえを */
	const char t2[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92";

	CYBOZU_TEST_ASSERT(t1 <= t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_or_equal_sc)
{
	/* あいうえお */
	std::string t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえを */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");

	CYBOZU_TEST_ASSERT(t1 <= t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_or_equal_sc2)
{
	/* あいうえお */
	const char t1[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";
	/* あいうえを */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");

	CYBOZU_TEST_ASSERT(t1 <= t2);
}


// <= CASE
CYBOZU_TEST_AUTO(string_util_test_less_than_or_equal_cc_equal)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 <= t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_or_equal_cs_equal)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえお */
	std::string t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 <= t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_or_equal_cs2_equal)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえお */
	const char t2[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";

	CYBOZU_TEST_ASSERT(t1 <= t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_or_equal_sc_equal)
{
	/* あいうえお */
	std::string t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 <= t2);
}

CYBOZU_TEST_AUTO(string_util_test_less_than_or_equal_sc2_equal)
{
	/* あいうえお */
	const char t1[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 <= t2);
}


/////////////////////
// > CASE
/////////////////////

CYBOZU_TEST_AUTO(string_util_test_greater_than_cc)
{
	/* あいうえを */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 > t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_cs)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえを */
	std::string t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");

	CYBOZU_TEST_ASSERT(t1 < t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_cs2)
{
	/* あいうえを */
	const char t1[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92";
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 > t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_sc)
{
	/* あいうえを */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");
	/* あいうえお */
	std::string t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 > t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_sc2)
{
	/* あいうえを */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");
	/* あいうえお */
	const char t2[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";

	CYBOZU_TEST_ASSERT(t1 > t2);
}

// >= CASE
CYBOZU_TEST_AUTO(string_util_test_greater_than_or_equal_cc)
{
	/* あいうえを */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 >= t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_or_equal_cs)
{

	/* あいうえを */
	std::string t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 >= t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_or_equal_cs2)
{
	/* あいうえを */
	const char t1[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92";
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 >= t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_or_equal_sc)
{
	/* あいうえを */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");
	/* あいうえお */
	std::string t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 >= t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_or_equal_sc2)
{
	/* あいうえを */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x82\x92");
	/* あいうえお */
	const char t2[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";

	CYBOZU_TEST_ASSERT(t1 >= t2);
}


// >= CASE
CYBOZU_TEST_AUTO(string_util_test_greater_than_or_equal_cc_equal)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 >= t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_or_equal_cs_equal)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえお */
	std::string t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 >= t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_or_equal_cs2_equal)
{
	/* あいうえお */
	String t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえお */
	const char t2[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";

	CYBOZU_TEST_ASSERT(t1 >= t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_or_equal_sc_equal)
{
	/* あいうえお */
	std::string t1("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 >= t2);
}

CYBOZU_TEST_AUTO(string_util_test_greater_than_or_equal_sc2_equal)
{
	/* あいうえお */
	const char t1[] ="\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A";
	/* あいうえお */
	String t2("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86\xE3\x81\x88\xE3\x81\x8A");

	CYBOZU_TEST_ASSERT(t1 >= t2);
}

///////// replace
/////// String

// replace [off, off + n) with rhs
CYBOZU_TEST_AUTO(string_replace_test_cybozu_string)
{
	/* String s("いろはにほへと"); */
	String s("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	String t("ABCDEFGHIJ");
	s.replace(2, 3, t);
	String checked("\xE3\x81\x84\xE3\x82\x8D" "ABCDEFGHIJ" "\xE3\x81\xB8\xE3\x81\xA8");
	/* CYBOZU_TEST_EQUAL(s, "いろABCDEFGHIJへと"); */
	CYBOZU_TEST_EQUAL(s, checked);
}

// replace [off, off + n) with rhs [rhsOff, rhsOff + count)
CYBOZU_TEST_AUTO(string_replace_test_cybozu_substring)
{
	/* String s("いろはにほへと"); */
	String s("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	String t("ABCDEFGHIJ");
	s.replace(2, 3, t, 3, 2);
	/* CYBOZU_TEST_EQUAL(s, "いろDEへと"); */
	String checked("\xE3\x81\x84\xE3\x82\x8D" "DE" "\xE3\x81\xB8\xE3\x81\xA8");
	CYBOZU_TEST_EQUAL(s, checked);
}

/////// Char[]
CYBOZU_TEST_AUTO(string_replace_test_cybozu_char_array)
{
	/* String s("いろはにほへと"); */
	String s("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	Char c[]={'A','B','C','D','E','F', 0};
	s.replace(3, 3, c, 4);
	/* CYBOZU_TEST_EQUAL(s, "いろはABCDと"); */
	String checked("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF" "ABCD" "\xE3\x81\xA8");
	CYBOZU_TEST_EQUAL(s, checked);
}

// replace [off, off + n) with [str, <null>)
CYBOZU_TEST_AUTO(string_replace_test_cybozu_char_array_zero)
{
	/* String s("いろはにほへと"); */
	String s("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	Char c[]={'A','B','C','D','E','F', 0};
	s.replace(3, 3, c);
	/* CYBOZU_TEST_EQUAL(s, "いろはABCDEFと"); */
	String checked("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF" "ABCDEF" "\xE3\x81\xA8");
	CYBOZU_TEST_EQUAL(s, checked);
}

// replace [off, off + n) with count * c
CYBOZU_TEST_AUTO(string_replace_test_cybozu_multiple_chars)
{
	/* String s("いろはにほへと"); */
	String s("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB\xE3\x81\xBB\xE3\x81\xB8\xE3\x81\xA8");
	Char c = 'W';
	s.replace(4, 2, 3, c);
	/* CYBOZU_TEST_EQUAL(s, "いろはにWWWと"); */
	String checked("\xE3\x81\x84\xE3\x82\x8D\xE3\x81\xAF\xE3\x81\xAB"
				   "WWW" "\xE3\x81\xA8");
	CYBOZU_TEST_EQUAL(s, checked);
}

/////// Iterator

// replace [begin, end) with rhs
CYBOZU_TEST_AUTO(string_replace_iterator)
{
	/* String s("わかよたれそ"); */
	String s("\xE3\x82\x8F\xE3\x81\x8B\xE3\x82\x88\xE3\x81\x9F\xE3\x82\x8C\xE3\x81\x9D");
	String t("abcdef");
	s.replace(s.begin()+1, s.end()-1, t);
	/* CYBOZU_TEST_EQUAL(s, "わabcdefそ"); */
	String checked("\xE3\x82\x8F" "abcdef" "\xE3\x81\x9D");
	CYBOZU_TEST_EQUAL(s, checked);
}

// replace [begin, end) with [str, str + count)
CYBOZU_TEST_AUTO(string_replace_iterator_cybozu_char_array)
{
	/* String s("わかよたれそ"); */
	String s("\xE3\x82\x8F\xE3\x81\x8B\xE3\x82\x88\xE3\x81\x9F\xE3\x82\x8C\xE3\x81\x9D");
	const Char t[] = {'A','B','C','D','E'};
	s.replace(s.begin()+1, s.end()-1, t, 3);
	/* CYBOZU_TEST_EQUAL( s, "わABCそ"); */
	String checked("\xE3\x82\x8F" "ABC" "\xE3\x81\x9D");
	CYBOZU_TEST_EQUAL(s, checked);
}

CYBOZU_TEST_AUTO(string_replace_iterator_cybozu_char_array_zero)
{
	/* String s("わかよたれそ"); */
	String s("\xE3\x82\x8F\xE3\x81\x8B\xE3\x82\x88\xE3\x81\x9F\xE3\x82\x8C\xE3\x81\x9D");
	const Char t[] = {'A','B','C','D','E', 0};
	s.replace(s.begin()+1, s.end()-1, t);
	/* CYBOZU_TEST_EQUAL( s, "わABCDEそ"); */
	String checked("\xE3\x82\x8F" "ABCDE" "\xE3\x81\x9D");
	CYBOZU_TEST_EQUAL(s, checked);
}

//replace [begin, end) with count * c
CYBOZU_TEST_AUTO(string_replace_iterator_cybozu_multiple_chars)
{
	/* String s("つねならん"); */
	String s("\xE3\x81\xA4\xE3\x81\xAD\xE3\x81\xAA\xE3\x82\x89\xE3\x82\x93");
	const Char c = 'N';
	s.replace(s.begin()+2, s.end()-2, 3, c);
	/* "つねNNNらん" */
	String checked("\xE3\x81\xA4\xE3\x81\xAD" "NNN" "\xE3\x82\x89\xE3\x82\x93");
	CYBOZU_TEST_EQUAL(s, checked);
}

// replace [begin, end) with [begin2, end2)
CYBOZU_TEST_AUTO(string_replace_iterator_iterator)
{
	/* String s("つねならん"); */
	String s("\xE3\x81\xA4\xE3\x81\xAD\xE3\x81\xAA\xE3\x82\x89\xE3\x82\x93");
	/* String t("ならのおくやま"); */
	String t("\xE3\x81\xAA\xE3\x82\x89\xE3\x81\xAE\xE3\x81\x8A\xE3\x81\x8F\xE3\x82\x84\xE3\x81\xBE");

	s.replace(s.begin()+2, s.end()-2, t.begin()+1, t.end()-1);
	/* CYBOZU_TEST_EQUAL( s, "つねらのおくやらん"); */
	String checked("\xE3\x81\xA4\xE3\x81\xAD\xE3\x82\x89\xE3\x81\xAE\xE3\x81\x8A\xE3\x81\x8F\xE3\x82\x84\xE3\x82\x89\xE3\x82\x93");
	CYBOZU_TEST_EQUAL(s, checked);
}

///////// size

// return length of sequence
CYBOZU_TEST_AUTO(string_size_test_size)
{
	String s("aiueo");
	CYBOZU_TEST_EQUAL(s.size(), 5);
}

// return length of sequence
CYBOZU_TEST_AUTO(string_size_test_length)
{
	String s("aiueo");
	CYBOZU_TEST_EQUAL(s.length(), 5);
}

// return maximum possible length of sequence
CYBOZU_TEST_AUTO(string_size_test_max_size)
{
	String s("aiueo");
	CYBOZU_TEST_ASSERT(s.max_size() >= s.length());
}

// determine new length, padding with null elements as needed
CYBOZU_TEST_AUTO(string_size_test_resize_null)
{
	String s1("aiueo");
	s1.resize(10);
	CYBOZU_TEST_EQUAL(s1.length(), 10);

	String t("aiueo");
	t.resize(2);
	CYBOZU_TEST_EQUAL(t, "ai");
}

// determine new length, padding with c elements as needed
CYBOZU_TEST_AUTO(string_size_test_resize_padding)
{
	String s1("aiueo");
	s1.resize(10, 'C');
	CYBOZU_TEST_EQUAL(s1.length(), 10);
	CYBOZU_TEST_EQUAL(s1, "aiueoCCCCC");
}

// return current length of allocated storage
CYBOZU_TEST_AUTO(string_size_test_capacity)
{
	String s1("aiueo");
	CYBOZU_TEST_ASSERT(s1.capacity() < s1.max_size());
	s1.reserve(100);
	CYBOZU_TEST_ASSERT(s1.capacity() >= 100);
}

// test if sequence is empty
CYBOZU_TEST_AUTO(string_size_test_empty)
{
	String s1;
	CYBOZU_TEST_ASSERT(s1.empty());
}

CYBOZU_TEST_AUTO(utf16)
{
	// abc a-i-u-
	const cybozu::Char16 utf16[6] = { 0x61, 0x62, 0x63, 0x3042, 0x3044, 0x3046 };
	const char utf8[12] = { 0x61, 0x62, 0x63, (char)0xE3, (char)0x81, (char)0x82, (char)0xE3, (char)0x81, (char)0x84, (char)0xE3, (char)0x81, (char)0x86 };
	cybozu::String16 s;
	cybozu::ConvertUtf8ToUtf16(&s, utf8, utf8 + 12);
	CYBOZU_TEST_EQUAL(s.size(), 6u);
	for (int i = 0; i < 6; i++) {
		CYBOZU_TEST_ASSERT(s[i] == utf16[i]);
	}
	std::string t;
	cybozu::ConvertUtf16ToUtf8(&t, utf16, utf16 + 6);
	CYBOZU_TEST_EQUAL(t.size(), 12u);
	for (int i = 0; i < 12; i++) {
		CYBOZU_TEST_EQUAL(t[i], utf8[i]);
	}
}

CYBOZU_TEST_AUTO(Utf8ref)
{
	const std::string utf8 = "\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1";
	const String s(utf8);
	cybozu::Utf8refT<std::string::const_iterator> ref(utf8.begin(), utf8.end());
	cybozu::Char c;
	size_t i = 0;
	while (ref.next(&c)) {
		CYBOZU_TEST_ASSERT(c == s[i]);
		i++;
	}
	CYBOZU_TEST_EQUAL(i, s.size());
}

CYBOZU_TEST_AUTO(Utf8ref_bad_char)
{
	const std::string utf8 = "\xe3\x81\x93\xe3";
	const String s(utf8.c_str(), 3);
	cybozu::Utf8ref ref(utf8.c_str(), utf8.size());
	cybozu::Char c;
	CYBOZU_TEST_ASSERT(ref.next(&c));
	CYBOZU_TEST_ASSERT(s[0] == c);
	CYBOZU_TEST_EXCEPTION(ref.next(&c), std::exception);
}

CYBOZU_TEST_AUTO(Utf8ref_ignore_bad_char)
{
	const std::string badUtf8 = "\xe3\x81\x93\xff\xff\xff\xe3\x82\x8c\xff\xff\xe3\x81\xaf" "UTF-8 1";
	const String s("\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf" "UTF-8 1");
	cybozu::Utf8refT<std::string::const_iterator> ref(badUtf8.begin(), badUtf8.end(), true);
	cybozu::Char c;
	size_t i = 0;
	while (ref.next(&c)) {
		CYBOZU_TEST_ASSERT(c == s[i]);
		i++;
	}
	CYBOZU_TEST_EQUAL(i, s.size());
}

CYBOZU_TEST_AUTO(equal)
{
	const cybozu::String a = "abc";
	const std::string b = "abc";
	const char *c = "abc";
	const cybozu::Char d[] = { 'a', 'b', 'c', '\0' };
	CYBOZU_TEST_EQUAL(a, a);
	CYBOZU_TEST_EQUAL(a, b);
	CYBOZU_TEST_EQUAL(a, c);
	CYBOZU_TEST_ASSERT(a == d);

	CYBOZU_TEST_EQUAL(b, a);
	CYBOZU_TEST_EQUAL(c, a);
	CYBOZU_TEST_ASSERT(d == a);

	CYBOZU_TEST_ASSERT(!(a != a));
	CYBOZU_TEST_ASSERT(!(a != b));
	CYBOZU_TEST_ASSERT(!(a != c));
	CYBOZU_TEST_ASSERT(!(a != d));

	CYBOZU_TEST_ASSERT(!(b != a));
	CYBOZU_TEST_ASSERT(!(c != a));
	CYBOZU_TEST_ASSERT(!(d != a));
#ifdef _MSC_VER
	const wchar_t e[] = L"abc";
	CYBOZU_TEST_ASSERT(a == e);
	CYBOZU_TEST_ASSERT(e == a);
	CYBOZU_TEST_ASSERT(!(a != e));
	CYBOZU_TEST_ASSERT(!(e != a));
#endif
}

CYBOZU_TEST_AUTO(less)
{
	const cybozu::String a = "ab";
	const std::string b = "abc";
	const char *c = "abc";
	const cybozu::Char d[] = { 'a', 'b', 'c', '\0' };
	CYBOZU_TEST_ASSERT(a < b);
	CYBOZU_TEST_ASSERT(a < c);
	CYBOZU_TEST_ASSERT(a < d);

	CYBOZU_TEST_ASSERT(a <= b);
	CYBOZU_TEST_ASSERT(a <= c);
	CYBOZU_TEST_ASSERT(a <= d);

	CYBOZU_TEST_ASSERT(b > a);
	CYBOZU_TEST_ASSERT(c > a);
	CYBOZU_TEST_ASSERT(d > a);

	CYBOZU_TEST_ASSERT(b >= a);
	CYBOZU_TEST_ASSERT(c >= a);
	CYBOZU_TEST_ASSERT(d >= a);
#ifdef _MSC_VER
	const wchar_t e[] = L"abc";
	CYBOZU_TEST_ASSERT(a < e);
	CYBOZU_TEST_ASSERT(a <= e);
	CYBOZU_TEST_ASSERT(e > a);
	CYBOZU_TEST_ASSERT(e >= a);
#endif
}

CYBOZU_TEST_AUTO(greater)
{
	const cybozu::String a = "abcd";
	const std::string b = "abc";
	const char *c = "abc";
	const cybozu::Char d[] = { 'a', 'b', 'c', '\0' };
	CYBOZU_TEST_ASSERT(a > b);
	CYBOZU_TEST_ASSERT(a > c);
	CYBOZU_TEST_ASSERT(a > d);

	CYBOZU_TEST_ASSERT(a >= b);
	CYBOZU_TEST_ASSERT(a >= c);
	CYBOZU_TEST_ASSERT(a >= d);

	CYBOZU_TEST_ASSERT(b < a);
	CYBOZU_TEST_ASSERT(c < a);
	CYBOZU_TEST_ASSERT(d < a);

	CYBOZU_TEST_ASSERT(b <= a);
	CYBOZU_TEST_ASSERT(c <= a);
	CYBOZU_TEST_ASSERT(d <= a);
#ifdef _MSC_VER
	const wchar_t e[] = L"abc";
	CYBOZU_TEST_ASSERT(a > e);
	CYBOZU_TEST_ASSERT(a >= e);
	CYBOZU_TEST_ASSERT(e < a);
	CYBOZU_TEST_ASSERT(e <= a);
#endif
}

#if CYBOZU_CPP_VERSION == CYBOZU_CPP_VERSION_CPP11
CYBOZU_TEST_AUTO(move)
{
	cybozu::String a, b;
	b = "abc";
	a = b;
	CYBOZU_TEST_EQUAL(a, "abc");
	CYBOZU_TEST_EQUAL(a, b);
	a = "123";
	a = std::move(b);
	CYBOZU_TEST_EQUAL(a, "abc");
	a.pop_back();
	CYBOZU_TEST_EQUAL(a, "ab");
}
#endif

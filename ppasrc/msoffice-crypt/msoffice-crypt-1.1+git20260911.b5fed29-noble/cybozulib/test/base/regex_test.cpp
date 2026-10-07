#ifdef _MSC_VER
	#pragma warning(disable : 4566)
#endif
/*
	don't remove BOM(EF BB BF) for VC
	現状の制約
	UTF-8のリテラルを書きたいときはBOMつきのUTF-8で保存。文字列はCYBOZU_RE()でくるむ
	VCでは/MT, /MTdでビルドしないとリンクエラーになる
	gccでは-lboost_regexが必要

	非対応なもの
	...
*/
#include <string>
#include <stdio.h>
#include <cybozu/test.hpp>
#include <cybozu/regex.hpp>

CYBOZU_TEST_AUTO(regex_search)
{
	cybozu::String str(CYBOZU_RE("こんにちはUTF-8です ゔ♡"));
	for (size_t i = 0; i < str.size(); i++) {
		printf("%04x ", str[i]);
	}
	printf("\n");

//	cybozu::regex r("[a-zA-Z]+");
	cybozu::regex r("\\w+");
	cybozu::smatch m;
	bool b = cybozu::regex_search(str, m, r);
	CYBOZU_TEST_ASSERT(b);
	CYBOZU_TEST_EQUAL(m.str(), "UTF");
	CYBOZU_TEST_EQUAL(m.prefix().str(), CYBOZU_RE("こんにちは"));
	CYBOZU_TEST_EQUAL(m.suffix().str(), CYBOZU_RE("-8です ゔ♡"));
	CYBOZU_TEST_EQUAL((int)m.position(), 5);
}

CYBOZU_TEST_AUTO(regex_token_iterator)
{
	cybozu::String data(CYBOZU_RE("あいうえおあああかきいあいくけこいいう"));
	cybozu::regex r(CYBOZU_RE("[あ-う]+"));
	cybozu::sregex_token_iterator i(data.begin(), data.end(), r);
	cybozu::sregex_token_iterator iend;

	const cybozu::String tbl[] = {
		CYBOZU_RE("あいう"),
		CYBOZU_RE("あああ"),
		CYBOZU_RE("いあい"),
		CYBOZU_RE("いいう"),
	};
	size_t pos = 0;
	while (i != iend) {
		cybozu::String s = *i++;
		CYBOZU_TEST_EQUAL(s, tbl[pos]);
		pos++;
	}
	CYBOZU_TEST_EQUAL(pos, CYBOZU_NUM_OF_ARRAY(tbl));
}

CYBOZU_TEST_AUTO(regex_replace)
{
	const cybozu::String s(CYBOZU_RE("サイボウズらららだ"));
	cybozu::regex r(CYBOZU_RE("ら+"));
	cybozu::String t = cybozu::regex_replace(s, r, CYBOZU_RE("live"));
	CYBOZU_TEST_EQUAL(t, CYBOZU_RE("サイボウズliveだ"));
}

CYBOZU_TEST_AUTO(regex_replace2)
{
	const cybozu::String s(CYBOZU_RE("cybozu Cybozu CYBOZU 坊主"));
	cybozu::regex r(CYBOZU_RE("cybozu|坊主"), cybozu::regex_constants::icase);
	cybozu::String t = cybozu::regex_replace(s, r, CYBOZU_RE("サイボウズ"));
	CYBOZU_TEST_EQUAL(t, CYBOZU_RE("サイボウズ サイボウズ サイボウズ サイボウズ"));
}

#include <stdio.h>
#include <iostream>
#include <cybozu/nlp/mecab.hpp>
#include <cybozu/test.hpp>

CYBOZU_TEST_AUTO(mecab)
{
	const char *const str =
		"\xE5\xA4\xAA" "\xE9\x83\x8E" "\xE3\x81\xAF" // 0:taro-wa
		"\xE7\xA7\x81" "\xE3\x81\xA8" // 9:watashi-to
		"\xE6\xAC\xA1" "\xE9\x83\x8E" "\xE3\x81\x8C" // 15:jiro-ga
		"\xE6\x8C\x81" "\xE3\x81\xA3" "\xE3\x81\xA6" // 24:mo-tte
		"\xE3\x81\x84" "\xE3\x82\x8B" // 33:iru
		"\xE6\x9C\xAC" "\xE3\x82\x92" // 39:hon-wo
		"\xE8\x8A\xB1" "\xE5\xAD\x90" "\xE3\x81\xAB" // 45:hanako-ni
		"\xE6\xB8\xA1" "\xE3\x81\x97" "\xE3\x81\x9F"; // 54:watashi-ta

	cybozu::nlp::Mecab mecab;
	mecab.set(str);
	const struct {
		int pos;
		size_t len;
	} nounTbl[] = {
		{ 0, 6 },
		{ 9, 3 },
		{ 15, 6 },
		{ 39, 3 },
		{ 45, 3 },
		{ 48, 3 },
	};
	size_t i = 0;
	while (!mecab.isEnd()) {
		if (mecab.isNoun()) {
			CYBOZU_TEST_EQUAL_POINTER(mecab.getPos(), str + nounTbl[i].pos);
			CYBOZU_TEST_EQUAL(mecab.getSize(), nounTbl[i].len);
			i++;
		}
		mecab.next();
	}
	CYBOZU_TEST_EQUAL(i, CYBOZU_NUM_OF_ARRAY(nounTbl));
}

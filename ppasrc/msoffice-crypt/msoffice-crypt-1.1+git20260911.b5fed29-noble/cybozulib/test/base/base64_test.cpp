#include <cybozu/test.hpp>
#include <cybozu/base64.hpp>
#include <string>

CYBOZU_TEST_AUTO(base64)
{
	const struct {
		std::string in;
		std::string out;
		size_t maxLineSize;
	} tbl[] = {
		{ "", "", 76 },
		{ "1", "MQ==\r\n", 8 },
		{ "12", "MTI=\r\n", 8 },
		{ "123", "MTIz\r\n", 8 },
		{ "1234", "MTIzNA==\r\n", 8 },
		{ "12345", "MTIzNDU=\r\n", 8 },
		{ "123456", "MTIzNDU2\r\n", 8 },
		{ "1234567", "MTIzNDU2\r\nNw==\r\n", 8 },
		{ "12345678", "MTIzNDU2\r\nNzg=\r\n", 8 },
		{ "123456789", "MTIzNDU2\r\nNzg5\r\n", 8 },
		{ "123456789a", "MTIzNDU2\r\nNzg5YQ==\r\n", 8 },
		{ "123456789ab", "MTIzNDU2\r\nNzg5YWI=\r\n", 8 },
		{ "123456789abc", "MTIzNDU2\r\nNzg5YWJj\r\n", 8 },
		{ "123456789abcd", "MTIzNDU2\r\nNzg5YWJj\r\nZA==\r\n", 8 },

		{ "1", "MQ==", 0 },
		{ "12", "MTI=", 0 },
		{ "123", "MTIz", 0 },
		{ "1234", "MTIzNA==", 0 },
		{ "12345", "MTIzNDU=", 0 },
		{ "123456", "MTIzNDU2", 0 },
		{ "1234567", "MTIzNDU2Nw==", 0 },
		{ "12345678", "MTIzNDU2Nzg=", 0 },
		{ "123456789", "MTIzNDU2Nzg5", 0 },
		{ "123456789a", "MTIzNDU2Nzg5YQ==", 0 },
		{ "123456789ab", "MTIzNDU2Nzg5YWI=", 0 },
		{ "123456789abc", "MTIzNDU2Nzg5YWJj", 0 },
		{ "123456789abcd", "MTIzNDU2Nzg5YWJjZA==", 0 },

		{ "123456789012345678901234567890123456789012345678901234567",
		  "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3\r\n", 76 },
		{ "123456789012345678901234567890123456789012345678901234567"
		  "890123456789012345678901234567890123456789012345678901234"
		  "567890123456789012345678901234567890123456789012345678901"
		  "23456789012345678901234567890",
		  "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3\r\n"
		  "ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0\r\n"
		  "NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx\r\n"
		  "MjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=\r\n", 76},
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		cybozu::StringInputStream is(tbl[i].in);
		std::string str;
		cybozu::StringOutputStream os(str);
		cybozu::EncodeToBase64(os, is, tbl[i].maxLineSize);
		CYBOZU_TEST_EQUAL(str.size(), tbl[i].out.size());
		CYBOZU_TEST_EQUAL(str, tbl[i].out);
	}

	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		cybozu::StringInputStream is(tbl[i].out);
		std::string str;
		cybozu::StringOutputStream os(str);
		cybozu::DecodeFromBase64(os, is);
		CYBOZU_TEST_EQUAL(str.size(), tbl[i].in.size());
		CYBOZU_TEST_EQUAL(str, tbl[i].in);
	}
}

CYBOZU_TEST_AUTO(decodeSkip)
{
	const struct {
		std::string in;
		std::string out;
	} tbl[] = {
		{ "123456789a", "MTIzNDU2\r\n$$Nz%%~~!!g5YQ==\r\n" },
		{ "123456789ab", "MTIzNDU>>2<<\r\nNzg5YWI=!!\r\n" },

		{ "123", "MTIz" },
		{ "1234", "MT	I z NA==" },
		{ "12345", "MTIzNDU=" },
		{ "123456", "MTIzNDU2" },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		cybozu::StringInputStream is(tbl[i].out);
		std::string str;
		cybozu::StringOutputStream os(str);
		cybozu::DecodeFromBase64(os, is);
		CYBOZU_TEST_EQUAL(str.size(), tbl[i].in.size());
		CYBOZU_TEST_EQUAL(str, tbl[i].in);
	}
}

CYBOZU_TEST_AUTO(ignoreAllEqual)
{
	/* we verify the number of '=' */
	const struct {
		std::string in;
		std::string out;
	} tbl[] = {
		{ "123", "M=T===Iz=" },
		{ "123", "M====TIz==" },
		{ "123", "MT===Iz===" },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		cybozu::StringInputStream is(tbl[i].out);
		std::string str;
		cybozu::StringOutputStream os(str);
		cybozu::DecodeFromBase64(os, is);
		CYBOZU_TEST_EQUAL(str, tbl[i].in);
	}
}

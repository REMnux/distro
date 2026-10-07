#include <sstream>
#include <cybozu/test.hpp>
#include <cybozu/config.hpp>
#include <fstream>
#include <string.h>
#include <assert.h>

CYBOZU_TEST_AUTO(isName)
{
	static const struct {
		const char *str;
		bool valid;
		char badChar;
	} tbl[] = {
		{ "", true, 0 },
		{ "abc", true, 0 },
		{ "abc$", false, '$' },
		{ "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_", true, 0 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		char badChar = 0;
		CYBOZU_TEST_EQUAL(cybozu::config_local::isName(tbl[i].str, &badChar), tbl[i].valid);
		if (!tbl[i].valid) {
			CYBOZU_TEST_EQUAL(badChar, tbl[i].badChar);
		}
	}
}

CYBOZU_TEST_AUTO(split)
{
	static const struct {
		const char *org;
		const char *key;
		const char *value;
	} tbl[] = {
		{ "abc=def", "abc", "def" },
		{ "abc==def", "abc", "=def" },
		{ "abc=", "abc", "" },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string key;
		std::string value;
		cybozu::config_local::split(key, value, tbl[i].org);
		CYBOZU_TEST_EQUAL(key, tbl[i].key);
		CYBOZU_TEST_EQUAL(value, tbl[i].value);
	}
}

CYBOZU_TEST_AUTO(load)
{
	const size_t N = 10;
	struct Pair {
		const char *key;
		const char *value;
	};
	struct SectionTbl {
		const char *sectionName;
		Pair pairTbl[N];
	};
	struct Tbl {
		std::string config;
		const char *msg;
		SectionTbl sectionTbl[N];
		std::string toString;
		std::string sectionName[3];
	};
	static const Tbl tbl[] = {
		{
			"key=111\r\n[aaa]\r\nkey=val",
			0,
			{
				{
					"",
					{
						{ "key", "111" },
					},
				},
				{
					"aaa",
					{
						{ "key", "val" },
					},
				},
			},
			"key=111\n[aaa]\nkey=val\n",
			{ "", "aaa" },
		},
		{
			"[sec1]\nk1= aaa   \r\n;asdfa\n;asdfads\r\n[sec2]\nccc=ddd\n[sec1]\nk2=bbb",
			0,
			{
				{
					"sec1",
					{
						{ "k1", " aaa   " },
						{ "k2", "bbb" },
					},
				},
				{
					"sec2",
					{
						{ "ccc", "ddd" },
					},
				},
			},
			"[sec1]\nk1= aaa   \nk2=bbb\n[sec2]\nccc=ddd\n",
			{ "sec1", "sec2" },
		},
		// ok
		{
			"",
			0,
			{}, "", {},
		},
		{
			";asdfasdfa",
			0,
			{}, "", {},
		},
		{
			"\n\r\n\n",
			0,
			{}, "", {},
		},
		{
			"key	=111",
			0,
			{
				{
					"",
					{
						{ "key", "111" },
					},
				},
			},
			"key=111\n",
			{ "" },
		},
		// error
		{
			"key=111\r\nkey=123\r\n",
			"key already exists",
			{}, "", {},
		},
		{
			"[sec1]\r\nkey=111\r\n[sec2]\r\naaa=ccc\r\n[sec1]\r\nkey=222",
			"key already exists",
			{}, "", {},
		},
		{
			"[asdf sd]",
			"bad section",
			{}, "", {},
		},
		{
			"[asdf",
			"bad section",
			{}, "", {},
		},
		{
			" key=111",
			"bad key",
			{}, "", {},
		},
		{
			"key123",
			"no equal",
			{}, "", {},
		},
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		const Tbl& t = tbl[i];
		cybozu::Config config;
		if (t.msg) {
			std::istringstream is(std::string(t.config));
			CYBOZU_TEST_EXCEPTION_MESSAGE(config.load(is), cybozu::Exception, t.msg);
		} else {
			std::istringstream is(std::string(t.config));
			config.load(is);
			CYBOZU_TEST_EQUAL(config.toString(), t.toString);
			for (size_t j = 0; j < N; j++) {
				const SectionTbl& sectionTbl = t.sectionTbl[j];
				if (sectionTbl.sectionName == 0) break;
				CYBOZU_TEST_EQUAL(sectionTbl.sectionName, t.sectionName[j]);
				const cybozu::Config::Section *section = static_cast<const cybozu::Config&>(config).querySection(sectionTbl.sectionName);
				assert(section);
				for (size_t k = 0; k < N; k++) {
					const char *key = sectionTbl.pairTbl[k].key;
					const char *value = sectionTbl.pairTbl[k].value;
					if (key == 0) break;
					CYBOZU_TEST_EQUAL(*section->queryValue(key), value);
				}
			}
		}
	}
}

CYBOZU_TEST_AUTO(append)
{
	cybozu::Config config;
	cybozu::Config::Section *section = config.appendSection("section");
	section->append("key", "value");
	section->append("key2", "value2");
	CYBOZU_TEST_EQUAL(config.toString(), "[section]\nkey=value\nkey2=value2\n");
	section->append("val", "123");
	int a = section->getValue("val");
	CYBOZU_TEST_EQUAL(a, 123);
	std::string b = section->getValue("val");
	CYBOZU_TEST_EQUAL(b, "123");
	uint64_t c = section->getValue("val");
	CYBOZU_TEST_EQUAL(c, 123u);
}

CYBOZU_TEST_AUTO(trim)
{
	static const struct {
		const char *in;
		const char *out;
	} tbl[] = {
		{ "", "" },
		{ "		 ", "" },
		{ "abc", "abc" },
		{ "a", "a" },
		{ "abc ", "abc" },
		{ "abc  ", "abc" },
		{ "abc	  ", "abc" },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string in = tbl[i].in;
		std::string out = tbl[i].out;
		std::string ret = in;
		cybozu::config_local::trimEndSpace(ret);
		CYBOZU_TEST_EQUAL(ret.size(), out.size());
		CYBOZU_TEST_EQUAL(ret, out);
	}
}

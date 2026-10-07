/*
	don't remove the top of BOM for VC
*/
#include <cybozu/test.hpp>
#include <cybozu/fmindex.hpp>
#include <cybozu/file.hpp>
#include <cybozu/mmap.hpp>
#include <cybozu/string.hpp>
#include <set>

typedef std::set<int> Set;

std::string g_textTbl[] = {
	"",
	"abracatabra",
	"cybozuabcabcintint}}",
};

struct Init {
	Init()
	{
		std::string path = cybozu::GetExePath();
		size_t pos = path.find("cybozulib");
		CYBOZU_TEST_ASSERT(pos != std::string::npos);
		path = path.substr(0, pos + 9) + "/include/cybozu/fmindex.hpp";
		cybozu::Mmap mmap(path);
		g_textTbl[0].assign(mmap.get(), (size_t)mmap.size());
	}
} init;

//	f.getPrevString(out, 0, f.wm.size() - 1);

template<class FMINDEX, class STRING>
Set searchPos1(const FMINDEX& f, const STRING& key)
{
	Set ret;
	size_t begin, end = 0;
	if (f.getRange(&begin, &end, key)) {
		while (begin != end) {
			ret.insert((int)f.convertPosition(begin));
			++begin;
		}
	}
	return ret;
}

// standard search
template<class STRING>
Set searchPos2(const STRING& text, const STRING& key)
{
	Set ret;
	size_t pos = 0;
	for (;;) {
		size_t q = text.find(key, pos);
		if (q == std::string::npos) break;
		ret.insert((int)q);
		pos = q + 1;
	}
	return ret;
}

template<class FMINDEX, class STRING>
void compareText(const FMINDEX& f, const STRING& text, const STRING *keyTbl, size_t keySize)
{
	for (size_t i = 0; i < keySize; i++) {
		const STRING& key = keyTbl[i];
		Set a = searchPos1(f, key);
		Set b = searchPos2(text, key);
		CYBOZU_TEST_EQUAL(a.size(), b.size());
		if (a.size() == b.size()) {
			size_t pos = 0;
			for (Set::const_iterator ia = a.begin(), ib = b.begin(); pos < a.size(); ++ia, ++ib, ++pos) {
				CYBOZU_TEST_EQUAL(*ia, *ib);
			}
		}
	}
	// recover string
	STRING org;
	f.getPrevString(org, 0, f.wm.size() - 1);
	CYBOZU_TEST_EQUAL(org.size(), text.size());
	CYBOZU_TEST_ASSERT(org == text);
}

template<class FMINDEX, class STRING>
void searchTest(const STRING& text, const STRING *keyTbl, size_t keySize)
{
	FMINDEX f;
	f.init(text.begin(), text.end());
	compareText(f, text, keyTbl, keySize);
	std::stringstream ss;
	f.save(ss);
	{
		FMINDEX ff;
		ff.load(ss);
		compareText(ff, text, keyTbl, keySize);
	}
}

CYBOZU_TEST_AUTO(string)
{
	static const std::string tbl[] = {
		"double", "int", "cybozu", "std", "}", "\t", "xxx",
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(g_textTbl); i++) {
		searchTest<cybozu::FMindex, std::string>(g_textTbl[i], tbl, CYBOZU_NUM_OF_ARRAY(tbl));
	}
}

CYBOZU_TEST_AUTO(wstring)
{
	static const cybozu::String text(CYBOZU_STR_W("あいうえおabcあいうえおaaabあああうえabうえあいう"));
	static const cybozu::String tbl[] = {
		CYBOZU_STR_W("あいう"),
		CYBOZU_STR_W("ab"),
		CYBOZU_STR_W("うえ"),
	};
	searchTest<cybozu::FMindexT<cybozu::Char>, cybozu::String>(text, tbl, CYBOZU_NUM_OF_ARRAY(tbl));
}

#include <fstream>
#include <cybozu/time.hpp>
#include <cybozu/fmindex.hpp>
#include <cybozu/mmap.hpp>
#include <cybozu/string.hpp>
#include <cybozu/hash.hpp>
#include <cybozu/benchmark.hpp>
#include <set>

#ifdef USE_UTF32
typedef cybozu::FMindexT<cybozu::Char> FMindex;
typedef cybozu::String String;
#else
typedef cybozu::FMindex FMindex;
typedef std::string String;
#endif

typedef std::set<int> Set;

void putSet(const Set& set)
{
	for (Set::const_iterator i = set.begin(), ie = set.end(); i != ie; ++i) {
		std::cout << *i << ' ';
	}
	std::cout << std::endl;
}

template<class STRING>
void simpleSearch(const std::string& inName, const std::string& queryFile, bool putHash)
{
	cybozu::Mmap m(inName);
	STRING text(m.get(), m.size());

	double beginTime = cybozu::GetCurrentTimeSec();

	std::ifstream qs(queryFile.c_str(), std::ios::binary);
	STRING key;
	uint64_t hash = 0;
	while (qs >> key) {
		if (!putHash) std::cout << "query " << key << std::endl;
		size_t p = 0;
		Set set;
		for (;;) {
			size_t q = text.find(key, p);
			if (q == std::string::npos) break;
			set.insert((int)q);
			p = q + 1;
		}
		if (putHash) {
			hash = cybozu::hash64(set.begin(), set.end(), hash);
		} else {
			putSet(set);
		}
	}
	if (putHash) printf("hash=%llx\n", (long long)hash);

	double endTime = cybozu::GetCurrentTimeSec();
	fprintf(stderr, "time: %gsec\n", endTime - beginTime);
}

template<class FMINDEX, class STRING>
void recover(const std::string& inName, const std::string& outName)
{
	std::ifstream is(inName.c_str(), std::ios::binary);
	FMINDEX f;
	f.load(is);

	double beginTime = cybozu::GetCurrentTimeSec();

	STRING str;
	f.getPrevString(str, 0, f.wm.size() - 1);
	double endTime = cybozu::GetCurrentTimeSec();
	fprintf(stderr, "time: %gsec\n", endTime - beginTime);
	std::ofstream os(outName.c_str(), std::ios::binary);
	os << str;
}

template<class FMINDEX, class STRING>
void search(const std::string& inName, const std::string& queryFile, bool putHash, bool bench)
{
	std::ifstream is(inName.c_str(), std::ios::binary);
	FMINDEX f;
	f.load(is);

	double beginTime = cybozu::GetCurrentTimeSec();

	std::ifstream qs(queryFile.c_str(), std::ios::binary);
	STRING key;
	uint64_t hash = 0;
	cybozu::CpuClock clkRange;
	cybozu::CpuClock clkPos;
	while (qs >> key) {
		if (!putHash) std::cout << "query " << key << std::endl;
		size_t begin, end = 0;
		if (bench) clkRange.begin();
		bool found = f.getRange(&begin, &end, key);
		if (bench) clkRange.end();
		Set set;
		if (found) {
			while (begin != end) {
				if (bench) clkPos.begin();
				int pos = (int)f.convertPosition(begin);
				if (bench) clkPos.end();
				set.insert(pos);
				begin++;
			}
		}
		if (putHash) {
			hash = cybozu::hash64(set.begin(), set.end(), hash);
		} else {
			putSet(set);
		}
	}
	if (putHash) printf("hash=%llx\n", (long long)hash);

	double endTime = cybozu::GetCurrentTimeSec();
	fprintf(stderr, "time: %gsec\n", endTime - beginTime);
	if (bench) {
		int rangeNum = (int)clkRange.getCount();
		int posNum = (int)clkPos.getCount();
		fprintf(stderr, "getRange %.2f(%d) pos %.2f(%d)\n", clkRange.getClock() / double(rangeNum), rangeNum, clkPos.getClock() / double(posNum), posNum);
	}
}

template<class FMINDEX, class STRING>
static void create(const std::string& inName, const std::string& outName, int skip)
{
	fprintf(stderr, "inName=%s, outName=%s, skip=%d\n", inName.c_str(), outName.c_str(), skip);

	double beginTime = cybozu::GetCurrentTimeSec();

	cybozu::Mmap m(inName);
	FMINDEX f;
	STRING text(m.get(), m.get() + m.size());
	f.init(text.begin(), text.end(), skip);

	double endTime = cybozu::GetCurrentTimeSec();
	fprintf(stderr, "create time %gsec\n", endTime - beginTime);
	std::ofstream os(outName.c_str(), std::ios::binary);
	f.save(os);
}

void usage()
{
	printf("fmindex_smpl.exe (-c|-s|-r|-ss) file1 file2 [-skip skip][-hash][-time]\n");
	printf(" -c : create index file\n");
	printf("  file1 : any UTF-8 string file\n");
	printf("  file2 : output index file\n");
	printf("  -skip skip : skip to sampling(default 8)\n");
	printf("  -hash : put position hash\n");
	printf("  -time : benchmark\n");
	printf(" -s : search mode\n");
	printf("  file1 : index file\n");
	printf("  file2 : query string file\n");
	printf(" -r : recover mode\n");
	printf("  file1 : index file\n");
	printf("  file2 : org index file\n");
	printf(" -ss: simple search\n");
	printf("  file1 : any UTF-8 string file\n");
	printf("  file2 : query string file\n");
	exit(1);
}

int main(int argc, char* argv[])
	try
{
	argc--, argv++;
	std::string fName1;
	std::string fName2;
	std::string mode;
	int skip = 8;
	bool putHash = false;
	bool bench = false;

	while (argc > 0) {
		if (strcmp(*argv, "-c") == 0) {
			mode = *argv;
		} else
		if (strcmp(*argv, "-s") == 0) {
			mode = *argv;
		} else
		if (strcmp(*argv, "-r") == 0) {
			mode = *argv;
		} else
		if (strcmp(*argv, "-ss") == 0) {
			mode = *argv;
		} else
		if (argc > 1 && strcmp(*argv, "-skip") == 0) {
			argc--, argv++;
			skip = atoi(*argv);
		} else
		if (strcmp(*argv, "-hash") == 0) {
			putHash = true;
		} else
		if (strcmp(*argv, "-time") == 0) {
			bench = true;
		} else
		if (**argv != '-' && fName1.empty()) {
			fName1 = *argv;
		} else
		if (**argv != '-' && fName2.empty()) {
			fName2 = *argv;
		} else
		{
			usage();
		}
		argc--, argv++;
	}
	if (fName1.empty() || fName2.empty() || mode.empty()) {
		usage();
	}
	if (mode == "-c") {
		create<FMindex, String>(fName1, fName2, skip);
	} else
	if (mode == "-s") {
		search<FMindex, String>(fName1, fName2, putHash, bench);
	} else
	if (mode == "-r") {
		recover<FMindex, String>(fName1, fName2);
	} else
	if (mode == "-ss") {
		simpleSearch<String>(fName1, fName2, putHash);
	} else
	{
		usage();
	}
} catch (std::exception& e) {
	printf("ERR %s\n", e.what());
	return 1;
}


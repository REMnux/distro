#include <vector>
#include <stdio.h>
#include <cybozu/nlp/mecab.hpp>
#include <cybozu/mmap.hpp>

int main(int argc, char *argv[])
{
	argc--, argv++;
	if (argc == 0) {
		fprintf(stderr, "mecab_smpl filename\n");
		return 1;
	}
	try {
		const std::string fileName = argv[0];
		cybozu::Mmap mmap(fileName);
		if (mmap.size() > (1 << 30)) {
			fprintf(stderr, "file is too large %lld\n", (long long)mmap.size());
			return 1;
		}

		cybozu::nlp::Mecab mecab;
		typedef std::vector<std::string> StrVec;
		StrVec sv;
		if (mecab.parse(sv, mmap.get(), (int)mmap.size())) {
			for (size_t i = 0, n = sv.size(); i < n; i++) {
				printf("%s ", sv[i].c_str());
			}
			printf("\n");
		}
		return 0;
	} catch (std::exception& e) {
		fprintf(stderr, "exception %s\n", e.what());
	} catch (...) {
		fprintf(stderr, "unknown exception\n");
	}
	return 1;
}

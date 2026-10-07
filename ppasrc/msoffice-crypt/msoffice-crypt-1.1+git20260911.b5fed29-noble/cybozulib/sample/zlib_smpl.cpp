#include <cybozu/zlib.hpp>
#include <cybozu/option.hpp>
#include <cybozu/mmap.hpp>
#include <fstream>

int main(int argc, char *argv[])
	try
{
	bool doUncomp = false;
	std::string inFile;
	std::string outFile;
	cybozu::Option opt;
	opt.appendBoolOpt(&doUncomp, "d", ": uncompress");
	opt.appendParam(&inFile, "input file");
	opt.appendParam(&outFile, "output file");
	opt.appendHelp("h", ": show thismessage");
	if (!opt.parse(argc, argv)) {
		opt.usage();
		return 0;
	}
	cybozu::Mmap f(inFile);
	std::string out;
	if (doUncomp) {
		out.resize(f.size() * 10);
		size_t size = cybozu::ZlibUncompress(&out[0], out.size(), f.get(), f.size());
		out.resize(size);
	} else {
		out.resize(f.size());
		size_t size = cybozu::ZlibCompress(&out[0], out.size(), f.get(), f.size());
		if (size == 0) {
			fprintf(stderr, "not compress\n");
			return 1;
		}
		out.resize(size);
	}
	std::ofstream ofs(outFile.c_str(), std::ios::binary);
	ofs.write(out.data(), out.size());
} catch (std::exception& e) {
	fprintf(stderr, "ERR %s\n", e.what());
	return 1;
}

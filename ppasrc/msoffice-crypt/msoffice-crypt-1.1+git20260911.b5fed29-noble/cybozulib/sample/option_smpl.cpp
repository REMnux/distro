/*
	how to use
*/
#include <stdio.h>
#include <cybozu/option.hpp>
#include <vector>

int main(int argc, char *argv[])
	try
{
	int x;
	bool b;
	double d;
	std::string y;
	std::vector<int> z;
	std::vector<std::string> w;
	std::string inName;
	std::vector<std::string> r;
	std::vector<std::string> vi;
	uint64_t u;

	cybozu::Option opt;

	opt.appendOpt(&x, 5, "x", "int");
	opt.appendBoolOpt(&b, "b", "bool");
	opt.appendMust(&d, "d", "double");
	opt.appendMust(&y, "y", "string");
	opt.appendVec(&z, "z", "int int int ...");
	opt.appendVec(&w, "w", "str str str ...");
	opt.appendOpt(&u, 0, "u", "uint64 val");
	opt.appendParam(&inName, "input-file", "text file");
	opt.appendParamVec(&vi, "remains", "sss");
	opt.appendHelp("h");

	if (opt.parse(argc, argv)) {
		opt.put();
	} else {
		opt.usage();
	}
} catch (std::exception& e) {
	printf("ERR %s\n", e.what());
}

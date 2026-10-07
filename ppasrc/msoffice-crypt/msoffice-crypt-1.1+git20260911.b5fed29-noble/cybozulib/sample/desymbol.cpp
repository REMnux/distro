/*
	convert <addr> to <file:line addr>
	input stdin
	output stdout
	sudo apt-get install libbfd-dev
	build this with -lbfd
*/
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cybozu/bfd.hpp>
#include <cybozu/stacktrace.hpp>
#include <cybozu/atoi.hpp>
#include <cybozu/option.hpp>
#include <cybozu/string_operation.hpp>

/*
	find "[0x" ([0-9a-f]+) "]"
*/
const void* findAddr(const std::string& str)
{
	size_t p = str.find("[0x");
	if (p == std::string::npos) return 0;
	size_t q = str.find("]", p + 3);
	if (q == std::string::npos) return 0;
	bool b;
	size_t addr = cybozu::hextoi(&b, &str[p + 3], q - p - 3);
	if (!b) return 0;
	return (const void*)addr;
}

void decode(std::string& str, cybozu::Bfd& bfd)
{
	const void *addr = findAddr(str);
	if (addr == 0) return;
	std::string file;
	std::string func;
	int line;
	if (!bfd.getInfo(&file, &func, &line, addr)) return;
	cybozu::Demangle(func, func);
	str = file + ':' + cybozu::itoa(line) + ' ' + func + ' ' + str;
}

bool tryDecodeOnelineAndPut(const std::string& str, cybozu::Bfd& bfd)
{
	const std::string oneline = "<<<STACKTRACE>>> ";
	if (str.find(oneline) != 0) return false;
	printf("<<<STACKTRACE\n");
	std::istringstream iss(str.substr(oneline.size()));
	std::string addrStr;
	while (iss >> addrStr) {
		if (addrStr.find("0x") != 0) break;
		bool b;
		size_t addr = cybozu::hextoi(&b, &addrStr[2], addrStr.size() - 2);
		if (!b) break;
		std::string file;
		std::string func;
		int line;
		if (bfd.getInfo(&file, &func, &line, (const void*)addr)) {
			cybozu::Demangle(func, func);
			printf("%s:%d %s ", file.c_str(), line, func.c_str());
		}
		printf("%s\n", addrStr.c_str());
	}
	printf(">>>STACKTRACE\n");
	return true;
}

int main(int argc, char **argv)
	try
{
	cybozu::Option opt;
	bool doCheckAll = false;
	std::string exeName;
	std::string textName;
	opt.appendBoolOpt(&doCheckAll, "a", ": check all text");
	opt.appendOpt(&textName, "-", "f", ": text file");
	opt.appendParam(&exeName, "exe", ": exec file");
	opt.appendHelp("h", ": put this message");
	if (!opt.parse(argc, argv)) {
		opt.usage();
		return 1;
	}
	const std::string beginStackTrace = "<<<STACKTRACE";
	const std::string endStackTrace = ">>>STACKTRACE";
	bool inStackTrace = false;
	cybozu::Bfd bfd(exeName);
	std::string line;
	std::istream *pis = 0;
	std::ifstream ifs;
	if (textName == "-") {
		pis = &std::cin;
	} else {
		ifs.open(textName.c_str(), std::ios::binary);
		pis = &ifs;
	}
	fprintf(stderr, "textName=%s, exeName=%s\n", textName.c_str(), exeName.c_str());
	while (std::getline(*pis, line)) {
		cybozu::Strip(line);
		if (tryDecodeOnelineAndPut(line, bfd)) {
			continue;
		}
		bool doDecode = false;
		if (doCheckAll) {
			doDecode = true;
		} else {
			if (inStackTrace) {
				if (line.find(endStackTrace) == 0) {
					inStackTrace = false;
				} else {
					doDecode = true;
				}
			} else {
				if (line.find(beginStackTrace) == 0) {
					inStackTrace = true;
				}
			}
		}
		if (doDecode) {
			decode(line, bfd);
		}
		printf("%s\n", line.c_str());
	}
} catch (std::exception& e) {
	printf("ERR %s\n", e.what());
}

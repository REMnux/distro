/*
	how to use two step option parser
*/
#include <stdio.h>
#include <cybozu/option.hpp>
#include <vector>

struct Opt {
	// common option
	int x;
	cybozu::Option opt1;

	// cmd option
	std::string cmd;

	std::string init_s;
	double run_d;
	char status_c;
	cybozu::Option opt2;

	int parse1(int argc, char *argv[])
	{
		opt1.appendOpt(&x, 5, "x", " :value");
		opt1.appendDelimiter("init");
		opt1.appendDelimiter("run");
		opt1.appendDelimiter("status");
		opt1.appendHelp("h");
		opt1.setUsage("option2 [opt] (init|run|status)", true);

		if (!opt1.parse(argc, argv)) return false;
		const int pos = opt1.getNextPositionOfDelimiter();
		if (pos == 0) return 0;
		cmd = argv[pos - 1];
		if (cmd == "init") {
			opt2.appendOpt(&init_s, "abc", "s", " :string");
		} else if (cmd == "run") {
			opt2.appendOpt(&run_d, 1.2, "d", " :double");
		} else if (cmd == "status") {
			opt2.appendOpt(&status_c, 'X', "c", " :char");
		} else {
			return 0;
		}
		opt2.appendHelp("h");
		return pos;
	}
	void parse(int argc, char *argv[])
	{
		int pos = parse1(argc, argv);
		if (pos == 0) {
			opt1.usage();
			exit(1);
		}
		if (!opt2.parse(argc, argv, pos)) {
			opt2.usage();
			exit(1);
		}
		puts("common");
		opt1.put();
		printf("opt for %s\n", cmd.c_str());
		opt2.put();
	}
};

int main(int argc, char *argv[])
{
	Opt opt;
	opt.parse(argc, argv);
}

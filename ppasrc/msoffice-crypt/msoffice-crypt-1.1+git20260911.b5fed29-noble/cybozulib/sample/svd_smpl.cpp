#include <stdio.h>
#include <stdlib.h>
#include <cybozu/nlp/svd.hpp>
#include <cybozu/atoi.hpp>

#define USE_DOUBLE

void usage()
{
	fprintf(stderr, "svd_smpl.exe input [output] [-r rank]\n"
		"  A = U S (V^T)\n"
		"  input : input matrix A\n"
		"  output: output basename.\n"
		"          create output.[U, S, V]\n"
		"          use input if not specified\n"
		"  rank  : rank of S\n"
		"matrix data format example\n"
		"M = (1 0   3)\n"
		"    (0 4.2 0)\n"
		"(dense type)\n"
		"# M D 2 3\n"
		"1 0 3\n"
		"0 4.2 0\n"
		"\n"
		"(sparse type)\n"
		"# M S 2 3\n"
		"0:1 2:3\n"
		"1:4.2\n");
	exit(1);
}

bool Run(const std::string& input, const std::string& output, int rank)
{
#ifdef USE_DOUBLE
	Eigen::SparseMatrix<double, Eigen::RowMajor> SA;
	Eigen::MatrixXd A;
	Eigen::MatrixXd U;
	Eigen::VectorXd S;
	Eigen::MatrixXd V;
#else
	Eigen::SparseMatrix<float, Eigen::RowMajor> SA;
	Eigen::MatrixXf A;
	Eigen::MatrixXf U;
	Eigen::VectorXf S;
	Eigen::MatrixXf V;
#endif
	fprintf(stderr, "loading matrix %s\n", input.c_str());
	if (cybozu::nlp::svd::LoadSparseMatrix(SA, input)) {
		fprintf(stderr, "computing SVD\n");
		cybozu::nlp::ComputeSVD(U, S, V, SA, rank);
	} else if (cybozu::nlp::svd::LoadMatrix(A, input)) {
		fprintf(stderr, "computing SVD\n");
		cybozu::nlp::ComputeSVD(U, S, V, A, rank);
	} else {
		return false;
	}
	cybozu::nlp::svd::SaveMatrix(output + ".U", U);
	cybozu::nlp::svd::SaveVector(output + ".S", S);
	cybozu::nlp::svd::SaveMatrix(output + ".V", V);
	return true;
}

int main(int argc, char *argv[])
{
	argc--, argv++;
	std::string input;
	std::string output;
	int rank = 10;

	while (argc > 0) {
		if (argc > 1 && strcmp(*argv, "-r") == 0) {
			argc--, argv++;
			rank = cybozu::atoi(*argv);
		} else
		if (input.empty()) {
			input = *argv;
		} else
		if (output.empty()) {
			output = *argv;
		} else
		{
			usage();
		}
		argc--, argv++;
	}
	if (input.empty()) {
		usage();
	}
	if (output.empty()) {
		output = input;
	}
	fprintf(stderr, "input=%s, output=%s, rank=%d\n", input.c_str(), output.c_str(), rank);
	Run(input, output, rank);
}

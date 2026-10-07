//#define USE_REDSVD
#ifdef USE_REDSVD
#include <../redsvd-read-only/src/redsvd.hpp>
#endif
#include <iostream>
#include <stdio.h>
#include <math.h>
#include <cybozu/inttype.hpp>
#define CYBOZU_NLP_SVD_USE_RANDOM
#include <cybozu/nlp/svd.hpp>
#include <cybozu/time.hpp>

template<class Matrix>
void SetUnitary(Matrix& m)
{
	cybozu::nlp::svd::InitRandomMatrix(m);
	cybozu::nlp::svd::OrthonormalizeMatrix(m);
}

double getTime()
{
	cybozu::Time t;
	t.setCurrentTime();
	return t.getTime() + t.getMsec() * 1e-3;
}

template<class Matrix, class Vector>
void test(int row, int col, int rank, int tryRank, bool isFull)
{
	printf("(%5d, %5d, %5d, %3d, %c) ", row, col, rank, tryRank, isFull ? 'F' : '-');
	typedef typename Matrix::Scalar Double;
	int s_rank = isFull ? std::min(row, col) : rank;
	Matrix U(row, s_rank);
	Vector S(s_rank);
	Matrix V(col, s_rank);
	SetUnitary(U);
	SetUnitary(V);
	S.setZero();
	for (int i = 0; i < rank; i++) {
		S(i) = (Double)((s_rank - i) * 0.5);
	}
	if (isFull) {
		for (int i = rank; i < s_rank; i++) {
			S(i) = (Double)(0.04 * (s_rank - i));
		}
	}
	Matrix A = U * S.asDiagonal() * V.transpose();
	Matrix UO, VO;
	Vector SO;
	{
#ifdef USE_REDSVD
		double b = getTime();
		REDSVD::RedSVD redsvd;
		redsvd.run(A, tryRank);
		double e = getTime();
		printf("%6.1fmsec ", (e - b) * 1e3);
		UO = redsvd.matrixU();
		SO = redsvd.singularValues();
		VO = redsvd.matrixV();
#else
		double b = getTime();
		cybozu::nlp::ComputeSVD(UO, SO, VO, A, tryRank);
		double e = getTime();
		printf("%6.1fmsec ", (e - b) * 1e3);
#endif
	}
#if 0
	if (row * col <= 10000) {
		double b = getTime();
		Eigen::JacobiSVD<Matrix> svd(A, Eigen::ComputeThinU | Eigen::ComputeThinV);
		double e = getTime();
		printf("%.2fmsec ", (e - b) * 1e3);
	} else {
		printf("---msec ");
	}
#endif

	double diff = 0;
	for (int i = 0; i < tryRank; ++i) {
		double v = fabs(S(i) - SO(i));
		if (S(i) > 0) {
			v /= S(i);
		}
		diff += v;
	}
	diff /= tryRank;
	printf("%6.2f %6.2f %7.4f ", S(0), S(rank - 1), diff);
	printf("%f ", (A - UO * SO.asDiagonal() * VO.transpose()).norm());
	int nearNum = 0;
	int orthNum = 0;
	for (int i = 0; i < tryRank; i++) {
		double u = fabs(U.col(i).dot(UO.col(i)));
		if (u > 0.85) nearNum++;
		if (u < 0.1) orthNum++;
	}
	printf("%d %d", nearNum, orthNum);
	printf("\n");
}

int main()
{
	const struct {
		int row;
		int col;
		int rank;
		int tryRank;
	} tbl[] = {
		{ 100, 100, 10, 10 },
		{ 100, 100, 10, 9 },
		{ 100, 100, 10, 9 },
		{ 100, 100, 10, 8 },
		{ 100, 100, 10, 8 },
		{ 100, 100, 50, 50 },
		{ 100, 100, 50, 50 },
		{ 100, 100, 50, 49 },
		{ 100, 100, 50, 48 },
		{ 100, 100, 50, 10 },
		{ 300, 300, 50, 48 },
		{ 300, 300, 50, 48 },
		{ 600, 600, 100, 95 },
		{ 600, 600, 100, 95 },
		{ 1000, 1000, 10, 10 },
		{ 1000, 1000, 10, 9 },
		{ 1000, 1000, 10, 8 },
		{ 1000, 1000, 20, 20 },
		{ 1000, 1000, 20, 19 },
		{ 1000, 1000, 20, 18 },
		{ 1000, 1000, 100, 100 },
		{ 1000, 1000, 100, 99 },
		{ 1000, 1000, 100, 90 },
		{ 10000, 10000, 100, 100 },
		{ 10000, 10000, 100, 91 },
		{ 10000, 10000, 300, 100 },
		{ 10000, 10000, 1000, 100 },
	};
	printf("(  row,   col,  rank,   r, f)       msec eigen-max min  diff\n");
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		test<Eigen::MatrixXd, Eigen::VectorXd>(tbl[i].row, tbl[i].col, tbl[i].rank, tbl[i].tryRank, false);
		if (tbl[i].row <= 1000) {
			test<Eigen::MatrixXd, Eigen::VectorXd>(tbl[i].row, tbl[i].col, tbl[i].rank, tbl[i].tryRank, true);
		}
	}
}

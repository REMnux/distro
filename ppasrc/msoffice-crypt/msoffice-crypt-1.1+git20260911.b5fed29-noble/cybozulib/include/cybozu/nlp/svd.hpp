#pragma once
/**
	@file
	@brief fast non-probabilistic SVD

	@author MITSUNARI Shigeo(@herumi)
	@author MITSUNARI Shigeo
*/
#include <assert.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
//#define CYBOZU_NLP_SVD_USE_RANDOM
#ifdef CYBOZU_NLP_SVD_USE_RANDOM
#include <cybozu/nlp/random.hpp>
#endif
#ifdef _MSC_VER
	#pragma warning(push)
	#pragma warning(disable : 4714) // force inline
#endif
#define EIGEN_YES_I_KNOW_SPARSE_MODULE_IS_NOT_STABLE_YET
#include <eigen3/Eigen/Sparse>
#include <eigen3/Eigen/Dense>
#include <eigen3/Eigen/Eigenvalues>
#ifdef _MSC_VER
//	#pragma warning(pop)
#endif

/***
	text format

	Matrix(dense)
	---
	# M D <row> <col>
	data1_1 data1_2 data1_3 ...
	data2_1 data2_2 ...
	....
	---

	Matrix(sparse)
	---
	# M S <row> <col>
	c1:data1_c1 c2:data1_c2 c3:data1_c3 ...
	c1:data2_c1 c2:data2_c2 c3:data2_c3 ...
	....
	---

	ex.
	M = (1.0 2.0 3.0)
	    (1.2 2.4 3.5)
	---
	# M D 2 3
	1.0 2.0 3.0
	1.2 2.4 3.5
	---

	M = (1.0 0   3.0)
	    (0   4.2 0  )
	---
	# M S 2 3
	0:1.0 2:3.0
	1:4.2
	---
*/
namespace cybozu { namespace nlp {

namespace svd {

#ifdef CYBOZU_NLP_SVD_USE_RANDOM
template<class Matrix>
void InitRandomMatrix(Matrix& M)
{
	cybozu::nlp::NormalRandomGenerator r;
	for (int i = 0; i < M.rows(); i++) {
		for (int j = 0; j < M.cols(); j++) {
			M(i, j) = typename Matrix::Scalar(r.get());
		}
	}
}
#endif

template<class Matrix>
void InitUnitMatrix(Matrix& M)
{
	M.setZero();
	const int row = M.rows();
	const int col = M.cols();
	assert(col <= row);
#if 1
	const int adj = 0;//(col & 1) ? row/2 : 0;
	for (int i = 0; i < row; i++) {
		M(i, (i * col + adj) / row) = 1;
	}
#else
	typedef typename Matrix::Scalar Double;
	const int q0 = row / col;
	const int r0 = row % col;
	const double rcol = 1.0 / col;
	int b = 0;
	int q = q0;
	int e = r0;
	int rowIdx = 0;
	int colIdx = 0;
	for (;;) {
		if (b > 0) {
			M(rowIdx, colIdx) = Double(b * rcol);
			rowIdx++;
		}
		for (int j = 0; j < q; j++) {
			M(rowIdx, colIdx) = 1;
			rowIdx++;
		}
		if (e > 0) {
			M(rowIdx, colIdx) = Double(e * rcol);
		}
		if (colIdx == col - 1) break;
		b = e == 0 ? 0 : col - e;
		e = r0 - b;
		if (e < 0) {
			q = q0 - 1;
			e += col;
		} else {
			q = q0;
		}
		colIdx++;
	}
	assert(rowIdx == row);
#endif
}
/*
	m(row, col) => M(row, r)
	r <= col
*/
template<class Matrix1, class Matrix2>
void CompressCol(Matrix1& out, const Matrix2& m, int r)
{
	typedef typename Matrix1::Scalar Double;
	const int row = m.rows();
	const int col = m.cols();
	assert(r <= col);
	out.resize(row, r);
#if 1
	int begin = 0;
	for (int j = 0; j < r; j++) {
		int end = std::min(((j + 1) * col + r - 1) / r, col);
//		printf("%d [%d, %d)\n", j, begin, end);
		for (int i = 0; i < row; i++) {
			double x = 0;
			for (int k = begin; k < end; k++) {
				x += m(i, k);
			}
			out(i, j) = Double(x);
		}
		begin = end;
	}
#else
	const int q0 = col / r;
	const int r0 = col % r;
	const double rr = 1.0 / r;
	int b = 0;
	int q = q0;
	int e = r0;
	int colIdx = 0;
	int rIdx = 0;
	for (;;) {
		for (int i = 0; i < row; i++) {
			double x = 0;
			int k = colIdx;
			if (b > 0) {
				x += m(i, k) * b * rr;
				k++;
			}
			for (int j = 0; j < q; j++) {
				x += m(i, k);
				k++;
			}
			if (e > 0) {
				x += m(i, k) * e * rr;
			}
			out(i, rIdx) = Double(x);
		}
		if (b > 0) colIdx++;
		colIdx += q;
		if (rIdx == r - 1) break;
		b = e == 0 ? 0 : r - e;
		e = r0 - b;
		if (e < 0) {
			q = q0 - 1;
			e += r;
		} else {
			q = q0;
		}
		rIdx++;
	}
	assert(colIdx == col);
#endif
}

template<class Matrix>
void OrthonormalizeMatrix(Matrix& M)
{
	const double eps = 1e-5;
	typedef typename Matrix::Scalar Double;
	for (int i = 0; i < M.cols(); i++) {
		double norm = M.col(i).norm();
		if (norm < eps) {
			M.col(i).setZero();
		} else {
			Double rev = Double(1.0 / norm);
			M.col(i) *= rev;
			for (int j = i + 1; j < M.cols(); j++) {
				Double x = M.col(i).dot(M.col(j));
				M.col(j) -= M.col(i) * x;
			}
		}
	}
}

inline bool LoadHeader(bool *isMatrix, bool *isSparse, int *row, int *col, std::ifstream& ifs, const std::string& input)
{
	ifs.open(input.c_str(), std::ios::binary);
	if (!ifs) {
		fprintf(stderr, "can't open %s\n", input.c_str());
		return false;
	}
	std::string line;
	if (std::getline(ifs, line)) {
		std::istringstream is(line);
		char c, vec, type;
		is >> c >> vec >> type >> *row >> *col;
		if (c != '#') {
			fprintf(stderr, "top char is #(%c)\n", c);
			goto ERR;
		}
		if (*row <= 0) {
			fprintf(stderr, "row(%d) should be positive\n", *row);
			goto ERR;
		}
		if (type != 'S' && type != 'D') {
			fprintf(stderr, "type is D(dense) or S(sparse) (%c)\n", type);
			goto ERR;
		}
		*isSparse = type == 'S';
		switch (vec) {
		case 'M':
			if (*col <= 0) {
				fprintf(stderr, "col(%d) should be positive\n", *col);
				goto ERR;
			}
			*isMatrix = true;
			break;
		case 'V':
			*col = 1;
			*isMatrix = false;
			break;
		default:
			fprintf(stderr, "vec is M(matrix) or V(vector) (%c)\n", vec);
			goto ERR;
		}
		fprintf(stderr, "input (%c, %c, %d, %d)\n", vec, type, *row, *col);
		return true;
	}
ERR:
	fprintf(stderr, "bad format top line must be '# (M|V) (D|S) <row> <col>'\n");
	return false;
}

template<class Matrix>
bool LoadMatrix(Matrix& M, const std::string& input)
{
	std::ifstream ifs;
	bool isMatrix = false;
	bool isSparse = false;
	int row = 0, col = 0;
	if (!LoadHeader(&isMatrix, &isSparse, &row, &col, ifs, input) || !isMatrix) {
		return false;
	}
	M.resize(row, col);
	if (isSparse) {
		for (int i = 0; i < row; i++) {
			M.row(i).setZero();
			std::string line;
			if (!std::getline(ifs, line)) {
				fprintf(stderr, "can't read %d line\n", i);
				return false;
			}
			std::istringstream is(line);
			for (;;) {
				int idx;
				char sep;
				double v;
				is >> idx >> sep >> v;
				if (!is) break;
				if (sep != ':' || idx < 0 || idx >= col) {
					fprintf(stderr, "can't read %s\n", line.c_str());
					return false;
				}
				M(i, idx) = typename Matrix::Scalar(v);
			}
		}
	} else {
		for (int i = 0; i < row; i++) {
			for (int j = 0; j < col; j++) {
				double v;
				ifs >> v;
				if (!ifs) {
					fprintf(stderr, "can't read (%d,%d)\n", i, j);
					return false;
				}
				M(i, j) = typename Matrix::Scalar(v);
			}
		}
	}
	return true;
}

template<class Matrix>
bool LoadSparseMatrix(Matrix& M, const std::string& input)
{
	std::ifstream ifs;
	bool isMatrix = false;
	bool isSparse = false;
	int row = 0, col = 0;
	if (!LoadHeader(&isMatrix, &isSparse, &row, &col, ifs, input) || !isMatrix) {
		return false;
	}
	if (!isSparse) {
		fprintf(stderr, "ERR not sparse\n");
		return false;
	}
	M.resize(row, col);
	for (int i = 0; i < row; i++) {
		std::string line;
		if (!std::getline(ifs, line)) {
			fprintf(stderr, "can't read %d line\n", i);
			return false;
		}
		std::istringstream is(line);
		M.startVec(i);
		for (;;) {
			int idx;
			char sep;
			double v;
			is >> idx >> sep >> v;
			if (!is) break;
			if (sep != ':' || idx < 0 || idx >= col) {
				fprintf(stderr, "can't read %s\n", line.c_str());
				return false;
			}
			M.insertBack(i, idx) = typename Matrix::Scalar(v);
		}
	}
	M.finalize();
	return true;
}

template<class Vector>
bool LoadVector(Vector& V, const std::string& input)
{
	std::ifstream ifs;
	bool isMatrix = false;
	bool isSparse = false;
	int row = 0, col = 0;
	if (!LoadHeader(&isMatrix, &isSparse, &row, &col, ifs, input) || isMatrix) {
		return false;
	}
	V.resize(row, 1);
	for (int i = 0; i < row; i++) {
		double v;
		ifs >> v;
		if (!ifs) {
			fprintf(stderr, "can't read (%d)\n", i);
			return false;
		}
		V(i) = typename Vector::Scalar(v);
	}
	return true;
}

template<class Matrix>
bool SaveMatrix(const std::string& outName, const Matrix& M)
{
	std::ofstream ofs(outName.c_str(), std::ios::binary);
	ofs << std::setprecision(8);

	ofs << "# M D " << M.rows() << " " << M.cols() << std::endl;
	for (int i = 0; i < M.rows(); i++) {
		for (int j = 0; j < M.cols(); j++) {
			if (j > 0) ofs << ' ';
			ofs << M(i, j);
		}
		ofs << std::endl;
	}
	return ofs.good();
}

template<class Matrix>
bool SaveSparseMatrix(const std::string& outName, const Matrix& M)
{
	std::ofstream ofs(outName.c_str(), std::ios::binary);
	ofs << std::setprecision(8);

	ofs << "# M S " << M.rows() << " " << M.cols() << std::endl;
	for (int i = 0; i < M.outerSize(); i++) {
		bool isFirst = true;
		for (typename Matrix::InnerIterator j(M, i); j; ++j) {
			if (isFirst) {
				isFirst = false;
			} else {
				ofs << ' ';
			}
			ofs << j.col() << ':' << j.value();
		}
		ofs << std::endl;
	}
	return ofs.good();
}

template<class Vector>
bool SaveVector(const std::string& outName, const Vector& V)
{
	std::ofstream ofs(outName.c_str(), std::ios::binary);
	ofs << std::setprecision(8);
	ofs << "# V D " << V.rows() << std::endl;
	for (int i = 0; i < V.rows(); i++) {
		ofs << V(i) << std::endl;
	}
	return ofs.good();
}

} // svd

/*
	approximate singular value decomposition
	A = U S t(V) with rank r

	t(M) : transpose of M
	t(U) U = I
	t(V) V = I

	R : compressed unit matrix
	Y = t(A) R
	Y = orthonormalize(Y) ; t(Y) Y = I
	B = A Y
	Z = orthonormalize(B) ; t(Z) Z = I
	C = t(Z) B
	C = U' S t(V')
	A \simeq A Y t(Y)
	 = B t(Y)
     \simeq Z t(Z) B t(Y)
	 = Z C t(Y)
	 = Z U' S t(V') t(Y)
	 = (Z U') S t(YV')
	 = U S V
*/
template<class Matrix, class Matrix2, class Vector>
bool ComputeSVD(Matrix& U, Vector& S, Matrix& V, const Matrix2& A, int rank)
{
	const int r = std::min<int>(static_cast<int>(std::min(A.cols(), A.rows())), rank);
	if (r <= 0) return false;

#if 1
	Matrix R(A.rows(), r);
//	svd::InitRandomMatrix(R);
	svd::InitUnitMatrix(R);
	Matrix Y = A.transpose() * R;
#else
	Matrix Y;
	svd::CompressCol(Y, A.transpose(), r);
#endif
	svd::OrthonormalizeMatrix(Y);
	const Matrix B = A * Y;
	Matrix Z = B;
	svd::OrthonormalizeMatrix(Z);
	const Matrix C = Z.transpose() * B;
	const Eigen::JacobiSVD<Matrix> svd(C, Eigen::ComputeThinU | Eigen::ComputeThinV);
	U = Z * svd.matrixU();
	S = svd.singularValues();
	V = Y * svd.matrixV();
	return true;
}

} } // cybozu::nlp


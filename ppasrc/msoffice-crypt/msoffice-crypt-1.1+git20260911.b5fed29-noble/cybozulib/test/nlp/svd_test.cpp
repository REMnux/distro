/*
	A = U S t(V)
	t(U) U = I
	t(V) V = I
*/
#include <cybozu/test.hpp>
#define CYBOZU_NLP_SVD_USE_RANDOM
#include <cybozu/nlp/svd.hpp>
#include <cybozu/file.hpp>

const double defaultEPS = 1e-5;
std::string dataPath;
std::string testName;
struct InitPath {
	InitPath()
	{
		dataPath = cybozu::GetExePath();
		size_t pos = dataPath.find("cybozulib");
		if (pos == std::string::npos) {
			puts("InitPath err");
			exit(1);
		}
		dataPath = dataPath.substr(0, pos + 9) + "/bin/";
		testName = dataPath + "/svd_test.txt";
	}
};

CYBOZU_TEST_SETUP_FIXTURE(InitPath);

template<class Matrix>
void testSame(const Matrix& A, const Matrix& B)
{
	double x = (A - B).norm();
	CYBOZU_TEST_NEAR(x, 0, defaultEPS);
}

template<class Matrix, class Vector>
void testUSV(const Matrix& U, const Vector& S, const Matrix& V, const Matrix& A)
{
	const Matrix B = U * S.asDiagonal() * V.transpose();
	testSame(A, B);
}
/*
	verity t(A) A = I
*/
template<class Matrix>
void testUnitary(const Matrix& A)
{
	Matrix B = A.transpose() * A;
	Matrix I;
	I.setIdentity(B.cols(), B.cols());
	testSame(B, I);
}

template<class Matrix>
double innerProductRow(const Matrix& A, int s, int t)
{
	double ret = 0;
	for (int i = 0; i < A.cols(); i++) {
		ret += A(s, i) * A(t, i);
	}
	return ret;
}

template<class Matrix, class Vector>
double innerProductUS(const Matrix& U, const Vector& S, int s, int t)
{
	double ret = 0;
	for (int i = 0; i < U.cols(); i++) {
		double v = S(i);
		ret += v * v * U(s, i) * U(t, i);
	}
	return ret;
}

/*
	A = U S trans(V)
	m = A.rows()
	A = trans(a_1, ..., a_m), U = trans(u_1, ..., u_m)
	product(a_s, a_t) = sum_{i=0}^{U.cols()} S(i)^2 * (u_s)_i (u_t)_i
*/
template<class Matrix, class Vector>
void testProduct(const Matrix& A, const Matrix& U, const Vector& S)
{
	for (int s = 0; s < U.rows(); s++) {
		for (int t = s; t < U.rows(); t++) {
			double x = innerProductRow(A, s, t);
			double y = innerProductUS(U, S, s, t);
			CYBOZU_TEST_NEAR(x, y, defaultEPS);
		}
	}
}

template<class Matrix>
void testSVD(const Matrix& A, int m, int n, int r)
{
	Matrix U, V;
	Eigen::VectorXd S;

	cybozu::nlp::ComputeSVD(U, S, V, A, r);

	CYBOZU_TEST_EQUAL(U.rows(), m);
	CYBOZU_TEST_EQUAL(U.cols(), r);
	CYBOZU_TEST_EQUAL(S.rows(), r);
	CYBOZU_TEST_EQUAL(V.rows(), n);
	CYBOZU_TEST_EQUAL(V.cols(), r);

	testUnitary(U);
	testUnitary(V);

	testUSV(U, S, V, A);
	testProduct(A, U, S);
}

CYBOZU_TEST_AUTO(rank2)
{
	const int m = 4;
	const int n = 3;
	const int r = 2;
	Eigen::MatrixXd A(m, n);
	A << 1, 2, 3, 4,
	     5, 6, 7, 8,
	     9, 10, 11, 12;

	testSVD(A, m, n, r);
}

CYBOZU_TEST_AUTO(rank3)
{
	const int m = 4;
	const int n = 3;
	const int r = 3;
	Eigen::MatrixXd A(m, n);
	A << 1, 2, 3, 4,
	     5, 6, 7, 8,
	     9, 10, 11, 13;

	testSVD(A, m, n, r);
}

CYBOZU_TEST_AUTO(file)
{
	const int m = 3;
	const int n = 4;
	Eigen::MatrixXd A(m, n);
	cybozu::nlp::svd::InitRandomMatrix(A);
	CYBOZU_TEST_ASSERT(cybozu::nlp::svd::SaveMatrix(testName, A));
	Eigen::MatrixXd B;
	CYBOZU_TEST_ASSERT(cybozu::nlp::svd::LoadMatrix(B, testName));
	testSame(A, B);
}

CYBOZU_TEST_AUTO(file2)
{
	const std::string path = dataPath + "../sample/data/svd/";
	Eigen::MatrixXd A;
	Eigen::MatrixXd B;
	CYBOZU_TEST_ASSERT(cybozu::nlp::svd::LoadMatrix(A, path + "test1"));
	CYBOZU_TEST_ASSERT(cybozu::nlp::svd::LoadMatrix(B, path + "test2"));
	testSame(A, B);
}

CYBOZU_TEST_AUTO(sparse)
{
	const std::string path = dataPath + "../sample/data/svd/";
	Eigen::SparseMatrix<float, Eigen::RowMajor> A;
	Eigen::SparseMatrix<float, Eigen::RowMajor> B;
	CYBOZU_TEST_ASSERT(cybozu::nlp::svd::LoadSparseMatrix(A, path + "test2"));
	CYBOZU_TEST_ASSERT(cybozu::nlp::svd::SaveSparseMatrix(testName, A));
	CYBOZU_TEST_ASSERT(cybozu::nlp::svd::LoadSparseMatrix(B, testName));
	testSame(A, B);
}

CYBOZU_TEST_AUTO(random1)
{
	const int m = 10;
	const int n = 30;
	const int r = 10;
	Eigen::MatrixXd A(m, n);
	cybozu::nlp::svd::InitRandomMatrix(A);
	testSVD(A, m, n, r);
}

CYBOZU_TEST_AUTO(random2)
{
	const int m = 10;
	const int n = 30;
	const int r = 8;
	Eigen::MatrixXd A(m, n), U(m, r), V(n, r), U2, V2;
	Eigen::VectorXd S(r), S2;
	cybozu::nlp::svd::InitRandomMatrix(U);
	cybozu::nlp::svd::OrthonormalizeMatrix(U);
	cybozu::nlp::svd::InitRandomMatrix(V);
	cybozu::nlp::svd::OrthonormalizeMatrix(V);
	// descending order
	for (int i = 0; i < r; i++) {
		S(i) = r - i;
	}
	A = U * S.asDiagonal() * V.transpose();
	cybozu::nlp::ComputeSVD(U2, S2, V2, A, r);
	testUnitary(U2);
	testUnitary(V2);
	testSame(S, S2);
	testUSV(U2, S2, V2, A);
}

CYBOZU_TEST_AUTO(multiUnitMatrix)
{
	int row = 13;
	int col = 15;
	int r = 4;
	Eigen::MatrixXd R(col, r);
	cybozu::nlp::svd::InitUnitMatrix(R);
	Eigen::MatrixXd A(row, col), B;
	cybozu::nlp::svd::InitRandomMatrix(A);
	cybozu::nlp::svd::CompressCol(B, A, r);
	double diff = ((A * R) - B).norm();
	CYBOZU_TEST_NEAR(diff, 0, defaultEPS);
}

CYBOZU_TEST_AUTO(multiUnitMatrix2)
{
	int row = 13;
	int col = 15;
	int r = 5;
	Eigen::MatrixXd R(col, r);
	cybozu::nlp::svd::InitUnitMatrix(R);
	Eigen::MatrixXd A(row, col), B;
	cybozu::nlp::svd::InitRandomMatrix(A);
	cybozu::nlp::svd::CompressCol(B, A, r);
	double diff = ((A * R) - B).norm();
	CYBOZU_TEST_NEAR(diff, 0, defaultEPS);
}


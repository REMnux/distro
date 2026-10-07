#include <cybozu/test.hpp>
#include <cybozu/nlp/top_score.hpp>
#include <cybozu/file.hpp>
#include <cybozu/nlp/random.hpp>
#include <algorithm>

struct Score {
	double v_;
	int pos_;
	Score(double v = 0, int pos = 0)
		: v_(v)
		, pos_(pos)
	{
	}
	bool operator<(const Score& rhs) const
	{
		return v_ > rhs.v_;
	}
};

CYBOZU_TEST_AUTO(top_score)
{
	cybozu::nlp::UniformRandomGenerator r;
	std::vector<Score> vs;
	const int N = 100;
	const int max = 13;
	cybozu::nlp::TopScore<int> ts(max);
	for (int i = 0; i < N; i++) {
		double v = r.getDouble();
		vs.push_back(Score(v, i));
		ts.add(v, i);
	}
	std::sort(vs.begin(), vs.end());
	const cybozu::nlp::TopScore<int>::Table ret = ts.getTable();
	for (int i = 0; i < max; i++) {
		CYBOZU_TEST_EQUAL(vs[i].v_, ret[i].score);
		CYBOZU_TEST_EQUAL(vs[i].pos_, ret[i].idx);
	}
}

